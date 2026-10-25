#!/usr/bin/env python3
"""Notify-only host watcher. Python 3.9+, standard library only."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request

ROOT = Path(os.environ.get('VPS_WATCH_ROOT', '/'))

def rooted(p):
    return ROOT / p.lstrip('/')

def load(path):
    return json.loads(Path(path).read_text())

def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.new')
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, ensure_ascii=False)
        f.flush(); os.fsync(f.fileno())
    os.chmod(temp, 0o600)
    os.replace(temp, path)

def new_state():
    return {'alerts': {}, 'pending': [], 'cursor': None, 'high': 0, 'previous': None}

def reconcile(state, problems, now):
    alerts = state['alerts']
    for key, text in problems.items():
        if key not in alerts or now - alerts[key]['queued'] >= 900:
            state['pending'].append({'text': '🚨 异常\n' + text, 'due': now, 'tries': 0})
            alerts[key] = {'queued': now, 'text': text}
    for key in list(alerts):
        if key not in problems:
            state['pending'].append({'text': '✅ 恢复\n' + alerts.pop(key)['text'], 'due': now, 'tries': 0})

def flush(state, send, now, persist=lambda: None):
    # FIFO retains alert-before-recovery order across network failure/restart.
    while state['pending']:
        item = state['pending'][0]
        if item['due'] > now:
            break
        if not send(item['text']):
            item['tries'] += 1
            item['due'] = now + min(300, 5 * 2 ** min(item['tries'], 6))
            persist(); break
        state['pending'].pop(0); persist()

def command(args, allow_failure=False):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        if allow_failure: return ''
        raise RuntimeError('command unavailable: ' + args[0]) from None
    # journalctl returns 1 for an empty matching interval on some versions.
    empty_journal = args[0] == 'journalctl' and r.returncode == 1 and not r.stdout.strip() and not r.stderr.strip()
    if r.returncode and not allow_failure and not empty_journal:
        raise RuntimeError('command failed: ' + args[0])
    return r.stdout.strip()

def telegram(config, text):
    stamp = datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    body = urllib.parse.urlencode({'chat_id': config['chat_id'], 'text':
        (config['name'] + '\n' + stamp + '\n' + text)[:3900], 'disable_web_page_preview': 'true'}).encode()
    req = urllib.request.Request('https://api.telegram.org/bot' + config['token'] + '/sendMessage', data=body)
    try:
        if config.get('telegram_proxy'):
            proxy = config['telegram_proxy']
            if urllib.parse.urlsplit(proxy).scheme not in ('socks5h', 'socks5'):
                return False
            # Pass token-bearing URL via stdin, never process arguments.
            options = {'url':'https://api.telegram.org/bot'+config['token']+'/sendMessage',
                       'proxy':proxy,'data':body.decode()}
            curl_config = '\n'.join(k+' = '+json.dumps(v) for k,v in options.items())+'\n'
            result = subprocess.run(['curl','--silent','--show-error','--fail','--connect-timeout','5','--max-time','15','--config','-'],
                                    input=curl_config,capture_output=True,text=True,timeout=18)
            if result.returncode: return False
            data = json.loads(result.stdout)
        else:
            with urllib.request.urlopen(req, timeout=12) as response:
                data = json.load(response)
        return (data.get('ok') is True and
                str(data.get('result', {}).get('chat', {}).get('id')) == str(config['chat_id']))
    except Exception:
        # Never log URL/exception body: Telegram embeds credentials in URLs.
        return False

def discover(run=command):
    services = []
    for line in run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain']).splitlines():
        parts = line.split()
        if not parts: continue
        name = parts[0]
        if name in ('vps-watch.service', 'baisi-watch.service'): continue
        props = dict(x.split('=', 1) for x in run(['systemctl', 'show', name, '-p', 'Type', '-p', 'SubState']).splitlines() if '=' in x)
        if props.get('Type') != 'oneshot' and props.get('SubState') == 'running': services.append(name)
    containers = run(['docker', 'ps', '--format', '{{.Names}}'], allow_failure=True).splitlines()
    return {'services': sorted(set(services)), 'containers': sorted(set(containers))}

def fingerprints():
    paths = set()
    dirs = ['/etc/systemd/system', '/lib/systemd/system', '/usr/lib/systemd/system',
            '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly',
            '/var/spool/cron', '/etc/ssh', '/root/.ssh', '/etc/sudoers.d', '/etc/profile.d', '/opt/vps-watch']
    for folder in dirs:
        p = rooted(folder)
        if p.exists(): paths.update(x for x in p.rglob('*') if x.is_file() or x.is_symlink())
    for name in ['/etc/crontab', '/etc/rc.local', '/etc/ld.so.preload', '/etc/passwd', '/etc/shadow',
                 '/etc/group', '/etc/gshadow', '/etc/sudoers', '/etc/vps-watch/config.json']:
        paths.add(rooted(name))
    result = {}
    for path in paths:
        key = '/' + str(path.relative_to(ROOT))
        try:
            st = path.lstat()
            prefix = '%s:%s:%s:' % (st.st_mode, st.st_uid, st.st_gid)
            if path.is_symlink(): value = 'link:' + os.readlink(path)
            else:
                digest = hashlib.sha256()
                with path.open('rb') as f:
                    for chunk in iter(lambda: f.read(65536), b''): digest.update(chunk)
                value = digest.hexdigest()
            result[key] = prefix + value
        except FileNotFoundError: result[key] = 'missing'
    return result

def sample(config, previous):
    cpu = list(map(int, rooted('/proc/stat').read_text().splitlines()[0].split()[1:]))
    total, idle = sum(cpu[:8]), cpu[3] + cpu[4]
    used = 0 if previous is None else 100 * (1 - (idle-previous[1])/max(1,total-previous[0]))
    mem = {line.split(':')[0]: int(line.split()[1]) for line in rooted('/proc/meminfo').read_text().splitlines()}
    fs = os.statvfs(ROOT)
    disk = 100 * (fs.f_blocks-fs.f_bfree)/max(1,fs.f_blocks-fs.f_bfree+fs.f_bavail)
    services = {n: command(['systemctl','is-active',n],allow_failure=True) or 'missing' for n in config['services']}
    containers = {n: command(['docker','inspect','--format','{{.State.Status}}',n],allow_failure=True) or 'missing' for n in config['containers']}
    bad = []
    for proc in rooted('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            name = (proc/'comm').read_text().strip()
            exe = os.readlink(proc/'exe')
            if name.lower() in ('ksysrqd','xmrig','xm64_hv','defunct','[slub_flushwq]') or '/.xhv/' in exe or exe.split(' (deleted)')[0] == '/usr/bin/defunct':
                bad.append('PID '+proc.name+' 特征匹配')
        except (FileNotFoundError, ProcessLookupError, PermissionError): pass
    for name in ['/root/.xhv','/usr/bin/defunct','/lib/systemd/system/defunct.dat']:
        if rooted(name).exists(): bad.append(name)
    return {'cpu':used,'memory':100*(1-mem['MemAvailable']/mem['MemTotal']), 'disk':disk,
            'services':services,'containers':containers,'malware':bad,'files':fingerprints()}, [total,idle]

def evaluate(s, baseline, high):
    problems = {}
    if high >= 3: problems['cpu'] = 'CPU 连续3个采样 >=90%%: %.1f%%' % s['cpu']
    for name in ('memory','disk'):
        if s[name] >= 90: problems[name] = name+' >=90%%: %.1f%%' % s[name]
    for name,status in s['services'].items():
        if status != 'active': problems['service:'+name] = '服务 '+name+': '+status
    for name,status in s['containers'].items():
        if status != 'running': problems['container:'+name] = '容器 '+name+': '+status
    if s['malware']: problems['malware'] = '已知恶意特征匹配（需核实）: '+', '.join(s['malware'])
    changed = sorted(k for k in set(s['files']) | set(baseline['files']) if s['files'].get(k) != baseline['files'].get(k))
    if changed: problems['files'] = '完整性变化，需人工审核，不代表必然入侵（仅路径）: '+', '.join(changed[:25])
    return problems

def parse_journal(text, cursor):
    events = []
    for line in text.splitlines():
        if not line.startswith('{'): continue
        row = json.loads(line)
        cursor = row.get('__CURSOR', cursor)
        msg = row.get('MESSAGE','')
        if not isinstance(msg,str) or not msg.startswith('Accepted '): continue
        stamp = datetime.datetime.fromtimestamp(int(row.get('__REALTIME_TIMESTAMP','0'))/1000000, datetime.timezone.utc).isoformat()
        # One authentication event per notification; omit key fingerprints.
        detail = msg.split(' ssh2', 1)[0]
        events.append('🔐 SSH 登录成功\n' + detail[:450] + '\n事件时间 ' + stamp)
    return events, cursor

def journal(state):
    # Unfiltered global cursor prevents gaps when ssh service names or sshd COMM change.
    # COMM filters match both old sshd and modern sshd-session, no --grep.
    if not state.get('cursor') and not state.get('journal_since'):
        # Remember the lower bound BEFORE reading an empty journal.
        state['journal_since'] = time.time()
        text = command(['journalctl','-n','1','-o','json','--no-pager'])
        _, state['cursor'] = parse_journal(text, None)
        return
    args = ['journalctl','--no-pager','-o','json','--show-cursor']
    if state.get('cursor'): args += ['--after-cursor',state['cursor']]
    else: args += ['--since','@'+str(state['journal_since'])]
    args += ['_COMM=sshd','_COMM=sshd-session']
    text = command(args)
    events,cursor = parse_journal(text,state['cursor'])
    state['cursor'] = cursor
    for event in events: state['pending'].append({'text':event,'due':time.time(),'tries':0})

def main():
    p = argparse.ArgumentParser(description='Notify-only VPS watcher; no claim of a clean host')
    modes=p.add_mutually_exclusive_group()
    for flag in ('once','test','init','exercise','accept-baseline'):
        modes.add_argument('--'+flag,action='store_true')
    p.add_argument('--confirm',action='store_true',help='explicitly accept reviewed integrity changes')
    args=p.parse_args()
    config=load(rooted('/etc/vps-watch/config.json'))
    directory=rooted('/var/lib/vps-watch'); directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    baselinepath=directory/'baseline.json'
    if args.test: return 0 if telegram(config,'🧪 真实通知测试（非故障）') else 2
    import fcntl
    lock=(directory/'watch.lock').open('a')
    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: raise RuntimeError('another watcher is active; stop service before changing state/baseline') from None
    if args.init or args.accept_baseline:
        if args.init and ROOT == Path('/') and command(['systemctl','is-enabled','vps-watch.service'],allow_failure=True) != 'enabled':
            raise RuntimeError('enable vps-watch.service before initializing baseline')
        if args.init and baselinepath.exists(): raise RuntimeError('baseline exists: never silently overwrite')
        if args.accept_baseline and not args.confirm: raise RuntimeError('review changes first; --accept-baseline requires --confirm; this does not certify a clean host')
        if args.accept_baseline and baselinepath.exists():
            save(directory/('baseline-before-'+str(time.time_ns())+'.json'),load(baselinepath))
        save(baselinepath,{'files':fingerprints(),'accepted_at':time.time()})
        print('Baseline recorded; change detection only, NOT a clean-system attestation.')
        return 0
    statepath=directory/'state.json'
    state=load(statepath) if statepath.exists() else new_state()
    persist=lambda:save(statepath,state)
    if args.exercise:
        for text in ('🧪 演练异常（非实际故障）','🧪 演练恢复（非实际故障）'):
            state['pending'].append({'text':text,'due':time.time(),'tries':0})
        persist(); flush(state,lambda text:telegram(config,text),time.time(),persist)
        return 0 if not state['pending'] else 2
    if not baselinepath.exists(): raise RuntimeError('baseline missing; enable unit then explicitly --init after review')
    while True:
        start=time.monotonic(); now=time.time()
        try:
            snap,previous=sample(config,state.get('previous'))
            state['previous']=previous
            state['high']=state.get('high',0)+1 if snap['cpu']>=90 else 0
            problems=evaluate(snap,load(baselinepath),state['high'])
            if rooted('/etc/vps-watch/test.flag').exists(): problems['exercise']='🧪 无害标记演练，非真实故障'
            if now>=state.get('journal_due',0):
                journal(state); state['journal_due']=now+30
            reconcile(state,problems,now)
            persist()  # Persist cursor AND pending events together before any network send.
            flush(state,lambda text:telegram(config,text),time.time(),persist)
            save(directory/'health.json',{'ok':True,'checked_at':now,'pid':os.getpid(),
                'pending':len(state['pending']),'problems':list(problems),
                'cpu':snap['cpu'],'memory':snap['memory'],'disk':snap['disk']})
            print('check complete pending='+str(len(state['pending'])),flush=True)
        except Exception as e:
            text='监控检查失败: '+type(e).__name__+'（请查看本地服务/日志/基线权限）'
            # Do not turn monitoring errors into false recoveries for existing alerts.
            existing={k:v['text'] for k,v in state['alerts'].items()}
            existing['monitor']=text; reconcile(state,existing,now); persist()
            flush(state,lambda text:telegram(config,text),time.time(),persist)
            save(directory/'health.json',{'ok':False,'checked_at':now,'pid':os.getpid(),'error':type(e).__name__,'pending':len(state['pending'])})
            print(text,flush=True)
            if args.once: return 1
        if args.once: return 0
        time.sleep(max(0.1,10-(time.monotonic()-start)))

if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as e:
        print('ERROR: '+str(e) if isinstance(e,RuntimeError) else 'ERROR: '+type(e).__name__)
        raise SystemExit(1)
