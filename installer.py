#!/usr/bin/env python3
"""Installer transaction; invoked by install.sh after platform/dependency checks."""
import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import watch


def deploy(source, root, config, start):
    root, source = Path(root), Path(source)
    paths = ['opt/vps-watch','etc/vps-watch','etc/systemd/system/vps-watch.service']
    backup = root/'var/backups/vps-watch'/('%s-%s' % (time.strftime('%Y%m%d-%H%M%S'),uuid.uuid4().hex[:8]))
    backup.mkdir(parents=True,mode=0o700)
    existed = {}
    for rel in paths + ['var/lib/vps-watch']:
        target = root/rel; existed[rel] = target.exists()
        if target.exists():
            dest = backup/rel; dest.parent.mkdir(parents=True,exist_ok=True)
            if target.is_dir(): shutil.copytree(target,dest,symlinks=True)
            else: shutil.copy2(target,dest)
    try:
        app = root/'opt/vps-watch'; app.mkdir(parents=True,exist_ok=True)
        for name in ('watch.py','installer.py','install.sh','vps-watch.service'):
            shutil.copy2(source/name,app/name)
        watch.save(root/'etc/vps-watch/config.json',config)
        (root/'etc/vps-watch').chmod(0o700)
        unit = root/'etc/systemd/system/vps-watch.service'; unit.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source/'vps-watch.service',unit); unit.chmod(0o644)
        state = root/'var/lib/vps-watch'; state.mkdir(parents=True,exist_ok=True,mode=0o700); state.chmod(0o700)
        if not start(): raise RuntimeError('service startup/health failed')
    except Exception:
        # Preserve current state: rolling it back loses queued events and SSH cursors.
        for rel in paths:
            target = root/rel
            if target.is_dir(): shutil.rmtree(target)
            elif target.exists(): target.unlink()
            if existed[rel]:
                previous = backup/rel; target.parent.mkdir(parents=True,exist_ok=True)
                if previous.is_dir(): shutil.copytree(previous,target,symlinks=True)
                else: shutil.copy2(previous,target)
        raise
    return backup


def validate_proxy(value):
    if not isinstance(value, str): raise ValueError('telegram_proxy must be a string')
    if not value: return value
    try:
        from urllib.parse import urlsplit
        url = urlsplit(value)
        if (url.scheme not in ('socks5h', 'socks5') or not url.hostname or
                not url.port or url.path or url.query or url.fragment or
                any(c.isspace() for c in value)):
            raise ValueError()
    except ValueError:
        raise ValueError('代理格式错误：请填 socks5h://地址:端口 或 socks5://地址:端口（可含 URL 编码的认证信息）') from None
    return value


def prompt_proxy(tty):
    while True:
        tty.write('Telegram 通知是否使用 SOCKS5 代理？[y/N]: '); tty.flush()
        answer = tty.readline()
        if not answer: raise EOFError('代理输入中断，未执行部署')
        answer = answer.strip().lower()
        if answer in ('', 'n', 'no'): return ''
        if answer not in ('y', 'yes'):
            tty.write('请输入 y 或 n。\n'); continue
        while True:
            value = getpass.getpass('代理地址（隐藏输入，例如 socks5h://127.0.0.1:7890）: ', stream=tty).strip()
            try:
                if not value: raise ValueError('已选择使用代理，请输入地址。')
                return validate_proxy(value)
            except ValueError as error:
                tty.write(str(error)+'\n'); tty.flush()


def ask_change(tty, label):
    while True:
        tty.write('是否修改'+label+'？[y/N，回车保留]: '); tty.flush()
        answer=tty.readline()
        if not answer: raise EOFError('配置输入中断，未执行部署')
        answer=answer.strip().lower()
        if answer in ('','n','no'): return False
        if answer in ('y','yes'): return True
        tty.write('请输入 y 或 n。\n')


def prompt_update(config, tty):
    config=dict(config)
    tty.write('已检测到旧配置；以下逐项选择，默认保留。Token 和代理凭据不回显。\n')
    for key,label in [('name','主机名称'),('token','Bot Token'),('chat_id','Chat ID'),('telegram_proxy','SOCKS5 代理设置')]:
        if not ask_change(tty,label): continue
        if key=='telegram_proxy':
            config[key]=prompt_proxy(tty)
            continue
        while True:
            if key=='name':
                tty.write('新主机名称: '); tty.flush(); raw=tty.readline()
                if not raw: raise EOFError('配置输入中断')
                value=raw.strip()
            else:
                value=getpass.getpass('新'+label+'（隐藏输入）: ',stream=tty).strip()
            if not value:
                tty.write('不能为空，请重新输入。\n'); continue
            if key=='chat_id' and not value.lstrip('-').isdigit():
                tty.write('Chat ID 必须是数字，可带负号。\n'); continue
            config[key]=value; break
    return config


def validated_config(config):
    if not isinstance(config,dict): raise ValueError('config must be an object')
    for key in ('token','chat_id','name'):
        if not str(config.get(key,'')).strip(): raise ValueError('missing '+key)
    config['chat_id'] = str(config['chat_id'])
    if not config['chat_id'].lstrip('-').isdigit(): raise ValueError('chat_id must be numeric Telegram chat id')
    for key in ('services','containers'):
        config.setdefault(key,[])
        if not isinstance(config[key],list) or not all(isinstance(x,str) and x and not x.startswith('-') for x in config[key]):
            raise ValueError('invalid target list: '+key)
    config['telegram_proxy'] = validate_proxy(config.get('telegram_proxy', ''))
    return config


def main():
    p=argparse.ArgumentParser(description='Manual installer; no automatic updates')
    p.add_argument('--config',type=Path); p.add_argument('--name')
    p.add_argument('--rediscover',action='store_true'); p.add_argument('--replace-targets',action='store_true')
    p.add_argument('--confirm-replace-targets',action='store_true')
    p.add_argument('--dry-run',action='store_true')
    p.add_argument('--non-interactive',action='store_true',help='preserve existing configuration without prompts')
    args=p.parse_args()
    if args.dry_run: print('DRY RUN: no writes'); return 0
    if os.geteuid()!=0: raise RuntimeError('root required')
    if os.environ.get('VPS_WATCH_ROOT','/')!='/': raise RuntimeError('prefixed root: use isolated deploy() tests')
    if watch.command(['systemctl','is-active','baisi-watch.service'],allow_failure=True)=='active':
        raise RuntimeError('baisi-watch running; aborting duplicate monitor')
    path=Path('/etc/vps-watch/config.json'); fresh=not path.exists()
    if not fresh:
        config=watch.load(path)  # --config never silently replaces an existing configuration.
        if not args.non_interactive:
            try: tty=open('/dev/tty','r+')
            except OSError:
                print('无交互终端：保留已有配置。')
            else:
                with tty: config=prompt_update(config,tty)
    elif args.config:
        st=args.config.stat()
        if st.st_uid!=0 or st.st_mode & 0o077: raise RuntimeError('--config must be root owned and mode 600')
        config=watch.load(args.config)
    else:
        if args.non_interactive: raise RuntimeError('首次非交互安装必须提供 --config 私有配置文件')
        with open('/dev/tty','r+') as tty:
            tty.write('主机标签: '); tty.flush(); name=tty.readline().strip()
            token=getpass.getpass('Telegram bot token: ',stream=tty)
            chat=getpass.getpass('Telegram numeric chat ID: ',stream=tty)
            proxy=prompt_proxy(tty)
        config={'name':name,'token':token,'chat_id':chat,'telegram_proxy':proxy}
    if args.name: config['name']=args.name
    elif not config.get('name'):
        with open('/dev/tty','r+') as tty:
            tty.write('主机标签: '); tty.flush(); config['name']=tty.readline().strip()
    if args.replace_targets and not (args.rediscover and args.confirm_replace_targets):
        raise RuntimeError('replacement requires --rediscover --replace-targets --confirm-replace-targets after review')
    if fresh or args.rediscover:
        found=watch.discover()
        print('Discovered targets (review): '+json.dumps(found,ensure_ascii=False))
        for key in ('services','containers'):
            config[key]=found[key] if args.replace_targets else sorted(set(config.get(key,[])) | set(found[key]))
    config=validated_config(config)
    enabled=watch.command(['systemctl','is-enabled','vps-watch.service'],allow_failure=True)=='enabled'
    existed=Path('/opt/vps-watch/watch.py').exists()
    watch.command(['systemctl','stop','vps-watch.service'],allow_failure=True)
    def start():
        watch.command(['systemctl','daemon-reload'])
        watch.command(['systemctl','enable','vps-watch.service'])
        baseline=Path('/var/lib/vps-watch/baseline.json')
        if not baseline.exists():
            if not fresh: raise RuntimeError('existing installation has no baseline: review and initialize explicitly')
            watch.command(['/usr/bin/python3','-B','/opt/vps-watch/watch.py','--init'])
        watch.command(['systemctl','restart','vps-watch.service'])
        before=None
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            time.sleep(5)
            info=dict(line.split('=',1) for line in watch.command(['systemctl','show','vps-watch.service','-p','MainPID','-p','NRestarts','-p','ActiveState']).splitlines() if '=' in line)
            h=Path('/var/lib/vps-watch/health.json')
            health=watch.load(h) if h.exists() else {}
            current=(info.get('MainPID'), info.get('NRestarts'))
            if info.get('ActiveState')!='active' or current[0] in ('0',None): continue
            if str(health.get('pid')) != current[0]: continue
            if before and before[0]==current and health.get('checked_at',0)>before[1] and health.get('ok') is True: return True
            if health.get('ok') is True: before=(current,health['checked_at'])
        return False
    try:
        backup=deploy(Path(__file__).parent,Path('/'),config,start)
    except Exception:
        watch.command(['systemctl','stop','vps-watch.service'],allow_failure=True)
        watch.command(['systemctl','daemon-reload'],allow_failure=True)
        if not enabled: watch.command(['systemctl','disable','vps-watch.service'],allow_failure=True)
        if existed: watch.command(['systemctl','restart','vps-watch.service'],allow_failure=True)
        raise RuntimeError('Install failed; code/unit/config rolled back. Inspect systemctl status/journal; backup retained.') from None
    print('Local installation healthy; backup: '+str(backup))
    if not watch.telegram(config,'🧪 安装/手动更新验证：真实 Telegram 投递测试。'):
        print('ERROR: installed locally but Telegram NOT VERIFIED; credentials/network/chat permissions need repair.')
        return 2
    print('Telegram actual send and destination chat id verified. Baseline preserved; review code-change alerts.')
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as e:
        # Explicit installer errors are sanitized; do not print config or URLs.
        print('ERROR: '+str(e) if isinstance(e,(RuntimeError,ValueError)) else 'ERROR: installer '+type(e).__name__)
        raise SystemExit(1)
