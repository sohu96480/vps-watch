import importlib.util
import pathlib
import tempfile
import unittest

P = pathlib.Path(__file__).resolve().parents[1]

class DurableTests(unittest.TestCase):
    def test_failed_alert_then_recovery_survive_reload(self):
        self.assertTrue((P/'watch.py').exists(), 'watch implementation missing')
        spec=importlib.util.spec_from_file_location('watch',P/'watch.py')
        w=importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'state.json'; s=w.new_state()
            w.reconcile(s,{'disk':'disk high'},100)
            w.save(path,s); s=w.load(path)
            w.flush(s,lambda text:False,100)
            self.assertEqual(len(s['pending']),1)
            w.reconcile(s,{},110); w.save(path,s); s=w.load(path)
            sent=[]; w.flush(s,lambda text:sent.append(text) or True,131)
            self.assertEqual(len(sent),2)
            self.assertIn('恢复',sent[1]); self.assertFalse(s['pending'])
            w.reconcile(s,{},112); self.assertFalse(s['pending'])

class DetectionTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('watch',P/'watch.py')
        self.w=importlib.util.module_from_spec(spec); spec.loader.exec_module(self.w)
    def test_socks_transport_keeps_credentials_out_of_argv(self):
        import subprocess,json
        from unittest.mock import patch
        c={'name':'test','token':'private-test-token','chat_id':'123','telegram_proxy':'socks5h://192.168.0.4:7890'}
        with patch.object(self.w.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps({'ok':True,'result':{'chat':{'id':123}}}),'')) as run:
            self.assertTrue(self.w.telegram(c,'test'))
            args=run.call_args.args[0]
            self.assertEqual(args[0],'curl')
            self.assertNotIn(c['token'],str(args))
            self.assertIn(c['telegram_proxy'],run.call_args.kwargs['input'])

    def test_empty_journal_exit_one_is_not_reader_failure(self):
        import subprocess
        from unittest.mock import patch
        w=self.w
        with patch.object(w.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','')):
            self.assertEqual(w.command(['journalctl','-o','json']), '')
        with patch.object(w.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','Failed to seek cursor')):
            with self.assertRaises(RuntimeError): w.command(['journalctl','-o','json'])

    def test_cpu_three_samples_and_integrity(self):
        w=self.w
        self.assertTrue(hasattr(w,'evaluate'), 'evaluation missing')
        s={'cpu':95,'memory':12,'disk':12,'files':{'a':'new'},'services':{},'containers':{},'malware':[]}
        self.assertNotIn('cpu',w.evaluate(s,{'files':{'a':'old'}},2))
        self.assertIn('cpu',w.evaluate(s,{'files':{'a':'old'}},3))
        self.assertIn('files',w.evaluate(s,{'files':{'a':'old'}},3))
    def test_service_detection_excludes_oneshot_and_self(self):
        w=self.w
        self.assertTrue(hasattr(w,'discover'), 'discovery missing')
        def run(args, **kw):
            if 'list-units' in args:return 'sshd.service loaded active running SSH\njob.service loaded active running job\nvps-watch.service loaded active running watch'
            if 'show' in args:
                return 'Type=oneshot\nSubState=running' if 'job.service' in args else 'Type=simple\nSubState=running'
            if args[:2]==['docker','ps']: return 'web\ncache'
            return ''
        self.assertEqual(w.discover(run),{'services':['sshd.service'],'containers':['cache','web']})
    def test_ssh_empty_and_event_timestamps(self):
        w=self.w
        self.assertTrue(hasattr(w,'parse_journal'), 'journal parser missing')
        self.assertEqual(w.parse_journal('',None),([],None))
        import json
        text='\n'.join(json.dumps(x) for x in [
          {'__CURSOR':'a','__REALTIME_TIMESTAMP':'1000000','MESSAGE':'Accepted publickey for user from 1.2.3.4'},
          {'__CURSOR':'b','__REALTIME_TIMESTAMP':'2000000','MESSAGE':'Failed password for user'},
          {'__CURSOR':'c','MESSAGE':'unrelated'}])
        events,cursor=w.parse_journal(text,None)
        self.assertEqual(cursor,'c'); self.assertEqual(len(events),1)
        self.assertIn('1970-',events[0]); self.assertIn('SSH 登录成功',events[0]); self.assertNotIn('失败',events[0])

    def test_failed_ssh_is_silent_but_advances_cursor(self):
        import json
        text=json.dumps({'__CURSOR':'failed','MESSAGE':'Failed password for root'})
        self.assertEqual(self.w.parse_journal(text,None),([], 'failed'))

    def test_each_success_gets_one_notification_without_key_material(self):
        import json
        rows=[{'__CURSOR':str(i),'__REALTIME_TIMESTAMP':'1000000',
               'MESSAGE':'Accepted publickey for root from 1.2.3.4 port 123 ssh2: ED25519 SECRET-FINGERPRINT'} for i in range(2)]
        events,cursor=self.w.parse_journal('\n'.join(map(json.dumps,rows)),None)
        self.assertEqual(len(events),2)
        self.assertIn('root',events[0]); self.assertIn('1.2.3.4',events[0])
        self.assertNotIn('SECRET-FINGERPRINT',events[0])

    def test_cli_baseline_requires_confirm_and_never_overwrites(self):
        import subprocess,os,json
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d); cfg=root/'etc/vps-watch/config.json'; cfg.parent.mkdir(parents=True)
            cfg.write_text(json.dumps({'name':'fixture','token':'not-real','chat_id':'1','services':[],'containers':[]}))
            env=dict(os.environ,VPS_WATCH_ROOT=d)
            def cli(*args):return subprocess.run(['python3',str(P/'watch.py'),*args],env=env,capture_output=True,text=True)
            self.assertEqual(cli('--init').returncode,0)
            baseline=root/'var/lib/vps-watch/baseline.json'; old=baseline.read_bytes()
            self.assertNotEqual(cli('--init').returncode,0); self.assertEqual(old,baseline.read_bytes())
            self.assertNotEqual(cli('--accept-baseline').returncode,0)
            self.assertEqual(cli('--accept-baseline','--confirm').returncode,0)
    def test_reminders_and_retry_backoff(self):
        w=self.w; s=w.new_state(); w.reconcile(s,{'x':'high'},10)
        w.flush(s,lambda text:False,10)
        calls=[]; w.flush(s,lambda text:calls.append(text) or True,11); self.assertFalse(calls)
        w.flush(s,lambda text:calls.append(text) or True,30); self.assertEqual(len(calls),1)
        w.reconcile(s,{'x':'high'},909); self.assertFalse(s['pending'])
        w.reconcile(s,{'x':'high'},910); self.assertEqual(len(s['pending']),1)

    def test_empty_initial_journal_does_not_skip_first_events(self):
        w=self.w; state=w.new_state(); calls=[]
        outputs=['', '{"__CURSOR":"a","__REALTIME_TIMESTAMP":"1000000","MESSAGE":"Accepted publickey"}']
        def cmd(args,**kw):calls.append(args); return outputs.pop(0)
        w.command=cmd
        w.journal(state); w.journal(state)
        self.assertEqual(len(state['pending']),1)
        self.assertIn('--since',calls[1]); self.assertNotIn('--grep',calls[1])
    def test_telegram_rejects_wrong_chat_and_api_false(self):
        w=self.w
        import io,json
        from unittest.mock import patch
        c={'name':'fixture','token':'fixture-only','chat_id':'123'}
        for result,expected in [({'ok':True,'result':{'chat':{'id':123}}},True),({'ok':True,'result':{'chat':{'id':999}}},False),({'ok':False},False)]:
            with patch.object(w.urllib.request,'urlopen',return_value=io.BytesIO(json.dumps(result).encode())):
                self.assertEqual(w.telegram(c,'test'),expected)
    def test_once_real_subprocess_fake_host_health(self):
        import os,json,subprocess
        with tempfile.TemporaryDirectory() as d:
            r=pathlib.Path(d)
            def put(name,text):
                p=r/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
            put('etc/vps-watch/config.json',json.dumps({'name':'fixture','token':'not-real','chat_id':'1','services':[],'containers':[]}))
            put('proc/stat','cpu 1 2 3 100 0 0 0 0\n')
            put('proc/meminfo','MemTotal: 1000 kB\nMemAvailable: 900 kB\n')
            put('bin/journalctl','#!/bin/sh\nexit 0\n'); (r/'bin/journalctl').chmod(0o755)
            env=dict(os.environ,VPS_WATCH_ROOT=d,PATH=str(r/'bin')+':'+os.environ['PATH'])
            for flag in ('--init','--once'):
                result=subprocess.run(['python3',str(P/'watch.py'),flag],env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            h=json.loads((r/'var/lib/vps-watch/health.json').read_text())
            self.assertTrue(h['ok']); self.assertEqual(h['pending'],0)

if __name__=='__main__': unittest.main()
