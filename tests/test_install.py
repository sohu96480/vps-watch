import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

P=Path(__file__).resolve().parents[1]

class InstallTests(unittest.TestCase):
    def test_proxy_default_preserve_and_validation(self):
        import installer as m
        base={'token':'fixture','chat_id':'1','name':'test'}
        self.assertEqual(m.validated_config(dict(base))['telegram_proxy'],'')
        for proxy in ('','socks5h://127.0.0.1:7890','socks5://user:pass@host:1080'):
            self.assertEqual(m.validated_config(dict(base,telegram_proxy=proxy))['telegram_proxy'],proxy)
        for proxy in ('http://host:80','socks5h://host','socks5h://host:bad',None):
            with self.assertRaises(ValueError):m.validated_config(dict(base,telegram_proxy=proxy))

    def test_proxy_prompt(self):
        import installer as m
        import io
        from unittest.mock import patch
        class Terminal(io.StringIO):
            def write(self, text): return len(text)
        self.assertEqual(m.prompt_proxy(Terminal('\n')),'')
        with patch.object(m.getpass,'getpass',return_value='socks5h://127.0.0.1:7890') as secret:
            self.assertEqual(m.prompt_proxy(Terminal('y\n')),'socks5h://127.0.0.1:7890')
            secret.assert_called_once()
        with patch.object(m.getpass,'getpass',side_effect=['http://host:80','socks5h://host:1080']):
            self.assertEqual(m.prompt_proxy(Terminal('y\n')),'socks5h://host:1080')

    def test_dry_run_supported_no_writes(self):
        self.assertTrue((P/'install.sh').exists(),'installer missing')
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); (r/'etc').mkdir(); (r/'etc/os-release').write_text('ID=debian\n'); (r/'run/systemd/system').mkdir(parents=True)
            before=sorted(str(x.relative_to(r)) for x in r.rglob('*'))
            result=subprocess.run(['bash',str(P/'install.sh'),'--dry-run'],env=dict(os.environ,VPS_WATCH_ROOT=d),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('DRY RUN',result.stdout)
            self.assertEqual(before,sorted(str(x.relative_to(r)) for x in r.rglob('*')))
    def test_reject_openwrt_before_changes(self):
        self.assertTrue((P/'install.sh').exists(),'installer missing')
        with tempfile.TemporaryDirectory() as d:
            r=Path(d); (r/'etc').mkdir(); (r/'etc/os-release').write_text('ID=openwrt\n')
            result=subprocess.run(['bash',str(P/'install.sh'),'--dry-run'],env=dict(os.environ,VPS_WATCH_ROOT=d),capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0); self.assertIn('OpenWrt',result.stderr)
            self.assertFalse((r/'opt').exists())
    def test_update_preserves_config_baseline_and_rollback(self):
        self.assertTrue((P/'installer.py').exists(),'transaction implementation missing')
        spec=importlib.util.spec_from_file_location('installer',P/'installer.py'); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); c=root/'etc/vps-watch/config.json'; c.parent.mkdir(parents=True)
            old={'token':'fixture-token','chat_id':'1','name':'old','services':['x.service'],'containers':['x']}; c.write_text(json.dumps(old))
            state=root/'var/lib/vps-watch'; state.mkdir(parents=True); (state/'baseline.json').write_text('{"files":{"old":"hash"}}')
            code=root/'opt/vps-watch'; code.mkdir(parents=True); (code/'watch.py').write_text('previous')
            m.deploy(P,root,dict(old,name='changed'),lambda:True)
            self.assertEqual(json.loads((state/'baseline.json').read_text()),{'files':{'old':'hash'}})
            self.assertEqual(json.loads(c.read_text())['services'],['x.service'])
            self.assertEqual(c.stat().st_mode & 0o777,0o600)
            previous=(code/'watch.py').read_bytes(); config=c.read_bytes()
            with self.assertRaises(RuntimeError):m.deploy(P,root,old,lambda:False)
            self.assertEqual((code/'watch.py').read_bytes(),previous); self.assertEqual(c.read_bytes(),config)
            self.assertTrue(list((root/'var/backups/vps-watch').iterdir()))

if __name__=='__main__':unittest.main()
