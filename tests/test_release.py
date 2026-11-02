from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from privacy_guard import audit
from render_routeros import render

class ReleaseTests(unittest.TestCase):
    def test_runtime_file_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'access-token').write_text('private')
            with self.assertRaises(ValueError):audit(p)
    def test_default_dns_script_has_no_plaintext_fallback(self):
        script,_=render('192.0.2.2');self.assertNotIn('netwatch add',script);self.assertIn('verify-doh-cert=yes',script)
    def test_fallback_requires_explicit_resolver_choice(self):
        script,_=render('192.0.2.2',['9.9.9.9']);self.assertIn('netwatch add',script);self.assertIn('ordinary DNS fallback active',script)
    def test_router_script_injection_rejected(self):
        with self.assertRaises(ValueError):render('192.0.2.2; /system reboot')

if __name__=='__main__':unittest.main()
