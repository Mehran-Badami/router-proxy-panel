import copy
import http.client
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

TEMP = tempfile.TemporaryDirectory()
os.environ['APP_DATA'] = TEMP.name
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import manager as m
import safe_fetch

EXAMPLE = 'vless://00000000-0000-4000-8000-000000000001@node.example:443?security=tls&type=ws&path=%2Fsocket&sni=tls.example#Example'

class AppTests(unittest.TestCase):
    def setUp(self):
        m.groups = []; m.nodes = []; m.trash = []
        m.job.update(running=False); m.scan.update(running=False)
        m.state.update(enabled=True,automatic=True)
        m.save('config.json',{})
        m.save('dns-bootstrap.json',{})

    def test_clean_install_has_no_server_or_external_process(self):
        with patch.object(m.subprocess,'Popen') as spawn:
            m.start(); spawn.assert_not_called()
        self.assertEqual(m.groups,[])

    def test_token_is_generated_not_shipped(self):
        self.assertGreaterEqual(len(m.TOKEN),32)
        self.assertTrue((Path(TEMP.name)/'access-token').exists())

    def test_parser_preserves_ws_host_and_tls_identity(self):
        out=m.parse(EXAMPLE)[0]['outbound']
        self.assertEqual(out['streamSettings']['wsSettings']['headers']['Host'],'node.example')
        self.assertEqual(out['streamSettings']['tlsSettings']['serverName'],'tls.example')

    def test_certificate_bypass_rejected(self):
        with self.assertRaises(ValueError): m.parse(EXAMPLE.replace('#Example','&allowInsecure=1#Example'))

    def test_bad_uuid_rejected(self):
        with self.assertRaises(ValueError): m.parse(EXAMPLE.replace('00000000-0000-4000-8000-000000000001','not-a-uuid'))

    def test_plaintext_transport_rejected(self):
        with self.assertRaises(ValueError): m.parse(EXAMPLE.replace('security=tls','security=none'))

    def test_cached_bootstrap_needs_no_dns_and_keeps_sni(self):
        out=m.parse(EXAMPLE)[0]['outbound']
        m.save('dns-bootstrap.json',{'node.example':{'address':'1.2.3.4'}})
        with patch.object(m.subprocess,'run') as run:
            result=m.secure_outbound(out); run.assert_not_called()
        self.assertEqual(result['settings']['vnext'][0]['address'],'1.2.3.4')
        self.assertEqual(result['streamSettings']['tlsSettings']['serverName'],'tls.example')
        self.assertEqual(out['settings']['vnext'][0]['address'],'node.example')

    def test_strict_bootstrap_cannot_fall_back(self):
        with patch.object(m,'SYSTEM_BOOTSTRAP',False),patch.object(m.subprocess,'run',side_effect=OSError()),patch.object(m.socket,'getaddrinfo') as dns:
            with self.assertRaises(ValueError):m.secure_outbound(m.parse(EXAMPLE)[0]['outbound'])
            dns.assert_not_called()

    def test_proxy_off_still_routes_doh_through_proxy(self):
        m.save('dns-bootstrap.json',{'node.example':{'address':'1.2.3.4'}})
        result=m.config(m.parse(EXAMPLE)[0]['outbound'],False)
        self.assertEqual(result['outbounds'][0]['protocol'],'freedom')
        self.assertEqual(result['outbounds'][1]['protocol'],'vless')
        self.assertEqual(result['routing']['rules'][0]['outboundTag'],'dns-vpn')

    def test_recovery_keeps_healthy_connection(self):
        with patch.object(m,'check_doh'),patch.object(m,'check_https'),patch.object(m,'activate') as activate:
            m.select_best();activate.assert_not_called()

    def test_recovery_stops_after_first_verified_candidate(self):
        m.nodes=m.normalize(m.parse(EXAMPLE),'example')
        with patch.object(m,'test',return_value=.1),patch.object(m,'activate') as activate:
            m.select_best(True);activate.assert_called_once()

    def test_failed_candidates_never_activated(self):
        m.nodes=m.normalize(m.parse(EXAMPLE),'example')
        with patch.object(m,'test',side_effect=ValueError('failed')),patch.object(m,'activate') as activate:
            m.select_best(True);activate.assert_not_called()

class DownloadTests(unittest.TestCase):
    def test_http_and_credentials_rejected(self):
        for url in ('http://example.com/sub','https://user:pass@example.com/sub'):
            with self.subTest(url=url),self.assertRaises(ValueError):safe_fetch.fetch_subscription(url)

    def test_private_resolution_rejected(self):
        with patch.object(safe_fetch.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):safe_fetch.public_addresses('example.com',443)

    def test_redirect_is_revalidated(self):
        response=Mock(status=302);response.getheader.return_value='http://example.com/sub'
        connection=Mock();connection.getresponse.return_value=response
        with patch.object(safe_fetch,'public_addresses',return_value=['1.2.3.4']),patch.object(safe_fetch,'PinnedHTTPS',return_value=connection):
            with self.assertRaises(ValueError):safe_fetch.fetch_subscription('https://example.com/sub')
            connection.close.assert_called()

    def test_response_size_bounded(self):
        response=Mock(status=200);response.read.return_value=b'x'*(safe_fetch.LIMIT+1)
        connection=Mock();connection.getresponse.return_value=response
        with patch.object(safe_fetch,'public_addresses',return_value=['1.2.3.4']),patch.object(safe_fetch,'PinnedHTTPS',return_value=connection):
            with self.assertRaises(ValueError):safe_fetch.fetch_subscription('https://example.com/sub')

class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=m.ThreadingHTTPServer(('127.0.0.1',0),m.Handler)
        m.ORIGIN='http://127.0.0.1:'+str(cls.server.server_port)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()

    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join()

    def request(self,path,method='GET',body=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=3)
        c.request(method,path,json.dumps(body) if body is not None else None,headers or {})
        r=c.getresponse();result=(r.status,dict(r.getheaders()),r.read());c.close();return result

    def test_unauthorized_root_has_login_not_management(self):
        code,_,body=self.request('/');self.assertEqual(code,200);self.assertIn(b'type="password"',body);self.assertNotIn(m.TOKEN.encode(),body)

    def test_status_requires_authentication(self):self.assertEqual(self.request('/api/status')[0],401)

    def test_login_sets_persistent_httponly_cookie(self):
        code,headers,_=self.request('/api/login','POST',{'key':m.TOKEN},{'Origin':m.ORIGIN})
        self.assertEqual(code,200);self.assertIn('Max-Age=',headers['Set-Cookie']);self.assertIn('HttpOnly',headers['Set-Cookie'])

    def test_cross_origin_change_rejected(self):
        code,_,_=self.request('/api/toggle','POST',{'enabled':False},{'Cookie':'access='+m.TOKEN,'Origin':'https://other.example'})
        self.assertEqual(code,403)

    def test_authenticated_status_does_not_return_secrets(self):
        code,_,body=self.request('/api/status',headers={'Cookie':'access='+m.TOKEN})
        self.assertEqual(code,200);self.assertNotIn(m.TOKEN.encode(),body);self.assertNotIn(b'outbound',body);self.assertNotIn(b'source',body)

    def test_wrong_login_key_rejected(self):
        self.assertEqual(self.request('/api/login','POST',{'key':'incorrect'},{'Origin':m.ORIGIN})[0],401)

if __name__=='__main__':unittest.main()
