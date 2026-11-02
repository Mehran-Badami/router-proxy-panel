import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import native_tun

ENV={'RPP_GATEWAY_MODE':'tun','RPP_GATEWAY_INTERFACE':'rpp-panel','RPP_LAN_CIDRS':'10.20.0.0/24'}

class NativeTunTests(unittest.TestCase):
    def test_existing_install_is_opt_in(self):
        self.assertIsNone(native_tun.settings({}))
        with patch.dict(os.environ,{'RPP_GATEWAY_MODE':'off','XRAY_TUN_FD':'invalid'}):
            self.assertIsNone(native_tun.inbound())
            self.assertEqual(native_tun.inherited_fds(),())

    def test_rejects_missing_broad_or_malformed_client_networks(self):
        for value in ['', '0.0.0.0/0','::/0','10.20.0.1/24','127.0.0.0/8',
                      '169.254.0.0/16','224.0.0.0/4','10.20.0.0/24,',
                      ','.join('10.20.0.0/24' for _ in range(17))]:
            with self.subTest(value=value),self.assertRaises(ValueError):
                native_tun.settings({**ENV,'RPP_LAN_CIDRS':value})

    def test_deduplicates_explicit_client_networks(self):
        s=native_tun.settings({**ENV,'RPP_LAN_CIDRS':'10.20.0.0/24, 10.21.0.5/32,10.20.0.0/24'})
        self.assertEqual(s['networks'],['10.20.0.0/24','10.21.0.5/32'])

    def test_rejects_invalid_modes_devices_and_mtu(self):
        for key,value in [('RPP_GATEWAY_MODE','automatic'),('RPP_GATEWAY_INTERFACE','lo'),
                          ('RPP_GATEWAY_INTERFACE','rpp0'),('RPP_GATEWAY_INTERFACE','bad/name'),
                          ('RPP_TUN_NAME','x'*16),('RPP_TUN_MTU','575'),
                          ('RPP_TUN_MTU','9001'),('RPP_TUN_MTU','invalid')]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                native_tun.settings({**ENV,key:value})

    def test_requires_actual_open_descriptor(self):
        with patch.dict(os.environ,ENV):
            for value in ['', '2','-1','invalid']:
                with self.subTest(value=value),patch.dict(os.environ,{'XRAY_TUN_FD':value}),self.assertRaises(ValueError):
                    native_tun.inherited_fds()
            with tempfile.TemporaryFile() as f:
                fd=f.fileno()
                with patch.dict(os.environ,{'XRAY_TUN_FD':str(fd)}):
                    self.assertEqual(native_tun.inherited_fds(),(fd,))
            with patch.dict(os.environ,{'XRAY_TUN_FD':str(fd)}),self.assertRaises(ValueError):
                native_tun.inherited_fds()

    def test_probes_never_open_tun_and_dns_keeps_vpn_when_disabled(self):
        # Use an isolated data directory if this module is run on its own.
        with tempfile.TemporaryDirectory() as data,patch.dict(os.environ,{**ENV,'APP_DATA':data}):
            import manager
            upstream={'protocol':'vless','settings':{'vnext':[{'address':'203.0.113.10','port':443,'users':[]}]}}
            with patch.object(manager,'secure_outbound',side_effect=lambda out,**kw:copy.deepcopy(out)):
                probe=manager.config(upstream,test=True)
                self.assertEqual([i['protocol'] for i in probe['inbounds']],['socks'])
                normal=manager.config(upstream,enabled=False)
                self.assertEqual(sum(i['protocol']=='tun' for i in normal['inbounds']),1)
                self.assertEqual(normal['outbounds'][0]['protocol'],'freedom')
                dns=next(o for o in normal['outbounds'] if o.get('tag')=='dns-vpn')
                self.assertEqual(dns['protocol'],'vless')
                self.assertEqual(normal['routing']['rules'][0]['inboundTag'],['secure-doh'])

if __name__=='__main__':unittest.main()
