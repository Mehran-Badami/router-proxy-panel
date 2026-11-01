import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from site_cleanup import retire,warm,ttl_seconds,ADDRESS_PATH,CONNECTION_PATH

def rule(name):return {'name':name,'match-subdomain':'true','disabled':'false','address-list':'rpp-sites'}
def address(key,ip,host='retired.example',**extra):
    return {'.id':key,'address':ip,'list':'rpp-sites','dynamic':'true','comment':'created for '+host+'.',**extra}
class Router:
    def __init__(self,addresses,connections=(),dns=(),cache=()):
        self.data={ADDRESS_PATH:copy.deepcopy(addresses),CONNECTION_PATH:copy.deepcopy(list(connections)),'/ip/dns/static':copy.deepcopy(list(dns)),'/ip/dns/cache':copy.deepcopy(list(cache))};self.writes=[];self.fail_connection=False
    def request(self,method,path,data=None):
        if method=='GET':return copy.deepcopy(self.data[path])
        if method=='PUT':
            if any(r.get('list')==data.get('list') and r.get('address')==data.get('address') for r in self.data[path]):raise ValueError('already have such entry')
            self.data[path].append({**data,'.id':'*new'+str(len(self.writes)),'dynamic':'true'});self.writes.append(path);return
        base,key=path.rsplit('/',1)
        if base==CONNECTION_PATH and self.fail_connection:raise OSError('connection lost')
        self.writes.append(path);self.data[base]=[r for r in self.data[base] if r['.id']!=key]

class CleanupTests(unittest.TestCase):
    def test_reenable_uses_unexpired_matching_public_ipv4_cache_and_can_disable_again(self):
        r=Router([],cache=[{'name':'www.retired.example','type':'A','data':'8.8.4.4','ttl':'2m3s'},
                          {'name':'other.example','type':'A','data':'1.1.1.1','ttl':'3m'},
                          {'name':'retired.example','type':'A','data':'192.168.1.2','ttl':'5m'},
                          {'name':'retired.example','type':'A','data':'8.8.8.8','ttl':'0s'}])
        self.assertEqual(warm(r,[rule('retired.example')],'rpp-sites'),1)
        self.assertEqual(r.data[ADDRESS_PATH][0]['timeout'],'123s')
        self.assertEqual(warm(r,[rule('retired.example')],'rpp-sites'),0)
        result=retire(r,[rule('retired.example')],[],'rpp-sites','rpp-proxy',[],lambda a:None)
        self.assertEqual(result['addresses_removed'],1)

    def test_ttl_formats_and_limits(self):
        for value,expected in [('1h2m3s',3723),('00:02:03',123),('1d00:00:00',86400),('2w',86400),('3ms',0),('unexpected',0)]:
            self.assertEqual(ttl_seconds(value),expected)

    def test_warm_preserves_static_coverage_and_replaces_retired_origin_before_cleanup(self):
        r=Router([address('*1','8.8.4.4','old.example')],cache=[{'name':'new.example','type':'A','data':'8.8.4.4','ttl':'20s'}])
        self.assertEqual(warm(r,[rule('new.example')],'rpp-sites'),0)
        result=retire(r,[rule('old.example')],[rule('new.example')],'rpp-sites','rpp-proxy',[],lambda a:None)
        self.assertEqual(result['shared_addresses'],1)
        self.assertEqual(result['addresses_removed'],0)
        r=Router([address('*s','8.8.4.0/24',dynamic='false')],cache=r.data['/ip/dns/cache'])
        self.assertEqual(warm(r,[rule('new.example')],'rpp-sites'),0)

    def test_removes_only_retired_dns_routes_and_matching_marked_connections(self):
        rows=[address('*1','192.0.2.1'),address('*2','192.0.2.2','active.example'),address('*3','192.0.2.3',dynamic='false'),address('*4','192.0.2.4',list='other'),address('*5','192.0.2.5',comment='operator')]
        conns=[{'.id':'*c1','dst-address':'192.0.2.1','connection-mark':'rpp-proxy'},{'.id':'*c2','dst-address':'192.0.2.1','connection-mark':'other'},{'.id':'*c3','dst-address':'192.0.2.2','connection-mark':'rpp-proxy'}]
        r=Router(rows,conns);saved=[]
        result=retire(r,[rule('retired.example')],[rule('active.example')],'rpp-sites','rpp-proxy',[],lambda a:saved.append(a))
        self.assertEqual(saved,[['192.0.2.1']]);self.assertEqual([x['.id'] for x in r.data[ADDRESS_PATH]],['*2','*3','*4','*5'])
        self.assertEqual([x['.id'] for x in r.data[CONNECTION_PATH]],['*c2','*c3'])
        self.assertEqual(result,{'addresses_removed':1,'connections_restarted':1,'shared_addresses':0})

    def test_shared_addresses_and_static_networks_keep_connections(self):
        for survivor in (address('*2','192.0.2.1','active.example'),address('*2','192.0.2.0/24',dynamic='false',comment='operator network')):
            r=Router([address('*1','192.0.2.1'),survivor],[{'.id':'*c','dst-address':'192.0.2.1:443','connection-mark':'rpp-proxy'}])
            result=retire(r,[rule('retired.example')],[],'rpp-sites','rpp-proxy',[],lambda a:None)
            self.assertEqual(result['shared_addresses'],1);self.assertEqual(len(r.data[CONNECTION_PATH]),1)

    def test_active_overlapping_or_unmanaged_dns_reference_is_preserved(self):
        for desired,dns in (([rule('example')],[]),([],[rule('retired.example')])):
            r=Router([address('*1','192.0.2.1')],dns=dns)
            retire(r,[rule('retired.example')],desired,'rpp-sites','rpp-proxy',[],lambda a:None)
            self.assertFalse(r.writes)

    def test_checkpoint_allows_retry_after_address_removed(self):
        r=Router([address('*1','192.0.2.1')],[{'.id':'*c','dst-address':'192.0.2.1','connection-mark':'rpp-proxy'}]);r.fail_connection=True;saved=[]
        with self.assertRaises(OSError):retire(r,[rule('retired.example')],[],'rpp-sites','rpp-proxy',[],lambda a:saved.extend(a))
        self.assertEqual(r.data[ADDRESS_PATH],[]);self.assertEqual(saved,['192.0.2.1'])
        r.fail_connection=False
        result=retire(r,[rule('retired.example')],[],'rpp-sites','rpp-proxy',saved,lambda a:None)
        self.assertEqual(result['connections_restarted'],1)

    def test_unknown_dns_origin_and_similar_suffix_are_not_owned(self):
        r=Router([address('*1','192.0.2.1','notretired.example'),address('*2','192.0.2.2',comment='created for retired.example. trailing')])
        retire(r,[rule('retired.example')],[],'rpp-sites','rpp-proxy',[],lambda a:None)
        self.assertFalse(r.writes)

    def test_active_regex_prevents_cleanup(self):
        r=Router([address('*1','192.0.2.1')],dns=[{'regexp':'.*','address-list':'rpp-sites'}])
        with self.assertRaises(ValueError):retire(r,[rule('retired.example')],[],'rpp-sites','rpp-proxy',[],lambda a:None)
        self.assertFalse(r.writes)

if __name__=='__main__':unittest.main()
