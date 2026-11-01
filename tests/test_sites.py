import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
import sites

class FakeRouter:
    def __init__(self,rows=()):self.rows=copy.deepcopy(list(rows));self.writes=0;self.fail=False
    def request(self,method,path,data=None):
        if path=='/ip/dns/forwarders':return [{'name':'RPP Secure DNS'}]
        if path=='/ip/firewall/mangle':return [{'dst-address-list':'rpp-sites'},{'action':'mark-routing','new-routing-mark':'rpp-proxy'}]
        if path=='/ip/firewall/filter':return []
        if path=='/ip/route':return [{'routing-table':'rpp-proxy','dst-address':'0.0.0.0/0','active':'true'}]
        if method=='GET':return copy.deepcopy(self.rows)
        self.writes+=1
        if self.fail:raise ValueError('simulated failure')
        if method=='PUT':self.rows.append({**data,'.id':'*'+str(self.writes)})
        else:
            from urllib.parse import unquote
            key=unquote(path.rsplit('/',1)[1]);row=next(r for r in self.rows if r['.id']==key)
            if method=='PATCH':row.update(data)
            elif method=='DELETE':self.rows.remove(row)

class SiteTests(unittest.TestCase):
    def item(self,**values):return dict(id='custom',name='Example',domains=['example.com'],enabled=True,subdomains=True,**values)
    def test_defaults_are_independent_and_google_opt_in(self):
        a=sites.defaults();a[0]['domains'].clear()
        self.assertTrue(sites.defaults()[0]['domains'])
        self.assertFalse(any(x['enabled'] for x in sites.defaults() if x['id'] in ('home','assistant')))
        self.assertNotIn('google.com',[d for x in sites.defaults() for d in x['domains']])
    def test_domain_validation_and_idna(self):
        self.assertEqual(sites.domain('EXAMPLE.COM.'),'example.com')
        self.assertTrue(sites.domain('مثال.com').startswith('xn--'))
        for bad in ['https://example.com','example.com/path','*.example.com','127.0.0.1','a.com; /system reboot','a..com','-a.com','localhost']:
            with self.subTest(bad=bad),self.assertRaises(ValueError):sites.domain(bad)
    def test_merge_duplicate_domains_and_disable(self):
        a=self.item();b={**a,'id':'other','subdomains':False}
        self.assertEqual(len(sites.records([a,b])),1)
        self.assertEqual(sites.records([a,b])[0]['match-subdomain'],'true')
        self.assertEqual(sites.records([{**a,'enabled':False}]),[])
    def test_invalid_schema_is_rejected(self):
        for value in [None,{},[self.item(),self.item()],[{**self.item(),'enabled':'false'}],[{**self.item(),'domains':[]}]]:
            with self.assertRaises(ValueError):sites.validate(value)
    def test_preset_upgrade_preserves_custom_and_disabled_choices(self):
        old=[{'id':'youtube','name':'My videos','enabled':False,'subdomains':False,'domains':['custom.example']}]
        merged=sites.merge_presets(old+[self.item()])
        y=next(x for x in merged if x['id']=='youtube')
        self.assertFalse(y['enabled']);self.assertFalse(y['subdomains'])
        self.assertIn('custom.example',y['domains']);self.assertIn('googlevideo.com',y['domains'])
        self.assertIn(self.item(),merged)
        self.assertEqual(merged,sites.merge_presets(merged))
    def test_reconcile_is_idempotent_and_preserves_unrelated(self):
        unrelated={'.id':'*unrelated','name':'private.example','comment':'operator record'}
        r=FakeRouter([unrelated]);desired=sites.records([self.item()])
        sites.sync(r,desired);count=r.writes;sites.sync(r,desired)
        self.assertEqual(count,r.writes);self.assertIn(unrelated,r.rows)
        sites.sync(r,[]);self.assertEqual(r.rows,[unrelated])
    def test_conflict_aborts_before_mutation(self):
        r=FakeRouter([{'.id':'*1','name':'example.com','comment':'operator'}])
        with self.assertRaises(ValueError):sites.sync(r,sites.records([self.item()]))
        self.assertEqual(r.writes,0)
    def test_store_apply_rollback_and_failed_retry_preserve_snapshot(self):
        db={};store=sites.SiteStore(lambda k,d:copy.deepcopy(db.get(k,d)),lambda k,v:db.__setitem__(k,copy.deepcopy(v)))
        router=FakeRouter()
        with patch.object(sites,'Router',return_value=router):
            store.update([self.item()]);store.apply();self.assertFalse(store.status()['pending'])
            store.update([]);router.fail=True
            with self.assertRaises(ValueError):store.apply()
            snapshot=copy.deepcopy(db['sites-previous.json']);self.assertFalse(store.status()['incomplete'])
            with self.assertRaises(ValueError):store.apply()
            self.assertEqual(snapshot,db['sites-previous.json'])
            router.fail=False;store.apply(restore=True)
            self.assertEqual([sites.clean(x) for x in router.rows],snapshot['records'])
            self.assertTrue(store.status()['pending'])
    def test_unconfigured_router_and_http_rejected(self):
        with patch.dict(os.environ,{'ROUTEROS_URL':'http://router.example'},clear=True),self.assertRaises(ValueError):sites.Router()

    def test_partial_write_failure_restores_original_rules(self):
        db={};store=sites.SiteStore(lambda k,d:copy.deepcopy(db.get(k,d)),lambda k,v:db.__setitem__(k,copy.deepcopy(v)))
        router=FakeRouter();original=router.request
        def fail_second(method,path,data=None):
            if method!='GET' and router.writes==1:
                router.writes+=1
                raise ValueError('connection interrupted')
            return original(method,path,data)
        router.request=fail_second
        with patch.object(sites,'Router',return_value=router):
            store.update([self.item(),{**self.item(),'id':'second','domains':['second.example']}])
            with self.assertRaises(ValueError):store.apply()
        self.assertEqual(router.rows,[])
        self.assertFalse(store.status()['incomplete'])
        self.assertTrue(store.status()['pending'])

    def test_failed_rollback_preserves_snapshot_for_retry(self):
        db={};store=sites.SiteStore(lambda k,d:copy.deepcopy(db.get(k,d)),lambda k,v:db.__setitem__(k,copy.deepcopy(v)))
        router=FakeRouter();original=router.request
        def fail_after_first(method,path,data=None):
            if method!='GET' and router.writes>=1:raise ValueError('router offline')
            return original(method,path,data)
        router.request=fail_after_first
        with patch.object(sites,'Router',return_value=router):
            store.update([self.item(),{**self.item(),'id':'second','domains':['second.example']}])
            with self.assertRaises(ValueError):store.apply()
            self.assertTrue(store.status()['incomplete'])
            self.assertEqual(db['sites-previous.json']['records'],[])
            with self.assertRaises(ValueError):store.apply()
            self.assertEqual(db['sites-previous.json']['records'],[])
            router.request=original
            store.apply(restore=True)
        self.assertEqual(router.rows,[])
        self.assertFalse(store.status()['incomplete'])

if __name__=='__main__':unittest.main()
