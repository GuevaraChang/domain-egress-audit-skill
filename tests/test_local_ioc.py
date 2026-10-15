import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import local_ioc
import domain_audit as audit

class LocalIOC(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / 'subdir' / 'cache.sqlite'
    def tearDown(self):
        self.temp.cleanup()

    def static_fetcher(self, url):
        if '/IPguard/' in url:
            return b'8.8.8.8 # honeypot sample\n9.9.9.9 # second\n1.1.1.1\n4.4.4.4\n5.5.5.5\n'
        if '/phishshield/' in url:
            s = "const PHISHING_BLACKLIST = new Set(['bad.example.net', 'phish.example.org', 'fraud.example.com', 'foo.bad.xyz', 'bar.evil.cn', 'oops.bad.info', 'fake.brand.co', 'phish.brand.xyz', 'mail.bad.link', 'scam.abc.top']);"
            return s.encode()
        if '/anti-AD/' in url:
            return ('#TITLE=anti-AD\n' + '\n'.join(f'tracker{i}.example.com' for i in range(1002))).encode()
        raise AssertionError('not allowlisted')

    def test_parse_statically_no_eval(self):
        raw = b"const PHISHING_BLACKLIST = new Set(['phish.bad.com', 'evil.example.org']);"
        parsed = local_ioc.parse_text('cn_phishshield', raw.decode())
        self.assertEqual(len(parsed), 2)
        with self.assertRaises(ValueError):
            local_ioc.parse_text('cn_phishshield', "eval('malicious.com')")
        self.assertFalse(local_ioc.is_domain('good.example.com/evil'))

    def test_default_update_and_fqdn_ip_and_no_subdomain_widening(self):
        results = local_ioc.update_feeds(self.db, fetcher=self.static_fetcher)
        self.assertEqual(set(results), {'cn_phishshield','cn_ipguard'})
        self.assertTrue(all(v['status']=='ok' for v in results.values()))
        found = local_ioc.inspect_cached('bad.example.net', ['8.8.8.8','10.0.0.1'], self.db)
        self.assertEqual(found['status'], 'ok')
        self.assertTrue(found['data']['target_not_uploaded'])
        self.assertEqual({m['kind'] for m in found['data']['matched']}, {'phishing_domain','attacking_ip'})
        self.assertEqual({m['match_type'] for m in found['data']['matched']}, {'exact_fqdn','resolved_ip_shared_infrastructure'})
        sub = local_ioc.inspect_cached('api.bad.example.net', [], self.db)
        self.assertEqual(sub['data']['matched'], [])

    def test_update_rejection_preserves_last_good_cache(self):
        local_ioc.update_feeds(self.db, fetcher=self.static_fetcher)
        old = local_ioc.list_feeds(self.db)
        res = local_ioc.update_feeds(self.db, fetcher=lambda u: b'error', names=['cn_ipguard'])
        self.assertEqual(res['cn_ipguard']['status'], 'error')
        self.assertEqual(old, local_ioc.list_feeds(self.db))
        self.assertTrue(local_ioc.inspect_cached('bad.example.net',['8.8.8.8'],self.db)['data']['matched'])

    def test_antiad_context_not_malicious(self):
        local_ioc.update_feeds(self.db, names=['cn_antiad'], fetcher=self.static_fetcher)
        res = local_ioc.inspect_cached('tracker7.example.com',[],self.db)
        self.assertEqual(res['data']['matched'][0]['strength'], 'context_only')
        src = {k: audit.source('skipped') for k in ('rdap','dns','virustotal','urlscan','tls','crtsh','ripestat')}
        src['dns'] = audit.source('ok', data={'ips':[{'ip':'1.1.1.1','globally_routable':True}]})
        src['local_ioc'] = res
        report = {'sources': src, 'business_context':{}, 'evidence_ledger':[{'id':'EV-13','source':'local_ioc'}]}
        result=audit.evaluate(report)
        assert any(x['type']=='local_adtracking' and x['severity']=='low' for x in result['findings'])
        self.assertFalse(any(x['type']=='confirmed_malicious' for x in result['findings']))

    def test_stale_ioc_does_not_trigger_fresh_threat(self):
        local_ioc.update_feeds(self.db, fetcher=self.static_fetcher)
        with local_ioc.connect(self.db) as c:
            c.execute('UPDATE feed_meta SET updated_at=?', ('2022-01-01T00:00:00+00:00',))
        res=local_ioc.inspect_cached('bad.example.net', ['8.8.8.8'],self.db)
        self.assertEqual(res['data']['eligible_feeds'],0)
        self.assertTrue(all(x['stale'] for x in res['data']['matched']))

    def test_missing_db_is_not_clean(self):
        res=local_ioc.inspect_cached('example.com',[],self.db)
        self.assertEqual(res['status'], 'not_configured')
        self.assertEqual(res['data']['assessment'], 'not_checked')

    def test_commercial_vt_policy_independent_ioc(self):
        with patch.object(audit,'req_json') as req:
            vt = audit.vt_check('example.com', 'secret', 'business')
        req.assert_not_called()
        self.assertEqual(vt['status'], 'skipped')

    def test_local_intel_is_independent_from_removed_vendors(self):
        local_ioc.update_feeds(self.db, fetcher=self.static_fetcher)
        hit = local_ioc.inspect_cached('bad.example.net', ['8.8.8.8'], self.db)
        self.assertEqual(hit['data']['eligible_feeds'], 2)
        self.assertEqual({x['feed'] for x in hit['data']['matched']},
                         {'cn_ipguard', 'cn_phishshield'})
        src = {k:audit.source('skipped') for k in ('rdap','dns','ripestat','crtsh','urlscan','virustotal','tls')}
        src['rdap'] = audit.source('ok', data={'age_days': 1000})
        src['dns'] = audit.source('ok', data={'ips':[{'ip':'8.8.8.8','globally_routable':True}]})
        src['local_ioc'] = hit
        ledger = [{'id':'EV-08','source':'local_ioc'}]
        verdict = audit.evaluate({'sources':src,'business_context':{},'evidence_ledger':ledger})
        kinds = {x['type'] for x in verdict['findings']}
        self.assertIn('local_phishing_ioc', kinds)
        self.assertIn('local_ip_association', kinds)
        self.assertNotIn('confirmed_malicious', kinds)

    def test_update_does_not_transmit_target_domain(self):
        calls=[]
        def fetch(u):
            calls.append(u)
            return self.static_fetcher(u)
        local_ioc.update_feeds(self.db,fetcher=fetch)
        self.assertTrue(all('ifuwuyun.com' not in u for u in calls))
        self.assertTrue(all(u.startswith('https://raw.githubusercontent.com/') for u in calls))

    def test_local_import_without_network(self):
        from argparse import Namespace
        file_path = Path(self.temp.name) / 'ipguard.txt'
        file_path.write_bytes(self.static_fetcher('https://raw.githubusercontent.com/chxovo/IPguard/main/blacklist.txt'))
        args=Namespace(feed='cn_ipguard',file=str(file_path),ioc_db=self.db,license_reviewed=False)
        with patch.object(local_ioc.requests,'get',side_effect=AssertionError('must not use network')):
            self.assertEqual(audit.ioc_import_cmd(args),0)
        result = local_ioc.inspect_cached('example.com',['8.8.8.8'],self.db)
        self.assertEqual(result['data']['matched'][0]['details'],'honeypot sample')

    def test_adtracking_cli_license_guard(self):
        from argparse import Namespace
        with self.assertRaises(ValueError):
            audit.ioc_update_cmd(Namespace(ioc_db=self.db,include_adtracking=True,license_reviewed=False))

if __name__ == '__main__':
    unittest.main()
