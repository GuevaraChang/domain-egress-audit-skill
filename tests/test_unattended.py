"""Offline unattended CLI regression tests. No external security APIs contacted."""
import contextlib
import io
import importlib.util
from pathlib import Path
import json
import tempfile
import unittest
from argparse import Namespace
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / 'scripts' / 'domain_audit.py'
spec = importlib.util.spec_from_file_location('domain_audit_automated', path)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class Unattended(unittest.TestCase):
    def test_context_is_optional_unknown_not_verified(self):
        ctx, note = a.read_context(None, 'ifuwuyun.com')
        self.assertIsNone(note)
        self.assertEqual(ctx['target_fqdn'], 'ifuwuyun.com')
        self.assertEqual(ctx['data_classification'], 'unknown')
        self.assertNotIn('owner_verified', ctx)
        self.assertEqual(a.effective_vt_usage({}), 'not_enabled')
        self.assertEqual(a.effective_vt_usage({'VT_USAGE':'noncommercial'},ctx), 'noncommercial')

    def test_auto_ioc_skips_when_both_fresh(self):
        fresh = datetime.now(timezone.utc).isoformat()
        meta=[{'feed':k,'updated_at': fresh} for k,v in a.local_ioc.FEEDS.items() if v['enabled_by_default']]
        with patch.object(a.local_ioc, 'list_feeds', return_value=meta), \
             patch.object(a.local_ioc, 'update_feeds') as update:
            result=a.auto_refresh_local_ioc('test.db')
        update.assert_not_called()
        self.assertEqual(result['status'], 'fresh_cache')

    def test_auto_ioc_refresh_missing_and_stale_only(self):
        old=(datetime.now(timezone.utc)-timedelta(days=12)).isoformat()
        with patch.object(a.local_ioc, 'list_feeds', return_value=[{'feed':'cn_phishshield','updated_at':old}]), \
             patch.object(a.local_ioc, 'update_feeds', return_value={
                 'cn_phishshield': {'status':'ok'},
                 'cn_ipguard': {'status':'error','error':'unreachable'}
             }) as update:
            res=a.auto_refresh_local_ioc('test.db')
        self.assertEqual(res['status'],'partial')
        self.assertFalse(res['target_sent'])
        self.assertEqual(set(update.call_args.kwargs['names']), {'cn_phishshield','cn_ipguard'})
        self.assertNotIn('cn_antiad',update.call_args.kwargs['names'])
        self.assertIn('cn_ipguard',res['errors'])

    def test_locate_baseline_uses_same_domain_and_skips_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            (p/'ifuwuyun.com_20261015T111111Z.json').write_text('{bad json',encoding='utf-8')
            (p/'ifuwuyun.com_20261014T111111Z.json').write_text(json.dumps({'domain':'ifuwuyun.com','sources':{}}))
            (p/'other.com_20261015T111111Z.json').write_text(json.dumps({'domain':'other.com','sources':{}}))
            item,filename=a.locate_baseline(p,'ifuwuyun.com')
        self.assertEqual(item['domain'],'ifuwuyun.com')
        self.assertIn('20261014',filename)

    def test_one_command_audit_produces_two_reports_without_manual_input(self):
        with tempfile.TemporaryDirectory() as d:
            db=Path(d)/'data'/'ioc.sqlite3'
            args=Namespace(domain='ifuwuyun.com',registered_domain=None,
                business_file=None, baseline=None, domestic_evidence=None, output=d,
                tls_probe=False, ioc_db=str(db), no_auto_baseline=False,
                no_auto_ioc_update=False)
            src_names=('rdap','dns','ripestat','crtsh','otx','urlscan','virustotal','tls',
                       'threatbook_api','local_ioc')
            mocksrc={k:a.source('not_configured',data={}) for k in src_names}
            mocksrc['dns']=a.source('ok',data={'records':{},'ips':[]})
            fake_report={'schema_version':'1.5.0','report_id':'SIMULATED','checked_at':a.utc_now(),
                         'domain':'ifuwuyun.com','registered_domain':'ifuwuyun.com','vt_usage':'business',
                         'business_context':{'target_fqdn':'ifuwuyun.com','context_status':'not_provided'},
                         'sources':mocksrc,'asset_inventory':[], 'evidence_ledger':[],
                         'domestic_cross_validation':{'matrix':[],'unique_vendor_count':0,'alignment':'insufficient_domestic_coverage','methodology':'demo'},
                         'evidence_coverage':{},'assessment':{'risk_label':'证据不足','decision':'不放通','pending_items':['数据未知'], 'findings':[]}}
            fake_report['technical_assessment']=a.technical_assessment(fake_report)
            with patch.object(a,'auto_refresh_local_ioc',return_value={'status':'partial','errors':{'cn_ipguard':'offline'}}), \
                 patch.object(a,'build_report',return_value=fake_report), \
                 patch.object(a,'read_env',return_value={'VT_USAGE':'business'}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(a.audit_cmd(args),0)
            files=list(Path(d).glob('ifuwuyun.com_*.json'))
            self.assertEqual(len(files),1)
            doc=json.loads(files[0].read_text(encoding='utf-8'))
            self.assertEqual(doc['execution']['mode'],'unattended')
            self.assertFalse(doc['execution']['manual_input_required'])
            self.assertEqual(doc['technical_assessment']['access_authorization'],'not_granted')
            self.assertEqual(doc['execution']['ioc_refresh']['status'],'partial')
            self.assertTrue(files[0].with_suffix('.html').exists())

if __name__ == '__main__':
    unittest.main()
