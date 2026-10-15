"""New V1.6: report clarity, injection safety, exact license onboarding guard."""
import contextlib
import io
import json
import importlib.util
from pathlib import Path
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('audit_html_v16', ROOT/'scripts'/'domain_audit.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
h = a.report_html


def sample(sources=None, findings=None):
    return {'domain':'example.net', 'report_id':'DEMO', 'checked_at':'2026-10-15T00:00:00Z',
            'sources': sources or {}, 'assessment': {'findings':findings or []}}


class HtmlReportTests(unittest.TestCase):
    def test_four_plain_language_verdicts(self):
        ok = {key:a.source('ok') for key in ['dns','local_ioc','otx']}
        ok['local_ioc']['data']={'feeds':[{'stale':False}]}
        self.assertEqual(h.summarize(sample(ok))['level'],'clear')
        self.assertEqual(h.summarize(sample({}))['level'],'unknown')
        self.assertEqual(h.summarize(sample(ok,[{'severity':'medium','detail':'异常解析'}]))['level'],'caution')
        self.assertEqual(h.summarize(sample(ok,[{'severity':'high','detail':'已确认恶意'}]))['level'],'danger')

    def test_stale_ioc_cannot_be_reported_as_clear(self):
        ok = {key:a.source('ok') for key in ['dns','local_ioc','otx']}
        ok['local_ioc']['data']={'feeds':[{'stale':True}]}
        self.assertEqual(h.summarize(sample(ok))['level'],'unknown')
        self.assertEqual(h.source_view('local_ioc',ok['local_ioc'],set())[1],'数据过期')

    def test_html_escapes_untrusted_domain_and_intel_values(self):
        report=sample({'otx':a.source('ok',data={'bad':'<script>alert(42)</script>'},summary='<img src=x onerror=alert(2)>')},
                      [{'severity':'medium','detail':'<svg onload=alert(1)>'}])
        report['domain']='<script>alert(5)</script>'
        html=h.render(report)
        self.assertTrue(html.startswith('<!DOCTYPE html>'))
        self.assertIn('&lt;script&gt;',html)
        self.assertIn('&lt;svg',html)
        self.assertNotIn('<script>',html)
        self.assertNotIn('<svg',html)
        self.assertIn('发现可疑问题',html)
        self.assertIn('未完成或未配置',html)
        self.assertIn('<details>',html)

    def test_unconfigured_source_never_marked_ok(self):
        html=h.render(sample({'otx': a.source('not_configured')}))
        self.assertIn('未配置',html)
        self.assertEqual(h.summarize(sample({}))['level'],'unknown')

    def test_audit_writes_html_and_json_without_context_file(self):
        with tempfile.TemporaryDirectory() as temp:
            args=Namespace(domain='example.net',registered_domain=None,business_file=None,
                baseline=None,domestic_evidence=None,output=temp,tls_probe=False,
                ioc_db=str(Path(temp)/'db.sqlite3'),no_auto_baseline=True,
                no_auto_ioc_update=True,no_prompt=True,markdown=False)
            mocksrc={k:a.source('not_configured') for k in
                     ('rdap','dns','ripestat','crtsh','otx','urlscan','virustotal','tls','threatbook_api','local_ioc')}
            mocksrc['dns']=a.source('ok',data={'ips':[], 'records':{}})
            fake=sample(mocksrc)
            fake.update({'registered_domain':'example.net', 'business_context': {'context_status':'not_provided'},
                         'technical_assessment':{'label':'模拟测试'},'evidence_ledger':[],'asset_inventory':[],
                         'domestic_cross_validation':{'matrix':[]},'assessment':{'findings':[], 'pending_items':[]}})
            with patch.object(a,'build_report',return_value=fake), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(a.audit_cmd(args),0)
            self.assertEqual(len(list(Path(temp).glob('*.html'))),1)
            self.assertEqual(len(list(Path(temp).glob('*.json'))),1)
            self.assertEqual(len(list(Path(temp).glob('*.md'))),0)
            text=list(Path(temp).glob('*.html'))[0].read_text('utf-8')
            self.assertIn('信息不足，暂时无法判断',text)

    def test_noninteractive_setup_and_no_api_key_leak(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'.env'
            with patch.object(a,'DEFAULT_ENV',path), contextlib.redirect_stdout(io.StringIO()):
                a.init_cmd(Namespace(non_interactive=True,force=False))
            self.assertNotIn('VT_USAGE=noncommercial',path.read_text('utf-8'))
            self.assertIn('ONBOARDING_DONE=no',path.read_text('utf-8'))
            self.assertFalse((Path(temp)/'reports').exists())

if __name__ == '__main__':
    unittest.main()
