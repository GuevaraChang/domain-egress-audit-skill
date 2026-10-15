"""Offline urlscan read-only detailed-history tests."""
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from argparse import Namespace
import contextlib
import io
import json

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'scripts'))
import domain_audit as audit
import report_html
UUID='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
URL='https://urlscan.io/result/'+UUID+'/'


def search_result():
    return {'results':[{'_id':UUID,'task':{'domain':'example.com','time':'2026-10-10T00:00:00Z'},
                        'page':{'url':'https://other.example.net/','domain':'other.example.net','status':200},
                        'result':URL}], 'total':1, 'has_more':False, 'search_date_limit_days':90}


def detail():
    return {'task':{'domain':'example.com','url':'https://example.com/','time':'2026-10-10T00:00:00Z'},
            'page':{'url':'https://other.example.net/','title':'Historical Login','status':200,'ip':'1.2.3.4'},
            'lists':{'domains':['example.com','cdn.other.example.net','analytics.example.org']},
            'stats':{'requests':37},
            'data':{'requests':[{'request':{'request':{'url':'https://cdn.other.example.net/app.js?token=PRIVATE'}}}]},
            'verdicts':{'urlscan':{'malicious':True,'score':90}}}

class HistoryTests(unittest.TestCase):
    def test_default_audit_only_reads_urlscan_and_keeps_other_checks(self):
        # Exercise the actual CLI, report builder, history parser and report writers.
        # The HTTP transport rejects every call except the expected GET endpoints.
        for empty, no_tls in ((False, False), (True, False), (False, True)):
            with self.subTest(empty=empty, no_tls=no_tls), tempfile.TemporaryDirectory() as tmp:
                calls = []
                def transport(method, url, **kwargs):
                    self.assertEqual(method.lower(), 'get')
                    self.assertIn(url, (audit.URLSCAN_SEARCH, audit.URLSCAN_RESULT + UUID + '/'))
                    calls.append(url)
                    response = unittest.mock.Mock(status_code=200)
                    response.json.return_value = ({'results':[]} if empty else search_result()) if url == audit.URLSCAN_SEARCH else detail()
                    return response
                dns = audit.source('ok', data={'ips':[{'ip':'1.1.1.1','globally_routable':True}], 'records':{}})
                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(audit, 'read_env', return_value={'URLSCAN_API_KEY':'TEST-SECRET', 'VT_API_KEY':'VT-SECRET', 'VT_API_TIER':'premium'}))
                    stack.enter_context(patch.object(audit.requests.sessions.Session, 'request', side_effect=transport))
                    checks = {}
                    for name in ('dns_check','rdap_check','ripestat_check','crt_check','vt_check','tls_check'):
                        checks[name] = stack.enter_context(patch.object(audit, name, return_value=dns if name == 'dns_check' else audit.source('ok')))
                    ioc = stack.enter_context(patch.object(audit.local_ioc, 'inspect_cached', return_value=audit.source('ok')))
                    refresh = stack.enter_context(patch.object(audit, 'auto_refresh_local_ioc', return_value={'status':'fresh_cache'}))
                    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                    flags = ['--no-tls-probe'] if no_tls else []
                    self.assertEqual(audit.main(['audit','--domain','example.com','--no-prompt','--output',tmp,'--markdown'] + flags), 0)
                self.assertEqual(calls, [audit.URLSCAN_SEARCH] * 2 if empty else [audit.URLSCAN_SEARCH, audit.URLSCAN_RESULT + UUID + '/'])
                for check in checks.values():
                    check.assert_called_once()
                self.assertEqual(checks['tls_check'].call_args.args[-1], not no_tls)
                ioc.assert_called_once()
                refresh.assert_called_once()
                result = next(Path(tmp).glob('*.json'))
                report = json.loads(result.read_text(encoding='utf-8'))
                self.assertEqual(set(report['sources']), {'dns','rdap','ripestat','crtsh','urlscan','virustotal','tls','local_ioc'})
                self.assertEqual(len(report['evidence_ledger']), 8)
                self.assertEqual(report['sources']['urlscan']['status'], 'empty' if empty else 'ok')
                for suffix in ('.json','.html','.md'):
                    content = result.with_suffix(suffix).read_text(encoding='utf-8')
                    self.assertNotIn('TEST-SECRET', content)
                    self.assertNotIn('urlscan_live', content)
                    self.assertNotIn('本次实时网页扫描', content)
                if not empty:
                    self.assertEqual(report['sources']['urlscan']['data']['results'][0]['page_title'], 'Historical Login')

    def test_search_details_are_fetched_and_summarized_not_raw_sensitive(self):
        with patch.object(audit,'req_json',side_effect=[search_result(),detail()]) as req:
            res=audit.urlscan_check('example.com','test-key')
        self.assertEqual(req.call_count,2)
        self.assertEqual(res['status'],'ok')
        self.assertEqual(res['data']['detailed_results'],1)
        self.assertEqual(res['data']['cross_domain_redirects'],1)
        record=res['data']['results'][0]
        self.assertEqual(record['page_title'],'Historical Login')
        self.assertEqual(record['total_requests'],37)
        self.assertIn('analytics.example.org',record['external_resource_domains'])
        self.assertTrue(record['urlscan_malicious'])
        self.assertEqual(record['screenshot_url'],'https://urlscan.io/screenshots/'+UUID+'.png')
        self.assertNotIn('PRIVATE',str(record))

    def test_missing_scan_detail_is_partial_not_clean(self):
        bad=audit.requests.HTTPError('429')
        response=unittest.mock.Mock();response.status_code=429;bad.response=response
        with patch.object(audit,'req_json',side_effect=[search_result(),bad]):
            res=audit.urlscan_check('example.com','test-key')
        self.assertEqual(res['status'],'partial')
        self.assertEqual(res['data']['detailed_results'],0)
        self.assertTrue(res['data']['detail_errors'])
        self.assertEqual(report_html.source_view('urlscan',res,set())[1],'部分完成')

    def test_search_no_results_is_empty_not_safe(self):
        with patch.object(audit,'req_json',return_value={'results':[]}):
            res=audit.urlscan_check('example.com','key')
        self.assertEqual(res['status'],'empty')
        self.assertIn('不证明网站安全',res['summary'])

    def test_invalid_uuid_cannot_be_used_to_call_arbitrary_url(self):
        with patch.object(audit,'req_json') as req:
            with self.assertRaises(ValueError):
                audit.urlscan_fetch_detail('../private?key=abc','key','example.com')
        req.assert_not_called()

    def test_html_history_section_and_html_escape(self):
        rec=detail()
        rec['page']['title']='<svg onload=alert(1)>'
        scan=audit.urlscan_scan_detail(rec,UUID,'example.com')
        r={'domain':'example.com','checked_at':'2026-10-15T12:00:00Z','report_id':'DEMO',
           'sources':{'urlscan':audit.source('ok',data={'detailed_results':1,'history_ips':['1.2.3.4'],
                                 'cross_domain_redirects':1,'results':[scan]}),
                      'dns':audit.source('ok'),'virustotal':audit.source('ok')},
           'assessment':{'findings':[]}}
        html=report_html.render(r)
        self.assertIn('网站历史扫描',html)
        self.assertIn('跨域跳转',html)
        self.assertIn('&lt;svg',html)
        self.assertNotIn('<svg onload',html)


    def test_related_subdomain_fallback_when_exact_empty(self):
        related={'results':[{'_id':UUID,'task':{'domain':'www.example.com','time':'2026-10-10T00:00:00Z'},
                             'page':{'domain':'www.example.com'}}], 'search_date_limit_days':90}
        doc=detail()
        doc['task']['domain']='www.example.com'
        doc['task']['url']='https://www.example.com/'
        doc['page']['url']='https://www.example.com/'
        with patch.object(audit,'req_json',side_effect=[{'results':[],'search_date_limit_days':90},related,doc]) as req:
            result=audit.urlscan_check('example.com','key')
        self.assertEqual(req.call_count,3)
        self.assertEqual(result['status'],'ok')
        self.assertEqual(result['data']['history_scope'],'related_subdomains_only')
        self.assertEqual(result['data']['exact_fqdn_results'],0)
        self.assertEqual(result['data']['results'][0]['relation_to_target'],'related_subdomain')
        self.assertEqual(result['data']['search_date_limit_days'],90)
        self.assertEqual(report_html.source_view('urlscan',result,set())[1],'仅关联子域名')

    def test_no_history_keeps_account_days_limit_not_safe(self):
        with patch.object(audit,'req_json',side_effect=[
            {'results':[],'search_date_limit_days':90}, {'results':[],'search_date_limit_days':90}]):
            result=audit.urlscan_check('example.com','key')
        self.assertEqual(result['status'],'empty')
        self.assertEqual(result['data']['history_scope'],'none')
        self.assertIn('90',result['summary'])
        self.assertIn('不证明网站安全',result['summary'])

    def test_report_missing_history_has_no_live_scan_panel(self):
        r={'domain':'example.com','checked_at':'2026-10-15T12:00:00Z','report_id':'DEMO',
           'sources':{'urlscan':audit.source('empty',data={'search_date_limit_days':90}),
                      'dns':audit.source('ok'),'virustotal':audit.source('ok')},
           'assessment':{'findings':[]}}
        page=report_html.render(r)
        self.assertNotIn('本次实时网页扫描',page)
        self.assertIn('最近 90 天',page)
        self.assertIn('不提交新的 urlscan 网页扫描任务',page)
        self.assertNotIn('实时扫描失败',page)

    def test_removed_live_cli_options_fail_before_audit(self):
        import contextlib
        import io
        for flags in (['--live-scan'], ['--no-live-scan'], ['--live-visibility','public']):
            with self.subTest(flags=flags), patch.object(audit,'audit_cmd') as cmd:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    audit.main(['audit','--domain','example.com'] + flags)
                self.assertEqual(error.exception.code,2)
                cmd.assert_not_called()

if __name__=='__main__':unittest.main()
