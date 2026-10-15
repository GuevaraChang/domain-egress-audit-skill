"""Offline urlscan detailed-history and opt-in remote scan tests."""
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from argparse import Namespace

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

    def test_default_live_submits_private(self):
        response=unittest.mock.Mock(status_code=200)
        response.json.return_value={'uuid':UUID}
        with patch.object(audit.requests,'post',return_value=response) as post, \
             patch.object(audit,'urlscan_fetch_detail',return_value={'page_title':'Demo'}):
            result=audit.urlscan_live_check('example.com','key',public_ips=['1.1.1.1'],delay=0,attempts=1)
        self.assertEqual(result['status'],'ok')
        self.assertEqual(post.call_args.kwargs['json']['visibility'],'private')
        self.assertEqual(post.call_count,1)

    def test_explicit_no_live_scan_never_submits(self):
        with patch.object(audit.requests,'post') as post:
            result=audit.urlscan_live_check('example.com','key',enabled=False,public_ips=['1.1.1.1'])
        post.assert_not_called()
        self.assertEqual(result['status'],'skipped')

    def test_opt_in_private_submits_only_domain_root(self):
        response=unittest.mock.Mock(status_code=200)
        response.json.return_value={'uuid':UUID}
        with patch.object(audit.requests,'post',return_value=response) as post, \
             patch.object(audit,'urlscan_fetch_detail',return_value={'page_title':'Safe Demo'}) as fetch:
            res=audit.urlscan_live_check('example.com','key',enabled=True,visibility='private',
                                         public_ips=['1.2.3.4'],delay=0,attempts=1)
        self.assertEqual(res['status'],'ok')
        self.assertEqual(post.call_args.kwargs['json'],{'url':'https://example.com/','visibility':'private'})
        self.assertFalse(post.call_args.kwargs['allow_redirects'])
        self.assertEqual(fetch.call_count,1)

    def test_live_requires_public_ip_and_key(self):
        with patch.object(audit.requests,'post') as post:
            self.assertEqual(audit.urlscan_live_check('example.com','key',enabled=True,public_ips=[])['status'],'skipped')
            self.assertEqual(audit.urlscan_live_check('example.com','',enabled=True,public_ips=['1.1.1.1'])['status'],'not_configured')
        post.assert_not_called()

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

    def test_report_shows_live_result_separately_from_missing_history(self):
        record=audit.urlscan_scan_detail(detail(),UUID,'example.com')
        r={'domain':'example.com','checked_at':'2026-10-15T12:00:00Z','report_id':'DEMO',
           'sources':{'urlscan':audit.source('empty',data={'search_date_limit_days':90}),
                      'urlscan_live':audit.source('ok',data={'result':record},url=URL),
                      'dns':audit.source('ok'),'virustotal':audit.source('ok')},
           'assessment':{'findings':[]}}
        page=report_html.render(r)
        self.assertIn('本次实时网页扫描',page)
        self.assertIn('最近 90 天',page)
        self.assertIn('扫描完成',page)
        self.assertIn('查看本次实时扫描',page)

    def test_cli_live_defaults_on_and_supports_disable(self):
        with patch.object(audit,'audit_cmd',return_value=0) as cmd:
            self.assertEqual(audit.main(['audit','--domain','example.com']),0)
            self.assertFalse(cmd.call_args.args[0].no_live_scan)
            self.assertEqual(audit.main(['audit','--domain','example.com','--no-live-scan']),0)
            self.assertTrue(cmd.call_args.args[0].no_live_scan)

if __name__=='__main__':unittest.main()
