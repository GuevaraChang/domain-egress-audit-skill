import importlib.util
import contextlib
import io
from argparse import Namespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'domain_audit.py'
spec = importlib.util.spec_from_file_location('domain_audit', MODULE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class TestDomainAudit(unittest.TestCase):
    def test_domain_validation(self):
        self.assertEqual(audit.validated_domain(' API.Example.COM. '), ('api.example.com', 'example.com'))
        for input_ in ('https://example.com/', '127.0.0.1', 'example.com:443', 'root@x.com',
                       'localhost', '../example.com', 'a..com', 'hidden.internal', 'abc.local'):
            with self.subTest(domain=input_):
                with self.assertRaises(ValueError):
                    audit.validated_domain(input_)

    def test_no_autopass_on_missing_context_and_sources(self):
        sources = {
            'rdap': audit.source('error', error='timeout'),
            'dns': audit.source('empty', data={'ips': []}),
            'urlscan': audit.source('not_configured'),
            'tls': audit.source('skipped'),
            'crtsh': audit.source('empty'),
            'ripestat': audit.source('skipped'),
        }
        report = {'sources': sources, 'business_context': {}}
        result = audit.evaluate(report)
        self.assertFalse(result['automatic_approval'])
        self.assertIn('证据不充分', result['risk_label'])
        self.assertGreaterEqual(len(result['pending_items']), 3)

    def test_urlscan_redirect_is_review_not_malicious_proof(self):
        sources = {
            'rdap': audit.source('ok', data={'age_days': 365}),
            'dns': audit.source('ok', data={'ips': [{'ip': '8.8.8.8', 'globally_routable': True}]}),
            'urlscan': audit.source('ok', data={'results':[{'redirected':'off-domain','task_url_host':'example.com','result_page_host':'other.example.net'}]}),
            'tls': audit.source('skipped'), 'crtsh': audit.source('ok'), 'ripestat': audit.source('ok'),
        }
        result = audit.evaluate({'sources': sources, 'business_context': {}})
        self.assertIn('可疑', result['risk_label'])
        self.assertIn('off_domain_redirect', [f['type'] for f in result['findings']])
        self.assertNotIn('高风险', result['risk_label'])

    def test_confirmed_malicious_manual_flag(self):
        s = {k: audit.source('skipped') for k in ('rdap','dns','urlscan','tls','crtsh','ripestat')}
        result = audit.evaluate({'sources': s, 'business_context': {'confirmed_malicious_evidence': True,'confirmed_malicious_evidence_reference': 'CASE-2026-001'}})
        self.assertIn('高风险', result['risk_label'])
        self.assertFalse(result['automatic_approval'])

    def test_probing_not_run_when_disabled(self):
        r = audit.tls_check('example.com', 443, [{'ip':'8.8.8.8','globally_routable':True}])
        self.assertEqual(r['status'], 'skipped')

    def test_context_domain_does_not_match(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'ctx.json'
            p.write_text('{"target_fqdn":"other.example.com"}', encoding='utf-8')
            with self.assertRaises(ValueError):
                audit.read_context(p, 'example.com')

    def test_build_report_offline_with_mock_sources(self):
        mock_dns = audit.source('ok', data={
            'ips': [{'ip': '8.8.8.8', 'globally_routable': True}],
            'records': {'A': ['8.8.8.8'], 'AAAA': [], 'CNAME': [], 'NS': ['ns.example.com']}})
        with patch.object(audit, 'dns_check', return_value=mock_dns), \
             patch.object(audit, 'rdap_check', return_value=audit.source('ok', data={'age_days': 3650})), \
             patch.object(audit, 'ripestat_check', return_value=audit.source('ok', data={'results': []})), \
             patch.object(audit, 'crt_check', return_value=audit.source('ok', data={})), \
             patch.object(audit, 'urlscan_check', return_value=audit.source('not_configured')), \
             patch.object(audit, 'tls_check', return_value=audit.source('skipped')), \
             patch.object(audit.local_ioc, 'inspect_cached', return_value=audit.source('not_configured')):
            report = audit.build_report('example.com', 'example.com', {}, env={})
        self.assertEqual(report['domain'], 'example.com')
        self.assertEqual(report['sources']['dns']['status'], 'ok')
        self.assertFalse(report['assessment']['automatic_approval'])

    def test_urlscan_original_domain_redirect_retained(self):
        """A redirect changes page.domain, but task.domain still identifies the queried FQDN."""
        fake = {'results': [
            {'page': {'domain': 'login.example.net', 'redirected': 'off-domain', 'url': 'https://login.example.net'},
             'task': {'domain': 'example.com', 'time': '2026-10-10T10:00:00Z'},
             'result': 'https://urlscan.io/result/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/', '_id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'},
            {'page': {'domain': 'unrelated.test'}, 'task': {'domain': 'unrelated.test'}},
        ]}
        with patch.object(audit, 'req_json', side_effect=[fake, {'task':{'domain':'example.com','url':'https://example.com/','time':'2026-10-10T10:00:00Z'}, 'page':{'url':'https://login.example.net/','domain':'login.example.net','redirected':'off-domain'}}]) as mock:
            result = audit.urlscan_check('example.com', 'test-key')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['data']['matched_results'], 1)
        self.assertEqual(result['data']['results'][0]['redirected'], 'off-domain')
        self.assertIn('task.domain.keyword', mock.call_args_list[0].kwargs['params']['q'])

    def test_outbound_api_does_not_follow_redirects(self):
        fake = unittest.mock.Mock()
        fake.status_code = 302
        fake.raise_for_status.return_value = None
        with patch.object(audit.requests, 'get', return_value=fake) as mock:
            with self.assertRaises(audit.requests.HTTPError):
                audit.req_json('https://example.com/api', headers={'api-key':'dummy'})
        self.assertFalse(mock.call_args.kwargs['allow_redirects'])

    def test_report_markdown_contains_audit_sections(self):
        sources = {k: audit.source('skipped') for k in ('rdap','dns','urlscan','tls','crtsh','ripestat')}
        sources['dns']['data'] = {'ips': [], 'records': {}}
        report = {'report_id': 'TEST', 'checked_at': audit.utc_now(), 'domain':'example.com',
                  'registered_domain': 'example.com', 'business_context': {}, 'sources': sources}
        report['assessment'] = audit.evaluate(report)
        md = audit.render_markdown(report)
        self.assertIn('域名安全检查报告', md)
        self.assertIn('已检查与未检查', md)
        self.assertIn('最终建议', md)
        self.assertNotIn('自动批准：是', md)


    def test_virustotal_requires_explicit_permission_even_with_key(self):
        with patch.object(audit, 'req_json') as mocked:
            result = audit.vt_check('example.com', 'hidden-key', 'not_enabled')
        mocked.assert_not_called()
        self.assertEqual(result['status'], 'skipped')
        self.assertEqual(result['data']['skip_reason'], 'permission_not_confirmed')

    def test_virustotal_noncommercial_no_key(self):
        with patch.object(audit, 'req_json') as mocked:
            result = audit.vt_check('example.com', '', 'noncommercial')
        mocked.assert_not_called()
        self.assertEqual(result['status'], 'not_configured')

    def test_virustotal_noncommercial_uses_v3_get_domain(self):
        data = {'data': {'attributes': {'last_analysis_stats': {
            'malicious': 2, 'suspicious': 1, 'harmless': 12, 'undetected': 50},
            'last_analysis_date': 1760000000, 'reputation': -3}}}
        with patch.object(audit, 'req_json', return_value=data) as mocked:
            result = audit.vt_check('example.com', 'local-key', 'noncommercial')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['data']['last_analysis_stats']['malicious'], 2)
        self.assertEqual(result['data']['last_analysis_stats']['suspicious'], 1)
        self.assertEqual(mocked.call_args.args[0], 'https://www.virustotal.com/api/v3/domains/example.com')
        self.assertEqual(mocked.call_args.kwargs['headers'], {'x-apikey': 'local-key'})
        self.assertNotIn('local-key', str(result))

    def test_virustotal_api_error_is_not_zero_hit(self):
        with patch.object(audit, 'req_json', side_effect=audit.requests.HTTPError('429')):
            result = audit.vt_check('example.com', 'key', 'noncommercial')
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('last_analysis_stats', result['data'])

    def test_vt_license_permission_gate(self):
        self.assertEqual(audit.effective_vt_usage({}), 'not_enabled')
        self.assertEqual(audit.effective_vt_usage({'VT_USAGE':'unexpected'}), 'not_enabled')
        self.assertEqual(audit.effective_vt_usage({'VT_USAGE':'noncommercial'}), 'noncommercial')
        self.assertEqual(audit.effective_vt_usage({'VT_API_TIER':'premium'}), 'licensed')
        self.assertEqual(audit.effective_vt_usage({'VT_USAGE':'noncommercial'}, {'usage_type':'business'}), 'noncommercial')

    def test_vt_detection_is_review_signal_not_confirmed_malicious(self):
        sources = {k: audit.source('skipped') for k in (
            'rdap','dns','urlscan','tls','crtsh','ripestat')}
        sources['dns']['data'] = {'ips': []}
        sources['virustotal'] = audit.source('ok', data={
            'last_analysis_stats': {'malicious': 2, 'suspicious': 1}})
        result = audit.evaluate({'sources': sources, 'business_context': {}})
        self.assertIn('virustotal_detection', [f['type'] for f in result['findings']])
        self.assertNotIn('高风险', result['risk_label'])
        self.assertFalse(result['automatic_approval'])

    def test_doctor_no_vt_request_without_permission(self):
        args=Namespace(online=True)
        env={'VT_API_KEY':'unused-key'}
        def public_response(url, **kwargs):
            self.assertNotIn('virustotal', url)
            return {'services':[1], 'status':'ok'}
        with patch.object(audit, 'read_env', return_value=env), \
             patch.object(audit, 'req_json', side_effect=public_response) as mocked, \
             contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(audit.doctor_cmd(args), 0)
        self.assertIn('未启用', buf.getvalue())
        self.assertEqual(mocked.call_count, 2)

    def test_setup_noninteractive_preserves_empty_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'.env'
            with patch.object(audit, 'DEFAULT_ENV', path), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(audit.init_cmd(Namespace(non_interactive=True,force=False)),0)
            config=path.read_text(encoding='utf-8')
        self.assertIn('ONBOARDING_DONE=no',config)
        self.assertNotIn('VT_USAGE=noncommercial',config)
        self.assertNotIn('VT_API_KEY=test',config)

    def test_setup_interactive_confirmed_vt_permission(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'.env'
            with patch.object(audit, 'DEFAULT_ENV', path), \
                 patch.object(audit.sys.stdin,'isatty',return_value=True), \
                 patch('builtins.input', side_effect=['y','1','n']), \
                 patch.object(audit.getpass,'getpass',side_effect=['', 'vt-secret']), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(audit.init_cmd(Namespace(non_interactive=False,force=False)),0)
            config=path.read_text(encoding='utf-8')
        self.assertIn('VT_USAGE=noncommercial',config)
        self.assertIn('ONBOARDING_DONE=yes',config)
        self.assertIn('VT_API_KEY=vt-secret',config)

    def test_business_context_does_not_change_user_api_authorization(self):
        self.assertEqual(audit.effective_vt_usage({'VT_USAGE':'noncommercial'}, {'usage_type':'business'}), 'noncommercial')
        with patch.object(audit,'req_json',return_value={'data':{'attributes':{'last_analysis_stats':{}}}}):
            result=audit.vt_check('example.com','authorized-key','noncommercial')
        self.assertEqual(result['status'],'ok')

    def test_business_local_setting_cannot_be_overridden_by_env(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'.env'
            path.write_text('VT_USAGE=business\nVT_API_KEY=abc\n',encoding='utf-8')
            with patch.dict(audit.os.environ, {'VT_USAGE': 'noncommercial'}, clear=False):
                obj=audit.read_env(path)
        self.assertEqual(obj['VT_USAGE'], 'business')

    def test_interactive_setup_can_skip_optional_keys(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'.env'
            with patch.object(audit, 'DEFAULT_ENV', path), \
                 patch.object(audit.sys.stdin,'isatty',return_value=True), \
                 patch('builtins.input', side_effect=['n', 'n']), \
                 patch.object(audit.getpass, 'getpass', return_value='') as hidden, \
                 contextlib.redirect_stdout(io.StringIO()):
                rc=audit.init_cmd(Namespace(non_interactive=False,force=False))
            contents=path.read_text(encoding='utf-8')
        self.assertEqual(rc,0)
        self.assertEqual(hidden.call_count,1)
        self.assertIn('ONBOARDING_DONE=yes',contents)

    def test_passive_asset_inventory_never_auto_expands_related_targets(self):
        src = {k: audit.source('skipped') for k in
               ('rdap', 'dns', 'ripestat', 'crtsh', 'urlscan', 'virustotal', 'tls')}
        src['dns'] = audit.source('ok', data={
            'records': {'A': ['8.8.8.8'], 'CNAME': ['cdn.vendor.net']},
            'ips': [{'ip': '8.8.8.8', 'globally_routable': True}]})
        src['urlscan'] = audit.source('ok', data={'results': [
            {'result_page_host': 'login.thirdparty.org', 'scan_time': '2026-07-01T00:00:00Z'}]})
        items = audit.build_asset_inventory({'domain': 'example.com', 'sources': src})
        self.assertEqual(items[0]['hostname'], 'example.com')
        self.assertTrue(items[0]['in_approved_scope'])
        self.assertEqual({i['hostname'] for i in items},
                         {'example.com', 'cdn.vendor.net', 'login.thirdparty.org'})
        self.assertTrue(all(not i['in_approved_scope'] for i in items[1:]))
        self.assertTrue(all(i['attribution_confidence'] == 'unconfirmed' for i in items))

    def test_evidence_ledger_distinguishes_query_time_from_observed_time(self):
        src = {k: audit.source('skipped') for k in
               ('rdap', 'dns', 'ripestat', 'crtsh', 'urlscan', 'virustotal', 'tls')}
        src['urlscan'] = audit.source('ok', data={'results': [
            {'scan_time': '2020-01-01T00:00:00Z'}]})
        src['virustotal'] = audit.source('skipped', data={'skip_reason': 'commercial_use_restriction'})
        ledger, summary = audit.evidence_ledger({'sources': src})
        self.assertEqual(ledger[4]['source'], 'urlscan')
        self.assertEqual(ledger[4]['observed_at'], '2020-01-01T00:00:00Z')
        self.assertGreater(ledger[4]['observation_age_days'], 90)
        self.assertIsNone(ledger[5]['observed_at'])
        self.assertEqual(summary['status_counts']['skipped'], 6)
        self.assertIn('urlscan', [x['source'] for x in summary['stale_observations_over_90_days']])

    def test_snapshot_diff_notes_changes_without_declaring_malicious(self):
        old = {'domain': 'example.com', 'report_id': 'OLD', 'checked_at': '2026-01-01T00:00:00Z',
               'sources': {
                   'dns': audit.source('ok', data={'ips': [{'ip': '8.8.8.8'}],
                      'records': {'CNAME': ['old.cdn.net']}}),
                   'rdap': audit.source('ok', data={'registrar': 'Registrar A'})}}
        cur = {'domain': 'example.com', 'sources': {
                   'dns': audit.source('ok', data={'ips': [{'ip': '1.1.1.1'}],
                      'records': {'CNAME': ['new.cdn.net']}}),
                   'rdap': audit.source('ok', data={'registrar': 'Registrar B'})},
               'assessment': {'pending_items': [], 'findings': [], 'risk_label': '低风险',
                              'decision': '待人工复核', 'automatic_approval': False}}
        audit.attach_baseline(cur, old)
        self.assertEqual(len(cur['baseline_comparison']['changes']), 3)
        self.assertEqual(cur['assessment']['findings'][0]['type'], 'baseline_change')
        self.assertIn('核实后再访问', cur['assessment']['decision'])
        self.assertFalse(cur['assessment']['automatic_approval'])

    def test_snapshot_compare_refuses_different_domain(self):
        with self.assertRaisesRegex(ValueError, '不一致'):
            audit.compare_reports({'domain': 'other.com', 'sources': {}},
                                  {'domain': 'example.com', 'sources': {}})

    def test_snapshot_compare_skips_broken_dns_source(self):
        old = {'domain': 'example.com', 'sources': {
            'dns': audit.source('ok', data={'ips': [{'ip': '1.1.1.1'}]}),
            'rdap': audit.source('error')}}
        now = {'domain': 'example.com', 'sources': {
            'dns': audit.source('error', data={'ips': []}), 'rdap': audit.source('error')}}
        self.assertEqual(audit.compare_reports(old, now)['changes'], [])

    def test_full_report_contains_traceable_evidence_and_inventory(self):
        fake_dns = audit.source('ok', data={'ips': [], 'records': {'CNAME': ['cdn.vendor.com']}})
        with patch.object(audit, 'dns_check', return_value=fake_dns), \
             patch.object(audit, 'rdap_check', return_value=audit.source('empty')), \
             patch.object(audit, 'ripestat_check', return_value=audit.source('skipped')), \
             patch.object(audit, 'crt_check', return_value=audit.source('empty')), \
             patch.object(audit, 'urlscan_check', return_value=audit.source('not_configured')), \
             patch.object(audit, 'tls_check', return_value=audit.source('skipped')), \
             patch.object(audit.local_ioc, 'inspect_cached', return_value=audit.source('not_configured')):
            report = audit.build_report('example.com', 'example.com', {'usage_type': 'business'}, env={})
        self.assertEqual(report['schema_version'], '2.2.0')
        self.assertEqual(len(report['evidence_ledger']), 9)
        self.assertIn('cdn.vendor.com', [x['hostname'] for x in report['asset_inventory']])
        md = audit.render_markdown(report)
        self.assertIn('已检查与未检查', md)
        self.assertIn('发现的问题', md)
        self.assertEqual(report['sources']['virustotal']['status'], 'not_configured')



if __name__ == '__main__':
    unittest.main()
