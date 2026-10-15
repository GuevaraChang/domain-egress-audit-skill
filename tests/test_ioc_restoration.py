"""Regression tests: retain approved open-source IOC while not reintroducing vendor APIs."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

scripts = Path(__file__).resolve().parents[1] / 'scripts'
import sys
sys.path.insert(0, str(scripts))
import local_ioc
import domain_audit as a
from report_html import render, source_view

class RestoreLocalIOC(unittest.TestCase):
    def test_default_feeds_preserved_without_vendor_keys(self):
        self.assertEqual(set(local_ioc.FEEDS), {'cn_phishshield','cn_ipguard','cn_antiad'})
        self.assertEqual({k for k,v in local_ioc.FEEDS.items() if v['enabled_by_default']},
                         {'cn_phishshield','cn_ipguard'})
        self.assertEqual(set(a.CREDENTIAL_NAMES), {'URLSCAN_API_KEY','VT_API_KEY'})
    def test_missing_cache_refresh_automatically(self):
        with patch.object(local_ioc,'list_feeds',return_value=[]), \
             patch.object(local_ioc,'update_feeds',return_value={
                'cn_phishshield':{'status':'ok'},'cn_ipguard':{'status':'ok'}}) as update:
            result = a.auto_refresh_local_ioc('/temp/noactual.db')
        self.assertEqual(result['status'],'updated')
        self.assertFalse(result['target_sent'])
        self.assertEqual(set(update.call_args.kwargs['names']),{'cn_phishshield','cn_ipguard'})
    def test_fresh_cache_does_not_redownload(self):
        today = a.utc_now()
        rows=[{'feed':x,'updated_at':today} for x in ('cn_phishshield','cn_ipguard')]
        with patch.object(local_ioc,'list_feeds',return_value=rows), \
             patch.object(local_ioc,'update_feeds') as update:
            result=a.auto_refresh_local_ioc('/temp/noactual.db')
        update.assert_not_called()
        self.assertEqual(result['status'],'fresh_cache')
    def test_missing_ioc_not_shown_as_safely_checked(self):
        item=a.source('not_configured', data={'eligible_feeds':0,'feeds':[]})
        view=source_view('local_ioc',item,set())
        self.assertEqual(view[0],'mute')
        self.assertIn('名单',view[2])

if __name__=='__main__': unittest.main()
