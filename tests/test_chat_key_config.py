"""Regression checks for removed providers and agent-assisted local key setup."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from argparse import Namespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('agent_config_audit', ROOT / 'scripts' / 'domain_audit.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class ChatKeyConfigTests(unittest.TestCase):
    def test_only_two_optional_credentials_supported(self):
        self.assertEqual(set(a.CREDENTIAL_NAMES), {'URLSCAN_API_KEY','VT_API_KEY'})
        self.assertEqual(len(a.report_html.SOURCE_NAMES), 7)
        for removed in ('OLD_API_KEY','UNSUPPORTED_API_KEY'):
            self.assertNotIn(removed, a.CONFIG_NAMES)

    def test_chat_supplied_urlscan_key_is_saved_privately_and_not_printed(self):
        with tempfile.TemporaryDirectory() as temp:
            envfile = Path(temp) / '.env'
            secret = 'TEST-CHAT-KEY-NOT-REAL-0987'
            args = Namespace(name='URLSCAN_API_KEY', stdin=True, vt_tier=None)
            capture = io.StringIO()
            with patch.object(a,'DEFAULT_ENV',envfile), patch.object(a.sys,'stdin',io.StringIO(secret+'\n')), \
                    contextlib.redirect_stdout(capture):
                self.assertEqual(a.set_key_cmd(args), 0)
                self.assertEqual(a.read_env()['URLSCAN_API_KEY'], secret)
            self.assertNotIn(secret, capture.getvalue())
            self.assertEqual(os.stat(envfile).st_mode & 0o777, 0o600)
            self.assertIn('ONBOARDING_DONE=yes', envfile.read_text())

    def test_unknown_key_name_rejected_and_no_write(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'.env'
            with patch.object(a,'DEFAULT_ENV',path),patch.object(a.sys,'stdin',io.StringIO('ignored\n')):
                with self.assertRaises(ValueError):
                    a.set_key_cmd(Namespace(name='OTX_API_KEY', stdin=True, vt_tier=None))
            self.assertFalse(path.exists())

    def test_empty_key_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'.env'
            with patch.object(a,'DEFAULT_ENV',path),patch.object(a.sys,'stdin',io.StringIO(' \n')):
                with self.assertRaises(ValueError):
                    a.set_key_cmd(Namespace(name='URLSCAN_API_KEY', stdin=True, vt_tier=None))
            self.assertFalse(path.exists())

    def test_virus_total_requires_verified_tier_before_auto_call(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'.env'
            with patch.object(a,'DEFAULT_ENV',path),contextlib.redirect_stdout(io.StringIO()):
                args=Namespace(name='VT_API_KEY', stdin=True,vt_tier=None)
                with patch.object(a.sys,'stdin',io.StringIO('test-key\n')):
                    a.set_key_cmd(args)
                self.assertEqual(a.effective_vt_usage(a.read_env()),'not_enabled')
                args.vt_tier='noncommercial'
                with patch.object(a.sys,'stdin',io.StringIO('test-key\n')):
                    a.set_key_cmd(args)
                self.assertEqual(a.effective_vt_usage(a.read_env()),'noncommercial')

if __name__ == '__main__':
    unittest.main()
