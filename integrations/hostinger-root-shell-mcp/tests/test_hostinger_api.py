import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import hostinger_api

class ApiTests(unittest.TestCase):
    def test_unconfigured_bindings(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(hostinger_api, "CREDENTIAL_DIRECTORY", Path(tmp)):
                result = hostinger_api.binding_status()
                self.assertEqual(len(result["accounts"]), 3)
                self.assertTrue(all(not x["credential_configured"] for x in result["accounts"]))
                self.assertEqual(hostinger_api.list_websites("hosting-1")["status"], "credential_not_configured")

    def test_unknown_target_denied(self):
        with self.assertRaises(ValueError):
            hostinger_api.list_websites("not-enrolled")

if __name__ == "__main__":
    unittest.main()
