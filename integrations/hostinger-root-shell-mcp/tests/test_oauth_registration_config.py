"""Ensure MCP registration lifetime changes do not weaken authentication."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "compose.yaml").read_text(encoding="utf-8")


class RegistrationContractTests(unittest.TestCase):
    def test_service_scoped_never_expiring_registration(self):
        match = re.search(
            r"(?ms)^  shell-oauth:\s*\n(?P<block>.*?)(?=^  [a-zA-Z0-9_.-]+:|\Z)",
            SOURCE,
        )
        self.assertIsNotNone(match)
        block = match.group("block")
        matches = re.findall(
            r'(?m)^      CLIENT_REGISTRATION_TTL:\s*[^\n]+',
            block,
        )
        self.assertEqual(matches, ['      CLIENT_REGISTRATION_TTL: "0"'])
        self.assertEqual(SOURCE.count("CLIENT_REGISTRATION_TTL:"), 1)
        for setting in (
            'PROD_MODE: "true"',
            "OIDC_ISSUER_URL:",
            "OIDC_CLIENT_ID:",
            "OIDC_CLIENT_SECRET:",
            "TOKEN_SIGNING_SECRET:",
            "REDIS_URL:",
            "no-new-privileges:true",
            "cap_drop:",
        ):
            self.assertIn(setting, block)

    def test_pinned_proxy_supports_never_expiring_dcr(self):
        source = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("ghcr.io/babs/mcp-auth-proxy:2.1.0", source)


if __name__ == "__main__":
    unittest.main()
