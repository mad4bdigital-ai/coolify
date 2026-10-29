"""Guard the long-lived ChatGPT MCP OAuth client registration contract.

The runtime image ghcr.io/babs/mcp-auth-proxy:2.1.0 documents 0 as
non-expiring sealed DCR client_ids. Access/refresh tokens remain short-lived.
"""
from pathlib import Path
import re
import unittest


COMPOSE_PATH = Path(__file__).resolve().parents[1] / "compose.yaml"


class TestOAuthClientRegistrationConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = COMPOSE_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^  shell-oauth:\s*\n(?P<body>.*?)(?=^  [a-zA-Z0-9_.-]+:|\Z)",
            cls.compose,
        )
        if match is None:
            raise AssertionError("shell-oauth service missing from Compose")
        cls.service = match.group("body")
        cls.other_services = cls.compose.replace(match.group(0), "", 1)

    def test_only_shell_oauth_has_nonexpiring_client_registration(self):
        configured = re.findall(
            r"(?m)^      CLIENT_REGISTRATION_TTL:\s*[^#\n]+",
            self.service,
        )
        self.assertEqual(configured, ['      CLIENT_REGISTRATION_TTL: "0"'])
        self.assertNotIn("CLIENT_REGISTRATION_TTL", self.other_services)

    def test_proxy_version_supports_zero_as_never_expire(self):
        self.assertIn("image: ghcr.io/babs/mcp-auth-proxy:2.1.0", self.service)

    def test_oauth_protection_unchanged(self):
        self.assertIn('PROD_MODE: "true"', self.service)
        for required in (
            "OIDC_ISSUER_URL:",
            "OIDC_CLIENT_ID:",
            "OIDC_CLIENT_SECRET:",
            "TOKEN_SIGNING_SECRET:",
            "UPSTREAM_MCP_URL:",
            "REDIS_URL:",
            "security_opt: [no-new-privileges:true]",
            "cap_drop: [ALL]",
        ):
            self.assertIn(required, self.service)


if __name__ == "__main__":
    unittest.main()
