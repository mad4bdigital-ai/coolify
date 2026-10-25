"""Regression guard: Traefik must use a network shared with the public proxy."""
from pathlib import Path
import re
import unittest

COMPOSE = (Path(__file__).resolve().parents[1] / "compose.yaml").read_text()

def section(name):
    start=COMPOSE.index("\n  "+name+":\n")
    match=re.search(r"(?m)^  [a-z][a-z0-9-]+:$",COMPOSE[start+4:])
    end=start+4+match.start() if match else -1
    return COMPOSE[start:] if end<0 else COMPOSE[start:end]

class ProxyNetworkTests(unittest.TestCase):
    def test_each_public_router_pins_shared_network(self):
        for name in ("coolify-mcp-oauth","public-file-upload","mcp-provider-registry"):
            with self.subTest(service=name):
                body=section(name)
                self.assertEqual(body.count("traefik.docker.network=coolify"),1)
                self.assertIn("      - coolify-internal",body)
    def test_oauth_full_authorization_routes(self):
        body=section("coolify-mcp-oauth")
        self.assertIn("PathPrefix(`/`)",body)
        self.assertIn("loadbalancer.server.port=8080",body)
    def test_upload_routes_override_general_oauth_router(self):
        self.assertIn("priority=100",section("coolify-mcp-oauth"))
        self.assertIn("priority=150",section("public-file-upload"))
        self.assertIn("priority=160",section("mcp-provider-registry"))

if __name__=="__main__":unittest.main()
