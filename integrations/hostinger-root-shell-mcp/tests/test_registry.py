"""Offline tests: no network access, secrets, or VPS changes."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import registry


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "inventory.json"
        self.patcher = patch.object(registry, "REGISTRY_FILE", self.path)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def write(self, entries):
        self.path.write_text(json.dumps({"targets": entries}), encoding="utf-8")

    def entry(self, **changes):
        return dict({"id": "hostinger_primary", "kind": "ssh",
                     "label": "Primary", "environment": "production",
                     "host": "187.7.76.129", "port": 22, "enabled": True},
                    **changes)

    def test_unconfigured(self):
        self.assertEqual(registry.list_targets(), {
            "configured": False, "count": 0, "targets": [],
            "secrets_included": False,
        })

    def test_list_and_filter(self):
        self.write([self.entry(), self.entry(id="staging_site",
                    kind="wordpress", host="stage.example.com",
                    port=443, environment="staging")])
        self.assertEqual(registry.list_targets()["count"], 2)
        self.assertEqual(registry.list_targets(kind="ssh")["count"], 1)
        self.assertEqual(registry.list_targets(environment="staging")["count"], 1)

    def test_secret_fields_never_returned(self):
        self.write([self.entry(password="do-not-return", token="private",
                               ssh_key="private")])
        rendered = json.dumps(registry.list_targets())
        self.assertNotIn("do-not-return", rendered)
        self.assertNotIn("private", rendered)

    def test_duplicate_ids(self):
        self.write([self.entry(), self.entry()])
        with self.assertRaises(ValueError):
            registry.load_registry()

    def test_invalid_id(self):
        self.write([self.entry(id="../escape")])
        with self.assertRaises(ValueError):
            registry.load_registry()

    def test_invalid_hosts(self):
        for host in ["", "user@host", "host/name", "a b", "https://host", "host:22"]:
            with self.subTest(host=host):
                self.write([self.entry(host=host)])
                with self.assertRaises(ValueError):
                    registry.load_registry()

    def test_ipv6(self):
        self.write([self.entry(host="2001:db8::10")])
        self.assertEqual(registry.load_registry()["targets"][0]["host"], "2001:db8::10")

    def test_invalid_ports(self):
        for port in [0, 65536, -1, True, "22"]:
            with self.subTest(port=port):
                self.write([self.entry(port=port)])
                with self.assertRaises(ValueError):
                    registry.load_registry()

    def test_no_credentials_required_for_inventory(self):
        self.write([self.entry()])
        self.assertEqual(registry.list_targets()["targets"][0]["id"], "hostinger_primary")


if __name__ == "__main__":
    unittest.main()
