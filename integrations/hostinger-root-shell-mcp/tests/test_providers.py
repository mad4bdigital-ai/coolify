"""Offline provider tests. No external requests or credentials."""
import unittest
from unittest.mock import patch

import providers


class ProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_target(self):
        with patch.object(providers, "load_registry", return_value={"targets": []}):
            with self.assertRaises(ValueError):
                await providers.check_reachability("missing")

    async def test_disabled_target(self):
        item = {"id": "edge", "kind": "ssh", "enabled": False,
                "host": "example.test", "port": 22}
        with patch.object(providers, "load_registry", return_value={"targets": [item]}):
            with self.assertRaises(ValueError):
                await providers.check_reachability("edge")

    async def test_reachability_success(self):
        item = {"id": "edge", "kind": "ssh", "enabled": True,
                "host": "example.test", "port": 22}

        class FakeWriter:
            def close(self):
                pass
            async def wait_closed(self):
                pass

        async def fake_connect(host, port):
            return object(), FakeWriter()

        with patch.object(providers, "load_registry", return_value={"targets": [item]}):
            with patch.object(providers.asyncio, "open_connection", new=fake_connect):
                result = await providers.check_reachability("edge")
        self.assertTrue(result["tcp_reachable"])
        self.assertFalse(result["authenticated"])
        self.assertFalse(result["data_access_verified"])

    async def test_https_wrong_kind(self):
        item = {"id": "edge", "kind": "ssh", "enabled": True,
                "host": "example.test", "port": 22}
        with patch.object(providers, "load_registry", return_value={"targets": [item]}):
            with self.assertRaises(ValueError):
                await providers.check_https_api("edge")


if __name__ == "__main__":
    unittest.main()
