"""Contract and guard tests for the scoped Registry SSH transport."""
import asyncio
import base64
import hashlib
import unittest
from unittest.mock import AsyncMock, patch

from remote_transport import remote_exec, remote_file_transfer

TARGET = "hosting-2"
SCOPE = "hosting-2:staging"
ROOT = "/home/u948953904/domains/allroyalegypt.com/public_html/staging"

class RegistryRemoteTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_other_target_cannot_use_staging_scope(self):
        result = await remote_exec("hosting-1", SCOPE, "site_root")
        self.assertEqual(result["state"], "DENIED")
        self.assertEqual(result["reason"], "scope_not_enrolled")

    async def test_unknown_scope_is_rejected(self):
        result = await remote_file_transfer(TARGET, "hosting-2:production",
                                            "test.zip", "ZmlsZQ==", "0" * 64)
        self.assertEqual(result["state"], "DENIED")
        self.assertEqual(result["reason"], "scope_not_enrolled")

    async def test_path_traversal_is_rejected_before_ssh(self):
        fake_target = {"id": TARGET, "port": 65002}
        fake_scope = {"root": ROOT}
        with patch("remote_transport.scope_for", return_value=(fake_target, fake_scope)):
            result = await remote_file_transfer(TARGET, SCOPE, "../test.zip", "", "0" * 64)
        self.assertEqual(result["state"], "DENIED")
        self.assertEqual(result["reason"], "invalid_filename_or_digest")

    async def test_checksum_mismatch_rejected_before_network(self):
        fake_target = {"id": TARGET, "port": 65002}
        fake_scope = {"root": ROOT}
        data = base64.b64encode(b"valid-file").decode()
        with patch("remote_transport.scope_for", return_value=(fake_target, fake_scope)):
            result = await remote_file_transfer(TARGET, SCOPE, "test.zip", data, "0" * 64)
        self.assertEqual(result["state"], "DENIED")
        self.assertEqual(result["reason"], "source_checksum_mismatch")

    async def test_unapproved_exec_operation_is_rejected(self):
        fake_target = {"id": TARGET, "port": 65002}
        fake_scope = {"root": ROOT}
        with patch("remote_transport.scope_for", return_value=(fake_target, fake_scope)), \
             patch("remote_transport.assert_scope", new=AsyncMock(return_value=ROOT)):
            result = await remote_exec(TARGET, SCOPE, "arbitrary_shell")
        self.assertEqual(result["state"], "DENIED")
        self.assertEqual(result["reason"], "operation_not_allowed")

    async def test_idempotent_existing_artifact(self):
        fake_target = {"id": TARGET, "port": 65002}
        fake_scope = {"root": ROOT}
        payload = b"example-artifact"
        expected = hashlib.sha256(payload).hexdigest()
        with patch("remote_transport.scope_for", return_value=(fake_target, fake_scope)), \
             patch("remote_transport.assert_scope", new=AsyncMock(return_value=ROOT)), \
             patch("remote_transport.ssh", new=AsyncMock(side_effect=["", ROOT + "/wp-content/uploads/mad4b-central-transport", "exists", expected + "  a.zip"])):
            result = await remote_file_transfer(TARGET, SCOPE, "a.zip",
                                                base64.b64encode(payload).decode(), expected)
        self.assertEqual(result["state"], "READBACK_VERIFIED")
        self.assertTrue(result["idempotent"])

if __name__ == "__main__":
    unittest.main()
