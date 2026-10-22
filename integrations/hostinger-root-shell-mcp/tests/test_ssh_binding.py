"""Local-only checks for per-target identity discovery."""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, AsyncMock

import ssh_binding


class SshBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bound = patch.object(ssh_binding, "BINDING_DIRECTORY", self.root)
        self.bound.start()
        self.addCleanup(self.bound.stop)
        self.target = {"id": "hosting-2", "kind": "ssh", "host": "example.invalid", "port": 65002}

    def test_missing_mount_fails_closed(self):
        got = ssh_binding.summarize_ssh_binding(self.target)
        self.assertEqual(got["status"], "identity_directory_not_mounted")
        self.assertFalse(got["authenticated"])

    def test_prepared_keys_require_verified_host_key(self):
        folder = self.root / "hosting-2"
        folder.mkdir()
        (folder / "id_ed25519").write_text("dummy")
        (folder / "id_ed25519").chmod(0o600)
        (folder / "id_ed25519.pub").write_text("dummy-public")
        (folder / "host_keys_candidate").write_text("candidate")
        got = ssh_binding.summarize_ssh_binding(self.target)
        self.assertEqual(got["status"], "identity_prepared_host_key_not_verified")
        self.assertFalse(got["verified_host_key_file_present"])
        self.assertFalse(got["authenticated"])
        self.assertFalse(got["data_access_verified"])

    def test_unprotected_key_rejected(self):
        folder = self.root / "hosting-2"
        folder.mkdir()
        (folder / "id_ed25519").write_text("dummy")
        (folder / "id_ed25519").chmod(0o644)
        (folder / "id_ed25519.pub").write_text("dummy-public")
        got = ssh_binding.summarize_ssh_binding(self.target)
        self.assertEqual(got["status"], "identity_incomplete_or_permissions_invalid")

    def test_symlink_key_rejected(self):
        folder = self.root / "hosting-2"
        folder.mkdir()
        actual = self.root / "other-key"
        actual.write_text("dummy")
        actual.chmod(0o600)
        (folder / "id_ed25519").symlink_to(actual)
        (folder / "id_ed25519.pub").write_text("dummy-public")
        got = ssh_binding.summarize_ssh_binding(self.target)
        self.assertEqual(got["status"], "identity_incomplete_or_permissions_invalid")

    def test_root_shell_identity_is_separate(self):
        got = ssh_binding.summarize_ssh_binding({"id": "hostinger-primary", "kind": "ssh"})
        self.assertEqual(got["status"], "managed_by_existing_root_shell")
        self.assertFalse(got["authenticated"])



class AuthenticationProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        binding_patch = patch.object(ssh_binding, "BINDING_DIRECTORY", self.root)
        binding_patch.start()
        self.addCleanup(binding_patch.stop)
        self.target = {"id": "hosting-2", "kind": "ssh", "host": "example.invalid",
                       "port": 65002, "username": "u123"}
        self.folder = self.root / "hosting-2"
        self.folder.mkdir()
        (self.folder / "id_ed25519").write_text("dummy")
        (self.folder / "id_ed25519").chmod(0o600)
        (self.folder / "id_ed25519.pub").write_text("dummy-pub")

    async def test_missing_host_pin_never_connects(self):
        import providers
        with patch.object(providers, "registered_target", return_value=self.target):
            with patch.object(ssh_binding.asyncio, "create_subprocess_exec") as connect:
                result = await ssh_binding.probe_authenticated_ssh("hosting-2")
        self.assertEqual(result["status"], "identity_prepared_host_key_not_verified")
        self.assertFalse(result["authenticated"])
        connect.assert_not_called()

    async def test_auth_success_uses_fixed_command_and_strict_pin(self):
        import providers
        (self.folder / "known_hosts_verified").write_text(
            "[example.invalid]:65002 ssh-ed25519 AAAATEST\n")
        (self.folder / "known_hosts_verified").chmod(0o600)
        fake_proc = type("MockProcess", (), {})()
        fake_proc.returncode = 0
        fake_proc.communicate = AsyncMock(return_value=(b"MAD4B_SSH_AUTH_OK", b""))
        with patch.object(providers, "registered_target", return_value=self.target):
            with patch.object(ssh_binding.asyncio, "create_subprocess_exec",
                              new=AsyncMock(return_value=fake_proc)) as connect:
                result = await ssh_binding.probe_authenticated_ssh("hosting-2")
        self.assertEqual(result["status"], "authenticated")
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["data_access_verified"])
        args = connect.call_args.args
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertEqual(args[-1], "printf MAD4B_SSH_AUTH_OK")
        self.assertIn("u123@example.invalid", args)
        self.assertNotIn("shell_access", " ".join(args))

    async def test_wrong_host_pin_never_connects(self):
        import providers
        (self.folder / "known_hosts_verified").write_text(
            "[another.invalid]:65002 ssh-ed25519 AAAATEST\n")
        (self.folder / "known_hosts_verified").chmod(0o600)
        with patch.object(providers, "registered_target", return_value=self.target):
            with patch.object(ssh_binding.asyncio, "create_subprocess_exec") as connect:
                result = await ssh_binding.probe_authenticated_ssh("hosting-2")
        self.assertEqual(result["status"], "target_host_key_pin_missing")
        connect.assert_not_called()

    async def test_failed_login_returns_only_classification(self):
        import providers
        (self.folder / "known_hosts_verified").write_text(
            "[example.invalid]:65002 ssh-ed25519 AAAATEST\n")
        (self.folder / "known_hosts_verified").chmod(0o600)
        fake_proc = type("MockProcess", (), {})()
        fake_proc.returncode = 255
        fake_proc.communicate = AsyncMock(
            return_value=(b"", b"Permission denied (publickey). PRIVATE_DIAGNOSTIC"))
        with patch.object(providers, "registered_target", return_value=self.target):
            with patch.object(ssh_binding.asyncio, "create_subprocess_exec",
                              new=AsyncMock(return_value=fake_proc)):
                result = await ssh_binding.probe_authenticated_ssh("hosting-2")
        self.assertEqual(result["status"], "public_key_auth_denied")
        self.assertFalse(result["authenticated"])
        self.assertNotIn("PRIVATE_DIAGNOSTIC", str(result))


if __name__ == "__main__":
    unittest.main()
