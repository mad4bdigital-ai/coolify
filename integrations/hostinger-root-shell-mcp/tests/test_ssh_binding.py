"""Local-only checks for per-target identity discovery."""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
