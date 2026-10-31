"""Bounded, site-scoped SSH operations using Registry's existing enrolled identity.

No caller-supplied shell command, remote absolute path, or private key material.
Staging scopes are explicitly declared; the host's inventory environment is
not substituted for the WordPress site's deployment environment.
"""
import asyncio
import base64
import binascii
import hashlib
import os
from pathlib import Path
import re
import shlex
import tempfile
import uuid

from providers import registered_target
from ssh_binding import BINDING_DIRECTORY, summarize_ssh_binding

# Scope roots MUST correspond to independently enrolled WordPress site profiles.
SCOPES = {
    "hosting-2:staging": {
        "target_id": "hosting-2",
        "root": "/home/u948953904/domains/allroyalegypt.com/public_html/staging",
        "site_uuid": "49c562d1-8f2f-456f-b454-26816c6ba4cb",
    },
}
FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}[.]zip$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
MAX_BYTES = 5 * 1024 * 1024
REMOTE_SECONDS = 25


def scope_for(target_id, scope_id):
    scope = SCOPES.get(scope_id)
    if not scope or scope["target_id"] != target_id:
        raise ValueError("scope_not_enrolled")
    target = registered_target(target_id)
    if target.get("kind") != "ssh" or not target.get("enabled", False):
        raise ValueError("target_not_enabled")
    if summarize_ssh_binding(target).get("status") != "identity_prepared_host_key_file_present":
        raise ValueError("ssh_identity_unavailable")
    if not target.get("username"):
        raise ValueError("ssh_username_not_enrolled")
    return target, scope


def ssh_args(target):
    directory = BINDING_DIRECTORY / target["id"]
    pin = directory / "known_hosts_verified"
    if pin.is_symlink() or not pin.is_file() or (pin.stat().st_mode & 0o077):
        raise ValueError("host_key_pin_invalid")
    host_key_id = f'[{target["host"]}]:{target["port"] or 22}'
    lines = pin.read_text(encoding="ascii").splitlines()
    if not any(host_key_id in line.split()[0].split(",") for line in lines if line.strip() and not line.startswith("#")):
        raise ValueError("host_key_pin_mismatch")
    opts = ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "UserKnownHostsFile=" + str(pin),
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8",
            "-i", str(directory / "id_ed25519")]
    destination = target["username"] + "@" + target["host"]
    return opts, destination


async def call(argv):
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=REMOTE_SECONDS)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise ValueError("remote_timeout")
    if proc.returncode != 0:
        raise ValueError("remote_execution_failed")
    return out[:8192].decode("utf-8", "replace").strip()


async def ssh(target, cmd):
    opts, destination = ssh_args(target)
    return await call(["ssh", "-F", "/dev/null", "-T", "-p",
                       str(target["port"] or 22), *opts, destination, cmd])


def upload_dir(scope):
    return scope["root"] + "/wp-content/uploads/mad4b-central-transport"


async def assert_scope(target, scope):
    root = scope["root"]
    actual = await ssh(target, "realpath " + shlex.quote(root + "/wp-content/uploads"))
    if actual != root + "/wp-content/uploads":
        raise ValueError("site_scope_mismatch")
    return root


async def remote_exec(target_id: str, scope_id: str, operation: str, filename: str = "") -> dict:
    """Run a predefined, Staging-scoped readback. No arbitrary shell arguments."""
    try:
        target, scope = scope_for(target_id, scope_id)
        root = await assert_scope(target, scope)
        if operation == "site_root":
            result = await ssh(target, "realpath " + shlex.quote(root))
        elif operation == "wp_cli_version":
            result = await ssh(target, "wp --version")
        elif operation == "file_sha256":
            if not FILENAME.fullmatch(filename):
                raise ValueError("invalid_filename")
            result = (await ssh(target, "sha256sum " + shlex.quote(upload_dir(scope) + "/" + filename))).split()[0]
        else:
            raise ValueError("operation_not_allowed")
        return {"contract": "mad4b.registry-remote-exec.v1", "state": "VERIFIED",
                "target": target_id, "scope": scope_id, "operation": operation,
                "result": result[:4096], "mutation_performed": False}
    except (OSError, ValueError, IndexError) as exc:
        return {"contract": "mad4b.registry-remote-exec.v1", "state": "DENIED",
                "reason": str(exc)[:120], "mutation_performed": False}


async def remote_file_transfer(target_id: str, scope_id: str, filename: str,
                               content_base64: str, expected_sha256: str) -> dict:
    """Transfer one verified ZIP into its enrolled site's uploads quarantine.

    Destination is derived from scope, never from caller-supplied paths.
    Repeated identical uploads are idempotent; different content is rejected.
    """
    contract = "mad4b.registry-remote-file-transfer.v1"
    try:
        target, scope = scope_for(target_id, scope_id)
        if not FILENAME.fullmatch(filename) or not SHA256.fullmatch(expected_sha256):
            raise ValueError("invalid_filename_or_digest")
        if len(content_base64) > (MAX_BYTES * 4 // 3 + 8):
            raise ValueError("artifact_too_large")
        try:
            payload = base64.b64decode(content_base64, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("invalid_base64") from None
        if not payload or len(payload) > MAX_BYTES:
            raise ValueError("artifact_too_large_or_empty")
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise ValueError("source_checksum_mismatch")
        await assert_scope(target, scope)
        parent = upload_dir(scope)
        await ssh(target, "mkdir -p " + shlex.quote(parent))
        if await ssh(target, "realpath " + shlex.quote(parent)) != parent:
            raise ValueError("destination_scope_mismatch")
        destination = parent + "/" + filename
        # Check an existing file before allocating or sending more data.
        exists = await ssh(target, "test -f " + shlex.quote(destination) + " && echo exists || echo absent")
        if exists == "exists":
            digest = (await ssh(target, "sha256sum " + shlex.quote(destination))).split()[0]
            if digest != expected_sha256:
                raise ValueError("conflicting_artifact_exists")
            return {"contract": contract, "state": "READBACK_VERIFIED",
                    "idempotent": True, "sha256": digest, "target": target_id,
                    "scope": scope_id, "remote_path": destination}
        suffix = uuid.uuid4().hex
        temp_remote = destination + ".upload-" + suffix
        local_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="mad4b-registry-", suffix=".zip", delete=False) as f:
                os.chmod(f.name, 0o600)
                f.write(payload)
                local_path = f.name
            opts, dest = ssh_args(target)
            await call(["scp", "-B", "-P", str(target["port"] or 22),
                        *opts, local_path, dest + ":" + temp_remote])
            digest = (await ssh(target, "sha256sum " + shlex.quote(temp_remote))).split()[0]
            if digest != expected_sha256:
                raise ValueError("uploaded_checksum_mismatch")
            await ssh(target, "mv -n " + shlex.quote(temp_remote) + " " + shlex.quote(destination))
            digest = (await ssh(target, "sha256sum " + shlex.quote(destination))).split()[0]
            if digest != expected_sha256:
                raise ValueError("readback_checksum_mismatch")
        finally:
            if local_path:
                Path(local_path).unlink(missing_ok=True)
        return {"contract": contract, "state": "READBACK_VERIFIED",
                "idempotent": False, "sha256": expected_sha256,
                "target": target_id, "scope": scope_id, "remote_path": destination}
    except (OSError, ValueError, IndexError) as exc:
        return {"contract": contract, "state": "DENIED", "reason": str(exc)[:120],
                "mutation_performed": False}
