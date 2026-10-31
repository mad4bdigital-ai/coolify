"""Target-scoped quarantine transfer for explicitly enrolled SSH hosting accounts.

MCP chunks are staged locally; commit verifies SHA-256 before initiating an
SFTP batch using a pinned SSH host key and a pre-enrolled private identity.
Remote account must provision 'mad4b-quarantine' directory beforehand.
No arbitrary target host, username, file path, command or install is accepted.
"""
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import asyncio
import fcntl
from pathlib import Path

from registry import load_registry
from ssh_binding import BINDING_DIRECTORY, _regular_file

ROOT = Path(os.environ.get("INFRA_UPLOAD_SPOOL", "/data/hosting-uploads"))
MAX_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 384 * 1024
HEX = re.compile(r"^[a-f0-9]{64}$")
ID = re.compile(r"^[a-f0-9]{32}$")
REMOTE_DIR = "mad4b-quarantine"

def target_for_upload(target_id):
    if not isinstance(target_id, str):
        raise ValueError("invalid_target_id")
    for target in load_registry()["targets"]:
        if target["id"] == target_id and target["enabled"] and target["kind"] in ("ssh", "sftp"):
            if target_id == "hostinger-primary" or not target.get("username"):
                raise ValueError("target_has_no_external_sftp_binding")
            return target
    raise ValueError("unknown_or_disabled_upload_target")

def _paths(transfer_id):
    if not isinstance(transfer_id, str) or not ID.fullmatch(transfer_id):
        raise ValueError("invalid_transfer_id")
    return ROOT / (transfer_id + ".json"), ROOT / (transfer_id + ".part")

def begin(target_id, size, sha256):
    target_for_upload(target_id)
    if type(size) is not int or not 1 <= size <= MAX_BYTES:
        raise ValueError("invalid_upload_size")
    if not isinstance(sha256, str) or not HEX.fullmatch(sha256):
        raise ValueError("invalid_sha256")
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    ident = secrets.token_hex(16)
    meta, part = _paths(ident)
    with part.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
    with meta.open("x", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump({"target_id": target_id, "sha256": sha256, "size": size, "offset": 0}, handle)
    return {"transfer_id": ident, "target_id": target_id, "offset": 0, "max_chunk_bytes": CHUNK_BYTES}

def _read(transfer_id, target_id):
    meta, part = _paths(transfer_id)
    if meta.is_symlink() or part.is_symlink() or not meta.is_file() or not part.is_file():
        raise ValueError("transfer_not_found")
    data = json.loads(meta.read_text(encoding="utf-8"))
    if data.get("target_id") != target_id:
        raise ValueError("transfer_target_mismatch")
    return data, meta, part

def chunk(target_id, transfer_id, offset, content_base64):
    target_for_upload(target_id)
    if not isinstance(content_base64, str) or len(content_base64) > 530000:
        raise ValueError("chunk_too_large")
    try:
        raw = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("invalid_base64") from None
    if not 1 <= len(raw) <= CHUNK_BYTES:
        raise ValueError("invalid_chunk_size")
    data, meta, part = _read(transfer_id, target_id)
    with part.open("r+b", buffering=0) as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        data, meta, part = _read(transfer_id, target_id)
        if type(offset) is not int or data["offset"] != offset or part.stat().st_size != offset:
            raise ValueError("offset_conflict")
        if offset + len(raw) > data["size"]:
            raise ValueError("size_exceeded")
        handle.seek(offset)
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
        data["offset"] += len(raw)
        temporary = meta.with_name(meta.name + ".tmp")
        try:
            temporary.write_text(json.dumps(data), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, meta)
        finally:
            temporary.unlink(missing_ok=True)
    return {"transfer_id": transfer_id, "target_id": target_id, "offset": data["offset"]}

def status(target_id, transfer_id):
    target_for_upload(target_id)
    data, _, part = _read(transfer_id, target_id)
    if part.stat().st_size != data["offset"]:
        raise ValueError("transfer_state_conflict")
    return {"target_id": target_id, "transfer_id": transfer_id, "offset": data["offset"], "size": data["size"], "sha256": data["sha256"]}

def sftp_argv(target):
    directory = BINDING_DIRECTORY / target["id"]
    private = directory / "id_ed25519"
    pinned = directory / "known_hosts_verified"
    if directory.is_symlink() or not _regular_file(private, private=True) or not _regular_file(pinned, private=True):
        raise ValueError("verified_ssh_binding_required")
    port = target["port"] or 22
    required = f'[{target["host"]}]:{port}'
    lines = pinned.read_text(encoding="ascii").splitlines()
    if not any(len(cols) >= 3 and required in cols[0].split(",")
               for line in lines if line.strip() and not line.startswith("#")
               for cols in [line.split()]):
        raise ValueError("target_host_key_pin_missing")
    return [
        "sftp", "-F", "/dev/null", "-b", "-", "-P", str(port),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UserKnownHostsFile=" + str(pinned),
        "-o", "ConnectTimeout=8",
        "-i", str(private),
        target["username"] + "@" + target["host"]
    ]

async def commit(target_id, transfer_id):
    target = target_for_upload(target_id)
    data, meta, part = _read(transfer_id, target_id)
    if part.stat().st_size != data["size"] or data["offset"] != data["size"]:
        raise ValueError("transfer_incomplete")
    digest = hashlib.sha256()
    with part.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != data["sha256"]:
        raise ValueError("checksum_mismatch")
    argv = sftp_argv(target)
    # Both remote path and local spool id are generated, not caller-supplied.
    remote = REMOTE_DIR + "/" + data["sha256"] + ".bin"
    temporary = REMOTE_DIR + "/." + transfer_id + ".part"
    batch = f'put {part} {temporary}\nrename {temporary} {remote}\n'.encode("ascii")
    proc = await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(batch), timeout=120)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise ValueError("sftp_timeout") from None
    if proc.returncode != 0:
        # Never return full stderr: it may contain infrastructure metadata.
        raise ValueError("sftp_upload_failed")
    part.unlink()
    meta.unlink()
    return {"state": "stored_on_hosting_quarantine", "target_id": target_id,
            "sha256": data["sha256"], "bytes": data["size"],
            "remote_path": remote}
