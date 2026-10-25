"""Consume opaque, pre-authorized local file references from a trusted host bridge.

This is NOT a ChatGPT file-ID resolver. A host-side attachment connector must
place bytes and owner-bound manifests into a restricted, non-public inbox first.
"""
import hashlib
import json
import os
import re
import secrets
from pathlib import Path

REF = re.compile(r"^[a-f0-9]{32}$")
SHA = re.compile(r"^[a-f0-9]{64}$")

def import_reference(inbox: Path, quarantine: Path, reference: str, principal: str,
                     expected_sha256: str, max_bytes: int):
    if not isinstance(reference,str) or not REF.fullmatch(reference):
        raise ValueError("invalid_attachment_reference")
    if not isinstance(principal,str) or not principal:
        raise ValueError("missing_principal")
    if not isinstance(expected_sha256,str) or not SHA.fullmatch(expected_sha256):
        raise ValueError("invalid_sha256")
    if not inbox.is_dir() or inbox.is_symlink():
        raise ValueError("attachment_bridge_unavailable")
    manifest = inbox / (reference + ".json")
    payload = inbox / (reference + ".bin")
    if any(p.is_symlink() or not p.is_file() for p in (manifest,payload)):
        raise ValueError("reference_not_found")
    details=json.loads(manifest.read_text(encoding="utf-8"))
    if details.get("principal") != principal:
        raise ValueError("reference_owner_mismatch")
    if details.get("sha256") != expected_sha256:
        raise ValueError("reference_hash_mismatch")
    if details.get("status") != "authorized":
        raise ValueError("reference_not_authorized")
    quarantine.mkdir(parents=True,exist_ok=True,mode=0o700)
    temp=quarantine/("."+secrets.token_hex(16)+".part")
    size=0
    digest=hashlib.sha256()
    try:
        # Protect against unbounded, mutable sources; verify final bytes.
        with payload.open("rb") as src,temp.open("xb") as dst:
            os.fchmod(dst.fileno(),0o600)
            for chunk in iter(lambda:src.read(1024*1024),b""):
                size+=len(chunk)
                if size>max_bytes: raise ValueError("size_limit")
                digest.update(chunk)
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        if not size or digest.hexdigest()!=expected_sha256:
            raise ValueError("checksum_mismatch")
        os.replace(temp,quarantine/(expected_sha256+".bin"))
        return {"state":"quarantined","sha256":expected_sha256,"bytes":size,
                "reference_consumed":False,"source":"authorized_host_bridge"}
    finally:
        temp.unlink(missing_ok=True)
