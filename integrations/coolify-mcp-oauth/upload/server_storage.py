"""Verified quarantine-to-VPS promotion with repeat-safe receipts.

Only a fixed staging directory and safe basenames are supported. Never executes
or installs artifacts. A repeated request may confirm an existing matching file,
but must never replace different bytes.
"""
import hashlib, os, re, secrets
from pathlib import Path
SHA=re.compile(r"^[0-9a-f]{64}$")
NAME=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

def _digest(path, max_bytes):
    h=hashlib.sha256();size=0
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):
            size+=len(block)
            if size>max_bytes:raise ValueError("size_limit")
            h.update(block)
    return size,h.hexdigest()

def promote(source:Path,target:Path,sha256:str,filename:str,max_bytes:int):
    if not isinstance(sha256,str) or not SHA.fullmatch(sha256):raise ValueError("invalid_sha256")
    if not isinstance(filename,str) or not NAME.fullmatch(filename) or filename in {".",".."} or ".." in filename:raise ValueError("invalid_filename")
    if not target.is_dir() or target.is_symlink():raise ValueError("destination_unavailable")
    destination=target/filename
    if destination.is_symlink():raise ValueError("destination_conflict")
    # A retried MCP call can be acknowledged without rewriting already verified data.
    if destination.exists():
        if not destination.is_file():raise ValueError("destination_conflict")
        size,digest=_digest(destination,max_bytes)
        if size<1 or digest!=sha256:raise ValueError("destination_conflict")
        return {"state":"stored_on_vps","sha256":sha256,"bytes":size,"filename":filename,"verified":True,"already_present":True}
    src=source/(sha256+".bin")
    if not src.is_file() or src.is_symlink():raise ValueError("artifact_not_found")
    tmp=target/("."+secrets.token_hex(16)+".part")
    digest=hashlib.sha256();size=0
    try:
        with src.open("rb") as inp, tmp.open("xb") as out:
            os.fchmod(out.fileno(),0o600)
            while True:
                chunk=inp.read(1024*1024)
                if not chunk:break
                size+=len(chunk)
                if size>max_bytes:raise ValueError("size_limit")
                digest.update(chunk);out.write(chunk)
            out.flush();os.fsync(out.fileno())
        if size==0 or digest.hexdigest()!=sha256:raise ValueError("checksum_mismatch")
        # Exclusive create prevents accidental overwrites on concurrent or replayed calls.
        try:
            os.link(tmp,destination)
        except FileExistsError:
            if destination.is_symlink() or not destination.is_file():raise ValueError("destination_conflict")
            existing_size,existing_hash=_digest(destination,max_bytes)
            if existing_size!=size or existing_hash!=sha256:raise ValueError("destination_conflict")
        final_size,final_hash=_digest(destination,max_bytes)
        if final_size!=size or final_hash!=sha256:raise ValueError("destination_readback_failed")
        return {"state":"stored_on_vps","sha256":sha256,"bytes":size,"filename":filename,"verified":True,"already_present":False}
    finally:
        if tmp.exists():tmp.unlink()
