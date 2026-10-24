"""Promote verified quarantine artifacts into a fixed VPS host upload directory.

No caller-controlled paths and no WordPress installation. Host upload directory
is mounted into the existing upload service as /data/server-quarantine.
"""
import hashlib, os, re, secrets
from pathlib import Path
SHA=re.compile(r"^[0-9a-f]{64}$")
NAME=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
def promote(source:Path,target:Path,sha256:str,filename:str,max_bytes:int):
    if not isinstance(sha256,str) or not SHA.fullmatch(sha256):raise ValueError("invalid_sha256")
    if not isinstance(filename,str) or not NAME.fullmatch(filename) or filename in {".",".."} or ".." in filename:raise ValueError("invalid_filename")
    src=source/(sha256+".bin")
    if not src.is_file() or src.is_symlink():raise ValueError("artifact_not_found")
    if not target.is_dir() or target.is_symlink():raise ValueError("destination_unavailable")
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
        os.replace(tmp,target/filename)
        return {"state":"stored_on_vps","sha256":sha256,"bytes":size,"path":str(target/filename)}
    finally:
        if tmp.exists():tmp.unlink()
