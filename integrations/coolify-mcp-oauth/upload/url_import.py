"""Quarantine import of a short-lived HTTPS download URL.

Fail-closed: only operator-configured exact hostname allowlist, HTTPS,
fixed public IP resolution, no redirects, byte limit, SHA256 verification.
"""
import hashlib, ipaddress, os, socket, ssl, tempfile, urllib.parse, http.client
from pathlib import Path

def import_url(root:Path, url:str, expected_sha256:str, max_bytes:int, allowed_hosts:set[str]):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!="https" or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None,443):
        raise ValueError("https_url_required")
    host=(parsed.hostname or "").lower().rstrip(".")
    if not host or host not in allowed_hosts:raise ValueError("host_not_allowlisted")
    if len(expected_sha256)!=64 or any(ch not in "0123456789abcdef" for ch in expected_sha256):
        raise ValueError("invalid_sha256")
    resolved=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
    addresses={item[4][0] for item in resolved}
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError("non_public_address")
    # Pin the resolved IP: SSL validates the original hostname with SNI.
    address=sorted(addresses)[0]
    class PinnedHTTPS(http.client.HTTPSConnection):
        def connect(self):
            sock=socket.create_connection((address,443),timeout=15)
            self.sock=ssl.create_default_context().wrap_socket(sock,server_hostname=host)
    conn=PinnedHTTPS(host,443,timeout=15)
    path=urllib.parse.urlunsplit(("","",parsed.path or "/",parsed.query,""))
    root.mkdir(parents=True,mode=0o700,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=".https-import-",dir=root)
    size=0;h=hashlib.sha256()
    try:
        with os.fdopen(fd,"wb") as out:
            os.fchmod(out.fileno(),0o600)
            conn.request("GET",path,headers={"Host":host,"Accept":"application/octet-stream"})
            response=conn.getresponse()
            if response.status!=200:raise ValueError("remote_status_not_200")
            while True:
                chunk=response.read(65536)
                if not chunk:break
                size+=len(chunk)
                if size>max_bytes:raise ValueError("size_limit")
                h.update(chunk);out.write(chunk)
            out.flush();os.fsync(out.fileno())
        if size==0 or h.hexdigest()!=expected_sha256:raise ValueError("checksum_mismatch")
        os.replace(tmp,root/(expected_sha256+".bin"))
        return {"sha256":expected_sha256,"bytes":size,"state":"quarantined"}
    finally:
        conn.close()
        if os.path.exists(tmp):os.unlink(tmp)
