#!/usr/bin/env python3
"""Upload an explicitly authorized local attachment or approved HTTPS source.

No ChatGPT conversation access. Never prints bearer tokens or signed URLs.
Server enforces files:upload, HTTPS source allowlist, size and SHA-256.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.request
import urllib.parse

def sha_file(path):
    digest=hashlib.sha256()
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1024*1024),b""):
            digest.update(chunk)
    return digest.hexdigest()

def endpoint(site, route):
    parsed=urllib.parse.urlsplit(site)
    if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query or parsed.path not in ("","/"):
        raise ValueError("HTTPS service origin required")
    return site.rstrip("/") + route

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirects_not_allowed")

def send(origin, bearer, method, data, digest, limit=32*1024*1024):
    if not bearer or not bearer.strip():
        raise ValueError("authorized bearer token required")
    headers={"Authorization":"Bearer "+bearer,"Accept":"application/json"}
    if method=="file":
        path=Path(data)
        if not path.is_file() or path.is_symlink() or not 1<=path.stat().st_size<=limit:
            raise ValueError("invalid_local_file")
        actual=sha_file(path)
        if digest and actual!=digest:raise ValueError("checksum_mismatch")
        # Existing strict OAuth guard issues a short-lived upload grant; this
        # legacy endpoint accepts that grant, not the OAuth bearer directly.
        grant_body=json.dumps({"expires_in_seconds":120,"sha256":actual,"max_bytes":path.stat().st_size}).encode()
        req=urllib.request.Request(endpoint(origin,"/v1/grants"),grant_body,headers={**headers,"Content-Type":"application/json"},method="POST")
        opener=urllib.request.build_opener(NoRedirect)
        with opener.open(req,timeout=15) as resp:
            grant=json.load(resp)["upload_token"]
        try:
            req=urllib.request.Request(endpoint(origin,"/v1/uploads"),path.read_bytes(),headers={"Authorization":"Bearer "+grant,"Content-Type":"application/octet-stream","X-Content-SHA256":actual},method="POST")
            with opener.open(req,timeout=45) as resp:return json.load(resp)
        finally:
            grant=None
    if method=="url":
        if not digest or len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("expected SHA-256 required")
        parsed=urllib.parse.urlsplit(data)
        if parsed.scheme!="https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("HTTPS source URL required")
        body=json.dumps({"url":data,"sha256":digest}).encode()
        req=urllib.request.Request(endpoint(origin,"/v1/import-url"),body,headers={**headers,"Content-Type":"application/json"},method="POST")
        with urllib.request.build_opener(NoRedirect).open(req,timeout=60) as resp:return json.load(resp)
    raise ValueError("unknown transport")

def main():
    parser=argparse.ArgumentParser(description="Upload authorized file bytes or approved HTTPS URL into quarantine")
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file")
    source.add_argument("--url")
    parser.add_argument("--origin",required=True)
    parser.add_argument("--sha256",default="")
    args=parser.parse_args()
    bearer=os.environ.get("MAD4B_UPLOAD_OAUTH_TOKEN","")
    result=send(args.origin,bearer,"file" if args.file else "url",args.file or args.url,args.sha256)
    # Do not print source URLs or bearer credentials.
    print(json.dumps({k:v for k,v in result.items() if k in ("state","sha256","bytes")}))

if __name__=="__main__":main()
