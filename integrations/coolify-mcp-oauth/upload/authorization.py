"""Explicit upload authorization. Never treat MCP initialize as upload permission.

The authorization provider must validate the presented OAuth access token and
return JSON identifying the authenticated principal with specific upload rights.
No provider configured => deny. The provider must be a trusted internal endpoint.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

AUTHZ_URL = os.environ.get("UPLOAD_AUTHZ_URL", "")
REQUIRED_PERMISSION = "files:upload"

def authorize(bearer: str, endpoint: str | None = None) -> str | None:
    url = AUTHZ_URL if endpoint is None else endpoint
    if not bearer.startswith("Bearer ") or len(bearer) > 8192:
        return None
    parsed = urllib.parse.urlsplit(url)
    # Trusted local sidecar/service only. Never contact caller-selected destinations.
    if parsed.scheme != "http" or parsed.hostname not in {"upload-authz", "coolify-mcp-oauth"} or parsed.port not in {8080} or parsed.username or parsed.password or parsed.fragment:
        return None
    req = urllib.request.Request(
        url,
        data=b'{"permission":"files:upload"}',
        method="POST",
        headers={"Authorization": bearer, "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            if response.status != 200 or "application/json" not in response.headers.get("Content-Type", ""):
                return None
            blob = response.read(4097)
            if len(blob) > 4096:
                return None
            result = json.loads(blob)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return None
    # Explicit permit, explicit action, stable subject. No client-supplied scope trust.
    if not isinstance(result, dict) or result.get("allowed") is not True:
        return None
    if result.get("permission") != REQUIRED_PERMISSION:
        return None
    subject = result.get("sub")
    if not isinstance(subject, str) or not (1 <= len(subject) <= 256):
        return None
    if any(ord(c) < 33 or ord(c) > 126 for c in subject):
        return None
    return subject

# Explicit staging override: authenticated OAuth proxy sessions may upload without
# external token introspection. Not the same as files:upload scope verification.
import hashlib

def oauth_login_authorize(bearer: str, verify_url: str | None = None) -> str | None:
    if not bearer.startswith("Bearer ") or not (8 < len(bearer) <= 8192):
        return None
    url = verify_url or os.environ.get("UPLOAD_OAUTH_VERIFY_URL","")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "coolify-mcp-oauth" or parsed.port != 8080 or parsed.path != "/mcp":
        return None
    payload=json.dumps({"jsonrpc":"2.0","id":"upload-auth","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"upload-auth-check","version":"1"}}}).encode()
    req=urllib.request.Request(url,data=payload,method="POST",headers={"Authorization":bearer,"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":"2025-11-25"})
    try:
        with urllib.request.urlopen(req,timeout=5) as response:
            if response.status!=200:return None
            raw=response.read(16385)
            if len(raw)>16384:return None
            if "text/event-stream" in response.headers.get("Content-Type",""):
                found=False
                for line in raw.decode("utf-8","replace").splitlines():
                    if line.startswith("data: "):
                        obj=json.loads(line[6:])
                        if obj.get("id")=="upload-auth" and isinstance(obj.get("result"),dict):found=True
                if not found:return None
            else:
                obj=json.loads(raw)
                if obj.get("id")!="upload-auth" or not isinstance(obj.get("result"),dict):return None
    except (urllib.error.URLError,ValueError,TimeoutError,OSError):return None
    # No durable user identity is asserted by initialize; bind transfers to this token.
    return hashlib.sha256(bearer.encode()).hexdigest()

def authorize_upload(bearer: str) -> str | None:
    mode=os.environ.get("UPLOAD_AUTHORIZATION_MODE","strict").strip().lower()
    if mode=="oauth_login":return oauth_login_authorize(bearer)
    if mode=="strict":return authorize(bearer)
    return None
