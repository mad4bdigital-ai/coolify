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
