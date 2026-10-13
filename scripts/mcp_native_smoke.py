#!/usr/bin/env python3
"""Read-only preflight of native Coolify MCP, no external packages.

Usage:
  COOLIFY_MCP_URL=https://coolify.example.com/mcp python3 scripts/mcp_native_smoke.py

Token is securely prompted for; never pass it as a CLI argument.
No tools/call is made, so this cannot modify Coolify resources.
"""
import getpass
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

URL = os.environ.get("COOLIFY_MCP_URL", "").strip()
if not URL.startswith("https://") or "@" in URL:
    sys.exit("ERROR: set COOLIFY_MCP_URL to a credential-free HTTPS endpoint")

token = getpass.getpass("Coolify read-only API token: ").strip()
if not token:
    sys.exit("ERROR: empty token")

headers = {
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-03-26",
}
# Token is never printed; do not print full MCP response, as tools can include sensitive metadata.
def call(method, params, ident):
    payload = json.dumps({"jsonrpc": "2.0", "id": ident, "method": method, "params": params}).encode()
    req = urllib.request.Request(URL, payload, headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20, context=ssl.create_default_context()) as r:
            status, content_type = r.status, r.headers.get("Content-Type", "")
            raw = r.read(2_000_001)
    except urllib.error.HTTPError as e:
        print(f"{method}: HTTP {e.code}")
        return None
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"{method}: TRANSPORT_ERROR {type(e).__name__}")
        return None
    if status != 200 or len(raw) > 2_000_000 or "application/json" not in content_type.lower():
        print(f"{method}: UNEXPECTED_HTTP_OR_CONTENT_TYPE http={status}")
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        print(f"{method}: INVALID_JSON")
        return None
    if parsed.get("jsonrpc") != "2.0" or parsed.get("id") != ident or "error" in parsed:
        print(f"{method}: JSONRPC_ERROR")
        return None
    print(f"{method}: HTTP=200 JSONRPC=PASS")
    return parsed.get("result", {})

try:
    result = call("initialize", {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "coolify-native-readonly-smoke", "version": "1.0.0"},
    }, 1)
    if not isinstance(result, dict) or not result.get("protocolVersion"):
        sys.exit("NATIVE_MCP_ACCEPTANCE=FAIL")
    print("SERVER_PROTOCOL=", result["protocolVersion"])
    tools = call("tools/list", {}, 2)
    if not isinstance(tools, dict) or not isinstance(tools.get("tools"), list):
        sys.exit("NATIVE_MCP_ACCEPTANCE=FAIL")
    names = [item.get("name") for item in tools["tools"] if isinstance(item, dict)]
    print("TOOL_COUNT=", len(names))
    print("REQUIRED_READ_TOOLS_PRESENT=", all(n in names for n in ("get_current_team", "get_infrastructure_overview")))
    if len(names) < 2 or not all(n in names for n in ("get_current_team", "get_infrastructure_overview")):
        sys.exit("NATIVE_MCP_ACCEPTANCE=FAIL")
    print("NATIVE_MCP_ACCEPTANCE=PASS")
finally:
    token = ""
