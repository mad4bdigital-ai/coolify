"""Bounded read-only hPanel browser bridge.

The remote worker is optional. No credential files, browser cookies, CDP ports,
or browser-debug access are exposed to the MCP server.
"""
import asyncio
import json
import os

WORKER_URL = "http://127.0.0.1:13871"
_ALLOWED = {"session_status", "list_websites"}
_MAX_RESPONSE = 48 * 1024

async def query_hpanel_worker(action: str) -> dict:
    if action not in _ALLOWED:
        return {"ok": False, "error": "ACTION_NOT_ALLOWED"}
    # Runs on VPS through the same enrolled root-shell SSH transport. Request is
    # constant, not constructed from user-supplied shell commands or URLs.
    import shlex
    host = os.environ["SHELL_SSH_HOST"]
    port = os.environ.get("SHELL_SSH_PORT", "22")
    key = "/run/secrets/ssh-keys/shell_access"
    known = "/run/secrets/hostinger_known_hosts"
    remote_command = "curl --fail --silent --show-error --max-time 15 --noproxy '*' " + shlex.quote(WORKER_URL + "/" + action)
    cmd = ["ssh", "-T", "-p", port, "-o", "BatchMode=yes",
           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=" + known, "-o", "ConnectTimeout=6",
           "-i", key, "root@" + host, remote_command]
    try:
        p = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                 stderr=asyncio.subprocess.PIPE)
        out, _ = await asyncio.wait_for(p.communicate(), timeout=22)
        if p.returncode != 0:
            return {"ok": False, "error": "BROWSER_WORKER_UNAVAILABLE"}
        if len(out) > _MAX_RESPONSE:
            return {"ok": False, "error": "RESPONSE_TOO_LARGE"}
        data = json.loads(out)
        if not isinstance(data, dict):
            raise ValueError("invalid worker response")
        # Only project known response fields; never forward cookies or tokens.
        if action == "session_status":
            return {"ok": bool(data.get("ok")), "authenticated": bool(data.get("authenticated")),
                    "account_alias": str(data.get("account_alias", ""))[:80],
                    "status": str(data.get("status", ""))[:80]}
        items = data.get("websites", [])
        if not isinstance(items, list):
            raise ValueError("invalid websites")
        return {"ok": bool(data.get("ok")), "status": str(data.get("status", ""))[:80], "websites": [
            {"name": str(x.get("name", ""))[:160], "domain": str(x.get("domain", ""))[:253]}
            for x in items[:100] if isinstance(x, dict)]}
    except (OSError, ValueError, asyncio.TimeoutError, json.JSONDecodeError):
        return {"ok": False, "error": "BROWSER_WORKER_UNAVAILABLE"}
