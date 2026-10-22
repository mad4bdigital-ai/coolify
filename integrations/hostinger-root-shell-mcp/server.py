"""Unrestricted root-command execution on the configured VPS over SSH.

Do not expose this MCP server directly; place it behind the OAuth proxy.
Each invocation is a fresh remote bash process (not a persistent terminal).
"""
import asyncio
import os
import shlex
from pathlib import Path
from mcp.server.fastmcp import FastMCP
from registry import list_targets
from providers import check_reachability, check_https_api
from hostinger_gateway import list_hostinger_accounts, plan_import

HOST = os.environ["SHELL_SSH_HOST"]
PORT = os.environ.get("SHELL_SSH_PORT", "22")
KEY_DIRECTORY = Path("/run/secrets/ssh-keys")

def available_keys() -> dict[str, Path]:
    """Only enumerate explicitly mounted SSH key files in this container."""
    if not KEY_DIRECTORY.is_dir():
        return {}
    return {
        p.name: p
        for p in sorted(KEY_DIRECTORY.iterdir())
        if p.is_file() and not p.is_symlink()
        and not p.name.endswith(".pub")
        and p.name not in ("known_hosts", "config")
    }


KNOWN_HOSTS = "/run/secrets/hostinger_known_hosts"
MAX_OUTPUT = 256 * 1024

server = FastMCP(
    "Hostinger VPS root shell",
    host="0.0.0.0",
    port=8000,
    json_response=True,
    stateless_http=True,
    instructions="Root-level shell on the enrolled VPS. All commands run as root via SSH. Commands may change or delete production data. Never claim commands are read-only unless they are.",
)

@server.tool()
def list_infrastructure_targets(environment: str = "", kind: str = "") -> dict:
    """Discover approved inventory entries; no scanning or network access."""
    try:
        return list_targets(environment=environment, kind=kind)
    except (OSError, ValueError) as exc:
        return {"error": str(exc), "targets": [], "secrets_included": False}

@server.tool()
async def probe_registered_target(target_id: str, timeout_seconds: int = 5) -> dict:
    """Check reachability of a registered infrastructure endpoint."""
    return await check_reachability(target_id, timeout_seconds)

@server.tool()
async def probe_registered_https(target_id: str) -> dict:
    """Check HTTPS reachability for registered web endpoints."""
    return await check_https_api(target_id)

@server.tool()
def list_hostinger_hpanel_accounts() -> dict:
    """List enrolled hPanel account aliases and capability metadata, never tokens."""
    return list_hostinger_accounts()

@server.tool()
def plan_hostinger_import(target_id: str, category: str = "websites") -> dict:
    """Prepare a review-only import route without contacting or changing systems."""
    return plan_import(target_id, category)

@server.tool()
def list_ssh_keys() -> dict:
    """List mounted SSH key choices without exposing secret contents."""
    return {"choices": list(available_keys()), "key_material_included": False}

@server.tool()
async def exec_root_shell(command: str, key_name: str = "", timeout_seconds: int = 60) -> dict:
    """Execute a bash command as root on Hostinger VPS. No command allowlist.

    Executes in a NEW bash shell for each call. Requires an authorized root SSH
    key configured on the VPS. The caller is responsible for command effects.
    """
    if not command or not command.strip():
        return {"error": "command is empty"}
    timeout = min(max(int(timeout_seconds), 1), 300)
    keys = available_keys()
    if key_name not in keys:
        return {"selection_required": True, "choices": list(keys)}
    remote = "bash -lc " + shlex.quote(command)
    argv = [
        "ssh", "-T", "-p", PORT,
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + KNOWN_HOSTS,
        "-o", "ConnectTimeout=10",
        "-i", str(keys[key_name]),
        "root@" + HOST, remote,
    ]
    process = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        timed_out = False
    except asyncio.TimeoutError:
        process.kill()
        stdout, stderr = await process.communicate()
        timed_out = True
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "stdout": stdout[:MAX_OUTPUT].decode("utf-8", "replace"),
        "stderr": stderr[:MAX_OUTPUT].decode("utf-8", "replace"),
        "stdout_truncated": len(stdout) > MAX_OUTPUT,
        "stderr_truncated": len(stderr) > MAX_OUTPUT,
        "max_output_bytes": MAX_OUTPUT,
        "executed_as": "root",
        "target": HOST,
    }

if __name__ == "__main__":
    server.run(transport="streamable-http")
