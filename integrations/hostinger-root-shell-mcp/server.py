"""Unrestricted root-command execution on the configured VPS over SSH.

Do not expose this MCP server directly; place it behind the OAuth proxy.
Each invocation is a fresh remote bash process (not a persistent terminal).
"""
import asyncio
import os
import shlex
from pathlib import Path
from mcp.server.fastmcp import FastMCP

HOST = os.environ["SHELL_SSH_HOST"]
PORT = os.environ.get("SHELL_SSH_PORT", "22")
KEY_DIR = Path("/run/secrets/ssh")
KNOWN_HOSTS = "/run/secrets/hostinger_known_hosts"
EXPECTED_KEY_NAME = os.environ.get("SHELL_SSH_KEY_NAME", "").strip()

def discover_key() -> str:
    """Discover one approved mounted key only, never scan host filesystem."""
    if not KEY_DIR.is_dir():
        raise RuntimeError("Approved SSH key directory not mounted")
    keys = sorted(
        p for p in KEY_DIR.iterdir()
        if p.is_file() and not p.is_symlink()
        and not p.name.endswith(".pub")
    )
    if EXPECTED_KEY_NAME:
        keys = [p for p in keys if p.name == EXPECTED_KEY_NAME]
    if len(keys) != 1:
        raise RuntimeError(f"Expected exactly one approved mounted SSH key, found {len(keys)}")
    return str(keys[0])
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
async def exec_root_shell(command: str, timeout_seconds: int = 60) -> dict:
    """Execute a bash command as root on Hostinger VPS. No command allowlist.

    Executes in a NEW bash shell for each call. Requires an authorized root SSH
    key configured on the VPS. The caller is responsible for command effects.
    """
    if not command or not command.strip():
        return {"error": "command is empty"}
    timeout = min(max(int(timeout_seconds), 1), 300)
    if not os.path.isfile(KNOWN_HOSTS):
        return {"error": "Verified SSH known_hosts file not mounted"}
    remote = "bash -lc " + shlex.quote(command)
    argv = [
        "ssh", "-T", "-p", PORT,
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + KNOWN_HOSTS,
        "-o", "ConnectTimeout=10",
        "-i", discover_key(),
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
