"""Unrestricted root-command execution on the configured VPS over SSH.

Do not expose this MCP server directly; place it behind the OAuth proxy.
Each invocation is a fresh remote bash process (not a persistent terminal).
"""
import asyncio
import os
import shlex
from mcp.server import MCPServer

HOST = os.environ["SHELL_SSH_HOST"]
PORT = os.environ.get("SHELL_SSH_PORT", "22")
KEY = "/run/secrets/hostinger_root_ssh_key"
KNOWN_HOSTS = "/run/secrets/hostinger_known_hosts"
MAX_OUTPUT = 256 * 1024

server = MCPServer(
    "Hostinger VPS root shell",
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
    remote = "bash -lc " + shlex.quote(command)
    argv = [
        "ssh", "-T", "-p", PORT,
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + KNOWN_HOSTS,
        "-o", "ConnectTimeout=10",
        "-i", KEY,
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
    server.run(transport="streamable-http", host="0.0.0.0", port=8000, json_response=True)
