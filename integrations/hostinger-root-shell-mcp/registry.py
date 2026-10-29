"""Explicit, read-only infrastructure inventory for the Shell MCP deployment.

No network scans, credential discovery, or calls to third-party systems.
Registry file is an operator-maintained list of authorized targets.
"""
import json
import os
import re
import ipaddress
from pathlib import Path
from ssh_binding import summarize_ssh_binding

REGISTRY_FILE = Path(os.environ.get("INFRA_REGISTRY_FILE", "/app/infrastructure-registry.json"))
VALID_ID = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
SUPPORTED_KINDS = {"ssh", "sftp", "mysql", "postgres", "https_api", "wordpress"}
VALID_HOST = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}[a-zA-Z0-9]$")

def validate_host(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("target host must be a nonempty hostname or IP address")
    if any(c in value for c in ("/", "@", ":", " ", "\\", "\n", "\r")):
        # IPv6 literals may include colons, but require explicit ipaddress parsing.
        try:
            return str(ipaddress.IPv6Address(value))
        except ValueError:
            raise ValueError("invalid host format") from None
    if not VALID_HOST.fullmatch(value):
        raise ValueError("invalid host format")
    return value

def validate_username(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value):
        raise ValueError("invalid SSH username")
    return value

def validate_port(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return value


def load_registry() -> dict:
    if not REGISTRY_FILE.is_file():
        return {"targets": [], "configured": False}
    data = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise ValueError("registry must contain a targets array")
    targets = []
    seen = set()
    for item in data["targets"]:
        if not isinstance(item, dict):
            raise ValueError("each target must be an object")
        name, kind = item.get("id"), item.get("kind")
        if not isinstance(name, str) or not VALID_ID.fullmatch(name) or name in seen:
            raise ValueError("invalid or duplicate target id")
        if kind not in SUPPORTED_KINDS:
            raise ValueError("unsupported target kind")
        seen.add(name)
        # An explicit projection prevents future secret fields from leaking.
        targets.append({
            "id": name, "kind": kind,
            "label": str(item.get("label", name))[:120],
            "environment": str(item.get("environment", "unknown"))[:60],
            "host": validate_host(item.get("host")),
            "port": validate_port(item.get("port")),
            "username": validate_username(item.get("username")),
            "enabled": item.get("enabled", True) is True,
        })
    return {"targets": targets, "configured": True}

def list_targets(environment: str = "", kind: str = "") -> dict:
    data = load_registry()
    filtered = [
        target for target in data["targets"]
        if (not environment or target["environment"] == environment)
        and (not kind or target["kind"] == kind)
    ]
    # Annotate SSH inventory with non-secret live file-presence checks.
    # A prepared identity is never proof of remote acceptance.
    presented = [
        {**target, "ssh_binding": summarize_ssh_binding(target)}
        if target["kind"] == "ssh" else target
        for target in filtered
    ]
    return {"configured": data["configured"], "count": len(presented),
            "targets": presented, "secrets_included": False}
