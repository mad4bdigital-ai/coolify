"""Explicit, read-only infrastructure inventory for the Shell MCP deployment.

No network scans, credential discovery, or calls to third-party systems.
Registry file is an operator-maintained list of authorized targets.
"""
import json
import os
import re
from pathlib import Path

REGISTRY_FILE = Path(os.environ.get("INFRA_REGISTRY_FILE", "/app/infrastructure-registry.json"))
VALID_ID = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
SUPPORTED_KINDS = {"ssh", "sftp", "mysql", "postgres", "https_api", "wordpress"}

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
            "host": str(item.get("host", ""))[:255],
            "port": item.get("port"),
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
    return {"configured": data["configured"], "count": len(filtered),
            "targets": filtered, "secrets_included": False}
