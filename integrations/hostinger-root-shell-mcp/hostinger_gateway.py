"""Hostinger multi-account routing metadata, independent of authentication.

Each target binds to an explicit hPanel account alias. No token or session
can be supplied through a tool parameter or retrieved through this module.
"""
from registry import load_registry, VALID_ID

ACCOUNT_MAP = {
    "hosting-1": "cloud-startup",
    "hosting-2": "allroyalegypt",
    "hosting-3": "egypttourgates",
}
SUPPORTED_OPERATIONS = ("inventory", "websites", "databases", "backups", "domains")
DESTINATION = "hostinger-primary"

def list_hostinger_accounts() -> dict:
    targets = {item["id"]: item for item in load_registry()["targets"]}
    results = []
    for target_id, alias in ACCOUNT_MAP.items():
        target = targets.get(target_id)
        if target is None:
            continue
        results.append({
            "account_alias": alias,
            "target_id": target_id,
            "label": target["label"],
            "enabled": target["enabled"],
            "provider": "hostinger_hpanel",
            "credential_binding": "not_configured",
            "supported_operations": list(SUPPORTED_OPERATIONS),
            "mail_scope": "excluded",
            "destination_target_id": DESTINATION,
        })
    return {"count": len(results), "accounts": results,
            "credential_values_included": False}

def plan_import(target_id: str, category: str = "websites") -> dict:
    """Create a non-executable, review-only import plan."""
    if target_id not in ACCOUNT_MAP:
        raise ValueError("account is not enrolled")
    if category not in SUPPORTED_OPERATIONS:
        raise ValueError("unsupported import category")
    source = next((t for t in load_registry()["targets"] if t["id"] == target_id), None)
    if source is None or not source["enabled"]:
        raise ValueError("source unavailable")
    return {"source_target_id": target_id, "destination_target_id": DESTINATION,
            "category": category, "mode": "plan_only", "read_only": True,
            "mail_included": False, "requires_credentials": True,
            "requires_explicit_execution_approval": True,
            "execution_performed": False}
