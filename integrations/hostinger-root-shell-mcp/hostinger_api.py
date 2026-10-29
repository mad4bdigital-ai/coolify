"""Read-only Hostinger hPanel website inventory with per-account isolation."""
import json
import os
import re
import urllib.request
import urllib.error
from pathlib import Path
from hostinger_gateway import ACCOUNT_MAP

API_BASE = "https://developers.hostinger.com"
CREDENTIAL_DIRECTORY = Path(os.environ.get("HOSTINGER_API_CREDENTIAL_DIRECTORY", "/run/secrets/hostinger-accounts"))
MAX_BODY = 512 * 1024
SAFE_ALIAS = re.compile(r"^[a-z][a-z0-9-]{1,63}$")

def binding_status() -> dict:
    accounts = []
    for target_id, alias in ACCOUNT_MAP.items():
        path = CREDENTIAL_DIRECTORY / (alias + ".token")
        present = path.is_file() and not path.is_symlink()
        accounts.append({"target_id": target_id, "alias": alias,
                         "credential_configured": present})
    return {"accounts": accounts, "credential_values_included": False}

def list_websites(target_id: str) -> dict:
    if target_id not in ACCOUNT_MAP:
        raise ValueError("target is not enrolled")
    alias = ACCOUNT_MAP[target_id]
    if not SAFE_ALIAS.fullmatch(alias):
        raise ValueError("invalid account alias")
    path = CREDENTIAL_DIRECTORY / (alias + ".token")
    if not path.is_file() or path.is_symlink():
        return {"target_id": target_id, "status": "credential_not_configured",
                "websites": [], "secrets_included": False}
    token = path.read_text(encoding="utf-8").strip()
    if not token or "\n" in token or "\r" in token:
        raise ValueError("credential invalid")
    request = urllib.request.Request(
        API_BASE + "/api/hosting/v1/websites",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise ValueError("response too large")
            data = json.loads(raw)
    except urllib.error.HTTPError as exc:
        return {"target_id": target_id, "status": "api_error",
                "http_status": exc.code, "websites": [], "secrets_included": False}
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        value = data.get("data", [])
        items = value if isinstance(value, list) else value.get("data", []) if isinstance(value, dict) else []
    else:
        items = []
    result = []
    for item in items[:100]:
        if not isinstance(item, dict):
            continue
        result.append({"domain": item.get("domain"), "website_type": item.get("website_type"),
                       "username": item.get("username")})
    return {"target_id": target_id, "status": "ok", "websites": result,
            "count": len(result), "secrets_included": False}

# Explicit fixed GET-only API diagnostics. Never accepts caller-provided URLs.
READ_ONLY_CHECKS = {
    "catalog": "/api/billing/v1/catalog",
    "subscriptions": "/api/billing/v1/subscriptions",
    "hosting_orders": "/api/hosting/v1/orders",
    "websites": "/api/hosting/v1/websites",
}

def diagnose_read_only_endpoints(target_id: str) -> dict:
    """Verify API accessibility without exposing body, credentials or billing data."""
    if target_id not in ACCOUNT_MAP:
        raise ValueError("target is not enrolled")
    alias = ACCOUNT_MAP[target_id]
    path = CREDENTIAL_DIRECTORY / (alias + ".token")
    if not path.is_file() or path.is_symlink():
        return {"target_id": target_id, "status": "credential_not_configured", "checks": []}
    token = path.read_text(encoding="utf-8").strip()
    if not token or "\n" in token or "\r" in token:
        raise ValueError("invalid credential")
    results = []
    for label, endpoint in READ_ONLY_CHECKS.items():
        request = urllib.request.Request(
            API_BASE + endpoint,
            headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                results.append({"operation": label, "http_status": response.status})
        except urllib.error.HTTPError as exc:
            # Hostinger publishes a safe, human-readable error message.
            # Return only a fixed classification, never a response body or token.
            category = "unknown"
            try:
                payload = json.loads(exc.read(4096))
                message = " ".join(str(payload.get(k, "")) for k in ("message", "error", "detail", "title")).lower()[:512] if isinstance(payload, dict) else ""
                if "forbidden" in message or "permission" in message or "access denied" in message or "not authorized" in message:
                    category = "access_denied"
                elif "unauthenticated" in message or "invalid token" in message:
                    category = "authentication_failed"
                elif "not found" in message:
                    category = "not_found"
                elif "rate limit" in message or "too many" in message:
                    category = "rate_limited"
                elif message:
                    category = "other_api_rejection"
            except (ValueError, UnicodeError, OSError):
                category = "non_json_or_unreadable_error"
            results.append({"operation": label, "http_status": exc.code,
                            "error_category": category,
                            "content_type": str(exc.headers.get("Content-Type", ""))[:70]})
            exc.close()
        except Exception as exc:
            results.append({"operation": label, "error_type": type(exc).__name__})
    return {"target_id": target_id, "checks": results, "read_only": True,
            "response_bodies_included": False, "secrets_included": False}
