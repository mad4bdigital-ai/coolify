"""Network reachability probes for explicitly enrolled infrastructure.

This module handles target metadata only. It does not open sessions, use
credentials, execute commands, transfer files, or query stored records.
"""
import asyncio
import ssl
import urllib.request
from registry import load_registry

DEFAULT_PORTS = {
    "ssh": 22, "sftp": 22, "mysql": 3306, "postgres": 5432,
    "https_api": 443, "wordpress": 443,
}


def registered_target(target_id: str) -> dict:
    matches = [item for item in load_registry()["targets"] if item["id"] == target_id]
    if len(matches) != 1:
        raise ValueError("target not enrolled")
    target = matches[0]
    if not target["enabled"]:
        raise ValueError("target disabled")
    return target


async def check_reachability(target_id: str, timeout_seconds: int = 5) -> dict:
    """Check TCP handshake against the enrolled host and port."""
    target = registered_target(target_id)
    port = target["port"] or DEFAULT_PORTS[target["kind"]]
    timeout = min(max(int(timeout_seconds), 1), 10)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target["host"], port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        reachable = True
    except (OSError, asyncio.TimeoutError):
        reachable = False
    return {"target_id": target_id, "kind": target["kind"], "port": port,
            "tcp_reachable": reachable, "authenticated": False,
            "data_access_verified": False}


async def check_https_api(target_id: str) -> dict:
    """HTTPS reachability for enrolled web endpoints without credentials."""
    target = registered_target(target_id)
    if target["kind"] not in ("wordpress", "https_api"):
        raise ValueError("target is not HTTPS-based")
    # Probe only origin; no redirects or credential headers.
    host = target["host"]
    port = target["port"] or 443
    if ":" in host:
        host = "[" + host + "]"
    url = f"https://{host}:{port}/"
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect()
    )
    def probe():
        try:
            with opener.open(urllib.request.Request(url, method="HEAD"), timeout=7) as resp:
                return resp.status
        except Exception:
            return None
    status = await asyncio.to_thread(probe)
    return {"target_id": target_id, "kind": target["kind"],
            "https_reachable": status is not None, "http_status": status,
            "authenticated": False, "data_access_verified": False}
