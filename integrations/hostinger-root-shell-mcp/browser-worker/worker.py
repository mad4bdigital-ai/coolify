"""MAD4B hPanel read-only browser worker. Never expose this service publicly."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

HOME = "https://hpanel.hostinger.com/"
PROFILE = os.environ.get("HPANEL_PROFILE_DIR", "/browser-profile")
TIMEOUT = 20000

def inspect(action):
    with sync_playwright() as pw:
        context = pw.chromium.launch_persistent_context(
            PROFILE, headless=True, args=["--no-sandbox"],
            viewport={"width": 1365, "height": 900})
        try:
            page = context.pages[0] if context.pages else context.new_page()
            page.goto(HOME, wait_until="domcontentloaded", timeout=TIMEOUT)
            page.wait_for_timeout(1500)
            url = urlsplit(page.url)
            if url.scheme != "https" or url.hostname not in ("hpanel.hostinger.com", "auth.hostinger.com"):
                return {"ok": False, "status": "UNEXPECTED_REDIRECT"}
            # Redirect URL alone is insufficient evidence of authentication.
            # Until a known signed-in hPanel element is certified, fail closed.
            if action == "session_status":
                return {"ok": True, "authenticated": False,
                        "status": "UNVERIFIED_SESSION", "account_alias": ""}
            return {"ok": False, "websites": [], "status": "SELECTOR_NOT_CERTIFIED"}
            # Do not infer websites from unstructured text; selectors must be
            # accepted against the real hPanel DOM before enabling extraction.
            return {"ok": False, "websites": [], "status": "SELECTOR_NOT_CERTIFIED"}
        finally:
            context.close()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/session_status", "/list_websites"):
            self.send_error(404)
            return
        try:
            response = inspect(self.path[1:])
        except Exception:
            response = {"ok": False, "status": "BROWSER_ERROR"}
        data = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        return

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 13871), Handler).serve_forever()
