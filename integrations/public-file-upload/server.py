#!/usr/bin/env python3
"""Authenticated public HTTPS upload receiver (TLS terminates at reverse proxy).
Only writes opaque files to a private quarantine; never extracts or runs files.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BYTES = int(os.environ.get("UPLOAD_MAX_BYTES", str(32 * 1024 * 1024)))
TARGET = Path(os.environ.get("UPLOAD_QUARANTINE", "/data/quarantine")).resolve()
TOKEN = os.environ.get("UPLOAD_API_TOKEN", "")
HEX = re.compile(r"^[a-fA-F0-9]{64}$")

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/healthz":
            self.reply(200, {"status": "ok"})
        else:
            self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/v1/uploads":
            return self.reply(404, {"error": "not_found"})
        authorization = self.headers.get("Authorization", "")
        if not TOKEN or not hmac.compare_digest(authorization, "Bearer " + TOKEN):
            return self.reply(401, {"error": "unauthorized"})
        length = self.headers.get("Content-Length", "")
        if not length.isdigit():
            return self.reply(411, {"error": "content_length_required"})
        count = int(length)
        if count < 1 or count > MAX_BYTES:
            return self.reply(413, {"error": "size_limit"})
        sha = self.headers.get("X-Content-SHA256", "").lower()
        if not HEX.fullmatch(sha):
            return self.reply(400, {"error": "sha256_required"})
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/octet-stream":
            return self.reply(415, {"error": "binary_required"})
        TARGET.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(prefix=".incoming-", dir=TARGET)
        actual = hashlib.sha256()
        remaining = count
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        return self.reply(400, {"error": "incomplete_body"})
                    remaining -= len(chunk)
                    actual.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if not hmac.compare_digest(actual.hexdigest(), sha):
                return self.reply(422, {"error": "checksum_mismatch"})
            final = TARGET / (sha + ".bin")
            os.replace(path, final)
            return self.reply(201, {"id": sha, "bytes": count, "sha256": sha, "state": "quarantined"})
        finally:
            if os.path.exists(path):
                os.unlink(path)

if __name__ == "__main__":
    if len(TOKEN) < 32:
        raise SystemExit("UPLOAD_API_TOKEN must have at least 32 characters")
    TARGET.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Internal container port only: deploy behind authenticated TLS reverse proxy.
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
