"""Internal file-upload authorization service. No token parsing or trust in MCP initialize.

Requires token introspection by a trusted authorization server. Denies by default.
Authorization is granted only to stable subjects in an operator-managed allowlist.
"""
import base64
import hmac
import ipaddress
import json
import os
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INTROSPECT_URL=os.environ.get("UPLOAD_INTROSPECT_URL","")
INTROSPECT_CLIENT_ID=os.environ.get("UPLOAD_INTROSPECT_CLIENT_ID","")
INTROSPECT_CLIENT_SECRET=os.environ.get("UPLOAD_INTROSPECT_CLIENT_SECRET","")
ALLOWED_SUBJECTS={s.strip() for s in os.environ.get("UPLOAD_ALLOWED_SUBJECTS","").split(",") if s.strip()}
EXPECTED_ISSUER=os.environ.get("UPLOAD_INTROSPECT_ISSUER","")
EXPECTED_AUDIENCE=os.environ.get("UPLOAD_INTROSPECT_AUDIENCE","")

def authorize_token(bearer):
    if not bearer.startswith("Bearer ") or len(bearer)>8192:return None
    if not INTROSPECT_URL or not INTROSPECT_CLIENT_ID or not INTROSPECT_CLIENT_SECRET or not EXPECTED_ISSUER or not EXPECTED_AUDIENCE or not ALLOWED_SUBJECTS:return None
    u=urllib.parse.urlsplit(INTROSPECT_URL)
    if u.scheme!="https" or not u.hostname or u.username or u.password or u.fragment:return None
    # Never allow introspection calls to internal hosts or IP literals.
    if u.hostname=="localhost" or "." not in u.hostname or u.hostname.endswith((".internal",".local")):return None
    try:
        ipaddress.ip_address(u.hostname)
        return None
    except ValueError:pass
    token=bearer.removeprefix("Bearer ").strip()
    auth=base64.b64encode((INTROSPECT_CLIENT_ID+":"+INTROSPECT_CLIENT_SECRET).encode()).decode()
    body=urllib.parse.urlencode({"token":token}).encode()
    req=urllib.request.Request(INTROSPECT_URL,data=body,headers={"Authorization":"Basic "+auth,"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=4) as resp:
            if resp.status!=200 or "application/json" not in resp.headers.get("Content-Type",""):return None
            raw=resp.read(4097)
            if len(raw)>4096:return None
            info=json.loads(raw)
    except (OSError,ValueError,TimeoutError,urllib.error.URLError):return None
    if info.get("active") is not True or info.get("iss")!=EXPECTED_ISSUER:return None
    aud=info.get("aud")
    if EXPECTED_AUDIENCE not in (aud if isinstance(aud,list) else [aud]):return None
    sub=info.get("sub")
    if not isinstance(sub,str) or sub not in ALLOWED_SUBJECTS:return None
    return sub

class Handler(BaseHTTPRequestHandler):
    def log_message(self,fmt,*args):pass
    def reply(self,status,obj):
        blob=json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Cache-Control","no-store")
        self.send_header("Content-Length",str(len(blob)))
        self.end_headers();self.wfile.write(blob)
    def do_GET(self):
        if self.path=="/healthz":return self.reply(200,{"status":"ok","authorization_configured":bool(INTROSPECT_URL and ALLOWED_SUBJECTS)})
        self.reply(404,{"error":"not_found"})
    def do_POST(self):
        if self.path!="/v1/authorize":return self.reply(404,{"error":"not_found"})
        size=self.headers.get("Content-Length","")
        if not size.isdecimal() or int(size)>1024:return self.reply(400,{"error":"invalid_request"})
        try:body=json.loads(self.rfile.read(int(size)))
        except (ValueError,UnicodeDecodeError):return self.reply(400,{"error":"invalid_request"})
        if body!={"permission":"files:upload"}:return self.reply(403,{"allowed":False})
        subject=authorize_token(self.headers.get("Authorization",""))
        if not subject:return self.reply(403,{"allowed":False})
        return self.reply(200,{"allowed":True,"permission":"files:upload","sub":subject})
if __name__=="__main__":
    ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
