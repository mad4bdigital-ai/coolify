"""Internal file-upload authorization service. No token parsing or trust in MCP initialize.

Requires token introspection by a trusted authorization server. Denies by default.
Authorization is granted only to stable subjects in an operator-managed allowlist.
"""
import base64
import hmac
import hashlib
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
AUTHORIZATION_BACKEND=os.environ.get("UPLOAD_AUTHZ_BACKEND","introspection").strip().lower()
ALLOWED_TOKEN_DIGESTS={value.strip().lower() for value in os.environ.get("UPLOAD_ALLOWED_TOKEN_SHA256","").split(",") if value.strip()}

def authorize_oauth_fingerprint(bearer):
    """Token-bound grant: verify via OAuth proxy AND operator-managed fingerprint."""
    if not bearer.startswith("Bearer ") or len(bearer)>8192:return None
    token=bearer[7:]
    if not token or not ALLOWED_TOKEN_DIGESTS:return None
    digest=hashlib.sha256(token.encode()).hexdigest()
    if not any(len(candidate)==64 and hmac.compare_digest(digest,candidate) for candidate in ALLOWED_TOKEN_DIGESTS):return None
    payload=json.dumps({"jsonrpc":"2.0","id":"upload-authz","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"upload-authz","version":"1"}}}).encode()
    request=urllib.request.Request("http://coolify-mcp-oauth:8080/mcp",data=payload,method="POST",headers={"Authorization":bearer,"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":"2025-11-25"})
    try:
        with urllib.request.urlopen(request,timeout=5) as response:
            if response.status!=200:return None
            body=response.read(16385)
            if len(body)>16384:return None
            content_type=response.headers.get("Content-Type","")
            if "text/event-stream" in content_type:
                values=[json.loads(line[6:]) for line in body.decode("utf-8","replace").splitlines() if line.startswith("data: ")]
                if not any(x.get("id")=="upload-authz" and isinstance(x.get("result"),dict) and x["result"].get("serverInfo") for x in values):return None
            else:
                result=json.loads(body)
                if result.get("id")!="upload-authz" or not isinstance(result.get("result"),dict) or not result["result"].get("serverInfo"):return None
    except (OSError,ValueError,urllib.error.URLError):
        return None
    return "oauth-token:"+digest

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
    scopes=info.get("scope",info.get("scp",[]))
    if isinstance(scopes,str):scopes=scopes.split()
    if not isinstance(scopes,list) or "files:upload" not in scopes:return None
    sub=info.get("sub")
    if not isinstance(sub,str) or sub not in ALLOWED_SUBJECTS:return None
    return sub

def authorize_registry_assertion(bearer):
    secret=os.environ.get("UPLOAD_SIGNING_SECRET","")
    if len(secret)<32 or not bearer.startswith("Bearer mad4b.") or len(bearer)>4096:return None
    try:
        encoded,signature=bearer[13:].split(".",1)
        if len(signature)!=64 or not hmac.compare_digest(hmac.new(secret.encode(),encoded.encode(),hashlib.sha256).hexdigest(),signature):return None
        data=json.loads(base64.urlsafe_b64decode(encoded+"="*((-len(encoded))%4)))
        now=__import__("time").time()
        sub=data.get("sub")
        if data.get("aud")!="mad4b-upload-authz" or data.get("permission")!="files:upload":return None
        if type(data.get("exp")) is not int or not now<data["exp"]<=now+60:return None
        if not isinstance(sub,str) or not __import__("re").fullmatch(r"[A-Za-z0-9@._:-]{1,200}",sub):return None
        return sub
    except (ValueError,TypeError,KeyError,UnicodeDecodeError):return None

def readiness():
    if AUTHORIZATION_BACKEND=="registry_assertion":
        ok=len(os.environ.get("UPLOAD_SIGNING_SECRET",""))>=32
        return {"ready":ok,"missing":[] if ok else ["signing_secret"]}
    if AUTHORIZATION_BACKEND=="oauth_fingerprint":
        valid=bool(ALLOWED_TOKEN_DIGESTS) and all(len(x)==64 and all(c in "0123456789abcdef" for c in x) for x in ALLOWED_TOKEN_DIGESTS)
        return {"ready":valid,"missing":[] if valid else ["allowed_token_sha256"]}
    fields={"introspection_url":bool(INTROSPECT_URL),"client_id":bool(INTROSPECT_CLIENT_ID),"client_secret":bool(INTROSPECT_CLIENT_SECRET),"issuer":bool(EXPECTED_ISSUER),"audience":bool(EXPECTED_AUDIENCE),"allowed_subjects":bool(ALLOWED_SUBJECTS)}
    return {"ready":all(fields.values()),"missing":[key for key,valid in fields.items() if not valid]}

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
        if self.path=="/healthz":return self.reply(200,{"status":"ok","authorization_configured":readiness()["ready"]})
        if self.path=="/readyz":
            report=readiness()
            return self.reply(200 if report["ready"] else 503,report)
        self.reply(404,{"error":"not_found"})
    def do_POST(self):
        if self.path!="/v1/authorize":return self.reply(404,{"error":"not_found"})
        size=self.headers.get("Content-Length","")
        if not size.isdecimal() or int(size)>1024:return self.reply(400,{"error":"invalid_request"})
        try:body=json.loads(self.rfile.read(int(size)))
        except (ValueError,UnicodeDecodeError):return self.reply(400,{"error":"invalid_request"})
        if body!={"permission":"files:upload"}:return self.reply(403,{"allowed":False})
        subject=(authorize_registry_assertion(self.headers.get("Authorization","")) if AUTHORIZATION_BACKEND=="registry_assertion" else authorize_oauth_fingerprint(self.headers.get("Authorization","")) if AUTHORIZATION_BACKEND=="oauth_fingerprint" else authorize_token(self.headers.get("Authorization","")) if AUTHORIZATION_BACKEND=="introspection" else None)
        if not subject:return self.reply(403,{"allowed":False})
        return self.reply(200,{"allowed":True,"permission":"files:upload","sub":subject})
if __name__=="__main__":
    ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
