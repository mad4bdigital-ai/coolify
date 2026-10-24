#!/usr/bin/env python3
"""Internet-facing, authenticated file intake. No execution or installation."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import time
import urllib.request
import urllib.error
import transfer
import url_import
import authorization
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BYTES=int(os.environ.get("UPLOAD_MAX_BYTES",str(32*1024*1024)))
TARGET=Path(os.environ.get("UPLOAD_QUARANTINE","/data/quarantine")).resolve()
OAUTH_VERIFY_URL=os.environ.get("UPLOAD_OAUTH_VERIFY_URL","http://coolify-mcp-oauth:8080/mcp")
SIGNING=os.environ.get("UPLOAD_SIGNING_SECRET","")
HEX=re.compile(r"^[a-f0-9]{64}$")
def enc(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def dec(s): return base64.urlsafe_b64decode(s+"="*((-len(s))%4))
def mint(payload):
    part=enc(json.dumps(payload,sort_keys=True,separators=(",",":")).encode())
    return part+"."+enc(hmac.new(SIGNING.encode(),part.encode(),hashlib.sha256).digest())
def read_grant(token):
    try:
        part,sig=token.split(".",1)
        expected=enc(hmac.new(SIGNING.encode(),part.encode(),hashlib.sha256).digest())
        if not hmac.compare_digest(sig,expected): return None
        value=json.loads(dec(part))
        if value.get("scope")!="upload" or not isinstance(value.get("jti"),str):return None
        if value.get("exp") is not None and time.time()>=value["exp"]:return None
        if (TARGET/"revoked"/value["jti"]).exists():return None
        return value
    except (ValueError,TypeError,KeyError,OverflowError):return None

class Handler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def reply(self,status,data):
        blob=json.dumps(data).encode()
        self.send_response(status)
        for k,v in (("Content-Type","application/json"),("Cache-Control","no-store"),("Content-Length",str(len(blob))),("X-Content-Type-Options","nosniff")):self.send_header(k,v)
        self.end_headers();self.wfile.write(blob)
    def auth(self):
        return self.headers.get("Authorization","").removeprefix("Bearer ")
    def upload_subject(self):
        # Authentication alone is insufficient: require verified files:upload permission.
        return authorization.authorize_upload(self.headers.get("Authorization",""))

    def body_json(self,limit=8192):
        length=self.headers.get("Content-Length","")
        if not length.isdecimal() or int(length)>limit:return None
        try:return json.loads(self.rfile.read(int(length)))
        except (ValueError,UnicodeDecodeError):return None
    def do_GET(self):
        return self.reply(200,{"status":"ok"}) if self.path=="/healthz" else self.reply(404,{"error":"not_found"})
    def transfer_request(self):
        principal=self.upload_subject()
        if principal is None:return self.reply(403,{"error":"upload_permission_required"})
        body_limit=(MAX_BYTES*2+8192 if self.path=="/mcp-upload" else (transfer.CHUNK_MAX*2+8192 if self.path=="/v1/transfers/chunk" else 8192))
        data=self.body_json(limit=body_limit)
        if not isinstance(data,dict):return self.reply(400,{"error":"invalid_payload"})
        if self.path=="/mcp-upload":
            mid=data.get("id")
            method=data.get("method")
            if method=="initialize":
                return self.reply(200,{"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mad4b-file-transfer","version":"0.1.0"}}})
            if method=="tools/list":
                tools=[]
                for name in transfer.OPS:
                    props={"content_base64":{"type":"string"},"sha256":{"type":"string"}} if name=="upload_file" else ({"size":{"type":"integer"},"sha256":{"type":"string"}} if name=="upload_begin" else ({"transfer_id":{"type":"string"},"offset":{"type":"integer"},"base64":{"type":"string"}} if name=="upload_chunk" else {"transfer_id":{"type":"string"}}))
                    tools.append({"name":name,"description":"Authorized resumable binary transfer; quarantines bytes, never executes files","inputSchema":{"type":"object","properties":props,"additionalProperties":False}})
                tools.append({"name":"upload_from_url","description":"Import allowlisted HTTPS download URL to quarantine after SHA256 verification","inputSchema":{"type":"object","properties":{"url":{"type":"string"},"sha256":{"type":"string"}},"required":["url","sha256"]}})
                return self.reply(200,{"jsonrpc":"2.0","id":mid,"result":{"tools":tools}})
            if method!="tools/call":return self.reply(400,{"error":"unsupported_mcp_method"})
            args=data.get("params") or {}
            operation=args.get("name")
            inputs=args.get("arguments") or {}
        else:
            operation=self.path.rsplit("/",1)[-1]
            mapping={"begin":"upload_begin","chunk":"upload_chunk","status":"upload_status","commit":"upload_commit"}
            operation=mapping.get(operation)
            inputs=data
            mid=None
        try:
            # Transfer ownership is scoped to the validated OAuth bearer; caller cannot override.
            inputs=dict(inputs)
            inputs["owner"]=principal
            if operation=="upload_from_url":
                hosts={h.strip().lower() for h in os.environ.get("UPLOAD_URL_ALLOWED_HOSTS","").split(",") if h.strip()}
                result=url_import.import_url(TARGET,inputs.get("url",""),inputs.get("sha256",""),MAX_BYTES,hosts)
            else:
                result=transfer.call(TARGET,operation,inputs,MAX_BYTES)
            if self.path=="/mcp-upload":return self.reply(200,{"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":json.dumps(result)}]}})
            return self.reply(200,result)
        except (ValueError,KeyError,OSError) as exc:
            if self.path=="/mcp-upload":return self.reply(200,{"jsonrpc":"2.0","id":mid,"result":{"isError":True,"content":[{"type":"text","text":str(exc)}]}})
            return self.reply(422,{"error":str(exc)})
    def do_POST(self):
        if self.path=="/v1/import-url":
            if self.upload_subject() is None:return self.reply(403,{"error":"upload_permission_required"})
            data=self.body_json()
            if not isinstance(data,dict):return self.reply(400,{"error":"invalid_payload"})
            hosts={h.strip().lower() for h in os.environ.get("UPLOAD_URL_ALLOWED_HOSTS","").split(",") if h.strip()}
            try:
                result=url_import.import_url(TARGET,data.get("url",""),data.get("sha256",""),MAX_BYTES,hosts)
                return self.reply(201,result)
            except (ValueError,OSError,TimeoutError) as exc:
                return self.reply(422,{"error":str(exc)})
        if self.path=="/mcp-upload" or self.path in ("/v1/transfers/begin","/v1/transfers/chunk","/v1/transfers/status","/v1/transfers/commit"):
            return self.transfer_request()
        if self.path=="/v1/grants":
            if self.upload_subject() is None:return self.reply(403,{"error":"upload_permission_required"})
            data=self.body_json()
            if not isinstance(data,dict):return self.reply(400,{"error":"invalid_payload"})
            # No fixed maximum lifetime. Each grant has its own requested positive expiry.
            ttl=data.get("expires_in_seconds")
            if type(ttl) is not int or ttl<=0:return self.reply(422,{"error":"positive_expiry_required"})
            exp=int(time.time())+ttl
            sha=data.get("sha256")
            if sha is not None and (not isinstance(sha,str) or not HEX.fullmatch(sha)):return self.reply(422,{"error":"invalid_sha256"})
            limit=data.get("max_bytes",MAX_BYTES)
            if type(limit) is not int or not 1<=limit<=MAX_BYTES:return self.reply(422,{"error":"invalid_max_bytes"})
            grant={"jti":secrets.token_hex(16),"scope":"upload","exp":exp,"sha256":sha,"max_bytes":limit}
            return self.reply(201,{"upload_token":mint(grant),"expires_at":exp,"grant_id":grant["jti"]})
        if self.path=="/v1/grants/revoke":
            if self.upload_subject() is None:return self.reply(403,{"error":"upload_permission_required"})
            data=self.body_json()
            jti=data.get("grant_id") if isinstance(data,dict) else None
            if not isinstance(jti,str) or not re.fullmatch("[a-f0-9]{32}",jti):return self.reply(422,{"error":"invalid_grant_id"})
            directory=TARGET/"revoked";directory.mkdir(mode=0o700,exist_ok=True)
            (directory/jti).touch(mode=0o600,exist_ok=True)
            return self.reply(200,{"revoked":True})
        if self.path!="/v1/uploads":return self.reply(404,{"error":"not_found"})
        token=self.auth();grant=read_grant(token)
        if not grant:return self.reply(401,{"error":"invalid_or_expired_grant"})
        length=self.headers.get("Content-Length","")
        if not length.isdecimal():return self.reply(411,{"error":"length_required"})
        count=int(length)
        if not 1<=count<=min(MAX_BYTES,grant["max_bytes"]):return self.reply(413,{"error":"size_limit"})
        sha=self.headers.get("X-Content-SHA256","").lower()
        if not HEX.fullmatch(sha) or grant.get("sha256") not in (None,sha):return self.reply(422,{"error":"sha256_scope_mismatch"})
        if self.headers.get("Content-Type","").split(";")[0].strip()!="application/octet-stream":return self.reply(415,{"error":"binary_required"})
        TARGET.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(prefix=".incoming-",dir=TARGET)
        digest=hashlib.sha256();remaining=count
        try:
            with os.fdopen(fd,"wb") as f:
                os.fchmod(f.fileno(),0o600)
                while remaining:
                    chunk=self.rfile.read(min(1024*1024,remaining))
                    if not chunk:return self.reply(400,{"error":"truncated"})
                    remaining-=len(chunk);digest.update(chunk);f.write(chunk)
                f.flush();os.fsync(f.fileno())
            if not hmac.compare_digest(digest.hexdigest(),sha):return self.reply(422,{"error":"checksum_mismatch"})
            os.replace(tmp,TARGET/(sha+".bin"))
            return self.reply(201,{"sha256":sha,"bytes":count,"state":"quarantined"})
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
if __name__=="__main__":
    if len(SIGNING)<32:raise SystemExit("UPLOAD_SIGNING_SECRET must have at least 32 characters")
    TARGET.mkdir(mode=0o700,parents=True,exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
