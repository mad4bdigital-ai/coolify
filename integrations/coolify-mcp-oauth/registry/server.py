"""Allowlisted MCP provider registry and dispatcher.

This proxy is intended to sit behind an authenticated MCP gateway. Provider
tools are namespaced and routed only to fixed, trusted internal services.
"""
import json, os, urllib.request, urllib.error, socket, hmac, hashlib, base64, time, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROVIDERS={"upload":{"url":"http://public-file-upload:8080/mcp-upload","prefix":"upload__"}}
# Optional Coolify provider: use the existing internal Coolify MCP implementation,
# never the future public aggregate URL, to avoid a proxy loop.
if os.environ.get("COOLIFY_SOURCE_MCP_URL") and os.environ.get("COOLIFY_SOURCE_AUTHORIZATION"):
    PROVIDERS["coolify"]={"url":os.environ["COOLIFY_SOURCE_MCP_URL"],"prefix":"" , "authorization":os.environ["COOLIFY_SOURCE_AUTHORIZATION"]}
def call_provider(url,request,token):
    body=json.dumps(request).encode()
    headers={"Content-Type":"application/json","Accept":"application/json","Authorization":token}
    req=urllib.request.Request(url,data=body,headers=headers,method="POST")
    with urllib.request.urlopen(req,timeout=8) as response:
        if response.status!=200:raise ValueError("provider_unavailable")
        return json.loads(response.read(1024*1024))
def authorize_identity(bearer):
    """Trust only a bearer authorized by the native Coolify MCP.

    The external OAuth proxy authenticates ChatGPT and forwards its configured,
    scoped upstream Coolify credential to this registry. Never call the OAuth
    proxy from here: after setting its upstream to Registry that creates a
    recursive dependency and breaks tools discovery / refresh.
    """
    core=PROVIDERS.get("coolify")
    if core is None:return None
    try:
        answer=call_provider(core["url"],{"jsonrpc":"2.0","id":"core-auth","method":"tools/list","params":{}},bearer)
        if isinstance(answer.get("result",{}).get("tools"),list):
            return "coolify"
    except (ValueError,KeyError,OSError,urllib.error.URLError):
        pass
    return None

def discover(token,identity=None):
    tools=[];routes={}
    for provider,config in PROVIDERS.items():
        if provider=="coolify" and identity=="upload_oauth":
            effective_url="http://coolify-mcp-oauth:8080/mcp"
            effective_token=token
        else:
            effective_url=config["url"]
            effective_token=token if identity=="coolify" and provider=="coolify" else config.get("authorization",token)
        try:
            if provider=="upload" and identity=="coolify":
                # Discover tool schemas, never grant upload rights based on Coolify login.
                with urllib.request.urlopen("http://public-file-upload:8080/internal/tool-catalog",timeout=4) as response:
                    answer={"result":{"tools":json.loads(response.read(131072)).get("tools",[])}}
            else:
                answer=call_provider(effective_url,{"jsonrpc":"2.0","id":"registry","method":"tools/list","params":{}},effective_token)
        except urllib.error.HTTPError as exc:
            # An unavailable optional provider must not hide the core Coolify catalog.
            # A denied Upload bearer must never be promoted into Upload authority.
            if provider=="upload" and exc.code in (401,403):continue
            raise
        for tool in answer.get("result",{}).get("tools",[]):
            name=tool.get("name")
            if not isinstance(name,str) or not name or len(name)>96:raise ValueError("invalid_tool_name")
            qualified=config["prefix"]+name
            if qualified in routes:raise ValueError("tool_collision")
            item=dict(tool);item["name"]=qualified
            tools.append(item);routes[qualified]=(effective_url,name,effective_token)
    return tools,routes

def verified_proxy_subject(handler):
    # Only the OAuth proxy itself may assert identity. Public Traefik routes
    # and other callers cannot inject an X-User-Sub header.
    subject=handler.headers.get("X-User-Sub","")
    if not re.fullmatch(r"[A-Za-z0-9@._:-]{1,200}",subject):return None
    peer=handler.client_address[0]
    try:
        trusted={row[4][0] for row in socket.getaddrinfo("coolify-mcp-oauth",None,type=socket.SOCK_STREAM)}
    except socket.gaierror:return None
    return subject if peer in trusted else None

def grant_upload_subject(subject):
    secret=os.environ.get("UPLOAD_SIGNING_SECRET","")
    if len(secret)<32 or not subject:return None
    blob=json.dumps({"sub":subject,"permission":"files:upload","aud":"mad4b-upload-authz","exp":int(time.time())+45},separators=(",",":"),sort_keys=True).encode()
    encoded=base64.urlsafe_b64encode(blob).rstrip(b"=").decode()
    sig=hmac.new(secret.encode(),encoded.encode(),hashlib.sha256).hexdigest()
    return "Bearer mad4b."+encoded+"."+sig

class Handler(BaseHTTPRequestHandler):
    def respond(self,status,payload):
        raw=json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)))
        self.send_header("Cache-Control","no-store")
        self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        return self.respond(200,{"status":"ok"}) if self.path=="/healthz" else self.respond(404,{"error":"not_found"})
    def do_POST(self):
        if self.path!="/mcp":return self.respond(404,{"error":"not_found"})
        auth=self.headers.get("Authorization","")
        if not auth.startswith("Bearer ") or len(auth)>8192:return self.respond(401,{"error":"authentication_required"})
        identity=authorize_identity(auth)
        if identity is None:return self.respond(401,{"error":"invalid_authorization"})
        length=self.headers.get("Content-Length","")
        if not length.isdecimal():return self.respond(413,{"error":"request_too_large"})
        size=int(length)
        # File bytes are base64-encoded inside MCP JSON; constrain the larger
        # payload to a verified, explicitly named attachment upload only.
        large_upload_limit=45*1024*1024
        if size>large_upload_limit:return self.respond(413,{"error":"request_too_large"})
        try:
            request=json.loads(self.rfile.read(size));method=request.get("method");identifier=request.get("id")
            name=(request.get("params") or {}).get("name") if isinstance(request,dict) else None
            if size>1024*1024 and not (method=="tools/call" and name in ("upload__upload_attachment","upload__upload_file")):
                return self.respond(413,{"error":"request_too_large"})
            if method=="server/discover":
                result={"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"mad4b-provider-registry","version":"0.1.0"}}}
                return self.respond(200,{"jsonrpc":"2.0","id":identifier,"result":result})
            if method=="notifications/initialized":
                self.send_response(202)
                self.send_header("Content-Length","0")
                self.end_headers()
                return
            if method=="initialize":return self.respond(200,{"jsonrpc":"2.0","id":identifier,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mad4b-provider-registry","version":"0.1.0"}}})
            tools,routes=discover(auth,identity)
            if method=="tools/list":return self.respond(200,{"jsonrpc":"2.0","id":identifier,"result":{"tools":tools}})
            if method!="tools/call":return self.respond(400,{"error":"unsupported_method"})
            p=request.get("params") or {};qualified=p.get("name")
            if qualified not in routes:return self.respond(200,{"jsonrpc":"2.0","id":identifier,"result":{"isError":True,"content":[{"type":"text","text":"unknown_tool"}]}})
            url,name,forward_auth=routes[qualified]
            if qualified.startswith("upload__"):
                subject=verified_proxy_subject(self)
                forward_auth=grant_upload_subject(subject)
                if not forward_auth:
                    return self.respond(403,{"error":"upload_permission_required"})
            result=call_provider(url,{"jsonrpc":"2.0","id":identifier,"method":"tools/call","params":{"name":name,"arguments":p.get("arguments") or {}}},forward_auth)
            return self.respond(200,result)
        except urllib.error.HTTPError as exc:
            if exc.code in (401,403):return self.respond(exc.code,{"error":"provider_authorization_failed"})
            return self.respond(503,{"error":"provider_unavailable"})
        except (ValueError,KeyError,OSError,urllib.error.URLError):
            return self.respond(503,{"error":"provider_unavailable"})
if __name__=="__main__":ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
