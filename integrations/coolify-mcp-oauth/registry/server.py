"""Allowlisted MCP provider registry and dispatcher.

This proxy is intended to sit behind an authenticated MCP gateway. Provider
tools are namespaced and routed only to fixed, trusted internal services.
"""
import json, os, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROVIDERS={"upload":{"url":"http://public-file-upload:8080/mcp-upload","prefix":"upload__"}}
def call_provider(url,request,token):
    body=json.dumps(request).encode()
    headers={"Content-Type":"application/json","Accept":"application/json","Authorization":token}
    req=urllib.request.Request(url,data=body,headers=headers,method="POST")
    with urllib.request.urlopen(req,timeout=8) as response:
        if response.status!=200:raise ValueError("provider_unavailable")
        return json.loads(response.read(1024*1024))
def discover(token):
    tools=[];routes={}
    for provider,config in PROVIDERS.items():
        answer=call_provider(config["url"],{"jsonrpc":"2.0","id":"registry","method":"tools/list","params":{}},token)
        for tool in answer.get("result",{}).get("tools",[]):
            name=tool.get("name")
            if not isinstance(name,str) or not name or len(name)>96:raise ValueError("invalid_tool_name")
            qualified=config["prefix"]+name
            if qualified in routes:raise ValueError("tool_collision")
            item=dict(tool);item["name"]=qualified
            tools.append(item);routes[qualified]=(config["url"],name)
    return tools,routes

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
        length=self.headers.get("Content-Length","")
        if not length.isdecimal() or int(length)>1024*1024:return self.respond(413,{"error":"request_too_large"})
        try:
            request=json.loads(self.rfile.read(int(length)));method=request.get("method");identifier=request.get("id")
            if method=="initialize":return self.respond(200,{"jsonrpc":"2.0","id":identifier,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"mad4b-provider-registry","version":"0.1.0"}}})
            tools,routes=discover(auth)
            if method=="tools/list":return self.respond(200,{"jsonrpc":"2.0","id":identifier,"result":{"tools":tools}})
            if method!="tools/call":return self.respond(400,{"error":"unsupported_method"})
            p=request.get("params") or {};qualified=p.get("name")
            if qualified not in routes:return self.respond(200,{"jsonrpc":"2.0","id":identifier,"result":{"isError":True,"content":[{"type":"text","text":"unknown_tool"}]}})
            url,name=routes[qualified]
            result=call_provider(url,{"jsonrpc":"2.0","id":identifier,"method":"tools/call","params":{"name":name,"arguments":p.get("arguments") or {}}},auth)
            return self.respond(200,result)
        except (ValueError,KeyError,OSError,urllib.error.URLError):
            return self.respond(503,{"error":"provider_unavailable"})
if __name__=="__main__":ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
