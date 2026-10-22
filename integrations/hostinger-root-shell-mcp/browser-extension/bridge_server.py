"""Loopback-only, paired, single-job hPanel browser extension bridge."""
import json, os, time, secrets, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
TOKEN=os.environ["MAD4B_BROWSER_PAIRING_TOKEN"]
LOCK=threading.Lock()
jobs={}
def prune():
    for key,value in list(jobs.items()):
        if time.monotonic()-value["created"]>65:jobs.pop(key,None)
class H(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def auth(self):
        return secrets.compare_digest(self.headers.get("Authorization",""),"Bearer "+TOKEN)
    def respond(self,code,data):
        content=json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Cache-Control","no-store")
        self.send_header("Content-Length",str(len(content)))
        self.end_headers();self.wfile.write(content)
    def do_GET(self):
        if not self.auth():return self.respond(403,{"error":"FORBIDDEN"})
        with LOCK:
            prune()
            if self.path=="/jobs":
                available=next(((k,v) for k,v in jobs.items() if not v["dispatched"]),None)
                if available:
                    k,v=available;v["dispatched"]=True
                    return self.respond(200,{"id":k})
                return self.respond(200,{})
            if self.path.startswith("/result/"):
                key=self.path.rsplit("/",1)[-1]
                item=jobs.get(key)
                return self.respond(200,{"ready":bool(item and item["result"] is not None),"result":item["result"] if item else None})
        self.respond(404,{"error":"NOT_FOUND"})
    def do_POST(self):
        if not self.auth():return self.respond(403,{"error":"FORBIDDEN"})
        size=int(self.headers.get("Content-Length","0"))
        if size<1 or size>30000:return self.respond(413,{"error":"INVALID_BODY"})
        try:payload=json.loads(self.rfile.read(size))
        except (ValueError,UnicodeError):return self.respond(400,{"error":"INVALID_JSON"})
        with LOCK:
            prune()
            if self.path=="/request":
                if any(v["result"] is None for v in jobs.values()):
                    return self.respond(409,{"error":"BUSY"})
                key=secrets.token_hex(12)
                jobs[key]={"created":time.monotonic(),"dispatched":False,"result":None}
                return self.respond(200,{"id":key})
            if self.path=="/results":
                key=payload.get("id")
                result=payload.get("result")
                if not isinstance(key,str) or key not in jobs or not jobs[key]["dispatched"]:
                    return self.respond(404,{"error":"UNKNOWN_JOB"})
                if not isinstance(result,dict):return self.respond(400,{"error":"INVALID_RESULT"})
                domains=result.get("domains",[])
                if not isinstance(domains,list):return self.respond(400,{"error":"INVALID_DOMAINS"})
                sites=result.get("sites",[])
                if not isinstance(sites,list):return self.respond(400,{"error":"INVALID_SITES"})
                allowed=("domain","site_type","created_on","site_status","account_email","hosting_plan","plan_expires","evidence","group_evidence")
                safe_sites=[{k:(str(x[k])[:255] if isinstance(x.get(k),str) else None) for k in allowed} for x in sites[:100] if isinstance(x,dict)]
                jobs[key]["result"]={"ok":result.get("ok") is True,"status":str(result.get("status",""))[:60],"sites":safe_sites,
                                     "domains":[str(v)[:253] for v in domains[:100]],"source":"hpanel-visible-dom"}
                return self.respond(200,{"ok":True})
        self.respond(404,{"error":"NOT_FOUND"})
if __name__=="__main__":
    HTTPServer(("127.0.0.1",13872),H).serve_forever()
