"""One-shot read-only request into the local Chromium extension bridge."""
import json
import pathlib
import time
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:13872"
TOKEN_FILE = pathlib.Path("/config/mad4b-bridge-private/token")

def main():
    token=TOKEN_FILE.read_text().strip()
    headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"}
    try:
        req=urllib.request.Request(BASE+"/request",data=b"{}",headers=headers,method="POST")
        with urllib.request.urlopen(req,timeout=5) as r: job=json.load(r)
        for _ in range(16):
            time.sleep(3)
            q=urllib.request.Request(BASE+"/result/"+job["id"],headers=headers)
            with urllib.request.urlopen(q,timeout=5) as r: reply=json.load(r)
            if reply.get("ready"):
                print(json.dumps(reply["result"]))
                return
        print(json.dumps({"ok":False,"status":"EXTENSION_RESPONSE_TIMEOUT","domains":[]}))
    except urllib.error.HTTPError as e:
        print(json.dumps({"ok":False,"status":"BRIDGE_HTTP_"+str(e.code),"domains":[]}))
    except Exception:
        print(json.dumps({"ok":False,"status":"BRIDGE_UNAVAILABLE","domains":[]}))

if __name__=="__main__":
    main()
