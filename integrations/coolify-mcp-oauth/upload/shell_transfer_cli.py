"""Shell-compatible uploader to the same quarantine transport.

Uses only Python stdlib. It runs on a machine that can read the source file
and reach the upload service. Authentication is the user's existing OAuth bearer
provided in the process environment (never logged or embedded in commands).
"""
import argparse, base64, hashlib, json, os, pathlib, urllib.request

def upload(path, base_url, bearer, chunk_bytes=256*1024):
    file=pathlib.Path(path)
    length=file.stat().st_size
    h=hashlib.sha256()
    with file.open("rb") as src:
        for part in iter(lambda:src.read(1024*1024),b""):h.update(part)
    digest=h.hexdigest()
    def request(name,body):
        payload=json.dumps(body).encode()
        req=urllib.request.Request(base_url.rstrip("/")+"/v1/transfers/"+name,
            data=payload,headers={"Authorization":"Bearer "+bearer,"Content-Type":"application/json"},
            method="POST")
        with urllib.request.urlopen(req,timeout=60) as response:
            return json.load(response)
    state=file.with_name(file.name+".mad4b-transfer.json")
    session=None
    if state.exists():
        previous=json.loads(state.read_text())
        if previous.get("sha256")==digest and previous.get("size")==length:
            try:
                remote=request("status",{"transfer_id":previous["transfer_id"]})
                if remote.get("sha256")==digest and remote.get("size")==length:
                    session={"transfer_id":previous["transfer_id"],"offset":remote["offset"]}
            except Exception:
                session=None
    if session is None:
        session=request("begin",{"size":length,"sha256":digest})
        state.write_text(json.dumps({"transfer_id":session["transfer_id"],"sha256":digest,"size":length}))
        os.chmod(state,0o600)
    ident=session["transfer_id"]
    with file.open("rb") as src:
        offset=session["offset"]
        src.seek(offset)
        while True:
            part=src.read(chunk_bytes)
            if not part:break
            response=request("chunk",{"transfer_id":ident,"offset":offset,"base64":base64.b64encode(part).decode()})
            offset=response["offset"]
    result=request("commit",{"transfer_id":ident})
    state.unlink(missing_ok=True)
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("file")
    p.add_argument("--url",required=True)
    args=p.parse_args()
    token=os.environ.get("MAD4B_OAUTH_ACCESS_TOKEN")
    if not token:raise SystemExit("MAD4B_OAUTH_ACCESS_TOKEN missing")
    result=upload(args.file,args.url,token)
    print(json.dumps(result))
