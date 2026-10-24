"""OAuth-scoped resumable uploads, callable over HTTP and MCP. Quarantine only."""
import base64, binascii, hashlib, json, os, re, secrets, time
from pathlib import Path

ID=re.compile(r"^[a-f0-9]{32}$")
HEX=re.compile(r"^[a-f0-9]{64}$")
CHUNK_MAX=512*1024
def paths(root,ident):
    if not isinstance(ident,str) or not ID.fullmatch(ident):raise ValueError("invalid_transfer_id")
    return root/"transfers"/(ident+".json"),root/"transfers"/(ident+".part")
def begin(root,payload,max_bytes):
    size=payload.get("size")
    digest=payload.get("sha256")
    if type(size)!=int or not 1<=size<=max_bytes:raise ValueError("invalid_size")
    if not isinstance(digest,str) or not HEX.fullmatch(digest):raise ValueError("invalid_sha256")
    ident=secrets.token_hex(16)
    meta,part=paths(root,ident);meta.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    with open(part,"xb") as f:os.fchmod(f.fileno(),0o600)
    with open(meta,"x") as f:
        os.fchmod(f.fileno(),0o600)
        json.dump({"size":size,"sha256":digest,"offset":0,"created":int(time.time())},f)
    return {"transfer_id":ident,"offset":0,"max_chunk_bytes":CHUNK_MAX}
def inspect(root,ident):
    meta,part=paths(root,ident)
    if not meta.exists() or not part.exists():raise ValueError("unknown_transfer")
    data=json.loads(meta.read_text())
    if time.time()-data["created"]>86400:raise ValueError("transfer_expired")
    real=part.stat().st_size
    if real!=data["offset"]:raise ValueError("transfer_state_conflict")
    return data,meta,part
def append(root,payload):
    ident=payload.get("transfer_id");data,meta,part=inspect(root,ident)
    offset=payload.get("offset")
    if type(offset)!=int or offset!=data["offset"]:raise ValueError("offset_conflict")
    encoded=payload.get("base64")
    if not isinstance(encoded,str) or len(encoded)>700000:raise ValueError("chunk_too_large")
    try:chunk=base64.b64decode(encoded,validate=True)
    except (binascii.Error,ValueError):raise ValueError("invalid_base64")
    if not chunk or len(chunk)>CHUNK_MAX or offset+len(chunk)>data["size"]:raise ValueError("invalid_chunk_size")
    # Exclusive append position. A conflicting concurrent writer must fail closed.
    with open(part,"r+b",buffering=0) as f:
        if f.seek(0,os.SEEK_END)!=offset:raise ValueError("offset_conflict")
        f.write(chunk);os.fsync(f.fileno())
    data["offset"]+=len(chunk)
    tmp=meta.with_suffix(".tmp")
    tmp.write_text(json.dumps(data));os.chmod(tmp,0o600);os.replace(tmp,meta)
    return {"transfer_id":ident,"offset":data["offset"],"size":data["size"]}
def status(root,payload):
    data,_,_=inspect(root,payload.get("transfer_id"))
    return {"offset":data["offset"],"size":data["size"],"sha256":data["sha256"]}
def finish(root,payload):
    ident=payload.get("transfer_id");data,meta,part=inspect(root,ident)
    if data["offset"]!=data["size"]:raise ValueError("incomplete_transfer")
    h=hashlib.sha256()
    with open(part,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    if h.hexdigest()!=data["sha256"]:raise ValueError("checksum_mismatch")
    target=root/(h.hexdigest()+".bin")
    os.replace(part,target);meta.unlink()
    return {"state":"quarantined","sha256":h.hexdigest(),"bytes":data["size"]}
OPS={"upload_begin":begin,"upload_chunk":append,"upload_status":status,"upload_commit":finish}
def call(root,method,params,max_bytes):
    if method not in OPS:raise ValueError("unknown_tool")
    if not isinstance(params,dict):raise ValueError("invalid_parameters")
    if method=="upload_begin":return begin(root,params,max_bytes)
    return OPS[method](root,params)
