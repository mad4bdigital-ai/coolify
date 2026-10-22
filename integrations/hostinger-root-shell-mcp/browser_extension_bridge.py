"""Restricted SSH transport for the private Chromium extension relay."""
import asyncio
import json
import os
import re

DOMAIN = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
REMOTE = ("docker", "exec", "mad4b-secure-browser-mad4b-secure-browser-1",
          "python3", "/config/hpanel-reader-extension/bridge_request.py")

async def extension_inventory() -> dict:
    host=os.environ["SHELL_SSH_HOST"]
    port=os.environ.get("SHELL_SSH_PORT","22")
    args=["ssh","-T","-p",port,"-o","BatchMode=yes","-o","IdentitiesOnly=yes",
          "-o","StrictHostKeyChecking=yes",
          "-o","UserKnownHostsFile=/run/secrets/hostinger_known_hosts",
          "-o","ConnectTimeout=8",
          "-i","/run/secrets/ssh-keys/shell_access",
          "root@"+host," ".join(REMOTE)]
    try:
        proc=await asyncio.create_subprocess_exec(*args,stdout=asyncio.subprocess.PIPE,
                                                   stderr=asyncio.subprocess.DEVNULL)
        stdout,_=await asyncio.wait_for(proc.communicate(),timeout=68)
        if proc.returncode!=0 or len(stdout)>50000:raise ValueError("transport")
        data=json.loads(stdout)
        if not isinstance(data,dict):raise ValueError("shape")
        domains=data.get("domains",[])
        if not isinstance(domains,list):raise ValueError("domains")
        return {"ok":data.get("ok") is True,
                "status":str(data.get("status",""))[:64],
                "source":"hpanel-visible-dom",
                "verified_inventory":False,
                "domains":[str(d) for d in domains[:100] if isinstance(d,str) and DOMAIN.fullmatch(d)]}
    except (OSError,ValueError,asyncio.TimeoutError):
        return {"ok":False,"status":"EXTENSION_BRIDGE_UNAVAILABLE",
                "verified_inventory":False,"domains":[]}
