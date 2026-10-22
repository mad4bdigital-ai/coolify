"""Restricted SSH transport for the private Chromium extension relay."""
import asyncio
import json
import os
import re

DOMAIN = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
EXCLUDED_NON_WEBSITE_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com"}

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
        sites=data.get("sites",[])\n        if not isinstance(sites,list):raise ValueError("sites")\n        safe_sites=[{"domain":x["domain"],"evidence":"domain_element_in_card","card_text":str(x.get("card_text",""))[:500],"account":None,"plan":None,"site_status":None} for x in sites[:100] if isinstance(x,dict) and isinstance(x.get("domain"),str) and DOMAIN.fullmatch(x["domain"]) and x["domain"].lower() not in EXCLUDED_NON_WEBSITE_DOMAINS]\n        return {"ok":data.get("ok") is True,\n                "sites":safe_sites,
                "status":str(data.get("status",""))[:64],
                "source":"hpanel-visible-dom",
                "verified_inventory":False,
                "domains":[str(d) for d in domains[:100] if isinstance(d,str) and DOMAIN.fullmatch(d) and d.lower() not in EXCLUDED_NON_WEBSITE_DOMAINS]}
    except (OSError,ValueError,asyncio.TimeoutError):
        return {"ok":False,"status":"EXTENSION_BRIDGE_UNAVAILABLE",
                "verified_inventory":False,"domains":[]}
