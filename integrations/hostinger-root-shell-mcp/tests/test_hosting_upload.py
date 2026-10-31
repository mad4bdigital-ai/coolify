"""Offline multi-hosting upload tests; no remote network activity."""
import asyncio
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import hosting_upload
import registry

class HostingUploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.inventory = root/"inventory.json"
        self.spool = root/"spool"
        self.inventory.write_text(json.dumps({"targets":[
            {"id":"hosting-a","kind":"ssh","host":"example.net","port":65002,"username":"userone","enabled":True},
            {"id":"hosting-b","kind":"ssh","host":"example.org","port":65002,"username":"usertwo","enabled":True},
            {"id":"disabled","kind":"ssh","host":"example.edu","username":"userthree","enabled":False}
        ]}))
        for obj,attr,value in [(registry,"REGISTRY_FILE",self.inventory),(hosting_upload,"ROOT",self.spool)]:
            p=patch.object(obj,attr,value);p.start();self.addCleanup(p.stop)

    def test_target_selection(self):
        self.assertEqual(hosting_upload.target_for_upload("hosting-a")["host"],"example.net")
        for ident in ("absent","disabled","../hosting-a"):
            with self.subTest(ident=ident),self.assertRaises(ValueError):
                hosting_upload.target_for_upload(ident)

    def test_chunk_and_status_are_target_scoped(self):
        raw=b"hosting archive fixture"*16
        sha=hashlib.sha256(raw).hexdigest()
        started=hosting_upload.begin("hosting-a",len(raw),sha)
        ident=started["transfer_id"]
        for operation,args in (
            (hosting_upload.status,("hosting-b",ident)),
            (hosting_upload.chunk,("hosting-b",ident,0,base64.b64encode(raw).decode()))
        ):
            with self.assertRaisesRegex(ValueError,"target_mismatch"):
                operation(*args)
        chunk=base64.b64encode(raw).decode()
        self.assertEqual(hosting_upload.chunk("hosting-a",ident,0,chunk)["offset"],len(raw))
        self.assertEqual(hosting_upload.status("hosting-a",ident)["sha256"],sha)
        with self.assertRaisesRegex(ValueError,"offset_conflict"):
            hosting_upload.chunk("hosting-a",ident,0,chunk)

    def test_commit_requires_checksum_before_network(self):
        raw=b"corrupt"
        ident=hosting_upload.begin("hosting-a",len(raw),"a"*64)["transfer_id"]
        hosting_upload.chunk("hosting-a",ident,0,base64.b64encode(raw).decode())
        with patch.object(hosting_upload,"sftp_argv") as network:
            with self.assertRaisesRegex(ValueError,"checksum_mismatch"):
                asyncio.run(hosting_upload.commit("hosting-a",ident))
            network.assert_not_called()

    def test_remote_endpoint_and_path_never_client_selected(self):
        raw=b"good"
        ident=hosting_upload.begin("hosting-a",len(raw),hashlib.sha256(raw).hexdigest())["transfer_id"]
        hosting_upload.chunk("hosting-a",ident,0,base64.b64encode(raw).decode())
        with patch.object(hosting_upload,"sftp_argv",return_value=["sftp","host"]),patch.object(hosting_upload.asyncio,"create_subprocess_exec") as process:
            fake=process.return_value
            fake.returncode=0
            async def communicate(payload):self.assertIn(b"mad4b-quarantine/",payload);return b"",b""
            fake.communicate.side_effect=communicate
            result=asyncio.run(hosting_upload.commit("hosting-a",ident))
        self.assertEqual(result["state"],"stored_on_hosting_quarantine")
        self.assertIn("hosting-a",result["target_id"])
        self.assertEqual(result["bytes"],len(raw))
        self.assertFalse((self.spool/(ident+".part")).exists())

if __name__=="__main__":
    unittest.main()
