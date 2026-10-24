"""Both attachment ingestion modes are explicit, non-magical and testable."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import attachment_transport_client as client

class Response:
    def __init__(self, obj): self.obj=obj
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def read(self, n=-1): return json.dumps(self.obj).encode()

class ClientTests(unittest.TestCase):
    def test_explicit_binary_attachment_success(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"sample.zip"
            path.write_bytes(b"legitimate attachment fixture")
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            calls=[]
            def fake(request, timeout):
                calls.append(request)
                return Response({"upload_token":"ephemeral-grant"} if len(calls)==1 else {"state":"quarantined","sha256":digest,"bytes":path.stat().st_size})
            with patch.object(client.urllib.request.OpenerDirector,"open",side_effect=fake):
                result=client.send("https://uploads.example.org","oauth-value","file",str(path),digest)
            self.assertEqual(result["sha256"],digest)
            self.assertTrue(calls[0].full_url.endswith("/v1/grants"))
            self.assertTrue(calls[1].full_url.endswith("/v1/uploads"))
            self.assertEqual(calls[1].data,path.read_bytes())
            self.assertIn("ephemeral-grant",calls[1].get_header("Authorization"))
    def test_file_digest_mismatch_never_contacts_server(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"sample.zip";path.write_bytes(b"sample")
            with patch.object(client.urllib.request.OpenerDirector,"open") as network:
                with self.assertRaisesRegex(ValueError,"checksum_mismatch"):
                    client.send("https://uploads.example.org","oauth","file",str(path),"a"*64)
                network.assert_not_called()
    def test_url_mode_uses_exact_authorized_endpoint(self):
        digest="a"*64
        calls=[]
        def fake(request,timeout):
            calls.append(request)
            return Response({"state":"quarantined","sha256":digest,"bytes":17})
        with patch.object(client.urllib.request.OpenerDirector,"open",side_effect=fake):
            result=client.send("https://uploads.example.org","oauth","url","https://approved.example.org/token-path",digest)
        self.assertEqual(result["state"],"quarantined")
        self.assertTrue(calls[0].full_url.endswith("/v1/import-url"))
        self.assertEqual(json.loads(calls[0].data)["sha256"],digest)
    def test_unapproved_transport_and_insecure_origin_fail(self):
        for origin in ("http://uploads.example.org","https://user:secret@uploads.example.org","https://uploads.example.org/path"):
            with self.assertRaises(ValueError):
                client.send(origin,"oauth","url","https://approved.example.org/sample","a"*64)
        with self.assertRaisesRegex(ValueError,"HTTPS source URL required"):
            client.send("https://uploads.example.org","oauth","url","http://internal.example/file","a"*64)
    def test_empty_bearer_denied(self):
        with self.assertRaisesRegex(ValueError,"bearer"):
            client.send("https://uploads.example.org","","url","https://approved.example.org/file","a"*64)

if __name__=="__main__":unittest.main()
