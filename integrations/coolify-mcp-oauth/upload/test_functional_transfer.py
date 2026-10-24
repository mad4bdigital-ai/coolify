import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
import transfer
import catalog
import server_storage

class FunctionalTransferTests(unittest.TestCase):
    def test_mcp_upload_and_vps_promotion(self):
        data=b"functional ZIP-equivalent test bytes"
        digest=hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            quarantine=root/"quarantine"
            destination=root/"vps";destination.mkdir()
            received=transfer.call(quarantine,"upload_file",{"content_base64":base64.b64encode(data).decode(),"sha256":digest,"owner":"test-user"},1024)
            self.assertEqual(received["sha256"],digest)
            result=server_storage.promote(quarantine,destination,digest,"sample.zip",1024)
            self.assertEqual(result["state"],"stored_on_vps")
            self.assertEqual(result["bytes"],len(data))
            self.assertEqual(hashlib.sha256((destination/"sample.zip").read_bytes()).hexdigest(),digest)
    def test_attachment_tool_is_in_catalog(self):
        tools={tool["name"]:tool for tool in catalog.list_tools()}
        self.assertIn("upload_attachment",tools)
        self.assertEqual(set(tools["upload_attachment"]["inputSchema"]["required"]),{"content_base64","sha256","filename"})
        self.assertTrue(catalog.supported("upload_attachment"))
    def test_tampered_bytes_are_not_saved(self):
        with tempfile.TemporaryDirectory() as temp:
            quarantine=Path(temp)/"quarantine"
            with self.assertRaisesRegex(ValueError,"checksum_mismatch"):
                transfer.call(quarantine,"upload_file",{"content_base64":base64.b64encode(b"wrong").decode(),"sha256":"a"*64,"owner":"test-user"},1024)
            self.assertFalse((quarantine/("a"*64+".bin")).exists())
if __name__=="__main__":unittest.main()
