"""Regression tests for quarantined resumable transfer, no external services."""
import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from transfer import call

class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.data=b"JetWooBuilder archive fixture bytes"
        self.sha=hashlib.sha256(self.data).hexdigest()
    def tearDown(self):self.temp.cleanup()
    def begin(self):
        return call(self.root,"upload_begin",{"size":len(self.data),"sha256":self.sha},1024)
    def test_valid_transfer(self):
        grant=self.begin()
        assert call(self.root,"upload_status",{"transfer_id":grant["transfer_id"]},1024)["offset"]==0
        call(self.root,"upload_chunk",{"transfer_id":grant["transfer_id"],"offset":0,"base64":base64.b64encode(self.data).decode()},1024)
        result=call(self.root,"upload_commit",{"transfer_id":grant["transfer_id"]},1024)
        self.assertEqual(result["sha256"],self.sha)
        self.assertEqual((self.root/(self.sha+".bin")).read_bytes(),self.data)
    def test_upload_file_direct(self):
        data={"content_base64":base64.b64encode(self.data).decode(),"sha256":self.sha,"owner":"person-a"}
        result=call(self.root,"upload_file",data,1024)
        self.assertEqual(result["bytes"],len(self.data))
        self.assertEqual((self.root/(self.sha+".bin")).read_bytes(),self.data)
    def test_upload_file_checksum_rejected(self):
        with self.assertRaisesRegex(ValueError,"checksum_mismatch"):
            call(self.root,"upload_file",{"content_base64":base64.b64encode(b"bad").decode(),"sha256":self.sha},1024)
    def test_owner_isolation(self):
        grant=call(self.root,"upload_begin",{"size":len(self.data),"sha256":self.sha,"owner":"person-a"},1024)
        with self.assertRaisesRegex(ValueError,"transfer_owner_mismatch"):
            call(self.root,"upload_status",{"transfer_id":grant["transfer_id"],"owner":"person-b"},1024)
        with self.assertRaisesRegex(ValueError,"transfer_owner_mismatch"):
            call(self.root,"upload_chunk",{"transfer_id":grant["transfer_id"],"offset":0,"base64":"YQ==","owner":"person-b"},1024)
    def test_wrong_offset_rejected(self):
        grant=self.begin()
        with self.assertRaisesRegex(ValueError,"offset_conflict"):
            call(self.root,"upload_chunk",{"transfer_id":grant["transfer_id"],"offset":1,"base64":"YQ=="},1024)
    def test_unfinished_transfer_rejected(self):
        grant=self.begin()
        with self.assertRaisesRegex(ValueError,"incomplete_transfer"):
            call(self.root,"upload_commit",{"transfer_id":grant["transfer_id"]},1024)
    def test_wrong_sha_rejected(self):
        grant=self.begin()
        call(self.root,"upload_chunk",{"transfer_id":grant["transfer_id"],"offset":0,"base64":base64.b64encode(b"x"*len(self.data)).decode()},1024)
        with self.assertRaisesRegex(ValueError,"checksum_mismatch"):
            call(self.root,"upload_commit",{"transfer_id":grant["transfer_id"]},1024)
    def test_invalid_identifier_rejected(self):
        with self.assertRaisesRegex(ValueError,"invalid_transfer_id"):
            call(self.root,"upload_status",{"transfer_id":"../../etc/passwd"},1024)
if __name__=="__main__":unittest.main()
