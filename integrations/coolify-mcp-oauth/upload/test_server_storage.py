import hashlib,tempfile,unittest
from pathlib import Path
from server_storage import promote
class ServerStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.src=self.root/"source";self.dst=self.root/"destination";self.src.mkdir();self.dst.mkdir();self.blob=b"verified zip bytes";self.sha=hashlib.sha256(self.blob).hexdigest();(self.src/(self.sha+".bin")).write_bytes(self.blob)
    def tearDown(self):self.tmp.cleanup()
    def test_verified_file_promoted(self):
        out=promote(self.src,self.dst,self.sha,"jet-woo-builder-2.3.5.zip",1024)
        self.assertEqual(out["state"],"stored_on_vps");self.assertEqual((self.dst/"jet-woo-builder-2.3.5.zip").read_bytes(),self.blob)
    def test_retry_returns_verified_receipt(self):
        first=promote(self.src,self.dst,self.sha,"package.zip",1024)
        second=promote(self.src,self.dst,self.sha,"package.zip",1024)
        self.assertTrue(first["verified"])
        self.assertFalse(first["already_present"])
        self.assertTrue(second["already_present"])
        self.assertEqual(second["sha256"],self.sha)
    def test_conflicting_destination_not_replaced(self):
        destination=self.dst/"package.zip"
        destination.write_bytes(b"different artifact")
        with self.assertRaisesRegex(ValueError,"destination_conflict"):
            promote(self.src,self.dst,self.sha,"package.zip",1024)
        self.assertEqual(destination.read_bytes(),b"different artifact")
    def test_recovery_receipt_after_source_removed(self):
        promote(self.src,self.dst,self.sha,"package.zip",1024)
        (self.src/(self.sha+".bin")).unlink()
        self.assertTrue(promote(self.src,self.dst,self.sha,"package.zip",1024)["already_present"])
    def test_traversal_rejected(self):
        with self.assertRaisesRegex(ValueError,"invalid_filename"):
            promote(self.src,self.dst,self.sha,"../config.php",1024)
    def test_wrong_checksum_rejected(self):
        (self.src/(self.sha+".bin")).write_bytes(b"altered")
        with self.assertRaisesRegex(ValueError,"checksum_mismatch"):
            promote(self.src,self.dst,self.sha,"package.zip",1024)
    def test_missing_file_rejected(self):
        with self.assertRaisesRegex(ValueError,"artifact_not_found"):
            promote(self.src,self.dst,"0"*64,"package.zip",1024)
if __name__=="__main__":unittest.main()
