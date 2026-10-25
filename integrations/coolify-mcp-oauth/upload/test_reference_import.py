import hashlib,json,tempfile,unittest
from pathlib import Path
from reference_import import import_reference

class RefTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.inbox=root/"inbox";self.inbox.mkdir()
        self.out=root/"out"
        self.ref="a"*32
        self.raw=b"authorized source bytes"
        self.sha=hashlib.sha256(self.raw).hexdigest()
        (self.inbox/(self.ref+".bin")).write_bytes(self.raw)
        (self.inbox/(self.ref+".json")).write_text(json.dumps({
            "principal":"owner1","sha256":self.sha,"status":"authorized"}))
    def call(self,owner="owner1",sha=None,ref=None):
        return import_reference(self.inbox,self.out,ref or self.ref,owner,sha or self.sha,1024)
    def test_verified_import(self):
        receipt=self.call()
        self.assertEqual(receipt["state"],"quarantined")
        self.assertEqual((self.out/(self.sha+".bin")).read_bytes(),self.raw)
    def test_wrong_owner_denied(self):
        with self.assertRaisesRegex(ValueError,"owner_mismatch"):
            self.call(owner="other")
    def test_wrong_sha_denied(self):
        with self.assertRaisesRegex(ValueError,"hash_mismatch"):
            self.call(sha="b"*64)
    def test_unsafe_reference_denied(self):
        with self.assertRaisesRegex(ValueError,"invalid_attachment_reference"):
            self.call(ref="../secret")
    def test_symlink_denied(self):
        p=self.inbox/(self.ref+".bin")
        actual=self.inbox/"actual";p.rename(actual);p.symlink_to(actual)
        with self.assertRaisesRegex(ValueError,"reference_not_found"):
            self.call()
    def test_not_authorized(self):
        p=self.inbox/(self.ref+".json")
        obj=json.loads(p.read_text());obj["status"]="pending";p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(ValueError,"not_authorized"):
            self.call()

if __name__=="__main__":unittest.main()
