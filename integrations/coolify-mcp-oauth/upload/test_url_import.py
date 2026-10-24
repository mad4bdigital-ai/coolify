"""Security regressions for temporary URL importer."""
import hashlib, tempfile, unittest
from pathlib import Path
from url_import import import_url

class UrlImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.hash=hashlib.sha256(b"x").hexdigest()
    def tearDown(self):self.tmp.cleanup()
    def test_http_rejected(self):
        with self.assertRaisesRegex(ValueError,"https_url_required"):
            import_url(self.root,"http://example.com/archive.zip",self.hash,1024,{"example.com"})
    def test_unlisted_host_rejected(self):
        with self.assertRaisesRegex(ValueError,"host_not_allowlisted"):
            import_url(self.root,"https://example.com/archive.zip",self.hash,1024,set())
    def test_localhost_rejected(self):
        with self.assertRaisesRegex(ValueError,"host_not_allowlisted"):
            import_url(self.root,"https://127.0.0.1/archive.zip",self.hash,1024,{"example.com"})
    def test_userinfo_rejected(self):
        with self.assertRaisesRegex(ValueError,"https_url_required"):
            import_url(self.root,"https://a:secret@example.com/a",self.hash,1024,{"example.com"})
if __name__=="__main__":unittest.main()
