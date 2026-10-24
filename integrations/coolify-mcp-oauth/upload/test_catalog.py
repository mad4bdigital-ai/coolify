import unittest
from unittest.mock import patch
import catalog
class CatalogTests(unittest.TestCase):
    def test_current_tools_discoverable(self):
        names={x["name"] for x in catalog.list_tools()}
        self.assertTrue({"upload_file","upload_begin","upload_chunk","upload_status","upload_commit","upload_server_file","upload_from_url"}<=names)
    def test_future_registered_transfer_discovered(self):
        with patch.dict(catalog.transfer.OPS,{"upload_future_test":lambda *a:None}):
            self.assertTrue(catalog.supported("upload_future_test"))
            self.assertIn("upload_future_test",{x["name"] for x in catalog.list_tools()})
    def test_unknown_rejected(self):
        self.assertFalse(catalog.supported("../unsafe"))
if __name__=="__main__":unittest.main()
