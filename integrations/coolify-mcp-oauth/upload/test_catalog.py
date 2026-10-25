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
    def test_descriptions_cannot_claim_native_attachment_resolution(self):
        descriptors={d["name"]:d for d in catalog.list_tools()}
        attachment=descriptors["upload_attachment"]
        self.assertIn("Does NOT resolve ChatGPT attachment IDs",attachment["description"])
        self.assertIn("content_base64",attachment["inputSchema"]["required"])
        self.assertNotIn("file_uri",attachment["inputSchema"]["properties"])
        server=descriptors["upload_server_file"]
        self.assertIn("Requires prior successful upload",server["description"])
        self.assertIn("does NOT install",server["description"])
    def test_https_tool_guides_without_inventing_attachment_urls(self):
        descriptors={d["name"]:d for d in catalog.list_tools()}
        tool=descriptors["upload_from_url"]
        description=tool["description"]
        self.assertIn("obtain an actual downloadable HTTPS URL",description)
        self.assertIn("NEVER invent or reconstruct a URL",description)
        self.assertIn("server allowlist",description)
        self.assertIn("sandbox:/",description)
        self.assertIn("nor installed",description)
        self.assertEqual(tool["inputSchema"]["required"],["url","sha256"])
        self.assertIn("do not guess",tool["inputSchema"]["properties"]["sha256"]["description"])
    def test_attachment_requires_real_transport_exclusively(self):
        spec=next(x for x in catalog.list_tools() if x["name"]=="upload_attachment")
        schema=spec["inputSchema"]
        self.assertIn("oneOf",schema)
        self.assertEqual(len(schema["oneOf"]),2)
        self.assertIn("url",schema["properties"])
        self.assertIn("content_base64",schema["properties"])
        self.assertNotIn("file_id",schema["properties"])
        self.assertNotIn("file_uri",schema["properties"])
    def test_no_unavailable_reference_bridge_advertised(self):
        names={x["name"] for x in catalog.list_tools()}
        self.assertNotIn("upload_from_reference",names)
        self.assertIn("upload_from_url",names)
        self.assertIn("upload_file",names)
    def test_unknown_rejected(self):
        self.assertFalse(catalog.supported("../unsafe"))
if __name__=="__main__":unittest.main()
