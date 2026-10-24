import unittest
from unittest.mock import patch
import server

class RegistryTests(unittest.TestCase):
    def test_namespaced_discovery(self):
        def fake(url,req,token):
            return {"result":{"tools":[{"name":"upload_server_file","inputSchema":{"type":"object"}}]}}
        with patch.object(server,"call_provider",side_effect=fake):
            tools,routes=server.discover("Bearer session")
        self.assertEqual(tools[0]["name"],"upload__upload_server_file")
        self.assertEqual(routes["upload__upload_server_file"][1],"upload_server_file")
    def test_collision_blocks(self):
        with patch.dict(server.PROVIDERS,{"other":{"url":"http://second:8080/mcp","prefix":"upload__"}}):
            with patch.object(server,"call_provider",return_value={"result":{"tools":[{"name":"x"}]}}):
                with self.assertRaisesRegex(ValueError,"tool_collision"):
                    server.discover("Bearer session")
    def test_bad_provider_name_denied(self):
        with patch.object(server,"call_provider",return_value={"result":{"tools":[{"name":""}]}}):
            with self.assertRaisesRegex(ValueError,"invalid_tool_name"):
                server.discover("Bearer session")
if __name__=="__main__":unittest.main()
