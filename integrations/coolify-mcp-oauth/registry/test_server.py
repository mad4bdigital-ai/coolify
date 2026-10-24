import unittest
import urllib.error
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
    def test_provider_auth_failure_remains_distinct(self):
        from io import BytesIO
        req=server.Handler.__new__(server.Handler)
        payload=b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
        req.path="/mcp"
        req.headers={"Authorization":"Bearer sample-token","Content-Length":str(len(payload))}
        req.rfile=BytesIO(payload)
        seen=[]
        req.respond=lambda status,obj:seen.append((status,obj))
        with patch.object(server,"discover",side_effect=urllib.error.HTTPError("http://provider",403,"Forbidden",{},None)):
            req.do_POST()
        self.assertEqual(seen[0][0],403)
        self.assertEqual(seen[0][1]["error"],"provider_authorization_failed")
    def test_bad_provider_name_denied(self):
        with patch.object(server,"call_provider",return_value={"result":{"tools":[{"name":""}]}}):
            with self.assertRaisesRegex(ValueError,"invalid_tool_name"):
                server.discover("Bearer session")
if __name__=="__main__":unittest.main()
