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
    def test_authenticated_tools_list_and_dispatch(self):
        from io import BytesIO
        payloads=[]
        def provider(url,request,token):
            self.assertEqual(token,"Bearer valid-identity")
            payloads.append(request)
            if request["method"]=="tools/list":
                return {"jsonrpc":"2.0","id":"registry","result":{"tools":[{"name":"upload_server_file","inputSchema":{"type":"object"}}]}}
            return {"jsonrpc":"2.0","id":request["id"],"result":{"content":[{"type":"text","text":"verified"}]}}
        def post(message):
            request=server.Handler.__new__(server.Handler)
            raw=__import__("json").dumps(message).encode()
            request.path="/mcp"
            request.headers={"Authorization":"Bearer valid-identity","Content-Length":str(len(raw))}
            request.rfile=BytesIO(raw)
            received=[]
            request.respond=lambda code,data: received.append((code,data))
            request.do_POST()
            return received[0]
        with patch.object(server,"call_provider",side_effect=provider):
            code,response=post({"jsonrpc":"2.0","id":1,"method":"tools/list"})
            self.assertEqual(code,200)
            self.assertEqual(response["result"]["tools"][0]["name"],"upload__upload_server_file")
            code,response=post({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"upload__upload_server_file","arguments":{"sha256":"a"*64,"filename":"test.zip"}}})
            self.assertEqual(code,200)
            self.assertEqual(response["result"]["content"][0]["text"],"verified")
            self.assertEqual(payloads[-1]["params"]["name"],"upload_server_file")
    def test_unknown_tool_does_not_reach_provider_call(self):
        from io import BytesIO
        request=server.Handler.__new__(server.Handler)
        raw=b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"untrusted","arguments":{}}}'
        request.path="/mcp"
        request.headers={"Authorization":"Bearer valid-identity","Content-Length":str(len(raw))}
        request.rfile=BytesIO(raw)
        received=[]
        request.respond=lambda code,data:received.append((code,data))
        with patch.object(server,"call_provider",return_value={"result":{"tools":[]}}) as upstream:
            request.do_POST()
        self.assertEqual(received[0][0],200)
        self.assertTrue(received[0][1]["result"]["isError"])
        self.assertEqual(upstream.call_count,1)
    def test_bad_provider_name_denied(self):
        with patch.object(server,"call_provider",return_value={"result":{"tools":[{"name":""}]}}):
            with self.assertRaisesRegex(ValueError,"invalid_tool_name"):
                server.discover("Bearer session")
if __name__=="__main__":unittest.main()
