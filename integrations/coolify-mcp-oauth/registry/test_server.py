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
        with patch.object(server,"authorize_identity",return_value="upload_oauth"),patch.object(server,"discover",side_effect=urllib.error.HTTPError("http://provider",403,"Forbidden",{},None)):
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
        with patch.object(server,"authorize_identity",return_value="upload_oauth"),patch.object(server,"call_provider",side_effect=provider):
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
        with patch.object(server,"authorize_identity",return_value="upload_oauth"),patch.object(server,"call_provider",return_value={"result":{"tools":[]}}) as upstream:
            request.do_POST()
        self.assertEqual(received[0][0],200)
        self.assertTrue(received[0][1]["result"]["isError"])
        self.assertEqual(upstream.call_count,1)
    def test_upload_auth_denial_preserves_coolify_catalog(self):
        providers={"upload":{"url":"http://upload:8080/mcp","prefix":"upload__"},"coolify":{"url":"http://coolify:8080/mcp","prefix":"","authorization":"Bearer trusted-core"}}
        def fake(url,req,token):
            if "upload" in url:
                raise urllib.error.HTTPError(url,403,"Forbidden",{},None)
            return {"result":{"tools":[{"name":"coolify_help","inputSchema":{"type":"object"}}]}}
        with patch.dict(server.PROVIDERS,providers,clear=True),patch.object(server,"call_provider",side_effect=fake):
            tools,routes=server.discover("Bearer user")
        self.assertEqual([t["name"] for t in tools],["coolify_help"])
        self.assertEqual(routes["coolify_help"][2],"Bearer trusted-core")
    def test_invalid_oauth_cannot_reach_privileged_provider(self):
        from io import BytesIO
        request=server.Handler.__new__(server.Handler)
        raw=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
        request.path="/mcp";request.headers={"Authorization":"Bearer forged-value","Content-Length":str(len(raw))}
        request.rfile=BytesIO(raw)
        received=[]
        request.respond=lambda code,data:received.append((code,data))
        with patch.object(server,"verify_client_token",return_value=False), patch.object(server,"call_provider") as upstream:
            request.do_POST()
        self.assertEqual(received[0][0],401)
        upstream.assert_not_called()
    def test_coolify_identity_lists_upload_but_does_not_grant_it(self):
        import io
        class CatalogResponse:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,n):return b'{"tools":[{"name":"upload_attachment","inputSchema":{"type":"object"}}]}'
        with patch.dict(server.PROVIDERS,{"coolify":{"url":"http://coolify:8080/mcp","prefix":""},"upload":{"url":"http://public-file-upload:8080/mcp-upload","prefix":"upload__"}},clear=True):
            with patch.object(server.urllib.request,"urlopen",return_value=CatalogResponse()) as discovery,patch.object(server,"call_provider",return_value={"result":{"tools":[{"name":"coolify_help"}]}}) as calls:
                tools,routes=server.discover("Bearer core","coolify")
        self.assertEqual({t["name"] for t in tools},{"coolify_help","upload__upload_attachment"})
        self.assertEqual(routes["upload__upload_attachment"][2],"Bearer core")
        self.assertEqual(calls.call_count,1)
        self.assertEqual(discovery.call_count,1)
    def test_unified_oauth_uses_proxy_without_core_server_credential(self):
        providers={"coolify":{"url":"http://coolify:8080/mcp","prefix":"","authorization":"Bearer privileged"},"upload":{"url":"http://upload:8080/mcp","prefix":"upload__"}}
        seen=[]
        def fake(url,req,token):
            seen.append((url,token))
            name="coolify_help" if "coolify-mcp-oauth" in url else "upload_file"
            return {"result":{"tools":[{"name":name}]}}
        with patch.dict(server.PROVIDERS,providers,clear=True),patch.object(server,"call_provider",side_effect=fake):
            tools,routes=server.discover("Bearer oauth","upload_oauth")
        self.assertEqual({t["name"] for t in tools},{"coolify_help","upload__upload_file"})
        self.assertTrue(all(token=="Bearer oauth" for _,token in seen))
        self.assertEqual(routes["coolify_help"][0],"http://coolify-mcp-oauth:8080/mcp")
        self.assertEqual(routes["upload__upload_file"][0],"http://upload:8080/mcp")
    def test_coolify_identity_uses_caller_token(self):
        with patch.object(server,"verify_client_token",return_value=False):
            with patch.dict(server.PROVIDERS,{"coolify":{"url":"http://coolify:8080/mcp","prefix":"","authorization":"Bearer privileged"}},clear=True):
                with patch.object(server,"call_provider",return_value={"result":{"tools":[]}}) as caller:
                    self.assertEqual(server.authorize_identity("Bearer personal"),"coolify")
                    self.assertEqual(caller.call_args.args[2],"Bearer personal")
    def test_large_non_upload_is_rejected(self):
        from io import BytesIO
        import json
        req=server.Handler.__new__(server.Handler)
        raw=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"coolify_help","arguments":{"unused":"a"*1048576}}}).encode()
        req.path="/mcp";req.headers={"Authorization":"Bearer valid","Content-Length":str(len(raw))};req.rfile=BytesIO(raw)
        seen=[];req.respond=lambda code,data:seen.append((code,data))
        with patch.object(server,"authorize_identity",return_value="coolify"),patch.object(server,"discover") as d:
            req.do_POST()
        self.assertEqual(seen[0][0],413)
        d.assert_not_called()
    def test_large_upload_reaches_discovery(self):
        from io import BytesIO
        import json
        req=server.Handler.__new__(server.Handler)
        raw=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"upload__upload_attachment","arguments":{"content_base64":"a"*1100000}}}).encode()
        req.path="/mcp";req.headers={"Authorization":"Bearer valid","Content-Length":str(len(raw))};req.rfile=BytesIO(raw)
        seen=[];req.respond=lambda code,data:seen.append((code,data))
        with patch.object(server,"authorize_identity",return_value="upload_oauth"),patch.object(server,"discover",return_value=([],{})):
            req.do_POST()
        self.assertEqual(seen[0][0],200)
    def test_bad_provider_name_denied(self):
        with patch.object(server,"call_provider",return_value={"result":{"tools":[{"name":""}]}}):
            with self.assertRaisesRegex(ValueError,"invalid_tool_name"):
                server.discover("Bearer session")
if __name__=="__main__":unittest.main()
