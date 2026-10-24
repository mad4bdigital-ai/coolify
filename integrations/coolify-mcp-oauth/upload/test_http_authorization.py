"""HTTP acceptance: read-only OAuth tokens cannot issue upload grants."""
import http.client, json, threading, unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from server import Handler

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.srv=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        self.thread=threading.Thread(target=self.srv.serve_forever,daemon=True)
        self.thread.start()
    def tearDown(self):
        self.srv.shutdown();self.srv.server_close();self.thread.join(timeout=2)
    def post(self):
        c=http.client.HTTPConnection("127.0.0.1",self.srv.server_port,timeout=3)
        payload=json.dumps({"expires_in_seconds":3600}).encode()
        c.request("POST","/v1/grants",payload,{"Authorization":"Bearer legitimate-but-readonly","Content-Type":"application/json"})
        r=c.getresponse();v=(r.status,json.loads(r.read()));c.close();return v
    def test_readonly_account_denied(self):
        with patch("server.authorization.authorize",return_value=None):
            status,data=self.post()
        self.assertEqual(status,403)
        self.assertEqual(data["error"],"upload_permission_required")
    def test_explicit_upload_permission_allows_grant(self):
        with patch("server.authorization.authorize",return_value="approved-user"):
            status,data=self.post()
        self.assertEqual(status,201)
        self.assertIn("upload_token",data)
if __name__=="__main__":unittest.main()
