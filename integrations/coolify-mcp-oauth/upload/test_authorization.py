"""Authorization is independent from successful OAuth authentication."""
import io
import json
import unittest
from unittest.mock import patch
import authorization

class Response:
    status=200
    headers={"Content-Type":"application/json"}
    def __init__(self,obj):self.stream=io.BytesIO(json.dumps(obj).encode())
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def read(self,n):return self.stream.read(n)

ENDPOINT="http://upload-authz:8080/v1/authorize"
class AuthorizationTests(unittest.TestCase):
    def test_unconfigured_denied(self):
        self.assertIsNone(authorization.authorize("Bearer good-token", ""))
    def test_untrusted_url_denied(self):
        self.assertIsNone(authorization.authorize("Bearer good-token","https://evil.example/"))
    def test_no_bearer_denied(self):
        self.assertIsNone(authorization.authorize("",ENDPOINT))
    def test_logged_in_but_without_upload_permission_denied(self):
        with patch.object(authorization.urllib.request,"urlopen",return_value=Response({"allowed":True,"sub":"user123","permission":"mcp:read"})):
            self.assertIsNone(authorization.authorize("Bearer token",ENDPOINT))
    def test_explicit_deny(self):
        with patch.object(authorization.urllib.request,"urlopen",return_value=Response({"allowed":False,"sub":"user123","permission":"files:upload"})):
            self.assertIsNone(authorization.authorize("Bearer token",ENDPOINT))
    def test_verified_upload_permission(self):
        with patch.object(authorization.urllib.request,"urlopen",return_value=Response({"allowed":True,"sub":"user123","permission":"files:upload"})):
            self.assertEqual(authorization.authorize("Bearer token",ENDPOINT),"user123")
    def test_oauth_login_only_mode_always_denied(self):
        with patch.dict(authorization.os.environ, {"UPLOAD_AUTHORIZATION_MODE":"oauth_login"}):
            with patch.object(authorization,"authorize") as permission_check:
                self.assertIsNone(authorization.authorize_upload("Bearer example-token"))
                permission_check.assert_not_called()
    def test_unknown_auth_mode_denied(self):
        with patch.dict(authorization.os.environ, {"UPLOAD_AUTHORIZATION_MODE":"unknown"}):
            self.assertIsNone(authorization.authorize_upload("Bearer example-token"))
    def test_missing_subject_denied(self):
        with patch.object(authorization.urllib.request,"urlopen",return_value=Response({"allowed":True,"permission":"files:upload"})):
            self.assertIsNone(authorization.authorize("Bearer token",ENDPOINT))
if __name__=="__main__":unittest.main()
