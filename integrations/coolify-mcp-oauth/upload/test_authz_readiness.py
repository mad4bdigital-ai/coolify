import unittest
import authz_service as service
from unittest.mock import patch
import hashlib
class ReadinessTests(unittest.TestCase):
    def test_missing_configuration_is_not_ready(self):
        result=service.readiness()
        self.assertEqual(result["ready"],bool(service.INTROSPECT_URL and service.INTROSPECT_CLIENT_ID and service.INTROSPECT_CLIENT_SECRET and service.EXPECTED_ISSUER and service.EXPECTED_AUDIENCE and service.ALLOWED_SUBJECTS))
        self.assertEqual(len(result["missing"])==0,result["ready"])
    def test_oauth_fingerprint_unlisted_is_denied_without_network(self):
        token="Bearer not-approved"
        with patch.object(service,"ALLOWED_TOKEN_DIGESTS",{"a"*64}),patch.object(service.urllib.request,"urlopen") as network:
            self.assertIsNone(service.authorize_oauth_fingerprint(token))
            network.assert_not_called()
    def test_approved_fingerprint_still_requires_live_oauth_verification(self):
        bearer="Bearer approved-example-token"
        digest=hashlib.sha256(bearer[7:].encode()).hexdigest()
        with patch.object(service,"ALLOWED_TOKEN_DIGESTS",{digest}),patch.object(service.urllib.request,"urlopen",side_effect=OSError("oauth unavailable")):
            self.assertIsNone(service.authorize_oauth_fingerprint(bearer))
    def test_fingerprint_readiness_defaults_to_denied(self):
        with patch.object(service,"AUTHORIZATION_BACKEND","oauth_fingerprint"),patch.object(service,"ALLOWED_TOKEN_DIGESTS",set()):
            self.assertEqual(service.readiness()["ready"],False)
    def test_registry_assertion_login_authorization(self):
        import authz_service as auth
        import json,base64,hmac,time
        subject="oauth-sub-123"
        secret="a"*64
        encoded=base64.urlsafe_b64encode(json.dumps({"sub":subject,"aud":"mad4b-upload-authz","permission":"files:upload","exp":int(time.time())+30},separators=(",",":"),sort_keys=True).encode()).rstrip(b"=").decode()
        token="Bearer mad4b."+encoded+"."+hmac.new(secret.encode(),encoded.encode(),hashlib.sha256).hexdigest()
        with patch.dict(auth.os.environ,{"UPLOAD_SIGNING_SECRET":secret}),patch.object(auth,"ALLOWED_SUBJECTS",set()):
            self.assertEqual(auth.authorize_registry_assertion(token),subject)
            self.assertIsNone(auth.authorize_registry_assertion(token[:-1]+"0"))
    def test_random_bearer_denied(self):
        self.assertIsNone(service.authorize_token("Bearer not-a-verified-token"))
if __name__=="__main__":unittest.main()
