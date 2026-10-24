import unittest
import authz_service as service
class ReadinessTests(unittest.TestCase):
    def test_missing_configuration_is_not_ready(self):
        result=service.readiness()
        self.assertEqual(result["ready"],bool(service.INTROSPECT_URL and service.INTROSPECT_CLIENT_ID and service.INTROSPECT_CLIENT_SECRET and service.EXPECTED_ISSUER and service.EXPECTED_AUDIENCE and service.ALLOWED_SUBJECTS))
        self.assertEqual(len(result["missing"])==0,result["ready"])
    def test_random_bearer_denied(self):
        self.assertIsNone(service.authorize_token("Bearer not-a-verified-token"))
if __name__=="__main__":unittest.main()
