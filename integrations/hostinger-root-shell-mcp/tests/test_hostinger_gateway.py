import unittest
from unittest.mock import patch
import hostinger_gateway as gateway

TARGETS = [{"id": "hostinger-primary", "enabled": True},
           {"id": "hosting-1", "label": "Cloud Startup", "enabled": True},
           {"id": "hosting-2", "label": "allroyalegypt", "enabled": True},
           {"id": "hosting-3", "label": "egypttourgates.com", "enabled": True}]

class GatewayTests(unittest.TestCase):
    @patch.object(gateway, "load_registry", return_value={"targets": TARGETS})
    def test_account_inventory(self, unused):
        inventory = gateway.list_hostinger_accounts()
        self.assertEqual(inventory["count"], 3)
        self.assertFalse(inventory["credential_values_included"])
        self.assertTrue(all(x["mail_scope"] == "excluded" for x in inventory["accounts"]))

    @patch.object(gateway, "load_registry", return_value={"targets": TARGETS})
    def test_plan_never_executes(self, unused):
        plan = gateway.plan_import("hosting-2", "backups")
        self.assertEqual(plan["destination_target_id"], "hostinger-primary")
        self.assertFalse(plan["execution_performed"])
        self.assertTrue(plan["requires_explicit_execution_approval"])

    def test_unknown_account(self):
        with self.assertRaises(ValueError):
            gateway.plan_import("random-host", "websites")

    def test_mail_cannot_be_imported(self):
        with self.assertRaises(ValueError):
            gateway.plan_import("hosting-1", "mail")

if __name__ == "__main__":
    unittest.main()
