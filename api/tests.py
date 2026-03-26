import json

from django.test import TestCase, override_settings
from django.urls import reverse


@override_settings(AML_AUTO_SYNC_DATASET=False, OPENAI_API_KEY="")
class TransactionApiTests(TestCase):
    def test_home_works(self):
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 200)

    def test_create_transaction(self):
        payload = {"account_id": "ACC-001", "amount": "550.25"}
        response = self.client.post(
            reverse("transactions"),
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["account_id"], "ACC-001")

    def test_high_value_transaction_is_flagged(self):
        payload = {"account_id": "ACC-002", "amount": "20000"}
        response = self.client.post(
            reverse("transactions"),
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()["is_suspicious"])
