"""Flask-to-Gemini integration regression tests; all provider requests mocked."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from test_gemini_service import valid_guidance


class GeminiRouteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.history = Path(temp.name) / "history.json"
        self.app = create_app({
            "TESTING": True,
            "AI_PROVIDER": "gemini",
            "GEMINI_API_KEY": "",
            "GEMINI_MODEL": "gemini-3.5-flash-lite",
            "INCIDENT_FILE": self.history,
        })
        self.client = self.app.test_client()

    def analyze(self, logs="ERROR service=payment-api request timeout"):
        return self.client.post("/api/analyze", json={"logs": logs})

    def test_gemini_is_active_and_health_never_discloses_key(self):
        health = self.client.get("/api/health").get_json()
        self.assertEqual(health["ai_provider"], "Google Gemini")
        self.assertEqual(health["model"], "gemini-3.5-flash-lite")
        self.assertFalse(health["api_key_configured"])
        self.app.config["GEMINI_API_KEY"] = "fake-private-gemini-key"
        health_text = self.client.get("/api/health").get_data(as_text=True)
        self.assertIn('"api_key_configured":true', health_text)
        self.assertNotIn("fake-private-gemini-key", health_text)

    def test_missing_key_is_honest_and_no_provider_called(self):
        with patch("gemini_service.request_guidance") as client:
            response = self.analyze()
        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertEqual(body["ai_provider"], "Google Gemini")
        self.assertEqual(body["analysis_mode"], "rule-based")
        self.assertIn("not configured", body["warnings"][0])
        client.assert_not_called()

    def test_real_gemini_route_calls_service_and_preserves_evidence(self):
        self.app.config["GEMINI_API_KEY"] = "fake-private-gemini-key"
        logs = "ERROR payment-api timeout password=sensitivepass token=privatetoken fake-private-gemini-key"
        with patch("gemini_service.request_guidance", return_value=valid_guidance()) as provider:
            response = self.analyze(logs)
        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertEqual(body["analysis_mode"], "AI-assisted")
        self.assertEqual(body["ai_provider"], "Google Gemini")
        self.assertEqual(body["ai_model"], "gemini-3.5-flash-lite")
        self.assertEqual(body["ai_guidance"], valid_guidance())
        self.assertEqual(body["total_error_lines"], 1)
        self.assertEqual(provider.call_count, 1)
        arguments = provider.call_args.args
        self.assertEqual(arguments[3], "gemini-3.5-flash-lite")
        for secret in ("sensitivepass", "privatetoken", "fake-private-gemini-key"):
            self.assertNotIn(secret, arguments[0])
            self.assertNotIn(secret, json.dumps(arguments[1]))
            self.assertNotIn(secret, self.history.read_text(encoding="utf-8"))
        self.assertEqual(self.client.get(f'/api/incidents/{body["id"]}').get_json(), body)

    def test_model_unavailable_returns_rule_based_not_made_up_ai(self):
        from google.genai.errors import ClientError
        self.app.config["GEMINI_API_KEY"] = "fake-private-gemini-key"
        private_response = "private-request-body-and-secret"
        error = ClientError(404, {"error": {"message": private_response, "status": "NOT_FOUND"}})
        with patch("gemini_service.request_guidance", side_effect=error):
            response = self.analyze()
        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertEqual(body["analysis_mode"], "rule-based")
        self.assertNotIn("ai_guidance", body)
        self.assertIn("HTTP 404", body["warnings"][0])
        self.assertNotIn(private_response, json.dumps(body))

    def test_rules_mode_never_calls_provider(self):
        self.app.config.update(AI_PROVIDER="rules", GEMINI_API_KEY="fake-private-gemini-key")
        with patch("gemini_service.request_guidance") as gemini:
            response = self.analyze()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["analysis_mode"], "rule-based")
        self.assertEqual(response.get_json()["ai_provider"], "Local rules")
        self.assertIn("Offline rules mode", response.get_json()["warnings"][0])
        gemini.assert_not_called()

    def test_invalid_provider_rejected_early(self):
        with self.assertRaisesRegex(ValueError, "AI_PROVIDER"):
            create_app({"AI_PROVIDER": "random"})


if __name__ == "__main__":
    unittest.main()
