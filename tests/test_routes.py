import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from test_gemini_service import valid_guidance


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "incidents.json"
        self.config = {"TESTING": True, "INCIDENT_FILE": self.path, "AI_PROVIDER": "gemini", "GEMINI_API_KEY": "", "MAX_LOG_BYTES": 1024}
        self.app = create_app(self.config)
        self.client = self.app.test_client()

    def analyze(self, logs="ERROR service=demo timeout"):
        return self.client.post("/api/analyze", json={"logs": logs})

    def test_application_assets_and_health(self):
        for url in ["/", "/static/css/style.css", "/static/js/app.js"]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            response.close()
        health = self.client.get("/api/health").get_json()
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["ai_provider"], "Google Gemini")
        self.assertFalse(health["api_key_configured"])
        self.assertEqual(health["max_log_bytes"], 1024)

    def test_samples_labelled_and_missing_sample_404(self):
        for name in ["payment", "database"]:
            result = self.client.get(f"/api/samples/{name}")
            self.assertEqual(result.status_code, 200)
            self.assertTrue(result.get_json()["sample"])
            self.assertIn("SAMPLE DATA", result.get_json()["logs"])
        self.assertEqual(self.client.get("/api/samples/other").status_code, 404)

    def test_analyze_retrieve_list_delete(self):
        response = self.analyze()
        self.assertEqual(response.status_code, 201)
        report = response.get_json()
        self.assertEqual(report["analysis_mode"], "rule-based")
        self.assertTrue(report["warnings"])
        url = f'/api/incidents/{report["id"]}'
        self.assertEqual(self.client.get(url).get_json(), report)
        self.assertEqual(self.client.get("/api/incidents").get_json()["incidents"], [report])
        self.assertEqual(self.client.delete(url).status_code, 200)
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.delete(url).status_code, 404)

    def test_persistence_between_apps(self):
        report = self.analyze().get_json()
        new_client = create_app(self.config).test_client()
        self.assertEqual(new_client.get(f'/api/incidents/{report["id"]}').get_json(), report)

    def test_valid_upload_utf8_bom_and_case_insensitive_extension(self):
        response = self.client.post("/api/analyze", data={"file": (io.BytesIO(b"\xef\xbb\xbfERROR timeout"), "test.LOG")})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["total_error_lines"], 1)

    def test_invalid_uploads(self):
        cases = [(b"ERROR fail", "test.exe"), (b"ERROR fail", "test.log.exe"), (b"", "empty.txt"), (b"\x00\x01binary", "binary.log"), (b"\xff\xfe", "utf16.txt")]
        for content, name in cases:
            with self.subTest(name=name):
                response = self.client.post("/api/analyze", data={"file": (io.BytesIO(content), name)})
                self.assertEqual(response.status_code, 400)
                self.assertIn("error", response.get_json())

    def test_invalid_json_and_missing_logs(self):
        for value in ({}, {"logs": 123}, {"logs": ""}, {"logs": " \n "}, [], {"logs": "ERROR", "is_sample": "false"}):
            with self.subTest(value=value):
                self.assertEqual(self.client.post("/api/analyze", json=value).status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", data="{oops", content_type="application/json").status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", data="ERROR", content_type="text/plain").status_code, 415)

    def test_missing_multiple_or_ambiguous_file(self):
        self.assertEqual(self.client.post("/api/analyze", data={}, content_type="multipart/form-data").status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", data={"file": [(io.BytesIO(b"ERROR"), "a.log"), (io.BytesIO(b"ERROR"), "b.log")]}).status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", data={"logs": "ERROR", "file": (io.BytesIO(b"ERROR"), "a.log")}).status_code, 400)

    def test_size_limits_for_text_file_and_entire_body(self):
        self.assertEqual(self.analyze("E" * 1025).status_code, 413)
        self.assertEqual(self.client.post("/api/analyze", data={"file": (io.BytesIO(b"E" * 1025), "big.log")}).status_code, 413)
        self.assertEqual(self.analyze("E" * 70000).status_code, 413)

    def test_missing_file_and_unknown_id(self):
        self.assertEqual(self.client.get("/api/incidents").get_json(), {"incidents": []})
        self.assertEqual(self.client.get("/api/incidents/unknown").status_code, 404)

    def test_corrupt_history_returns_503_and_is_preserved(self):
        content = "{broken history"
        self.path.write_text(content, encoding="utf-8")
        with patch("app.add_gemini_guidance") as provider:
            for method, url in [("get", "/api/incidents"), ("get", "/api/incidents/unknown"), ("delete", "/api/incidents/unknown")]:
                self.assertEqual(getattr(self.client, method)(url).status_code, 503)
            self.assertEqual(self.analyze().status_code, 503)
        provider.assert_not_called()
        self.assertEqual(self.path.read_text(encoding="utf-8"), content)

    def test_api_failure_and_invalid_response_fallback(self):
        self.app.config["GEMINI_API_KEY"] = "fake-key"
        for error in (RuntimeError("private detail"), ValueError("bad AI shape")):
            with self.subTest(error=error), patch("gemini_service.request_guidance", side_effect=error):
                response = self.analyze()
                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.get_json()["analysis_mode"], "rule-based")
                self.assertTrue(response.get_json()["warnings"])

    def test_secret_redaction_before_provider_and_storage(self):
        self.app.config["GEMINI_API_KEY"] = "configured-private-key"
        with patch("gemini_service.request_guidance", return_value=valid_guidance()) as provider:
            response = self.analyze("ERROR timeout password=supersecret token=tokenvalue configured-private-key")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["analysis_mode"], "AI-assisted")
        sent_logs = provider.call_args.args[0]
        sent_report = json.dumps(provider.call_args.args[1])
        for value in ["supersecret", "tokenvalue", "configured-private-key"]:
            self.assertNotIn(value, sent_logs)
            self.assertNotIn(value, sent_report)
            self.assertNotIn(value, self.path.read_text(encoding="utf-8"))
            self.assertNotIn(value, self.client.get("/api/health").get_data(as_text=True))
        self.assertNotIn("logs", response.get_json())

    def test_sample_label_retained(self):
        self.assertTrue(self.analyze("# SAMPLE DATA\nERROR timeout").get_json()["is_sample"])

    def test_cross_origin_writes_rejected(self):
        self.assertEqual(self.client.post("/api/analyze", json={"logs": "ERROR"}, headers={"Origin": "https://other.example"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
