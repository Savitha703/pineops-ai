"""Offline checks of diagnostic telemetry; live results are recorded separately."""

import unittest
from unittest.mock import patch

import httpx
from google.genai.errors import ServerError

from check_gemini import run_single_probe


class DiagnosticTests(unittest.TestCase):
    def run_with_transport(self, handler, *, metadata, result):
        original_init = httpx.Client.__init__

        def init_with_offline_transport(client, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            original_init(client, *args, **kwargs)

        # Exercise the installed SDK's real request building, without network.
        with patch.object(httpx.Client, "__init__", init_with_offline_transport):
            run_single_probe("fake-private-key", "gemini-flash-latest", metadata=metadata, diagnostics=result)

    def test_controlled_request_preserves_explicit_server_deadline(self):
        result = {"timeout_ms_per_attempt": 120000, "server_deadline_seconds": 90}

        def unavailable(request):
            return httpx.Response(503, json={"error": {"message": "Unavailable", "status": "UNAVAILABLE"}})

        with self.assertRaises(ServerError):
            self.run_with_transport(unavailable, metadata=False, result=result)
        self.assertEqual(result["observed_requests"], [{
            "method": "POST", "server_timeout_seconds": "90", "read_timeout_seconds": 120.0,
        }])
        self.assertEqual(result["observed_http_statuses"], [503])
        self.assertNotIn("fake-private-key", str(result))
        self.assertNotIn("usable_text_received", result)

    def test_metadata_get_does_not_make_a_generation_request(self):
        result = {"timeout_ms_per_attempt": 20000, "server_deadline_seconds": 20}

        def metadata_response(request):
            self.assertEqual(request.method, "GET")
            return httpx.Response(200, json={
                "name": "models/gemini-flash-latest", "supportedGenerationMethods": ["generateContent"],
                "inputTokenLimit": 1000, "outputTokenLimit": 128,
            })

        self.run_with_transport(metadata_response, metadata=True, result=result)
        self.assertEqual(len(result["observed_requests"]), 1)
        self.assertEqual(result["http_status"], 200)
        self.assertTrue(result["model_metadata"]["supports_generate_content"])
        self.assertNotIn("usable_text_received", result)


if __name__ == "__main__":
    unittest.main()
