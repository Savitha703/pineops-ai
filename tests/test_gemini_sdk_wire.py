"""Check actual google-genai request generation using an offline HTTP transport."""

import json
import unittest
from unittest.mock import patch

import httpx

from gemini_service import DEFAULT_MODEL, request_guidance
from incident_analyzer import analyze_logs
from test_gemini_service import valid_guidance


class GeminiSdkWireTests(unittest.TestCase):
    def test_real_sdk_payload_and_structured_response_round_trip(self):
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={
                "candidates": [{"content": {"parts": [{"text": json.dumps(valid_guidance())}], "role": "model"},
                                "finishReason": "STOP"}],
                "usageMetadata": {"promptTokenCount": 80, "candidatesTokenCount": 90, "totalTokenCount": 170},
            })

        original_init = httpx.Client.__init__
        def mock_transport(client, *args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            original_init(client, *args, **kwargs)

        key = "fake-private-gemini-key"
        with patch.object(httpx.Client, "__init__", mock_transport):
            result = request_guidance(
                "ERROR payment-api request_id=abc123 timeout password=topsecret fake-private-gemini-key",
                analyze_logs("ERROR payment-api timeout"), key, DEFAULT_MODEL,
            )
        self.assertEqual(result, valid_guidance())
        self.assertEqual(len(requests), 1)
        request = requests[0]
        self.assertEqual(request.method, "POST")
        self.assertIn("generateContent", str(request.url))
        payload = json.loads(request.content)
        self.assertEqual(payload["generationConfig"]["responseMimeType"], "application/json")
        self.assertIn("responseJsonSchema", payload["generationConfig"])
        self.assertEqual(payload["generationConfig"]["maxOutputTokens"], 3072)
        self.assertNotIn("topsecret", json.dumps(payload))
        self.assertNotIn(key, json.dumps(payload))
        self.assertEqual(request.extensions["timeout"]["read"], 60.0)


if __name__ == "__main__":
    unittest.main()
