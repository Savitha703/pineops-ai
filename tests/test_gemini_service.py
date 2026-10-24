import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from gemini_service import (
    ANALYSIS_TIMEOUT_MS, MINIMAL_TIMEOUT_MS, add_ai_guidance, describe_gemini_error,
    generate_with_retry, gemini_http_options, request_guidance,
    request_minimal_generation, validate_guidance,
)
from incident_analyzer import analyze_logs


def valid_guidance():
    return dict(summary="The logs show a timeout signal requiring investigation.",
                hypotheses=["An upstream dependency may be responding slowly."],
                diagnostic_checks=["Compare request latency with dependency health metrics."],
                limitations="The root cause and customer impact remain unknown from this limited log snippet.")


class GeminiTests(unittest.TestCase):
    def test_missing_key_does_not_call_provider(self):
        with patch("gemini_service.request_guidance") as provider:
            result = add_ai_guidance(analyze_logs("ERROR timeout"), "ERROR timeout", "", "test-model")
        provider.assert_not_called()
        self.assertEqual(result["analysis_mode"], "rule-based")
        self.assertIn("not configured", result["warnings"][0])

    def test_failure_is_honest_and_does_not_leak_exception(self):
        with patch("gemini_service.request_guidance", side_effect=RuntimeError("private-token")):
            result = add_ai_guidance(analyze_logs("ERROR timeout"), "ERROR timeout", "fake-key", "test-model")
        self.assertEqual(result["analysis_mode"], "rule-based")
        self.assertIn("fallback", result["warnings"][0])
        self.assertNotIn("private-token", str(result))

    def test_invalid_response_falls_back(self):
        with patch("gemini_service.request_guidance", side_effect=ValueError("bad JSON")):
            result = add_ai_guidance(analyze_logs("ERROR timeout"), "ERROR timeout", "fake-key", "test-model")
        self.assertEqual(result["analysis_mode"], "rule-based")
        self.assertNotIn("ai_guidance", result)
        self.assertIn("discarded", result["warnings"][0])

    def test_supported_sdk_passes_actual_logs_model_and_schema(self):
        response = SimpleNamespace(text=json.dumps(valid_guidance()))
        with patch("google.genai.Client") as client_class:
            client = MagicMock()
            client_class.return_value.__enter__.return_value = client
            client.models.generate_content.return_value = response
            result = request_guidance("ERROR timeout request_id=actual-request", analyze_logs("ERROR timeout"), "fake-key", "configured-model")
        call = client.models.generate_content.call_args.kwargs
        self.assertEqual(call["model"], "configured-model")
        self.assertIn("actual-request", call["contents"])
        self.assertEqual(call["config"].response_mime_type, "application/json")
        self.assertTrue(call["config"].response_json_schema)
        self.assertEqual(result, valid_guidance())

    def test_ai_assistance_preserves_parser_facts(self):
        initial = analyze_logs("ERROR timeout")
        expected = initial["total_error_lines"]
        with patch("gemini_service.request_guidance", return_value=valid_guidance()):
            report = add_ai_guidance(initial, "ERROR timeout", "fake-key", "test-model")
        self.assertEqual(report["analysis_mode"], "AI-assisted")
        self.assertEqual(report["total_error_lines"], expected)
        self.assertIn("Unknown", report["root_cause"])

    def test_malformed_shapes_rejected(self):
        for value in (None, [], {}, dict(valid_guidance(), extra="x"), dict(valid_guidance(), summary=123), dict(valid_guidance(), diagnostic_checks=[]), dict(valid_guidance(), hypotheses=[123])):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_guidance(value)

    def test_unsafe_diagnostics_and_certainty_rejected(self):
        cases = [dict(valid_guidance(), diagnostic_checks=["Restart the database service now."]), dict(valid_guidance(), diagnostic_checks=["Check logs; sudo rm /data"]), dict(valid_guidance(), hypotheses=["The database is definitely broken."]), dict(valid_guidance(), summary="The confirmed root cause is the database."), dict(valid_guidance(), limitations="Everything is working as expected.")]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_guidance(value)

    def test_sdk_malformed_json_is_rejected(self):
        with patch("google.genai.Client") as client_class:
            client_class.return_value.__enter__.return_value.models.generate_content.return_value = SimpleNamespace(text="this is not JSON")
            with self.assertRaises(ValueError):
                request_guidance("ERROR timeout", {}, "fake-key", "configured-model")

    def test_provider_failures_are_distinguished(self):
        from google.genai.errors import ClientError, ServerError

        cases = [
            (400, "API key not valid. Please pass a valid API key.", "INVALID_ARGUMENT", "invalid_credentials"),
            (400, "GenerateContentRequest.model: unexpected model name format", "INVALID_ARGUMENT", "invalid_model"),
            (403, "Permission denied for this project.", "PERMISSION_DENIED", "permission_denied"),
            (404, "Requested model was not found.", "NOT_FOUND", "unsupported_model"),
            (429, "Quota exceeded for this project.", "RESOURCE_EXHAUSTED", "quota_exceeded"),
            (503, "The model is temporarily unavailable.", "UNAVAILABLE", "provider_error"),
        ]
        for code, message, status, category in cases:
            with self.subTest(code=code, category=category):
                error_class = ServerError if code >= 500 else ClientError
                error = error_class(code, {"error": {"message": message, "status": status}})
                result = describe_gemini_error(error)
                self.assertEqual(result["category"], category)
                self.assertEqual(result["http_status"], code)
                self.assertEqual(result["provider_status"], status)

    def test_network_failure_has_no_fabricated_http_status(self):
        import httpx

        result = describe_gemini_error(httpx.ConnectError("private proxy details"))
        self.assertEqual(result["category"], "network_failure")
        self.assertIsNone(result["http_status"])
        self.assertNotIn("private proxy details", result["message"])

    def test_diagnostic_message_redacts_key_and_omits_response_details(self):
        from google.genai.errors import ClientError

        error = ClientError(400, {"error": {"message": "Rejected configured-private-key at https://example.test/?key=configured-private-key", "status": "INVALID_ARGUMENT", "details": {"secret": "do-not-return"}}})
        result = describe_gemini_error(error, "configured-private-key")
        self.assertNotIn("configured-private-key", str(result))
        self.assertNotIn("do-not-return", str(result))
        self.assertNotIn("https://", result["message"])

    def test_api_failure_warning_includes_safe_category_and_real_code(self):
        from google.genai.errors import ClientError

        error = ClientError(429, {"error": {"message": "private request details", "status": "RESOURCE_EXHAUSTED"}})
        with patch("gemini_service.request_guidance", side_effect=error):
            result = add_ai_guidance(analyze_logs("ERROR timeout"), "ERROR timeout", "fake-key", "test-model")
        self.assertEqual(result["analysis_mode"], "rule-based")
        self.assertIn("HTTP 429", result["warnings"][0])
        self.assertIn("quota", result["warnings"][0])
        self.assertNotIn("private request details", str(result))

    def test_transient_failures_retry_with_exponential_backoff(self):
        from google.genai.errors import ServerError

        client = MagicMock()
        expected_response = SimpleNamespace(text="OK")
        client.models.generate_content.side_effect = [
            ServerError(504, {"error": {"message": "Deadline expired", "status": "DEADLINE_EXCEEDED"}}),
            expected_response,
        ]
        diagnostics = {}
        with patch("gemini_service.time.sleep") as sleep:
            response = generate_with_retry(client, model="test-model", contents="tiny prompt", config={}, diagnostics=diagnostics)
        self.assertIs(response, expected_response)
        self.assertEqual(client.models.generate_content.call_count, 2)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1])
        self.assertEqual([item.get("http_status") for item in diagnostics["attempt_results"]], [504, None])

    def test_retry_exhaustion_preserves_last_real_provider_error(self):
        from google.genai.errors import ServerError

        client = MagicMock()
        error = ServerError(504, {"error": {"message": "Deadline expired", "status": "DEADLINE_EXCEEDED"}})
        client.models.generate_content.side_effect = error
        diagnostics = {}
        with patch("gemini_service.time.sleep") as sleep:
            with self.assertRaises(ServerError) as caught:
                generate_with_retry(client, model="test-model", contents="tiny prompt", config={}, diagnostics=diagnostics)
        self.assertIs(caught.exception, error)
        self.assertEqual(client.models.generate_content.call_count, 2)
        self.assertEqual(sleep.call_count, 1)
        self.assertFalse(diagnostics["attempt_results"][-1]["will_retry"])

    def test_client_transport_timeout_retries_without_inventing_http_code(self):
        import httpx

        client = MagicMock()
        client.models.generate_content.side_effect = [httpx.ReadTimeout("private connection details"), SimpleNamespace(text="OK")]
        diagnostics = {}
        with patch("gemini_service.time.sleep") as sleep:
            generate_with_retry(client, model="test-model", contents="tiny prompt", config={}, diagnostics=diagnostics)
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(diagnostics["attempt_results"][0]["category"], "client_timeout")
        self.assertIsNone(diagnostics["attempt_results"][0]["http_status"])
        self.assertNotIn("private connection details", str(diagnostics))

    def test_permanent_errors_quota_and_connection_errors_never_retry(self):
        import httpx
        from google.genai.errors import ClientError, ServerError

        errors = [ClientError(code, {"error": {"message": "Rejected"}}) for code in [400, 401, 403, 404, 429]]
        errors += [ServerError(501, {"error": {"message": "Not implemented"}}), httpx.ConnectError("TLS/network failure"), ValueError("invalid response")]
        for error in errors:
            with self.subTest(error_type=type(error).__name__, code=getattr(error, "code", None)):
                client = MagicMock()
                client.models.generate_content.side_effect = error
                with patch("gemini_service.time.sleep") as sleep:
                    with self.assertRaises(type(error)):
                        generate_with_retry(client, model="test-model", contents="tiny prompt", config={})
                self.assertEqual(client.models.generate_content.call_count, 1)
                sleep.assert_not_called()

    def test_supported_sdk_options_have_one_internal_attempt(self):
        options = gemini_http_options(MINIMAL_TIMEOUT_MS)
        self.assertEqual(options.timeout, 30000)
        self.assertEqual(options.retry_options.attempts, 1)

    def test_minimal_prompt_and_output_budget_are_small(self):
        with patch("google.genai.Client") as client_class:
            client = client_class.return_value.__enter__.return_value
            client.models.generate_content.return_value = SimpleNamespace(text="OK")
            self.assertEqual(request_minimal_generation("fake-key", "test-model"), "OK")
        call = client.models.generate_content.call_args.kwargs
        self.assertLess(len(call["contents"]), 40)
        self.assertEqual(call["config"].max_output_tokens, 128)
        self.assertEqual(client_class.call_args.kwargs["http_options"].timeout, MINIMAL_TIMEOUT_MS)

    def test_structured_request_has_separate_timeout_and_output_budget(self):
        with patch("google.genai.Client") as client_class:
            client = client_class.return_value.__enter__.return_value
            client.models.generate_content.return_value = SimpleNamespace(text=json.dumps(valid_guidance()))
            request_guidance("ERROR timeout", analyze_logs("ERROR timeout"), "fake-key", "test-model")
        self.assertEqual(client_class.call_args.kwargs["http_options"].timeout, ANALYSIS_TIMEOUT_MS)
        self.assertEqual(client.models.generate_content.call_args.kwargs["config"].max_output_tokens, 3072)

    def test_real_sdk_transport_does_not_multiply_application_retries(self):
        import httpx
        from google import genai
        from google.genai.errors import ServerError

        calls = []

        def unavailable(request):
            calls.append(request)
            return httpx.Response(503, json={"error": {"message": "Unavailable", "status": "UNAVAILABLE"}})

        options = gemini_http_options(MINIMAL_TIMEOUT_MS)
        options.httpx_client = httpx.Client(transport=httpx.MockTransport(unavailable))
        with genai.Client(api_key="fake-key", http_options=options) as client:
            with patch("gemini_service.time.sleep"):
                with self.assertRaises(ServerError):
                    generate_with_retry(client, model="gemini-flash-latest", contents="Reply OK.", config={})
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].headers["X-Server-Timeout"], "30")

    def test_exhausted_provider_timeout_keeps_honest_rule_based_fallback(self):
        from google.genai.errors import ServerError

        error = ServerError(504, {"error": {"message": "Deadline expired", "status": "DEADLINE_EXCEEDED"}})
        with patch("google.genai.Client") as client_class, patch("gemini_service.time.sleep"):
            client = client_class.return_value.__enter__.return_value
            client.models.generate_content.side_effect = error
            report = add_ai_guidance(analyze_logs("ERROR timeout"), "ERROR timeout", "fake-key", "test-model")
        self.assertEqual(client.models.generate_content.call_count, 2)
        self.assertEqual(report["analysis_mode"], "rule-based")
        self.assertNotIn("ai_guidance", report)
        self.assertIn("HTTP 504", report["warnings"][0])
        self.assertIn("remained unavailable", report["warnings"][0])


if __name__ == "__main__":
    unittest.main()
