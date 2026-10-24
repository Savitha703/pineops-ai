import unittest

from incident_analyzer import analyze_logs, normalize_error, parse_timestamp, redact_secrets


class AnalyzerTests(unittest.TestCase):
    def test_empty_logs_rejected(self):
        for value in ("", " \n\t", None, 123):
            with self.subTest(value=value), self.assertRaises(ValueError):
                analyze_logs(value)

    def test_binary_content_rejected(self):
        with self.assertRaises(ValueError):
            analyze_logs("ERROR binary\x00data")

    def test_unstructured_text_has_unknown_cause(self):
        result = analyze_logs("not a normal log\nnot a timestamp")
        self.assertEqual(result["severity"], "Low")
        self.assertEqual(result["total_error_lines"], 0)
        self.assertIn("Unknown", result["root_cause"])
        self.assertEqual(result["time_range"]["start"], None)

    def test_generic_error_has_unknown_hypothesis(self):
        result = analyze_logs("ERROR Something failed")
        self.assertIn("unknown", result["likely_causes"][0])
        self.assertEqual(result["severity"], "Medium")

    def test_blank_lines_are_not_counted(self):
        result = analyze_logs("\nINFO healthy\n\nERROR failed\n")
        self.assertEqual(result["total_lines"], 2)
        self.assertEqual(result["total_error_lines"], 1)

    def test_repeated_errors_group_dynamic_values(self):
        result = analyze_logs("2026-10-23T09:00:00Z ERROR timeout after 3000ms request_id=abc\n2026-10-23T09:00:02Z ERROR timeout after 4000ms request_id=def")
        self.assertEqual(result["unique_error_patterns"], 1)
        pattern = result["error_patterns"][0]
        self.assertEqual(pattern["count"], 2)
        self.assertEqual(pattern["first_occurrence"], "2026-10-23T09:00:00+00:00")
        self.assertEqual(pattern["last_occurrence"], "2026-10-23T09:00:02+00:00")

    def test_status_codes_are_not_merged(self):
        self.assertNotEqual(normalize_error("ERROR HTTP 500"), normalize_error("ERROR HTTP 503"))

    def test_all_common_signals_detected_without_error_label(self):
        result = analyze_logs("request timed out\ndatabase connection refused\nPOST /orders status=503\nauthentication failed\nout of memory")
        self.assertEqual(result["total_error_lines"], 5)
        self.assertTrue(all(count >= 1 for count in result["signal_counts"].values()))

    def test_success_http_codes_not_counted(self):
        result = analyze_logs("INFO status=200\nINFO POST /health 201\nINFO GET /cache status=304")
        self.assertEqual(result["total_error_lines"], 0)

    def test_http_access_log_format(self):
        self.assertEqual(analyze_logs("GET /orders 502")["signal_counts"]["HTTP 5xx"], 1)

    def test_overlapping_signals_count_line_once(self):
        result = analyze_logs("ERROR database connection timeout")
        self.assertEqual(result["total_error_lines"], 1)
        self.assertEqual(result["signal_counts"]["Timeout"], 1)
        self.assertEqual(result["signal_counts"]["Database connection"], 1)

    def test_severity_rules(self):
        cases = [("INFO ready", "Low"), ("ERROR failed", "Medium"), ("ERROR failed\n" * 10, "High"), ("HTTP 503\n" * 3, "High"), ("database connection refused\n" * 3, "High"), ("out of memory\n" * 3, "Critical"), ("FATAL process failed", "Critical")]
        for logs, expected in cases:
            with self.subTest(expected=expected):
                result = analyze_logs(logs)
                self.assertEqual(result["severity"], expected)
                self.assertTrue(result["severity_rationale"])
                self.assertIn("customer impact", result["severity_notice"])

    def test_timestamp_offsets_and_invalid_dates(self):
        self.assertEqual(parse_timestamp("2026-10-23T10:00:00+05:30 INFO"), "2026-10-23T04:30:00+00:00")
        self.assertIsNone(parse_timestamp("2026-99-99 25:61:00 ERROR"))
        self.assertEqual(parse_timestamp("2026-10-23 10:00:00,123 ERROR"), "2026-10-23T10:00:00.123000+00:00")

    def test_unsorted_timestamps_use_actual_bounds(self):
        result = analyze_logs("2026-10-23T09:02:00Z ERROR failed\n2026-10-23T09:00:00Z ERROR failed")
        self.assertEqual(result["time_range"]["start"], "2026-10-23T09:00:00+00:00")
        self.assertEqual(result["error_patterns"][0]["last_occurrence"], "2026-10-23T09:02:00+00:00")

    def test_service_identified_and_safe_checks(self):
        result = analyze_logs("ERROR service=checkout-api database connection refused")
        self.assertEqual(result["service"], "checkout-api")
        self.assertIn("Database team", result["escalation"]["team"])
        self.assertTrue(result["recommended_steps"])

    def test_secrets_are_redacted(self):
        cases = ['password=hunter22', '"api_key": "topsecret"', 'Authorization: Bearer abc.def.ghi', 'postgres://admin:supersecret@db:5432/app', 'refresh_token=refreshsecret', 'Cookie=sessionsecret', 'client_secret="contains spaces"', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.secretvalue', '-----BEGIN PRIVATE KEY-----\nsecret-pem\n-----END PRIVATE KEY-----']
        secrets = ['hunter22', 'topsecret', 'abc.def.ghi', 'supersecret', 'refreshsecret', 'sessionsecret', 'contains spaces', 'secretvalue', 'secret-pem']
        for source, secret in zip(cases, secrets):
            with self.subTest(source=source):
                self.assertNotIn(secret, redact_secrets(source))
                self.assertIn("REDACTED", redact_secrets(source))

    def test_analysis_does_not_persist_raw_logs(self):
        result = analyze_logs("ERROR password=supersecret Something failed")
        self.assertNotIn("supersecret", str(result))
        self.assertNotIn("logs", result)
        self.assertEqual(result["analysis_mode"], "rule-based")

    def test_all_cookie_values_are_removed(self):
        result = redact_secrets("ERROR Cookie: session=private; access=also-private\nERROR timeout")
        self.assertNotIn("private", result)
        self.assertIn("ERROR timeout", result)


if __name__ == "__main__":
    unittest.main()
