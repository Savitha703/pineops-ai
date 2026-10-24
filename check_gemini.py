"""Real, minimal Gemini connection test; never writes to incident history."""

import argparse
import json
import re
import time
import os
from importlib.metadata import version
from pathlib import Path

from app import create_app
from gemini_service import (
    DEFAULT_MODEL, ANALYSIS_TIMEOUT_MS, MAX_GENERATION_ATTEMPTS, MINIMAL_TIMEOUT_MS,
    RETRY_DELAYS_SECONDS, describe_gemini_error, request_guidance, request_minimal_generation,
)
from incident_analyzer import analyze_logs


def run_single_probe(api_key, model, *, metadata, diagnostics):
    """One HTTP operation with an explicit server deadline and safe telemetry."""
    import httpx
    from google import genai
    from google.genai import types

    def capture_request(request):
        # Never inspect or log authorization headers, URLs, or request bodies.
        diagnostics.setdefault("observed_requests", []).append({
            "method": request.method,
            "server_timeout_seconds": request.headers.get("X-Server-Timeout"),
            "read_timeout_seconds": request.extensions.get("timeout", {}).get("read"),
        })

    def capture_response(response):
        diagnostics.setdefault("observed_http_statuses", []).append(response.status_code)

    with httpx.Client(event_hooks={"request": [capture_request], "response": [capture_response]}) as transport:
        options = types.HttpOptions(
            timeout=diagnostics["timeout_ms_per_attempt"],
            headers={"X-Server-Timeout": str(diagnostics["server_deadline_seconds"])},
            retry_options=types.HttpRetryOptions(attempts=1),
            httpx_client=transport,
        )
        with genai.Client(api_key=api_key, http_options=options) as client:
            if metadata:
                info = client.models.get(model=model)
                actions = info.supported_actions or []
                name = info.name or ""
                diagnostics["model_metadata"] = {
                    "name": name if re.fullmatch(r"models/gemini-[A-Za-z0-9._-]+", name) and api_key not in name else "(name omitted)",
                    "supports_generate_content": "generateContent" in actions,
                    "input_token_limit": info.input_token_limit,
                    "output_token_limit": info.output_token_limit,
                }
            else:
                response = client.models.generate_content(
                    model=model, contents="Reply with OK only.",
                    config=types.GenerateContentConfig(max_output_tokens=128),
                )
                diagnostics["usable_text_received"] = bool(response.text and response.text.strip())
                if not diagnostics["usable_text_received"]:
                    from gemini_service import GuidanceValidationError
                    raise GuidanceValidationError("Gemini returned no usable text.")
    diagnostics["http_status"] = diagnostics["observed_http_statuses"][-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--analysis", action="store_true", help="Test the real structured-analysis request with synthetic logs.")
    mode.add_argument("--metadata", action="store_true", help="Fetch configured-model metadata once; no generation request.")
    mode.add_argument("--controlled", action="store_true", help="Generate once with a 120-second client timeout and 90-second server deadline.")
    options = parser.parse_args()
    app = create_app()
    # Standalone network diagnostic; never called automatically by the dashboard.
    key = os.getenv("GEMINI_API_KEY", "").strip()
    model = os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    result = {
        "env_file_exists": (Path(__file__).resolve().parent / ".env").is_file(),
        "api_key_configured": bool(key and key != "your_gemini_api_key_here"),
        "sdk_version": version("google-genai"),
        "model": model if re.fullmatch(r"(?:models/)?gemini-[A-Za-z0-9._-]+", model) and (not key or key not in model) else "(invalid model name; value hidden)",
        "test": "structured_analysis" if options.analysis else "minimal_generation",
        "timeout_ms_per_attempt": ANALYSIS_TIMEOUT_MS if options.analysis else MINIMAL_TIMEOUT_MS,
        "max_attempts": MAX_GENERATION_ATTEMPTS,
        "backoff_seconds": list(RETRY_DELAYS_SECONDS),
    }
    if options.metadata or options.controlled:
        result.update(
            test="model_metadata" if options.metadata else "controlled_generation",
            timeout_ms_per_attempt=20000 if options.metadata else 120000,
            server_deadline_seconds=20 if options.metadata else 90,
            max_attempts=1, backoff_seconds=[],
        )
    if not result["api_key_configured"]:
        result.update(result="failed", category="missing_configuration", http_status=None,
                      message="GEMINI_API_KEY is missing or a placeholder. Set it in .env beside app.py, then restart Flask.")
        print(json.dumps(result, indent=2))
        return 1
    started = time.perf_counter()
    try:
        if options.metadata or options.controlled:
            run_single_probe(key, model, metadata=options.metadata, diagnostics=result)
        elif options.analysis:
            logs = "2026-10-23T09:00:00Z ERROR service=connection-test request timeout"
            request_guidance(logs, analyze_logs(logs), key, model, diagnostics=result)
        else:
            request_minimal_generation(key, model, diagnostics=result)
        message = "Model metadata was retrieved; this does not verify generation or remaining quota." if options.metadata else "A real Gemini generation response was received and validated. No incident was saved."
        result.update(result="success", message=message)
    except Exception as error:
        result.update(result="failed", **describe_gemini_error(error, key))
    result["elapsed_seconds"] = round(time.perf_counter() - started, 2)
    print(json.dumps(result, indent=2))
    return 0 if result["result"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
