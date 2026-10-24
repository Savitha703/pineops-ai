# PineOps AI — Gemini-Ready Incident Analyzer

A working **Technology Operations Intern** case-study prototype for analyzing simulated application incidents. The UI is the original Flask + HTML/CSS/JavaScript dashboard. It identifies recurring errors, gives preliminary severity and probable causes, recommends read-only troubleshooting and escalation, and exports saved incident reports.

**The app uses Google Gemini by default.** Local-only rules remain available as an offline alternative. Gemini is **optional**: if no key is configured or the provider fails, the app still works and clearly labels its output `rule-based`. It never fabricates an AI success.

## Quick start — Windows / VS Code

Open a terminal inside the extracted `incident-analyzer` directory:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

Edit the new local `.env` file:

```dotenv
AI_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.5-flash-lite
MAX_LOG_BYTES=204800
PORT=5000
```

Replace `your_gemini_api_key_here` with a valid Gemini key from [Google AI Studio](https://aistudio.google.com/app/apikey). **Never edit `.env.example` with real credentials. Never commit `.env`.** The attached original ZIP included an `.env` file, so consider replacing/rotating its previous keys before sharing the project again.

Start the app:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open **http://127.0.0.1:5000**. In **Settings**, verify that the selected provider says **Google Gemini**, and the key is `Configured (not verified)`. That indicator checks presence, not live access. Navigate to **Analyze Logs** → load **Payment API** → click **Analyze Incident**. When AI succeeds, the report shows **AI-assisted** and separate **Google Gemini investigation notes**. If Gemini fails, the report clearly says **rule-based** and includes a warning.

### macOS / Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
# Edit .env to add your own Gemini API key.
.venv/bin/python app.py
```

### Check Gemini independently (uses a live request)

With `.env` set and your virtual environment active:

```powershell
.\.venv\Scripts\python.exe check_gemini.py --metadata
.\.venv\Scripts\python.exe check_gemini.py
.\.venv\Scripts\python.exe check_gemini.py --analysis
```

`--metadata` checks the selected model's metadata, **not** actual generation. The normal command submits a tiny `Reply with OK only` prompt. `--analysis` sends only a synthetic incident through the real JSON generation and validation path. These commands **may use your account quota** and do not write to incident history. Output includes sanitized success/failure categories, HTTP statuses (when provided), and timings, but no API key.

If you are demonstrating offline, use `AI_PROVIDER=rules` in `.env` and restart Flask.

## How it works

```text
Browser UI
  → Flask POST /api/analyze
  → validate, limit size, redact common secrets
  → deterministic log parser: errors, patterns, counts, severity, impact uncertainty
  → selected optional provider:
       Gemini (default) / Local rules
  → validate model JSON, require uncertainty and safe read-only suggestions
  → persist safe JSON to data/incidents.json
  → render evidence, troubleshooting, notes and downloadable report
```

The log parser stays authoritative for log counts, signal groups and preliminary severity. The LLM is used only to write tentative hypotheses and diagnostic guidance. The app never executes model-suggested operations. The Gemini request contains a bounded set of important **redacted** log lines and the preliminary analysis, reducing unnecessary provider latency and data volume.

### Files

| File | Responsibility |
|---|---|
| `app.py` | Flask routes, Gemini/offline mode, redaction and persistence |
| `incident_analyzer.py` | Parsing, grouping, severity rules, evidence and local recommendations |
| `gemini_service.py` | Gemini structured generation, errors, bounded retries, safe fallback |
| `ai_validation.py` | Strict JSON shape, uncertainty checks and read-only diagnostics |
| `incident_store.py` | Validated incident JSON with atomic writes |
| `check_gemini.py` | Safe live model diagnostics (only when manually run) |
| `sample_logs/` | Synthetic payment and database incident examples |
| `tests/` | Automated offline tests, including the actual SDK request shape |
| `PRESENTATION.md` | Ten-minute demo and Q&A script |
| `REPAIR_REPORT.md` | What changed, verification results and remaining limitations |

The existing local history of **10 synthetic incidents** was retained in `data/incidents.json`. It is used in the dashboard totals and tagged as sample data, not production incidents.

## Run tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
```

The tests are intentionally offline (Gemini calls are mocked) so they do not consume provider quota. The included `test_gemini_sdk_wire.py` checks that the installed `google-genai` SDK constructs a valid structured-generation HTTP request and parses a mock response. It does **not** verify your actual API key or Google's availability.

## Gemini troubleshooting

| Symptom | Likely cause and action |
|---|---|
| Settings says key not configured | Set `GEMINI_API_KEY` in **`.env` beside `app.py`**, not `.env.example`; restart. |
| HTTP 400 invalid model | Use the exact ID `gemini-3.5-flash-lite`; check `GEMINI_MODEL` spelling. |
| HTTP 401 / API key invalid | Create a valid Gemini API key and check restrictions; replace/rotate keys that were shared. |
| HTTP 403 | Check Google project, API key permissions and API access. |
| HTTP 404 | Selected model may not be available; check official [model IDs](https://ai.google.dev/gemini-api/docs/models). |
| HTTP 429 | Rate limit, quota or billing constraint. Check Google AI Studio rate limits. |
| HTTP 503 / 504 or timeout | Provider availability or request deadline. The app retries temporary errors only once, then uses local rules. Try again later or use offline mode for the demo. |
| Report says `rule-based` | This is an intentional, honest fallback. Read the warning and run `check_gemini.py` to diagnose. |

Google lists `gemini-3.5-flash-lite` as a stable, lower-latency model with structured-output support. Availability can vary by account; see [official model docs](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite) and [troubleshooting](https://ai.google.dev/gemini-api/docs/troubleshooting).

## Supported inputs and limitations

- Accept pasted text or `.log`/`.txt` UTF-8 uploads (including UTF-8 BOM); 200 KiB default limit.
- Use sample/simulated data only for the assignment. API logs must be reviewed before sharing with a provider.
- Common secrets are redacted, **not** full PII/compliance-grade scrubbing. Do not upload production logs with confidential content.
- Severity and root-cause hypotheses are preliminary. Logs alone cannot confirm outage impact, customer impact, or an actual root cause.
- Gemini request timeouts are currently 60 seconds per attempt, with one retry after one second for provider 408/500/502/503/504 or client timeout. If Google stays unavailable, the local fallback keeps the app usable.
- `data/incidents.json` is single-user local JSON storage; not intended for production hosting, authentication or multi-process concurrency.
- All AI notes require human review. No external service remediation is executed.

## For your interview

Use the Payment API demo first, then the Database Errors demo. Show error patterns, severity rationale and how unknown impact is disclosed. Open a Gemini-assisted report **only if the live request actually succeeds**, otherwise demonstrate the honest rule-based fallback and explain how AI is integrated and tested. Finish by downloading a saved JSON report and showing the Settings page. See [PRESENTATION.md](PRESENTATION.md).
