
# PineOps AI — AI-Powered Incident Analyzer

**Incident Intelligence | Technology Operations**

🌐 **Live Demo:** [https://pineops-ai.vercel.app](https://pineops-ai.vercel.app)

**GitHub Repository:** [PineOps AI](https://github.com/Savitha703/pineops-ai)

---

PineOps AI is a working AI-powered incident analysis prototype designed to help Technology Operations and L1/L2 support engineers investigate issues in simulated application logs. It detects recurring failures, assesses incident severity, summarizes likely causes, recommends troubleshooting and escalation steps, and produces a shareable two-page PDF incident report.

The application includes an **Ask AI About This Incident** chat assistant for follow-up investigation, with responses grounded in the saved incident evidence.

**AI implementation:** PineOps AI uses Google Gemini for AI-generated investigation and conversational guidance. An offline, rule-based fallback remains available when AI is not configured or a provider request fails. The application distinguishes AI-generated findings from local rule-based results rather than claiming AI succeeded when it did not.

> **Project status:** Demonstration prototype using synthetic logs only. It is not an official Pine Labs product or a production incident-management system.

## Features

- Upload `.log` and `.txt` application logs, or paste log text.
- Detect repeated errors, affected services, failure patterns and timestamps.
- Classify incidents as **Critical, High, Medium or Low**, with a reasoned preliminary assessment.
- Generate AI-written incident summaries, root-cause hypotheses, potential-impact assessments, diagnostic checks and escalation guidance.
- Keep observed log evidence separate from assumptions and hypotheses.
- Ask conversational follow-up questions about a saved incident through **Ask AI About This Incident**.
- Export a concise **two-page PDF incident report** with error details and available AI findings.
- Review saved incident history and use sample payment/database logs for demonstrations.
- Fall back to clearly labeled **local rules** when AI is unavailable.

## Quick start — Windows / VS Code

Open a terminal in the `incident-analyzer` project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
```

Edit the new local `.env` file to configure your provider:

```dotenv
AI_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.5-flash-lite
MAX_LOG_BYTES=204800
PORT=5000
```

Get your own API key from [Google AI Studio](https://aistudio.google.com/app/apikey) and use a model available to your account. **Never put real credentials in `.env.example` or commit `.env` to Git.** Rotate any key that has previously been shared.

Start the application:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open **http://127.0.0.1:5000**. Load a sample log under **Analyze Logs**, analyze the incident, inspect the AI findings and download the PDF report. Open a saved incident to ask follow-up questions in the chat assistant.

### macOS / Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
# Edit .env to add your own API key.
.venv/bin/python app.py
```

### Check AI connectivity

With `.env` configured, run the optional Gemini diagnostic commands:

```powershell
.\.venv\Scripts\python.exe check_gemini.py --metadata
.\.venv\Scripts\python.exe check_gemini.py
.\.venv\Scripts\python.exe check_gemini.py --analysis
```

The metadata check does **not** prove successful generation. The normal test makes a small live generation request, while `--analysis` exercises structured incident analysis using synthetic data. Live requests may consume API quota and do not save incidents.

For a demonstration without an AI connection, set `AI_PROVIDER=rules` in `.env` and restart the server.

## How it works

```text
Browser dashboard
  |
  v
Flask API (/api/analyze)
  |
  +--> Validate log input and size; redact common secrets
  |
  +--> Python parser: error patterns, counts, timestamps and severity
  |
  +--> AI investigation using Gemini (when available)
  |      - Incident summary and potential impact
  |      - Evidence-based root-cause hypotheses
  |      - Diagnostic checks and escalation guidance
  |
  +--> Validate the AI response and label the analysis mode
  |      - If AI is unavailable: clearly labeled local-rule fallback
  |
  +--> Save incident analysis locally
  |
  +--> Dashboard, follow-up AI chat and two-page PDF export
```

**Design principle:** Python remains authoritative for extracted log evidence, quantitative counts and rule-based severity. The AI formulates contextual hypotheses and suggested diagnostic actions. The application does not treat correlation as proof of root cause or execute AI-recommended operations.

### Project files

| File / directory | Responsibility |
|---|---|
| `app.py` | Flask application, API routes, report generation and application configuration |
| `incident_analyzer.py` | Log parsing, error grouping, preliminary severity and evidence extraction |
| `gemini_service.py` | Gemini-powered incident analysis and API error handling |
| `incident_chat.py` | Follow-up incident questions using saved evidence |
| `ai_validation.py` | Validation and safety checks for structured AI outputs |
| `incident_store.py` | Local persistence of saved incident analyses |
| `check_gemini.py` | Optional Gemini API diagnostics |
| `templates/` | Dashboard HTML |
| `static/` | JavaScript, CSS and PineOps AI logo |
| `sample_logs/` | Synthetic payment and database log samples |
| `tests/` | Automated tests for parsing, routes, AI integration and storage |
| `requirements.txt` | Python dependencies |
| `.env.example` | Example environment configuration without secrets |

## Run automated tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
```

The automated tests are designed to run without consuming Gemini API quota; AI responses are mocked where appropriate. Tests that mock the SDK verify integration behavior but do not establish that a real provider request will succeed.

## AI integration troubleshooting

| Symptom | What to check |
|---|---|
| API key not configured | Put `GEMINI_API_KEY` in `.env` next to `app.py`, then restart Flask. |
| Invalid model / HTTP 400 or 404 | Check `GEMINI_MODEL` and whether your account can access that exact model ID. |
| Authentication error / HTTP 401 or 403 | Review API key validity, restrictions and Google project access. |
| Rate limit / HTTP 429 | Check available quota and billing or rate-limit settings. |
| Timeout / HTTP 503 or 504 | Retry later, or demonstrate offline mode. |
| Report indicates local rules | The AI request was not completed; inspect the displayed diagnostic message. |
| Chat cannot answer from evidence | The saved incident may not contain enough log detail; provide more relevant synthetic logs. |

See the [Gemini API documentation](https://ai.google.dev/gemini-api/docs) for provider-specific model and API details.

## Supported inputs and limitations

- Accepts pasted log text and UTF-8 `.log`/`.txt` uploads, with a configurable input size limit (200 KiB by default).
- Only **synthetic sample data** should be used for this public demo. Do not upload production logs or confidential incident information.
- Redaction covers common credential patterns but is **not** a complete PII or compliance-grade sanitization solution.
- Root-cause hypotheses and impact assessments are provisional; logs alone cannot establish customer impact or a confirmed root cause.
- AI-generated suggestions require human review. The tool does not run remediation commands.
- The follow-up chat uses saved incident evidence; it may not have access to every line in the original uploaded log file.
- Saved incident history uses local JSON storage and is not designed for authenticated, concurrent or persistent production hosting.
- On ephemeral hosting services, locally stored incident history can be lost when the service restarts or redeploys.

---

**PineOps AI** is an independent educational case-study prototype developed for a Technology Operations assignment.
