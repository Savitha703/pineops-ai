"""PineOps AI: a small, local Flask application. Run with python app.py."""

import os
from pathlib import Path
from io import BytesIO

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.exceptions import HTTPException

from gemini_service import DEFAULT_MODEL as DEFAULT_GEMINI_MODEL, add_ai_guidance as add_gemini_guidance, key_is_configured as gemini_key_is_configured
from incident_analyzer import analyze_logs, parse_lines, redact_secrets
from incident_store import IncidentStore, StorageError
from postgres_incident_store import PostgresIncidentStore
from incident_chat import ask_incident_question, sanitize_question, sanitize_history

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        MAX_LOG_BYTES=int(os.getenv("MAX_LOG_BYTES", "204800")),
        AI_PROVIDER=os.getenv("AI_PROVIDER", "gemini").strip().lower(),
        GEMINI_API_KEY=os.getenv("GEMINI_API_KEY", ""),
        GEMINI_MODEL=os.getenv("GEMINI_MODEL", "").strip() or DEFAULT_GEMINI_MODEL,
        INCIDENT_FILE=BASE_DIR / "data" / "incidents.json",
    )
    if test_config:
        app.config.update(test_config)
    if app.config["AI_PROVIDER"] not in {"gemini", "rules"}:
        raise ValueError("AI_PROVIDER must be gemini or rules.")
    # Allow modest multipart/JSON overhead; the actual log has a separate limit.
    app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_LOG_BYTES"] + 65536
    store = (
        PostgresIncidentStore(os.environ["DATABASE_URL"])
        if os.environ.get("DATABASE_URL") and test_config is None
        else IncidentStore(app.config["INCIDENT_FILE"])
    )
    app.extensions["incident_store"] = store

    @app.before_request
    def reject_cross_origin_writes():
        origin = request.headers.get("Origin")
        if request.method in {"POST", "DELETE"} and origin and origin != request.host_url.rstrip("/"):
            return jsonify(error="Cross-origin writes are not allowed."), 403

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        provider = app.config["AI_PROVIDER"]
        configured = gemini_key_is_configured(app.config["GEMINI_API_KEY"]) if provider == "gemini" else False
        return jsonify(status="ok", name="PineOps AI", version="1.1.0",
                       ai_provider={"gemini": "Google Gemini", "rules": "Local rules"}[provider],
                       model=app.config["GEMINI_MODEL"] if provider == "gemini" else "None (offline)",
                       api_key_configured=configured,
                       chat_enabled=provider == "gemini" and configured,
                       chat_route="/api/incidents/<incident_id>/ask",
                       max_log_bytes=app.config["MAX_LOG_BYTES"])

    @app.get("/api/samples/<sample_name>")
    def sample(sample_name):
        names = {"payment": "payment_api.log", "database": "database_errors.log"}
        if sample_name not in names:
            return jsonify(error="Sample not found."), 404
        return jsonify(logs=(BASE_DIR / "sample_logs" / names[sample_name]).read_text(encoding="utf-8"),
                       sample=True, name=sample_name)

    @app.post("/api/analyze")
    def analyze():
        logs, is_sample = read_log_request(app.config["MAX_LOG_BYTES"])
        # Redact the active Gemini credential before further processing.
        for raw_key in (app.config["GEMINI_API_KEY"],):
            key = raw_key.strip()
            if key and len(key) >= 12:
                logs = logs.replace(key, "[REDACTED]")
        redacted_logs = redact_secrets(logs)
        store.list_incidents()  # Detect corrupt storage before a paid AI request.
        report = analyze_logs(redacted_logs, is_sample=is_sample)
        provider = app.config["AI_PROVIDER"]
        if provider == "gemini":
            report = add_gemini_guidance(report, redacted_logs, app.config["GEMINI_API_KEY"], app.config["GEMINI_MODEL"])
        else:
            report["ai_provider"] = "Local rules"
            report["warnings"].append("Offline rules mode selected. No logs were sent to an AI provider.")
        return jsonify(store.save_incident(report)), 201

    @app.get("/api/incidents")
    def incidents():
        return jsonify(incidents=store.list_incidents())

    @app.get("/api/incidents/<incident_id>")
    def incident(incident_id):
        report = store.get_incident(incident_id)
        if report is None:
            return jsonify(error="Incident not found."), 404
        return jsonify(report)

    @app.get("/api/incidents/<incident_id>/pdf")
    def download_incident_pdf(incident_id):
        """Export the existing saved analysis. Do not re-run the AI or use canned text."""
        report = store.get_incident(incident_id)
        if report is None:
            return jsonify(error="Incident not found."), 404
        pdf_content = build_incident_pdf(report)
        return send_file(
            BytesIO(pdf_content),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"PineOpsAI_{report['id']}_Report.pdf",
        )

    @app.post("/api/incidents/<incident_id>/ask")
    def ask_about_incident(incident_id):
        """Follow-up questions against persisted, redacted parser evidence only."""
        report = store.get_incident(incident_id)
        if report is None:
            return jsonify(error="Incident not found."), 404
        if app.config["AI_PROVIDER"] != "gemini":
            return jsonify(error="Ask AI requires AI_PROVIDER=gemini in .env and a Flask restart."), 503
        api_key = app.config["GEMINI_API_KEY"]
        if not gemini_key_is_configured(api_key):
            return jsonify(error="Gemini is not configured. Set GEMINI_API_KEY and restart Flask."), 503
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="Send a JSON question."), 400
        question = sanitize_question(payload.get("question"))
        history = sanitize_history(payload.get("history", []))
        try:
            result = ask_incident_question(report, question, api_key, app.config["GEMINI_MODEL"], history)
        except Exception:
            # Avoid serializing arbitrary SDK errors or provider response bodies.
            return jsonify(error="AI could not answer this question. Please retry or check your Gemini quota and connection."), 502
        response = jsonify(result)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.delete("/api/incidents/<incident_id>")
    def delete_incident(incident_id):
        if not store.delete_incident(incident_id):
            return jsonify(error="Incident not found."), 404
        return jsonify(deleted=incident_id)

    @app.errorhandler(StorageError)
    def storage_error(error):
        return jsonify(error=str(error)), 503

    @app.errorhandler(ValueError)
    def validation_error(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(HTTPException)
    def http_error(error):
        message = "Request is too large. Reduce the log size." if error.code == 413 else error.description
        return jsonify(error=message), error.code

    return app



def build_incident_pdf(report):
    """Produce exactly two pages from saved parser evidence and *actual* AI guidance.

    Report data was validated and secret-redacted before storage. This exporter
    does not call the model and deliberately does not substitute hardcoded rule-
    based troubleshooting steps for missing AI content. Long content is clipped
    visibly to enforce the two-page interview handout format.
    """
    from datetime import datetime, timezone, timedelta
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfgen.canvas import Canvas
    from incident_analyzer import redact_secrets

    navy = colors.HexColor("#14213D")
    violet = colors.HexColor("#6554DA")
    ink = colors.HexColor("#213048")
    muted = colors.HexColor("#687792")
    pale = colors.HexColor("#F2F4FA")
    border = colors.HexColor("#E2E7F0")
    red = colors.HexColor("#BA394D")
    page_width, page_height = A4
    margin = 40
    content_width = page_width - 2 * margin
    buffer = BytesIO()
    pdf = Canvas(buffer, pagesize=A4, pageCompression=1)
    pdf.setTitle(f"PineOps AI Incident Report - {report['id']}")
    pdf.setAuthor("PineOps AI - local incident analyzer")

    def clean(value):
        if value is None:
            return "Not available"
        value = redact_secrets(str(value))
        replacements = {
            "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
            "\u2014": "-", "\u2212": "-", "\u2018": "'", "\u2019": "'",
            "\u201c": '"', "\u201d": '"', "\u2022": "-", "\u2192": "->",
            "\u00a0": " ", "\u2026": "...", "\u200b": "",
        }
        for original, replacement in replacements.items():
            value = value.replace(original, replacement)
        # Helvetica is bundled into virtually every PDF reader. Unsupported
        # symbols are replaced instead of rendering as black squares.
        return " ".join(value.encode("cp1252", errors="replace").decode("cp1252").split())

    def clipped_lines(value, width, max_lines, font="Helvetica", size=9):
        """Wrap plain text, cutting with an explicit marker if it is too long."""
        text = clean(value)
        words = text.split(" ")
        lines = []
        current = ""
        for word in words:
            candidate = f"{current} {word}" if current else word
            if stringWidth(candidate, font, size) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
                current = ""
            # Break unusually long strings such as a huge log signature.
            while stringWidth(word, font, size) > width and word:
                n = len(word)
                while n > 1 and stringWidth(word[:n], font, size) > width:
                    n -= 1
                lines.append(word[:n])
                word = word[n:]
            current = word
        if current:
            lines.append(current)
        if not lines:
            lines = ["-"]
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            tail = " ... [shortened]"
            while lines[-1] and stringWidth(lines[-1] + tail, font, size) > width:
                lines[-1] = lines[-1][:-1]
            lines[-1] += tail
        return lines

    def write(value, x, top, width, *, max_lines=2, font="Helvetica",
              size=9, leading=12, color=ink):
        lines = clipped_lines(value, width, max_lines, font, size)
        pdf.setFont(font, size)
        pdf.setFillColor(color)
        for index, line in enumerate(lines):
            pdf.drawString(x, top - index * leading, line)
        return top - len(lines) * leading

    def line(y):
        pdf.setStrokeColor(border)
        pdf.setLineWidth(.75)
        pdf.line(margin, y, page_width-margin, y)

    def heading(label, y, note=None):
        pdf.setFont("Helvetica-Bold", 10.5)
        pdf.setFillColor(navy)
        pdf.drawString(margin, y, label)
        if note:
            pdf.setFont("Helvetica", 7.7)
            pdf.setFillColor(muted)
            pdf.drawRightString(page_width-margin, y+1, clean(note))
        return y - 18

    def header(page_number, title):
        pdf.setFillColor(navy)
        pdf.rect(0, page_height-89, page_width, 89, fill=1, stroke=0)
        pdf.setFillColor(colors.HexColor("#A69DFF"))
        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(margin, page_height-32, "PINEOPS AI / INCIDENT INTELLIGENCE")
        pdf.setFillColor(colors.white)
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(margin, page_height-58, title)
        pdf.setFont("Helvetica", 8)
        pdf.setFillColor(colors.HexColor("#DADEED"))
        pdf.drawString(margin, page_height-76, clean(report['id']))
        pdf.drawRightString(page_width-margin, page_height-75, f"PAGE {page_number} / 2")
        line(48)
        pdf.setFillColor(muted)
        pdf.setFont("Helvetica", 7.5)
        source = "SYNTHETIC SAMPLE DATA" if report.get("is_sample") else "USER-SUPPLIED LOG ANALYSIS"
        pdf.drawString(margin, 34, source + "  |  PRELIMINARY - VERIFY BEFORE ACTION")
        pdf.drawRightString(page_width-margin, 34, "PineOps AI")

    def time_fmt(value, short=False):
        if not value:
            return "N/A"
        try:
            time = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            # Store timestamps unchanged; convert only for the report display.
            # India uses a fixed UTC+05:30 offset year-round (no DST).
            local_time = time.astimezone(timezone(timedelta(hours=5, minutes=30)))
            return local_time.strftime("%I:%M:%S %p" if short else "%d %b %Y %I:%M %p")
        except (TypeError, ValueError):
            return clean(value)

    ai = report.get("ai_guidance") if report.get("analysis_mode") == "AI-assisted" else None
    if not isinstance(ai, dict):
        ai = None
    extension = report.get("ai_extensions") if ai and isinstance(report.get("ai_extensions"), dict) else {}
    provider = "AI-Analyzed" if ai else "Local rules only"
    model = report.get("ai_model", "") if ai else ""

    # Page 1: metrics and traceable error evidence.
    header(1, "INCIDENT ANALYSIS")
    pdf.setFillColor(pale)
    pdf.roundRect(margin, 708, content_width, 36, 7, stroke=0, fill=1)
    fields = [
        ("SERVICE", report.get("service", "Unknown")),
        ("SAVED AT", time_fmt(report.get("created_at"))),
        ("ANALYSIS", provider),
    ]
    for i, (label, value) in enumerate(fields):
        x = margin + 13 + i * (content_width / 3)
        write(label, x, 735, content_width/3-19, max_lines=1,
              font="Helvetica-Bold", size=7, color=muted)
        write(value, x, 721, content_width/3-19, max_lines=1,
              font="Helvetica-Bold", size=8.7, color=ink)

    metric_data = [
        (str(report.get("total_lines", 0)), "LOG LINES"),
        (str(report.get("total_error_lines", 0)), "ERROR LINES"),
        (str(report.get("unique_error_patterns", 0)), "ERROR PATTERNS"),
        (clean(report.get("severity", "Unknown")), "PRELIMINARY SEVERITY"),
    ]
    cell_w = (content_width - 21) / 4
    for i, (value, label) in enumerate(metric_data):
        x = margin + i * (cell_w + 7)
        pdf.setStrokeColor(border)
        pdf.setFillColor(colors.white)
        pdf.roundRect(x, 648, cell_w, 52, 7, stroke=1, fill=1)
        pdf.setFont("Helvetica-Bold", 16 if i < 3 else 13)
        pdf.setFillColor(red if value == "Critical" else ink)
        pdf.drawString(x+10, 674, value)
        pdf.setFont("Helvetica", 7.0)
        pdf.setFillColor(muted)
        pdf.drawString(x+10, 660, label)

    heading("01  INCIDENT SUMMARY", 627, "AI-generated" if ai else "AI response not saved")
    if ai:
        write(ai.get("summary", ""), margin, 607, content_width, max_lines=4, size=9.1, leading=12.2)
    else:
        write("No AI-generated summary is stored for this incident. Run AI analysis again to include generated findings here.",
              margin, 607, content_width, max_lines=4, size=9.1, leading=12.2, color=muted)

    heading("02  SEVERITY & EVIDENCE RATIONALE", 547, "Parser-derived, not an AI diagnosis")
    write(report.get("severity_rationale", "No severity explanation saved."),
          margin, 527, content_width, max_lines=3, size=8.9, leading=12)
    write("Severity is provisional; the supplied logs alone cannot confirm affected users or complete service impact.",
          margin, 489, content_width, max_lines=1, size=8.0, leading=11, color=muted)

    patterns = report.get("error_patterns") or []
    heading("03  RECURRING ERROR SIGNATURES", 467, f"Top {min(len(patterns), 7)} of {len(patterns)}")
    pdf.setFillColor(navy)
    pdf.roundRect(margin, 425, content_width, 25, 4, fill=1, stroke=0)
    column_x = [margin + 10, margin + 291, margin + 327, margin + 411]
    for x, label in zip(column_x, ["NORMALIZED ERROR PATTERN", "COUNT", "SIGNALS", "FIRST - LAST"]):
        pdf.setFillColor(colors.white)
        pdf.setFont("Helvetica-Bold", 7)
        pdf.drawString(x, 434, label)
    row_top = 425
    for i, item in enumerate(patterns[:7]):
        row_bottom = row_top - 30
        if i % 2 == 0:
            pdf.setFillColor(pale)
            pdf.rect(margin, row_bottom, content_width, 30, fill=1, stroke=0)
        write(item.get("pattern", ""), column_x[0], row_top-12, 274,
              max_lines=2, size=7.75, leading=10.5)
        write(item.get("count", ""), column_x[1], row_top-16, 27,
              max_lines=1, font="Helvetica-Bold", size=9)
        write(", ".join(item.get("signals") or []) or "Other", column_x[2], row_top-12, 78,
              max_lines=2, size=7.2, leading=10.5, color=muted)
        first, last = time_fmt(item.get("first_occurrence"), True), time_fmt(item.get("last_occurrence"), True)
        write(first, column_x[3], row_top-12, 100, max_lines=1, size=7.5)
        write(last, column_x[3], row_top-24, 100, max_lines=1, size=7.5)
        row_top = row_bottom
    if not patterns:
        write("No recognized error signatures were found in these logs.",
              margin+8, 406, content_width-16, size=9, color=muted)
    line(207)
    heading("04  LOG EVIDENCE & POSSIBLE IMPACT", 189, "Parser evidence + AI impact hypothesis")
    evidence = report.get("observed_evidence") or []
    strongest = sorted(
        ((name, count) for name, count in (report.get("signal_counts") or {}).items() if count > 0),
        key=lambda pair: pair[1], reverse=True,
    )
    key_facts = ([evidence[0]] if evidence else [])
    key_facts += [f"{name}: {count} matching log lines (signals can overlap)." for name, count in strongest[:1]]
    for i, item in enumerate(key_facts[:2]):
        y = 169 - i*24
        pdf.setFillColor(violet)
        pdf.circle(margin+3, y+1, 2.2, stroke=0, fill=1)
        write(item, margin+13, y+3, content_width-15, max_lines=2, size=8.3, leading=10.2)
    if ai:
        impact = extension.get("impact_assessment") or "AI impact assessment was not captured in this older incident. Run AI analysis again."
    else:
        impact = "AI impact assessment unavailable; rules-only analysis."
    write("Potential impact (AI): " + impact, margin, 107, content_width,
          max_lines=2, size=8.0, leading=10.4, color=ink)
    tr = report.get("time_range") or {}
    write(f"Observed time window: {time_fmt(tr.get('start'))} to {time_fmt(tr.get('end'))}.",
          margin, 75, content_width, max_lines=1, size=7.8, leading=10, color=muted)
    pdf.showPage()

    # Page 2: only actual AI narrative is represented as AI guidance.
    header(2, "AI INVESTIGATION & NEXT STEPS")
    pdf.setFillColor(pale)
    pdf.roundRect(margin, 710, content_width, 34, 7, fill=1, stroke=0)
    write(f"ANALYSIS: {provider}", margin+11, 731, content_width-22,
          max_lines=1, font="Helvetica-Bold", size=8.6, color=navy)
    write("AI-generated investigation; verify findings against logs and system telemetry." if ai else "No AI-generated notes are available for this saved incident.",
          margin+11, 718, content_width-22, max_lines=1, size=8.0, color=muted)

    hypotheses = list(ai.get("hypotheses", [])) if ai else []
    checks = list(ai.get("diagnostic_checks", [])) if ai else []
    heading("05  POSSIBLE CAUSES", 687, "AI-generated hypotheses" if ai else "No AI findings")
    if ai:
        # The points below are verbatim from this incident's AI result; we may
        # shorten very long individual points to fit the requested two pages.
        for index, item in enumerate(hypotheses[:4]):
            y = 669 - index*49
            pdf.setFillColor(violet)
            pdf.setFont("Helvetica-Bold", 9.2)
            pdf.drawString(margin, y, f"{index+1:02d}")
            write(item, margin+26, y, content_width-28,
                  max_lines=3, size=8.9, leading=11.1)
        if len(hypotheses)>4:
            write(f"Showing 4 of {len(hypotheses)} AI hypotheses due to the two-page limit.",
                  margin, 472, content_width, max_lines=1, size=7.6, color=muted)
    else:
        write("AI analysis is unavailable for this incident. No canned root cause or generic troubleshooting steps are substituted in this PDF.",
              margin, 669, content_width, max_lines=3, size=9, leading=12, color=muted)

    line(464)
    heading("06  RECOMMENDED TROUBLESHOOTING", 446, "Read-only diagnostics generated by AI" if ai else "AI checks unavailable")
    if ai:
        for index, item in enumerate(checks[:5]):
            y = 428 - index*46
            pdf.setFillColor(violet)
            pdf.setFont("Helvetica-Bold", 8.8)
            pdf.drawString(margin, y, f"{index+1:02d}")
            write(item, margin+26, y, content_width-29,
                  max_lines=3, size=8.65, leading=10.7)
        if len(checks)>5:
            write(f"Showing 5 of {len(checks)} generated diagnostic checks.",
                  margin, 199, content_width, max_lines=1, size=7.6, color=muted)
    else:
        write("No AI diagnostic steps are saved. Run AI analysis again when available.",
              margin, 428, content_width, max_lines=3, color=muted)

    line(195)
    heading("07  ESCALATION ROUTING", 177, "AI-generated; validate routing" if ai else "AI unavailable")
    if ai:
        escalation = extension.get("escalation_guidance") or "Escalation guidance not captured in this older AI response. Run AI analysis again."
    else:
        escalation = "No model-generated escalation guidance saved."
    write(escalation, margin, 157, content_width,
          max_lines=4, size=8.4, leading=10.5)
    write("Follow local on-call and incident priority policy; suggested routing is not confirmed.",
          margin, 117, content_width, max_lines=1, size=7.7, color=muted)

    line(109)
    heading("08  LIMITATIONS & CONFIDENCE", 94)
    limitation = ai.get("limitations", "") if ai else "No AI analysis was stored. Root cause and impact remain unverified."
    write(limitation, margin, 76, content_width,
          max_lines=2, size=8.0, leading=10.3, color=muted)
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()


def read_log_request(max_bytes):
    """Accept either JSON logs or one multipart UTF-8 file, never both."""
    is_sample = False
    if request.is_json:
        data = request.get_json()
        if not isinstance(data, dict) or not isinstance(data.get("logs"), str):
            raise ValueError("Send a JSON object with a text 'logs' field.")
        logs = data["logs"]
        is_sample = data.get("is_sample", False)
        if type(is_sample) is not bool:
            raise ValueError("The is_sample field must be true or false.")
    elif request.mimetype == "multipart/form-data":
        files = request.files.getlist("file")
        if len(files) != 1 or set(request.files) != {"file"}:
            raise ValueError("Upload exactly one file using the 'file' field.")
        if request.form.get("logs", "").strip():
            raise ValueError("Send a file or pasted logs, not both.")
        file = files[0]
        if Path(file.filename or "").suffix.lower() not in {".log", ".txt"}:
            raise ValueError("Only .log and .txt files are accepted.")
        raw = file.read(max_bytes + 1)
        if len(raw) > max_bytes:
            from werkzeug.exceptions import RequestEntityTooLarge
            raise RequestEntityTooLarge()
        try:
            logs = raw.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError("File must contain UTF-8 text. Save it as UTF-8 and try again.") from error
    else:
        from werkzeug.exceptions import UnsupportedMediaType
        raise UnsupportedMediaType("Use application/json for pasted logs or multipart/form-data for a file.")
    if len(logs.encode("utf-8")) > max_bytes:
        from werkzeug.exceptions import RequestEntityTooLarge
        raise RequestEntityTooLarge()
    parse_lines(logs)
    return logs, is_sample or "# SAMPLE DATA" in logs


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=False)
