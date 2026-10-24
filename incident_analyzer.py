"""Readable, deterministic log analysis. No network calls or system commands."""

import re
from datetime import datetime, timezone


SIGNALS = {
    "Timeout": r"\b(?:time[ -]?out|timed out|deadline exceeded)\b",
    "Database connection": r"(?:database|db|postgres|mysql|sql|connection pool).*?(?:connection|connect|refused|exhaust|unavailable|too many)|(?:connection refused|could not connect).*?(?:database|db|postgres|mysql)",
    "HTTP 5xx": r"\bHTTP(?:/[\d.]+)?\s+5\d\d\b|\b(?:status|status_code|response_code)[=: ]+5\d\d\b|\b(?:GET|POST|PUT|DELETE|PATCH)\s+\S+\s+5\d\d\b",
    "Authentication": r"\b(?:unauthorized|forbidden|authentication failed|invalid (?:token|credentials)|access denied|login failed)\b|\b(?:HTTP\s+|status[=: ]+)(?:401|403)\b",
    "Resource exhaustion": r"\b(?:out of memory|oom|oomkilled|disk full|no space left|too many open files|pool exhausted|too many connections|cpu saturated|memory exhausted)\b",
}
SIGNAL_REGEX = {name: re.compile(pattern, re.I) for name, pattern in SIGNALS.items()}
ERROR_LEVEL = re.compile(r"\b(?:ERROR|ERR|FATAL|CRITICAL|PANIC|SEVERE|EXCEPTION)\b|\b\w+(?:Error|Exception)\b", re.I)
TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
SEVERITY_NOTICE = "Preliminary suggestion only. Verify actual severity against customer impact and service health. Log frequency alone does not establish an outage."


def redact_secrets(text):
    """Best-effort redaction before parsing, provider requests, or persistence."""
    text = re.sub(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?(?:-----END [^-\r\n]*PRIVATE KEY-----|\Z)",
                  "[REDACTED PRIVATE KEY]", text, flags=re.S)
    text = re.sub(r"(?i)\b(authorization\s*[:=]\s*)(?:bearer|basic)\s+[^\s,;]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?im)(\b(?:cookie|set-cookie)\s*[:=]\s*)[^\r\n]+", r"\1[REDACTED]", text)
    # Handles password=x, JSON \"api_key\":\"x\", and URL query credentials.
    secret_names = r"password|passwd|pwd|api[_-]?key|access[_-]?key(?:[_-]?id)?|secret(?:[_-]?(?:key|access[_-]?key))?|(?:access[_-]?|refresh[_-]?|id[_-]?|auth[_-]?|session[_-]?)?token|client[_-]?secret|authorization|cookie|set-cookie"
    text = re.sub(rf"(?i)(\b(?:{secret_names})\b[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&}}]+)",
                  r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    text = re.sub(r"\b(?:AIza[\w-]{20,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9_-]{20,})\b", "[REDACTED]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED JWT]", text)
    return text


def parse_timestamp(line):
    match = TIMESTAMP.search(line)
    if not match:
        return None
    try:
        value = datetime.fromisoformat(match.group().replace(",", ".").replace("Z", "+00:00"))
        # Keep comparison deterministic. The report discloses this assumption.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def parse_lines(logs):
    if not isinstance(logs, str) or not logs.strip():
        raise ValueError("Provide at least one non-empty log line.")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in logs):
        raise ValueError("Logs contain binary or unsupported control characters. Use a UTF-8 text file.")
    return [line.strip() for line in logs.splitlines() if line.strip()]


def normalize_error(line):
    """Group changing timestamps/IDs/numbers while preserving HTTP status codes."""
    text = TIMESTAMP.sub("", line).strip(" []-:")
    text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<id>", text, flags=re.I)
    text = re.sub(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "<ip>", text)
    text = re.sub(r"(?i)\b(request_id|trace_id|transaction_id|order_id|pid)[=: ]+[^\s,;]+", r"\1=<id>", text)
    text = re.sub(r"\b\d+(?:\.\d+)?(?=ms\b|MB\b|GB\b|s\b|\b)", lambda match: match.group() if re.fullmatch(r"[45]\d\d", match.group()) else "<n>", text)
    return re.sub(r"\s+", " ", text).strip()[:500]


def classify_severity(error_count, signal_counts, fatal_count):
    if fatal_count or signal_counts.get("Resource exhaustion", 0) >= 3:
        return "Critical", "Fatal/panic/critical log entries or at least three resource-exhaustion signals require urgent impact verification."
    if error_count >= 10 or signal_counts.get("Database connection", 0) >= 3 or signal_counts.get("HTTP 5xx", 0) >= 3:
        return "High", "At least ten error lines, three database-connection errors, or three HTTP 5xx errors indicate repeated failure signals."
    if error_count:
        return "Medium", "One or more error signals were detected without meeting the higher urgency thresholds."
    return "Low", "No recognized error signals were found. This does not prove the service is healthy."


def build_guidance(signal_counts):
    causes, steps, teams = [], [], []
    checks = {
        "Timeout": ("An upstream dependency may be slow or unreachable; the logs do not establish why.", "Compare request latency and timeout timestamps with dependency health and network telemetry.", "Service owner / SRE"),
        "Database connection": ("Database reachability or connection-pool pressure may be involved; verify database health.", "Inspect database availability, connection limits, pool utilization, and recent configuration changes using read-only views.", "Database team"),
        "HTTP 5xx": ("A service or upstream dependency may be failing; status codes alone do not establish the root cause.", "Trace failing request IDs across service logs and compare 5xx rates with successful requests.", "Service owner / SRE"),
        "Authentication": ("Credentials, permissions, or identity-provider availability may be involved.", "Check credential expiry and permissions without printing secrets; inspect identity-provider health.", "Identity / security team"),
        "Resource exhaustion": ("Resource pressure or a capacity limit may be involved; its origin is unverified.", "Inspect memory, disk, file-descriptor, and connection metrics around the reported timestamps.", "Infrastructure / SRE"),
    }
    for signal, count in signal_counts.items():
        if count:
            cause, step, team = checks[signal]
            causes.append(cause)
            steps.append(step)
            if team not in teams:
                teams.append(team)
    if not causes:
        causes = ["Root cause is unknown. The supplied lines do not identify a specific failure mechanism."]
    return causes, ["Verify customer impact, service health, and whether the supplied logs cover the incident window."] + steps + ["Compare the incident window with recent deployments and configuration changes; preserve evidence before making changes."], teams or ["Service owner"]


def analyze_logs(logs, is_sample=False):
    if not isinstance(logs, str):
        raise ValueError("Logs must be supplied as text.")
    redacted_logs = redact_secrets(logs)
    lines = parse_lines(redacted_logs)
    patterns, timestamps = {}, []
    signal_counts = dict.fromkeys(SIGNALS, 0)
    error_count = fatal_count = 0
    services = []
    for line in lines:
        timestamp = parse_timestamp(line)
        if timestamp:
            timestamps.append(timestamp)
        service_match = re.search(r"\bservice[=:]\s*[\"']?([\w.-]{1,80})", line, flags=re.I)
        if service_match and service_match.group(1) not in services:
            services.append(service_match.group(1))
        matched_signals = [name for name, regex in SIGNAL_REGEX.items() if regex.search(line)]
        # Authentication failures and HTTP statuses count even without ERROR labels.
        if not ERROR_LEVEL.search(line) and not matched_signals:
            continue
        error_count += 1
        fatal_count += bool(re.search(r"\b(?:FATAL|CRITICAL|PANIC)\b", line, re.I))
        for signal in matched_signals:
            signal_counts[signal] += 1
        key = normalize_error(line)
        if key not in patterns:
            patterns[key] = dict(pattern=key, count=0, first_occurrence=None, last_occurrence=None,
                                 signals=matched_signals or ["Other errors"])
        pattern = patterns[key]
        pattern["count"] += 1
        if timestamp:
            pattern["first_occurrence"] = min(pattern["first_occurrence"] or timestamp, timestamp)
            pattern["last_occurrence"] = max(pattern["last_occurrence"] or timestamp, timestamp)
    severity, rationale = classify_severity(error_count, signal_counts, fatal_count)
    causes, steps, teams = build_guidance(signal_counts)
    evidence = [f"{error_count} of {len(lines)} non-empty lines match recognized error levels or failure signals.",
                f"{len(patterns)} normalized error patterns were identified."]
    evidence += [f"{name}: {count} matching lines." for name, count in signal_counts.items() if count]
    service = ", ".join(services[:3]) or "Unknown service"
    dominant = max(signal_counts, key=signal_counts.get) if any(signal_counts.values()) else "Log review"
    return dict(
        title=f"{dominant} · {service}", service=service, severity=severity,
        severity_rationale=rationale, severity_notice=SEVERITY_NOTICE,
        analysis_mode="rule-based", is_sample=bool(is_sample), total_lines=len(lines),
        total_error_lines=error_count, unique_error_patterns=len(patterns),
        time_range={"start": min(timestamps) if timestamps else None, "end": max(timestamps) if timestamps else None,
                    "note": "Parsed timestamps are normalized to UTC; timestamps without a timezone are assumed UTC. Unsupported formats are not inferred."},
        summary=f"Detected {error_count} error lines across {len(patterns)} patterns in {len(lines)} supplied lines for {service}. " + ("Review the observed signals and verify service impact." if error_count else "No recognized errors were found; unrecognized log formats may still contain failures."),
        observed_evidence=evidence, likely_causes=causes, root_cause="Unknown; diagnostic verification is required.",
        confidence_limitations="Log snippets cannot confirm root cause, customer impact, or complete service health. Pattern grouping is heuristic; signal categories may overlap.",
        potential_impact="Requests or dependent operations may be affected; the scope and customer impact are unknown." if error_count else "Impact is unknown. No recognized error signals were detected in this snippet.",
        recommended_steps=steps, escalation={"team": "; ".join(teams), "reason": "Route to the owners of the observed signals; confirm urgency using service metrics and customer impact." if error_count else "Consult the service owner if symptoms continue; this snippet does not establish a failure."},
        error_patterns=sorted(patterns.values(), key=lambda item: item["count"], reverse=True),
        signal_counts=signal_counts, warnings=[],
    )
