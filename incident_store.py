"""Single-process JSON history with validation and atomic replacement."""

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from uuid import uuid4


class StorageError(Exception):
    """The existing history could not be safely read or written."""


def validate_report(report):
    """Validate stored report structure before using or replacing the file."""
    text_fields = ["id", "created_at", "title", "service", "severity", "severity_rationale", "severity_notice", "analysis_mode", "summary", "root_cause", "confidence_limitations", "potential_impact"]
    if not isinstance(report, dict) or any(not isinstance(report.get(key), str) for key in text_fields):
        raise ValueError("Missing report fields.")
    if not re.fullmatch(r"INC-[A-F0-9]{12}", report["id"]):
        raise ValueError("Invalid incident ID.")
    if datetime.fromisoformat(report["created_at"]).tzinfo is None:
        raise ValueError("Creation time must have a timezone.")
    if report["severity"] not in {"Critical", "High", "Medium", "Low"} or report["analysis_mode"] not in {"rule-based", "AI-assisted"}:
        raise ValueError("Invalid classification.")
    for key in ["total_lines", "total_error_lines", "unique_error_patterns"]:
        if type(report.get(key)) is not int or report[key] < 0:
            raise ValueError("Invalid count.")
    if type(report.get("is_sample")) is not bool:
        raise ValueError("Missing source label.")
    for key in ["observed_evidence", "likely_causes", "recommended_steps", "warnings"]:
        if not isinstance(report.get(key), list) or any(not isinstance(item, str) for item in report[key]):
            raise ValueError("Invalid report list.")
    if not isinstance(report.get("time_range"), dict) or not all(key in report["time_range"] for key in ["start", "end", "note"]):
        raise ValueError("Invalid time range.")
    if not isinstance(report["time_range"]["note"], str):
        raise ValueError("Invalid timestamp note.")
    for key in ["start", "end"]:
        value = report["time_range"][key]
        if value is not None and (not isinstance(value, str) or datetime.fromisoformat(value).tzinfo is None):
            raise ValueError("Invalid timestamp value.")
    if not isinstance(report.get("escalation"), dict) or any(not isinstance(report["escalation"].get(key), str) for key in ["team", "reason"]):
        raise ValueError("Invalid escalation.")
    if not isinstance(report.get("signal_counts"), dict) or any(type(count) is not int or count < 0 for count in report["signal_counts"].values()):
        raise ValueError("Invalid signals.")
    if not isinstance(report.get("error_patterns"), list):
        raise ValueError("Invalid patterns.")
    for pattern in report["error_patterns"]:
        if not isinstance(pattern, dict) or not isinstance(pattern.get("pattern"), str) or type(pattern.get("count")) is not int or pattern["count"] < 1:
            raise ValueError("Invalid pattern.")
        if not all(key in pattern and (pattern[key] is None or isinstance(pattern[key], str)) for key in ["first_occurrence", "last_occurrence"]):
            raise ValueError("Invalid occurrence timestamp.")
        if not isinstance(pattern.get("signals"), list) or any(not isinstance(signal, str) for signal in pattern["signals"]):
            raise ValueError("Invalid pattern signals.")
    if report["unique_error_patterns"] != len(report["error_patterns"]) or report["total_error_lines"] != sum(item["count"] for item in report["error_patterns"]) or report["total_error_lines"] > report["total_lines"]:
        raise ValueError("Inconsistent counts.")
    if report["analysis_mode"] == "AI-assisted":
        from ai_validation import validate_guidance
        validate_guidance(report.get("ai_guidance"))


class IncidentStore:
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.lock = RLock()  # One app instance protects threaded read/modify/write.

    def _read(self):
        if not self.file_path.exists():
            return []
        try:
            data = json.loads(self.file_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1 or not isinstance(data.get("incidents"), list):
                raise ValueError("Unsupported history structure.")
            seen_ids = set()
            for report in data["incidents"]:
                validate_report(report)
                if report["id"] in seen_ids:
                    raise ValueError("Duplicate incident ID.")
                seen_ids.add(report["id"])
            return data["incidents"]
        except (OSError, ValueError, TypeError, KeyError) as error:
            raise StorageError("History could not be read or is corrupted. The existing file has been preserved. Back up data/incidents.json and restore a valid copy before saving more analyses.") from error

    def _write(self, incidents):
        temporary_path = None
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.file_path.parent, suffix=".tmp", delete=False) as handle:
                temporary_path = Path(handle.name)
                json.dump({"schema_version": 1, "incidents": incidents}, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.file_path)
        except OSError as error:
            raise StorageError("Could not save history. Check available disk space and file permissions; existing history was not intentionally replaced.") from error
        finally:
            if temporary_path and temporary_path.exists():
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass  # Preserve the original error if temporary cleanup fails.

    def list_incidents(self):
        with self.lock:
            return sorted(self._read(), key=lambda item: item["created_at"], reverse=True)

    def get_incident(self, incident_id):
        return next((item for item in self.list_incidents() if item["id"] == incident_id), None)

    def save_incident(self, analysis):
        with self.lock:
            incidents = self._read()
            report = dict(analysis, id="INC-" + uuid4().hex[:12].upper(), created_at=datetime.now(timezone.utc).isoformat())
            validate_report(report)
            incidents.append(report)
            self._write(incidents)
            return report

    def delete_incident(self, incident_id):
        with self.lock:
            incidents = self._read()
            remaining = [item for item in incidents if item["id"] != incident_id]
            if len(remaining) == len(incidents):
                return False
            self._write(remaining)
            return True
