"""Optional Neon PostgreSQL incident history for PineOps AI.

This adapter has the same four public operations as incident_store.IncidentStore.
It preserves the report JSON without modifying Gemini, chat, or PDF behavior.
"""

from datetime import datetime, timezone
from uuid import uuid4

from incident_store import StorageError, validate_report


class PostgresIncidentStore:
    def __init__(self, database_url):
        if not isinstance(database_url, str) or not database_url.strip():
            raise StorageError("DATABASE_URL is not configured.")
        try:
            import psycopg
            from psycopg.types.json import Jsonb
        except ImportError as exc:
            raise StorageError("PostgreSQL driver missing. Install requirements.txt.") from exc

        self._psycopg = psycopg
        self._jsonb = Jsonb
        self._url = database_url.strip()
        try:
            with self._connect() as conn:
                conn.execute(
                    """CREATE TABLE IF NOT EXISTS pineops_incidents (
                         id TEXT PRIMARY KEY,
                         created_at TIMESTAMPTZ NOT NULL,
                         payload JSONB NOT NULL
                    )"""
                )
        except Exception as exc:
            raise StorageError("Cannot initialize Neon incident storage. Check DATABASE_URL and database availability.") from exc

    def _connect(self):
        # Neon pooled connections may use PgBouncer. Avoid session-prepared statements.
        return self._psycopg.connect(
            self._url,
            connect_timeout=10,
            prepare_threshold=None,
        )

    def list_incidents(self):
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT payload FROM pineops_incidents ORDER BY created_at DESC, id DESC"
                ).fetchall()
            reports = [row[0] for row in rows]
            for report in reports:
                validate_report(report)
            return reports
        except Exception as exc:
            raise StorageError("Cannot read incident history from Neon. Please check database availability.") from exc

    def get_incident(self, incident_id):
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT payload FROM pineops_incidents WHERE id = %s",
                    (incident_id,),
                ).fetchone()
            if row is None:
                return None
            validate_report(row[0])
            return row[0]
        except Exception as exc:
            raise StorageError("Cannot read the incident from Neon. Please check database availability.") from exc

    def save_incident(self, analysis):
        report = dict(
            analysis,
            id="INC-" + uuid4().hex[:12].upper(),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        validate_report(report)
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO pineops_incidents (id, created_at, payload) VALUES (%s, %s, %s)",
                    (report["id"], report["created_at"], self._jsonb(report)),
                )
            return report
        except Exception as exc:
            raise StorageError("Cannot save the incident to Neon. No local fallback was used.") from exc

    def delete_incident(self, incident_id):
        try:
            with self._connect() as conn:
                result = conn.execute(
                    "DELETE FROM pineops_incidents WHERE id = %s",
                    (incident_id,),
                )
                return result.rowcount > 0
        except Exception as exc:
            raise StorageError("Cannot delete the incident from Neon. Please check database availability.") from exc
