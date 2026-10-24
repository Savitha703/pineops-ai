import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from incident_analyzer import analyze_logs
from incident_store import IncidentStore, StorageError


class IncidentStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "data" / "incidents.json"
        self.store = IncidentStore(self.path)

    def save(self):
        return self.store.save_incident(analyze_logs("ERROR service=demo request timeout"))

    def test_missing_file_is_empty_without_writing(self):
        self.assertEqual(self.store.list_incidents(), [])
        self.assertFalse(self.path.exists())

    def test_save_list_get_and_reopen_complete_report(self):
        report = self.save()
        self.assertRegex(report["id"], r"^INC-[A-F0-9]{12}$")
        reopened_store = IncidentStore(self.path)
        self.assertEqual(reopened_store.get_incident(report["id"]), report)
        self.assertEqual(reopened_store.list_incidents(), [report])

    def test_ids_are_unique_and_newest_first(self):
        first, second = self.save(), self.save()
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(self.store.list_incidents()[0]["id"], second["id"])

    def test_delete_persists(self):
        report = self.save()
        self.assertTrue(self.store.delete_incident(report["id"]))
        self.assertEqual(IncidentStore(self.path).list_incidents(), [])
        self.assertIsNone(self.store.get_incident(report["id"]))
        self.assertFalse(self.store.delete_incident("missing"))

    def test_corrupt_json_never_overwritten(self):
        self.path.parent.mkdir()
        for content in ('{"incomplete":', '', '[]', '{"schema_version": 1, "incidents": [{}]}'):
            with self.subTest(content=content):
                self.path.write_text(content, encoding="utf-8")
                with self.assertRaises(StorageError):
                    self.save()
                with self.assertRaises(StorageError):
                    self.store.list_incidents()
                with self.assertRaises(StorageError):
                    self.store.delete_incident("missing")
                self.assertEqual(self.path.read_text(encoding="utf-8"), content)

    def test_inconsistent_report_and_duplicate_ids_preserved(self):
        report = self.save()
        for incidents in ([report, report], [dict(report, total_error_lines=100)]):
            content = json.dumps({"schema_version": 1, "incidents": incidents})
            self.path.write_text(content, encoding="utf-8")
            with self.assertRaises(StorageError):
                self.save()
            self.assertEqual(self.path.read_text(encoding="utf-8"), content)

    def test_failed_atomic_replace_preserves_existing_file(self):
        self.save()
        original = self.path.read_bytes()
        with patch("incident_store.os.replace", side_effect=PermissionError("locked")):
            with self.assertRaises(StorageError):
                self.save()
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_invalid_nested_timestamp_is_preserved(self):
        report = self.save()
        report["time_range"]["start"] = ["invalid"]
        content = json.dumps({"schema_version": 1, "incidents": [report]})
        self.path.write_text(content, encoding="utf-8")
        with self.assertRaises(StorageError):
            self.save()
        self.assertEqual(self.path.read_text(encoding="utf-8"), content)

    def test_threaded_saves_do_not_lose_reports(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: self.save(), range(8)))
        self.assertEqual(len(self.store.list_incidents()), 8)


if __name__ == "__main__":
    unittest.main()
