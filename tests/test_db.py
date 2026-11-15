"""
Unit tests for RepoGuard SQLite database manager.
"""

import tempfile
import unittest
from pathlib import Path

from core.db_manager import DatabaseManager
from core.models import (
    Dependency,
    DependencyFinding,
    RiskMetrics,
    ScanReport,
    SeverityLevel,
    Vulnerability,
)


class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_audit.db"
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_and_load_scan(self):
        dep = Dependency(ecosystem="PyPI", name="flask", version="0.12", manifest_path="requirements.txt")
        vuln = Vulnerability(
            advisory_id="GHSA-test1234",
            summary="Denial of service in flask",
            severity=SeverityLevel.HIGH,
            reference_url="https://example.com/advisory",
        )
        finding = DependencyFinding(dependency=dep, vulnerabilities=[vuln])
        metrics = RiskMetrics.calculate([finding])

        report = ScanReport(
            repo_url="https://github.com/example/test-repo",
            owner="example",
            repo_name="test-repo",
            commit_sha="abcdef123456",
            scanned_at="2026-11-15 10:00:00 UTC",
            status="COMPLETED",
            findings=[finding],
            metrics=metrics,
        )

        scan_id = self.db.save_scan(report)
        self.assertIsNotNone(scan_id)

        loaded = self.db.load_scan(scan_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.owner, "example")
        self.assertEqual(loaded.repo_name, "test-repo")
        self.assertEqual(len(loaded.findings), 1)
        self.assertEqual(loaded.findings[0].dependency.name, "flask")
        self.assertEqual(len(loaded.findings[0].vulnerabilities), 1)
        self.assertEqual(loaded.findings[0].vulnerabilities[0].advisory_id, "GHSA-test1234")


if __name__ == "__main__":
    unittest.main()
