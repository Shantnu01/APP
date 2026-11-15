"""
RepoGuard Database Manager
Encapsulates thread-safe SQLite persistence for repositories, scans,
dependency inventories, and vulnerability advisory findings.
"""

from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Dict, Any, Generator

from core.models import (
    Dependency,
    DependencyFinding,
    RiskMetrics,
    ScanReport,
    SeverityLevel,
    Vulnerability,
)


class DatabaseManager:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = Path(__file__).resolve().parent.parent / "repoguard.db"
        else:
            self.db_path = db_path
        self._init_db()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS repositories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL UNIQUE,
                    owner TEXT NOT NULL,
                    name TEXT NOT NULL,
                    added_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repository_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
                    commit_sha TEXT NOT NULL,
                    scanned_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    dependency_count INTEGER NOT NULL DEFAULT 0,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    risk_rating TEXT NOT NULL DEFAULT 'Safe'
                );

                CREATE TABLE IF NOT EXISTS dependencies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    manifest_path TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dependency_id INTEGER NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
                    advisory_id TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reference_url TEXT NOT NULL,
                    published TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repository_id);
                CREATE INDEX IF NOT EXISTS idx_deps_scan ON dependencies(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_dep ON findings(dependency_id);
                """
            )

    def save_scan(self, report: ScanReport) -> int:
        with self._connection() as conn:
            cursor = conn.cursor()

            # Insert or get repository
            cursor.execute("SELECT id FROM repositories WHERE url = ?", (report.repo_url,))
            row = cursor.fetchone()
            if row:
                repo_id = row["id"]
            else:
                cursor.execute(
                    "INSERT INTO repositories (url, owner, name, added_at) VALUES (?, ?, ?, ?)",
                    (report.repo_url, report.owner, report.repo_name, report.scanned_at),
                )
                repo_id = cursor.lastrowid

            # Insert scan
            cursor.execute(
                """
                INSERT INTO scans (
                    repository_id, commit_sha, scanned_at, status,
                    dependency_count, finding_count, risk_score, risk_rating
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repo_id,
                    report.commit_sha,
                    report.scanned_at,
                    report.status,
                    report.metrics.total_dependencies,
                    report.metrics.total_vulnerabilities,
                    report.metrics.risk_score,
                    report.metrics.risk_rating,
                ),
            )
            scan_id = cursor.lastrowid
            report.scan_id = scan_id

            # Insert dependencies and findings
            for finding in report.findings:
                dep = finding.dependency
                cursor.execute(
                    """
                    INSERT INTO dependencies (scan_id, ecosystem, package_name, version, manifest_path)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (scan_id, dep.ecosystem, dep.name, dep.version, dep.manifest_path),
                )
                dep_id = cursor.lastrowid

                for vuln in finding.vulnerabilities:
                    cursor.execute(
                        """
                        INSERT INTO findings (
                            dependency_id, advisory_id, summary, severity, reference_url, published
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            dep_id,
                            vuln.advisory_id,
                            vuln.summary,
                            vuln.severity.value,
                            vuln.reference_url,
                            vuln.published,
                        ),
                    )

            conn.commit()
            return scan_id

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    s.id AS scan_id,
                    r.url AS repo_url,
                    r.owner,
                    r.name AS repo_name,
                    s.commit_sha,
                    s.scanned_at,
                    s.status,
                    s.dependency_count,
                    s.finding_count,
                    s.risk_score,
                    s.risk_rating
                FROM scans s
                JOIN repositories r ON s.repository_id = r.id
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def load_scan(self, scan_id: int) -> Optional[ScanReport]:
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    s.id AS scan_id,
                    r.url AS repo_url,
                    r.owner,
                    r.name AS repo_name,
                    s.commit_sha,
                    s.scanned_at,
                    s.status
                FROM scans s
                JOIN repositories r ON s.repository_id = r.id
                WHERE s.id = ?
                """,
                (scan_id,),
            )
            scan_row = cursor.fetchone()
            if not scan_row:
                return None

            cursor.execute(
                "SELECT id, ecosystem, package_name, version, manifest_path FROM dependencies WHERE scan_id = ?",
                (scan_id,),
            )
            dep_rows = cursor.fetchall()

            findings_list: List[DependencyFinding] = []
            for dep_row in dep_rows:
                dep_id = dep_row["id"]
                dep = Dependency(
                    ecosystem=dep_row["ecosystem"],
                    name=dep_row["package_name"],
                    version=dep_row["version"],
                    manifest_path=dep_row["manifest_path"],
                )

                cursor.execute(
                    "SELECT advisory_id, summary, severity, reference_url, published FROM findings WHERE dependency_id = ?",
                    (dep_id,),
                )
                vuln_rows = cursor.fetchall()
                vulns = [
                    Vulnerability(
                        advisory_id=v["advisory_id"],
                        summary=v["summary"],
                        severity=SeverityLevel.from_str(v["severity"]),
                        reference_url=v["reference_url"],
                        published=v["published"],
                    )
                    for v in vuln_rows
                ]
                findings_list.append(DependencyFinding(dependency=dep, vulnerabilities=vulns))

            metrics = RiskMetrics.calculate(findings_list)

            return ScanReport(
                repo_url=scan_row["repo_url"],
                owner=scan_row["owner"],
                repo_name=scan_row["repo_name"],
                commit_sha=scan_row["commit_sha"],
                scanned_at=scan_row["scanned_at"],
                status=scan_row["status"],
                findings=findings_list,
                metrics=metrics,
                scan_id=scan_id,
            )

    def delete_scan(self, scan_id: int) -> None:
        with self._connection() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()

    def clear_all(self) -> None:
        with self._connection() as conn:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM dependencies")
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM repositories")
            conn.commit()
