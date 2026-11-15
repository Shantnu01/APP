#!/usr/bin/env python3
"""
RepoGuard - Multi-Ecosystem Repository Security & Dependency Vulnerability Auditor

Course: AA1 - Advanced Programming Practices
Faculty: Prof. Salomi Samsudeen
Development Team:
- Shantnu (Team Lead & Core Backend Architect)
- Arya Agrawal (Frontend GUI & Data Visualization Engineer)
- Raiyan Kamal (Database, Java XML Parser & Multi-Ecosystem Engineer)
"""

import os
import sys
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def enable_windows_dpi_awareness():
    """Enables crisp high-DPI rendering on Windows displays."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                import ctypes
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


def run_cli_audit(url: str, output_format: str = "text"):
    """Command-line interface mode for automated pipeline or headless scanning."""
    from core.github_engine import GitHubEngine
    from parsers import parse_manifests
    from core.osv_scanner import OSVScanner
    from core.models import RiskMetrics, ScanReport
    from core.reporter import AuditReporter
    from datetime import datetime, timezone

    print(f"[RepoGuard CLI] Auditing repository: {url}")
    owner, repo, canonical = GitHubEngine.parse_repo_url(url)
    engine = GitHubEngine()

    print(f"[*] Resolving commit SHA for {owner}/{repo}...")
    sha = engine.get_commit_sha(owner, repo)
    print(f"[*] Downloading snapshot ({sha[:8]})...")
    manifests = engine.fetch_manifest_files(owner, repo, sha)
    print(f"[*] Found {len(manifests)} manifest files.")

    deps = parse_manifests(manifests)
    print(f"[*] Discovered {len(deps)} pinned dependencies across Python, npm, Maven, and Go.")

    print(f"[*] Cross-referencing against OSV vulnerability database...")
    scanner = OSVScanner()
    findings = scanner.scan_dependencies(deps)

    metrics = RiskMetrics.calculate(findings)
    report = ScanReport(
        repo_url=canonical,
        owner=owner,
        repo_name=repo,
        commit_sha=sha,
        scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        status="COMPLETED",
        findings=findings,
        metrics=metrics,
    )

    print("\n" + "=" * 60)
    print(f" AUDIT SUMMARY: {owner}/{repo}")
    print("=" * 60)
    print(f"  Total Dependencies  : {metrics.total_dependencies}")
    print(f"  Vulnerable Packages : {metrics.vulnerable_dependencies}")
    print(f"  Clean Packages      : {metrics.clean_dependencies}")
    print(f"  Total Advisories    : {metrics.total_vulnerabilities}")
    print(f"  Critical Severities : {metrics.critical_count}")
    print(f"  High Severities     : {metrics.high_count}")
    print(f"  Risk Index Score    : {metrics.risk_score} / 100 ({metrics.risk_rating} Risk)")
    print("=" * 60)

    if output_format == "html":
        out_file = f"repoguard_{repo}_report.html"
        AuditReporter.export_html(report, out_file)
        print(f"[+] HTML Report generated at: {out_file}")
    elif output_format == "json":
        out_file = f"repoguard_{repo}_report.json"
        AuditReporter.export_json(report, out_file)
        print(f"[+] JSON Report generated at: {out_file}")


def main():
    parser = argparse.ArgumentParser(description="RepoGuard Security & Dependency Auditor")
    parser.add_argument("--cli", type=str, help="Run in headless CLI mode against the specified GitHub URL")
    parser.add_argument("--format", type=str, choices=["text", "html", "json"], default="text", help="Output format for CLI mode")
    args = parser.parse_args()

    if args.cli:
        run_cli_audit(args.cli, args.format)
    else:
        enable_windows_dpi_awareness()
        from gui.main_window import MainWindow
        app = MainWindow()
        app.mainloop()


if __name__ == "__main__":
    main()
