"""
RepoGuard Audit Reporter
Exports vulnerability findings and risk summaries into CSV, JSON, and
publication-ready standalone HTML executive reports.
"""

from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Union
from core.models import ScanReport, SeverityLevel


class AuditReporter:
    @staticmethod
    def export_csv(report: ScanReport, destination: Union[str, Path]) -> None:
        """Exports tabular findings to standard CSV."""
        with open(destination, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Ecosystem",
                "Package Name",
                "Installed Version",
                "Manifest Path",
                "Advisory ID",
                "Severity",
                "Advisory Summary",
                "Reference URL",
            ])

            for finding in report.findings:
                dep = finding.dependency
                if not finding.vulnerabilities:
                    writer.writerow([
                        dep.ecosystem,
                        dep.name,
                        dep.version,
                        dep.manifest_path,
                        "CLEAN",
                        "NONE",
                        "No known published advisories found",
                        "",
                    ])
                else:
                    for v in finding.vulnerabilities:
                        writer.writerow([
                            dep.ecosystem,
                            dep.name,
                            dep.version,
                            dep.manifest_path,
                            v.advisory_id,
                            v.severity.value,
                            v.summary,
                            v.reference_url,
                        ])

    @staticmethod
    def export_json(report: ScanReport, destination: Union[str, Path]) -> None:
        """Exports complete hierarchical scan data to formatted JSON."""
        data = {
            "repository": {
                "url": report.repo_url,
                "owner": report.owner,
                "name": report.repo_name,
                "commit_sha": report.commit_sha,
                "scanned_at": report.scanned_at,
            },
            "metrics": {
                "risk_score": report.metrics.risk_score,
                "risk_rating": report.metrics.risk_rating,
                "total_dependencies": report.metrics.total_dependencies,
                "vulnerable_dependencies": report.metrics.vulnerable_dependencies,
                "clean_dependencies": report.metrics.clean_dependencies,
                "total_vulnerabilities": report.metrics.total_vulnerabilities,
                "severity_counts": {
                    "critical": report.metrics.critical_count,
                    "high": report.metrics.high_count,
                    "moderate": report.metrics.moderate_count,
                    "low": report.metrics.low_count,
                    "unknown": report.metrics.unknown_count,
                },
            },
            "findings": [
                {
                    "ecosystem": f.dependency.ecosystem,
                    "package": f.dependency.name,
                    "version": f.dependency.version,
                    "manifest": f.dependency.manifest_path,
                    "is_vulnerable": f.has_vulnerabilities,
                    "vulnerabilities": [
                        {
                            "advisory_id": v.advisory_id,
                            "severity": v.severity.value,
                            "summary": v.summary,
                            "reference_url": v.reference_url,
                            "published": v.published,
                        }
                        for v in f.vulnerabilities
                    ],
                }
                for f in report.findings
            ],
            "audit_team": ["Shantnu", "Arya Agrawal", "Raiyan Kamal"],
            "tool": "RepoGuard Security Auditor v2.0",
        }

        with open(destination, mode="w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_html(report: ScanReport, destination: Union[str, Path]) -> None:
        """Generates a standalone, beautifully formatted executive HTML audit report."""
        m = report.metrics

        rating_colors = {
            "Critical": "#DC2626",
            "High": "#EA580C",
            "Moderate": "#D97706",
            "Low": "#2563EB",
            "Safe": "#16A34A",
        }
        badge_bg = rating_colors.get(m.risk_rating, "#4B5563")

        rows_html = []
        for finding in report.findings:
            dep = finding.dependency
            if not finding.vulnerabilities:
                rows_html.append(f"""
                <tr class="clean-row">
                    <td><span class="eco-badge">{dep.ecosystem}</span></td>
                    <td><strong>{dep.name}</strong></td>
                    <td><code>{dep.version}</code></td>
                    <td><span class="badge badge-clean">CLEAN</span></td>
                    <td>-</td>
                    <td>No known vulnerabilities detected.</td>
                    <td><span class="manifest-path">{dep.manifest_path}</span></td>
                </tr>
                """)
            else:
                for v in finding.vulnerabilities:
                    sev_class = f"badge-{v.severity.value.lower()}"
                    link_html = f'<a href="{v.reference_url}" target="_blank" class="adv-link">{v.advisory_id} &nearr;</a>' if v.reference_url else v.advisory_id
                    rows_html.append(f"""
                    <tr class="vuln-row">
                        <td><span class="eco-badge">{dep.ecosystem}</span></td>
                        <td><strong>{dep.name}</strong></td>
                        <td><code>{dep.version}</code></td>
                        <td><span class="badge {sev_class}">{v.severity.value}</span></td>
                        <td>{link_html}</td>
                        <td>{v.summary}</td>
                        <td><span class="manifest-path">{dep.manifest_path}</span></td>
                    </tr>
                    """)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RepoGuard Security Audit &mdash; {report.owner}/{report.repo_name}</title>
    <style>
        :root {{
            --bg: #0F172A;
            --surface: #1E293B;
            --surface-card: #334155;
            --text-main: #F8FAFC;
            --text-muted: #94A3B8;
            --border: #475569;
            --accent: #38BDF8;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header-title h1 {{
            margin: 0 0 5px 0;
            font-size: 28px;
            letter-spacing: -0.5px;
        }}
        .header-title p {{
            margin: 0;
            color: var(--text-muted);
            font-size: 14px;
        }}
        .risk-badge {{
            background: {badge_bg};
            padding: 12px 24px;
            border-radius: 12px;
            text-align: center;
            color: #FFF;
            box-shadow: 0 4px 14px rgba(0,0,0,0.4);
        }}
        .risk-badge .score {{
            font-size: 32px;
            font-weight: 800;
            display: block;
            line-height: 1;
        }}
        .risk-badge .label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
            font-weight: 600;
        }}
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        }}
        .card .title {{
            font-size: 13px;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        .card .value {{
            font-size: 26px;
            font-weight: 700;
        }}
        .crit-text {{ color: #EF4444; }}
        .high-text {{ color: #F97316; }}
        .mod-text {{ color: #F59E0B; }}
        .clean-text {{ color: #10B981; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.25);
            font-size: 14px;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #111827;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        tr:hover {{
            background: rgba(255,255,255,0.03);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: #FFF;
        }}
        .badge-critical {{ background: #DC2626; }}
        .badge-high {{ background: #EA580C; }}
        .badge-moderate {{ background: #D97706; }}
        .badge-low {{ background: #2563EB; }}
        .badge-unknown {{ background: #64748B; }}
        .badge-clean {{ background: #16A34A; }}
        .eco-badge {{
            background: var(--surface-card);
            padding: 3px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}
        .manifest-path {{
            font-family: monospace;
            font-size: 11px;
            color: var(--text-muted);
        }}
        .adv-link {{
            color: var(--accent);
            text-decoration: none;
            font-weight: 600;
        }}
        .adv-link:hover {{
            text-decoration: underline;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title">
                <h1>RepoGuard Security Audit Report</h1>
                <p>Repository: <a href="{report.repo_url}" target="_blank" style="color:var(--accent); text-decoration:none;">{report.owner}/{report.repo_name}</a> &bull; Commit: <code>{report.commit_sha[:10]}</code> &bull; Scanned: {report.scanned_at}</p>
            </div>
            <div class="risk-badge">
                <span class="score">{m.risk_score}</span>
                <span class="label">{m.risk_rating} Risk</span>
            </div>
        </div>

        <div class="cards-grid">
            <div class="card">
                <div class="title">Total Dependencies</div>
                <div class="value">{m.total_dependencies}</div>
            </div>
            <div class="card">
                <div class="title">Clean Packages</div>
                <div class="value clean-text">{m.clean_dependencies}</div>
            </div>
            <div class="card">
                <div class="title">Total Advisories</div>
                <div class="value">{m.total_vulnerabilities}</div>
            </div>
            <div class="card">
                <div class="title">Critical Severity</div>
                <div class="value crit-text">{m.critical_count}</div>
            </div>
            <div class="card">
                <div class="title">High Severity</div>
                <div class="value high-text">{m.high_count}</div>
            </div>
            <div class="card">
                <div class="title">Moderate Severity</div>
                <div class="value mod-text">{m.moderate_count}</div>
            </div>
        </div>

        <h2>Detailed Vulnerability & Dependency Inventory</h2>
        <table>
            <thead>
                <tr>
                    <th>Ecosystem</th>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Severity</th>
                    <th>Advisory ID</th>
                    <th>Summary</th>
                    <th>Manifest File</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows_html)}
            </tbody>
        </table>

        <div class="footer">
            <p>Generated by <strong>RepoGuard Security Auditor v2.0</strong></p>
            <p>Project Team: <strong>Shantnu, Arya Agrawal, Raiyan Kamal</strong> &bull; Course: <strong>AA1 - Advanced Programming Practices</strong> &bull; Faculty: <strong>Prof. Salomi Samsudeen</strong></p>
        </div>
    </div>
</body>
</html>"""

        with open(destination, mode="w", encoding="utf-8") as f:
            f.write(html_content)
