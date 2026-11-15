"""
RepoGuard OSV Vulnerability Scanner
Asynchronously queries the Open Source Vulnerabilities (OSV) API using thread pooling
to cross-reference extracted dependencies against known security advisories.
"""

from __future__ import annotations
import json
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from core.models import (
    Dependency,
    DependencyFinding,
    SeverityLevel,
    Vulnerability,
)

OSV_API_URL = "https://api.osv.dev/v1/query"
USER_AGENT = "RepoGuard-Vulnerability-Scanner/2.0 (Academic; Shantnu, Arya Agrawal, Raiyan Kamal)"


class OSVScanner:
    def __init__(self, max_workers: int = 6, timeout: int = 25):
        self.max_workers = max_workers
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context()

    def _extract_severity(self, vuln_data: dict) -> SeverityLevel:
        """Derives standard severity level from OSV database_specific or CVSS fields."""
        # 1. Check database_specific.severity
        db_spec = vuln_data.get("database_specific", {})
        if isinstance(db_spec, dict):
            raw_sev = db_spec.get("severity")
            if raw_sev and isinstance(raw_sev, str):
                return SeverityLevel.from_str(raw_sev)

        # 2. Check ecosystem_specific
        eco_spec = vuln_data.get("ecosystem_specific", {})
        if isinstance(eco_spec, dict):
            raw_sev = eco_spec.get("severity")
            if raw_sev and isinstance(raw_sev, str):
                return SeverityLevel.from_str(raw_sev)

        # 3. Check severity array (CVSS vectors)
        severities = vuln_data.get("severity", [])
        if isinstance(severities, list):
            for s in severities:
                if isinstance(s, dict) and s.get("type") == "CVSS_V3":
                    score_str = s.get("score", "")
                    # If score is numeric (e.g. "9.8")
                    try:
                        score_val = float(score_str)
                        if score_val >= 9.0:
                            return SeverityLevel.CRITICAL
                        elif score_val >= 7.0:
                            return SeverityLevel.HIGH
                        elif score_val >= 4.0:
                            return SeverityLevel.MODERATE
                        else:
                            return SeverityLevel.LOW
                    except ValueError:
                        pass

        # 4. Keyword heuristic in summary or details
        text = (vuln_data.get("summary", "") + " " + vuln_data.get("details", "")).lower()
        if "critical" in text or "remote code execution" in text or "rce" in text:
            return SeverityLevel.CRITICAL
        elif "high" in text or "denial of service" in text or "dos" in text:
            return SeverityLevel.HIGH
        elif "moderate" in text or "medium" in text:
            return SeverityLevel.MODERATE

        return SeverityLevel.UNKNOWN

    def _extract_reference_url(self, vuln_data: dict, advisory_id: str) -> str:
        """Finds the most informative reference URL or generates canonical OSV link."""
        refs = vuln_data.get("references", [])
        if isinstance(refs, list):
            # Prefer advisory or web links
            for r in refs:
                if isinstance(r, dict) and r.get("type") in {"ADVISORY", "WEB"}:
                    url = r.get("url", "")
                    if url.startswith("http"):
                        return url
            # Fallback to any URL
            for r in refs:
                if isinstance(r, dict):
                    url = r.get("url", "")
                    if url.startswith("http"):
                        return url

        return f"https://osv.dev/vulnerability/{advisory_id}"

    def check_dependency(self, dep: Dependency) -> DependencyFinding:
        """Queries OSV for a single dependency version."""
        payload = {
            "package": {
                "name": dep.name,
                "ecosystem": dep.ecosystem,
            },
            "version": dep.version,
        }

        req = Request(
            OSV_API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )

        vulnerabilities: List[Vulnerability] = []

        try:
            with urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vulns_raw = data.get("vulns", [])

                for v in vulns_raw:
                    adv_id = v.get("id", "UNKNOWN-ADVISORY")
                    summary = v.get("summary") or v.get("details", "No detailed summary provided.")
                    # Truncate summary if too long for clean presentation
                    if len(summary) > 200:
                        summary = summary[:197] + "..."

                    severity = self._extract_severity(v)
                    ref_url = self._extract_reference_url(v, adv_id)
                    published = v.get("published", "")

                    vulnerabilities.append(
                        Vulnerability(
                            advisory_id=adv_id,
                            summary=summary,
                            severity=severity,
                            details=v.get("details", ""),
                            reference_url=ref_url,
                            published=published,
                        )
                    )

        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            # Gracefully handle per-dependency failure without terminating the whole audit
            pass
        except Exception:
            pass

        return DependencyFinding(dependency=dep, vulnerabilities=vulnerabilities)

    def scan_dependencies(
        self,
        dependencies: List[Dependency],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> List[DependencyFinding]:
        """
        Executes parallel vulnerability resolution for all discovered dependencies.
        Optional callback signature: progress_callback(completed, total, current_item_name)
        """
        findings: List[DependencyFinding] = []
        total = len(dependencies)
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_dep = {
                executor.submit(self.check_dependency, dep): dep for dep in dependencies
            }

            for future in as_completed(future_to_dep):
                dep = future_to_dep[future]
                try:
                    finding = future.result()
                    findings.append(finding)
                except Exception:
                    findings.append(DependencyFinding(dependency=dep, vulnerabilities=[]))

                completed += 1
                if progress_callback:
                    progress_callback(completed, total, f"{dep.name} ({dep.ecosystem})")

        return findings
