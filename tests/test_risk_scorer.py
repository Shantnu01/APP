"""
Unit tests for RepoGuard risk metrics scoring calculation.
"""

import unittest
from core.models import (
    Dependency,
    DependencyFinding,
    RiskMetrics,
    SeverityLevel,
    Vulnerability,
)


class TestRiskMetrics(unittest.TestCase):
    def test_clean_dependencies(self):
        findings = [
            DependencyFinding(dependency=Dependency("PyPI", "safe-pkg", "1.0.0", "req.txt")),
            DependencyFinding(dependency=Dependency("npm", "clean-lib", "2.0.0", "pkg.json")),
        ]
        metrics = RiskMetrics.calculate(findings)
        self.assertEqual(metrics.total_dependencies, 2)
        self.assertEqual(metrics.clean_dependencies, 2)
        self.assertEqual(metrics.vulnerable_dependencies, 0)
        self.assertEqual(metrics.risk_score, 0.0)
        self.assertEqual(metrics.risk_rating, "Safe")

    def test_critical_vulnerability(self):
        vuln = Vulnerability(
            advisory_id="GHSA-test",
            summary="RCE flaw",
            severity=SeverityLevel.CRITICAL,
        )
        findings = [
            DependencyFinding(
                dependency=Dependency("Maven", "vuln-pkg", "1.0.0", "pom.xml"),
                vulnerabilities=[vuln],
            )
        ]
        metrics = RiskMetrics.calculate(findings)
        self.assertEqual(metrics.critical_count, 1)
        self.assertEqual(metrics.risk_rating, "Critical")
        self.assertGreater(metrics.risk_score, 50.0)


if __name__ == "__main__":
    unittest.main()
