"""
RepoGuard Core Data Models
Defines immutable and structured representations for dependencies,
vulnerabilities, audit metrics, and complete scan reports.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, val: str) -> "SeverityLevel":
        if not val:
            return cls.UNKNOWN
        val_upper = val.strip().upper()
        if "CRIT" in val_upper:
            return cls.CRITICAL
        if "HIGH" in val_upper:
            return cls.HIGH
        if "MOD" in val_upper or "MED" in val_upper:
            return cls.MODERATE
        if "LOW" in val_upper:
            return cls.LOW
        return cls.UNKNOWN

    @property
    def badge_color(self) -> str:
        colors = {
            SeverityLevel.CRITICAL: "#DC2626",  # Red
            SeverityLevel.HIGH: "#EA580C",      # Orange
            SeverityLevel.MODERATE: "#D97706",  # Amber/Yellow
            SeverityLevel.LOW: "#2563EB",       # Blue
            SeverityLevel.UNKNOWN: "#64748B",   # Slate Gray
        }
        return colors.get(self, "#64748B")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    manifest_path: str

    @property
    def display_name(self) -> str:
        return f"{self.name} @ {self.version}"


@dataclass
class Vulnerability:
    advisory_id: str
    summary: str
    severity: SeverityLevel
    details: str = ""
    reference_url: str = ""
    published: str = ""


@dataclass
class DependencyFinding:
    dependency: Dependency
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def highest_severity(self) -> SeverityLevel:
        if not self.vulnerabilities:
            return SeverityLevel.UNKNOWN
        order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MODERATE,
            SeverityLevel.LOW,
            SeverityLevel.UNKNOWN,
        ]
        for level in order:
            if any(v.severity == level for v in self.vulnerabilities):
                return level
        return SeverityLevel.UNKNOWN


@dataclass
class RiskMetrics:
    total_dependencies: int = 0
    vulnerable_dependencies: int = 0
    clean_dependencies: int = 0
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    moderate_count: int = 0
    low_count: int = 0
    unknown_count: int = 0
    risk_score: float = 0.0  # Normalized 0.0 - 100.0
    risk_rating: str = "Safe"  # "Safe", "Low", "Medium", "High", "Critical"

    @classmethod
    def calculate(cls, findings: List[DependencyFinding]) -> "RiskMetrics":
        total_deps = len(findings)
        vuln_deps = sum(1 for f in findings if f.has_vulnerabilities)
        clean_deps = total_deps - vuln_deps

        total_vulns = 0
        crit = high = mod = low = unk = 0

        for f in findings:
            for v in f.vulnerabilities:
                total_vulns += 1
                if v.severity == SeverityLevel.CRITICAL:
                    crit += 1
                elif v.severity == SeverityLevel.HIGH:
                    high += 1
                elif v.severity == SeverityLevel.MODERATE:
                    mod += 1
                elif v.severity == SeverityLevel.LOW:
                    low += 1
                else:
                    unk += 1

        # Calculate weighted composite risk score (0 to 100)
        # Weights: Critical=10, High=6, Moderate=3, Low=1, Unknown=1.5
        raw_score = (crit * 10.0) + (high * 6.0) + (mod * 3.0) + (low * 1.0) + (unk * 1.5)
        # Scale logarithmically/proportionally to cap at 100
        if total_deps > 0:
            weighted_density = (raw_score / total_deps) * 20.0
            risk_score = min(100.0, max(0.0, weighted_density))
        else:
            risk_score = 0.0

        if crit > 0 or risk_score >= 75.0:
            risk_rating = "Critical"
        elif high > 0 or risk_score >= 50.0:
            risk_rating = "High"
        elif mod > 0 or risk_score >= 25.0:
            risk_rating = "Moderate"
        elif low > 0 or risk_score > 0.0:
            risk_rating = "Low"
        else:
            risk_rating = "Safe"

        return cls(
            total_dependencies=total_deps,
            vulnerable_dependencies=vuln_deps,
            clean_dependencies=clean_deps,
            total_vulnerabilities=total_vulns,
            critical_count=crit,
            high_count=high,
            moderate_count=mod,
            low_count=low,
            unknown_count=unk,
            risk_score=round(risk_score, 1),
            risk_rating=risk_rating,
        )


@dataclass
class ScanReport:
    repo_url: str
    owner: str
    repo_name: str
    commit_sha: str
    scanned_at: str
    status: str
    findings: List[DependencyFinding]
    metrics: RiskMetrics
    scan_id: Optional[int] = None
