"""
Core data models for ReconAI findings.

All agents return Finding objects. The orchestrator collects them
into a ReconResult which flows to the AI analyzer and report generator.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def color(self) -> str:
        return {
            "critical": "red",
            "high": "dark_orange",
            "medium": "yellow",
            "low": "cyan",
            "info": "bright_black",
        }[self.value]

    @property
    def weight(self) -> int:
        """For sorting — higher = more severe."""
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class FindingType(str, Enum):
    DNS = "dns"
    PORT = "port"
    SERVICE = "service"
    WAF = "waf"
    TECH = "tech"
    OSINT = "osint"
    SCREENSHOT = "screenshot"
    AI_ANALYSIS = "ai_analysis"
    ERROR = "error"


@dataclass
class Finding:
    agent: str
    type: FindingType
    title: str
    description: str
    severity: Severity = Severity.INFO
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    mitre_techniques: list[str] = field(default_factory=list)
    raw: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "type": self.type.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "mitre_techniques": self.mitre_techniques,
        }


@dataclass
class ReconResult:
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    ai_analysis: str | None = None
    ai_attack_paths: list[str] = field(default_factory=list)
    error_count: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def by_type(self, type_: FindingType) -> list[Finding]:
        return [f for f in self.findings if f.type == type_]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.weight, reverse=True)

    @property
    def critical_count(self) -> int:
        return len(self.by_severity(Severity.CRITICAL))

    @property
    def high_count(self) -> int:
        return len(self.by_severity(Severity.HIGH))

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "findings": [f.to_dict() for f in self.findings],
            "ai_analysis": self.ai_analysis,
            "ai_attack_paths": self.ai_attack_paths,
            "error_count": self.error_count,
            "summary": {
                "total": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": len(self.by_severity(Severity.MEDIUM)),
                "low": len(self.by_severity(Severity.LOW)),
                "info": len(self.by_severity(Severity.INFO)),
            },
        }
