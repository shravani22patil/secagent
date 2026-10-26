"""The non-negotiable output contract. extra='forbid' everywhere; invariants are cross-checked."""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.validators import validate_ip

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


def severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class OpenPort(_Strict):
    port: int = Field(ge=1, le=65535, description="Port number")
    protocol: Literal["tcp", "udp"] = "tcp"


class DetectedService(_Strict):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    name: str = Field(min_length=1, max_length=64, description="Service name, e.g. ssh")
    product: str | None = Field(default=None, max_length=128, description="e.g. OpenSSH")
    version: str | None = Field(default=None, max_length=64, description="e.g. 7.2p2")
    banner: str | None = Field(default=None, max_length=256)


class IdentifiedCVE(_Strict):
    cve_id: str = Field(pattern=CVE_PATTERN)
    severity: Severity
    cvss_score: float = Field(ge=0, le=10)
    affected_port: int = Field(ge=1, le=65535)
    affected_service: str = Field(max_length=160, description="product + version")
    summary: str = Field(max_length=500)
    exploit_path: str = Field(max_length=600, description="High-level attack path, no payloads")

    @model_validator(mode="after")
    def _derive_severity(self) -> "IdentifiedCVE":
        # Severity is a pure function of the CVSS score; never trust the model's label.
        object.__setattr__(self, "severity", severity_from_cvss(self.cvss_score))
        return self


class RemediationStep(_Strict):
    step: int = Field(ge=1)
    action: str = Field(min_length=3, max_length=500)
    priority: Severity
    related_cves: list[str] = Field(default_factory=list)


class ReconFindings(_Strict):
    """Handoff contract between Agent 1 (recon) and Agent 2 (analyst)."""

    target_host: str
    open_ports: list[OpenPort]
    detected_services: list[DetectedService]


class ThreatReport(_Strict):
    target_host: str
    open_ports: list[OpenPort]
    detected_services: list[DetectedService]
    identified_cves: list[IdentifiedCVE]
    recommended_remediation_plan: list[RemediationStep] = Field(min_length=1)

    @field_validator("target_host")
    @classmethod
    def _ip_only(cls, v: str) -> str:
        return validate_ip(v)

    @model_validator(mode="after")
    def _invariants(self) -> "ThreatReport":
        open_set = {(p.port, p.protocol) for p in self.open_ports}
        open_nums = {p.port for p in self.open_ports}
        for s in self.detected_services:
            if (s.port, s.protocol) not in open_set:
                raise ValueError(f"service on {s.port}/{s.protocol} is not listed in open_ports")
        for c in self.identified_cves:
            if c.affected_port not in open_nums:
                raise ValueError(f"{c.cve_id} references port {c.affected_port} which is not open")
        ids = {c.cve_id for c in self.identified_cves}
        steps = self.recommended_remediation_plan
        if [s.step for s in steps] != list(range(1, len(steps) + 1)):
            raise ValueError("remediation steps must be numbered consecutively starting at 1")
        for s in steps:
            unknown = set(s.related_cves) - ids
            if unknown:
                raise ValueError(f"step {s.step} references unknown CVEs: {sorted(unknown)}")
        uncovered = ids - {c for s in steps for c in s.related_cves}
        if uncovered:
            raise ValueError(f"CVEs without a remediation step: {sorted(uncovered)}")
        return self
