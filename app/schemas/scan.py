"""HTTP request/response contracts."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.validators import validate_ip, validate_port_spec
from app.schemas.report import ThreatReport


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str | None = Field(default=None, description="IPv4/IPv6 address to assess")
    raw_scan_data: str | None = Field(
        default=None, max_length=200_000, description="Pre-collected nmap normal-format output"
    )
    ports: str = "1-1024"
    authorization_confirmed: Literal[True] = Field(
        description="Must be true: caller attests written authorisation to test the target"
    )

    @field_validator("target")
    @classmethod
    def _target(cls, v: str | None) -> str | None:
        return validate_ip(v) if v is not None else v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str) -> str:
        return validate_port_spec(v)

    @model_validator(mode="after")
    def _need_input(self) -> "ScanRequest":
        if not self.target and not self.raw_scan_data:
            raise ValueError("provide 'target' and/or 'raw_scan_data'")
        return self


DataSource = Literal["live_nmap", "mock_fixture", "provided_scan_data"]
EVIDENCE_NOTE = (
    "CVE entries are candidate matches between the product/version strings reported by nmap and a small local "
    "knowledge base. Backported patches or misleading banners can make a match a false positive, and nothing "
    "was exploited or otherwise verified. Treat each as an observation to confirm, not a confirmed vulnerability."
)


class ScanEvidence(BaseModel):
    """Proof that nmap actually ran for THIS request (present only when data_source == 'live_nmap')."""

    tool: Literal["nmap"] = "nmap"
    nmap_version: str | None = None
    command: list[str]
    exit_code: int
    elapsed_s: float | None = None
    hosts_up: int = 0


class ScanResponse(BaseModel):
    scan_id: str
    status: Literal["completed"] = "completed"
    # Which pipeline produced the analysis. NOT where the data came from: see data_source.
    execution_mode: Literal["agentic", "deterministic_fallback"]
    # Where the observations came from. Only 'live_nmap' means a real scan happened.
    data_source: DataSource
    real_scan: bool
    scan_evidence: ScanEvidence | None = None
    evidence_note: str = EVIDENCE_NOTE
    duration_ms: int
    tool_calls: int
    warnings: list[str] = Field(default_factory=list)
    report: ThreatReport

    @model_validator(mode="after")
    def _label_integrity(self) -> "ScanResponse":
        live = self.data_source == "live_nmap"
        if self.real_scan != live:
            raise ValueError("real_scan must be true if and only if data_source is 'live_nmap'")
        if live != (self.scan_evidence is not None):
            raise ValueError("scan_evidence must be present if and only if data_source is 'live_nmap'")
        return self
