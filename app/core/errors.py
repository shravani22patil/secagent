"""Domain exceptions. Only ToolExecutionError is ever converted into agent-visible text."""
from __future__ import annotations


class SecAgentError(Exception):
    """Base class."""


class ScopeViolation(SecAgentError):
    """Target is outside the authorised scope."""


class GroundingError(SecAgentError):
    """Agent output cannot be reconciled with what the tools actually observed."""


class ReportParseError(SecAgentError):
    """Agent output could not be parsed into the ThreatReport schema."""


class InvalidScanRequest(SecAgentError):
    """Request is well-formed but exceeds a configured limit (e.g. too many ports)."""


class ScanFailed(SecAgentError):
    """The scan could not be completed. Never answered with substitute/mock data in live mode."""

    def __init__(self, message: str, *, code: str = "SCAN_FAILED", http_status: int = 502):
        super().__init__(message)
        self.code, self.http_status = code, http_status


class ToolExecutionError(SecAgentError):
    """Raised by tool handlers; the guard converts it into a self-correction payload."""

    def __init__(self, code: str, message: str, *, retryable: bool = True, hint: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.hint = hint
