"""Deterministic pipeline: same tools, same schema, zero LLM. Used when the agent path fails."""
from __future__ import annotations

from app.core.errors import ScanFailed, ScopeViolation
from app.schemas.report import ThreatReport
from app.services.analysis import build_report_from_kb
from app.tools.context import ScanContext
from app.tools.recon import build_registry


def run_deterministic_pipeline(ctx: ScanContext) -> ThreatReport:
    registry = build_registry(ctx)
    if ctx.raw_scan_data:
        first = registry.call("parse_scan_output", {"source": "provided_scan"})
    else:
        first = registry.call("nmap_scan", {"target": ctx.target, "ports": ctx.ports})
    if not first.ok:
        if first.error_code == "OUT_OF_SCOPE":
            raise ScopeViolation(first.message or "target out of scope")
        status = {"TOOL_TIMEOUT": 504, "TOOL_UNAVAILABLE": 503}.get(first.error_code or "", 502)
        # Deliberately NO substitute data: a failed live scan is reported as failed, never as mock output.
        raise ScanFailed(first.message or "scan failed", code=first.error_code or "SCAN_FAILED", http_status=status)
    if not ctx.raw_scan_data:  # verify versions via banners where nmap gave none
        for svc in ctx.snapshot_services():
            if not svc.version:
                registry.call("banner_grab", {"target": ctx.target, "port": svc.port})  # best-effort
    return build_report_from_kb(ctx)
