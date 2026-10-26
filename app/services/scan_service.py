"""Orchestrates one scan: scope check -> agent attempts (timeout + retry + backoff) -> fallback."""
from __future__ import annotations

import asyncio
import time
import uuid

from app.core.config import Settings
from app.core.errors import InvalidScanRequest, ScanFailed
from app.core.logging import get_logger, scan_id_var
from app.core.scope import authorize_live_target
from app.core.validators import expand_ports
from app.repositories.cve_repository import CVERepository
from app.repositories.report_repository import FileReportRepository
from app.schemas.report import ThreatReport
from app.schemas.scan import ScanEvidence, ScanRequest, ScanResponse
from app.services.analysis import reconcile_report
from app.services.fallback import run_deterministic_pipeline
from app.tools.context import ScanContext

log = get_logger("secagent.service")


class ScanService:
    def __init__(self, settings: Settings, cve_repo: CVERepository, reports: FileReportRepository) -> None:
        self.settings, self.cve_repo, self.reports = settings, cve_repo, reports
        self._sem = asyncio.Semaphore(settings.max_concurrent_scans)

    async def run(self, req: ScanRequest) -> ScanResponse:
        scan_id = uuid.uuid4().hex[:12]
        token = scan_id_var.set(scan_id)
        started = time.perf_counter()
        try:
            self._enforce_scope(req)
            async with self._sem:
                report, mode, warnings, ctx = await self._execute(scan_id, req)
            if ctx.data_source is None:
                raise ScanFailed("no scan data source was recorded; refusing to label the result", code="NO_DATA_SOURCE")
            self.reports.save(scan_id, report, mode, ctx.data_source)
            ms = int((time.perf_counter() - started) * 1000)
            log.info("scan_completed", extra={"ctx": {"mode": mode, "data_source": ctx.data_source, "duration_ms": ms,
                                                       "cves": len(report.identified_cves)}})
            return ScanResponse(
                scan_id=scan_id, execution_mode=mode, data_source=ctx.data_source, real_scan=ctx.data_source == "live_nmap",
                scan_evidence=ScanEvidence(**ctx.scan_evidence) if ctx.data_source == "live_nmap" and ctx.scan_evidence else None,
                duration_ms=ms, tool_calls=len(ctx.tool_trace), warnings=warnings + ctx.notes, report=report)
        finally:
            scan_id_var.reset(token)

    # ------------------------------------------------------------------
    def _enforce_scope(self, req: ScanRequest) -> None:
        if req.raw_scan_data or not req.target:
            return  # offline parsing never touches the network
        if len(expand_ports(req.ports)) > self.settings.max_ports:
            raise InvalidScanRequest(f"ports: at most {self.settings.max_ports} ports per scan (SECAGENT_MAX_PORTS)")
        if self.settings.tool_mode == "live":
            authorize_live_target(self.settings, req.target)  # raises ScopeViolation (HTTP 403)

    def _ctx(self, scan_id: str, req: ScanRequest) -> ScanContext:
        return ScanContext(scan_id=scan_id, settings=self.settings, cve_repo=self.cve_repo,
                           target=req.target, ports=req.ports, raw_scan_data=req.raw_scan_data,
                           data_source="provided_scan_data" if req.raw_scan_data else None)

    async def _execute(self, scan_id: str, req: ScanRequest) -> tuple[ThreatReport, str, list[str], ScanContext]:
        warnings: list[str] = []
        if self.settings.agents_available:
            for attempt in range(1, self.settings.scan_max_attempts + 1):
                ctx = self._ctx(scan_id, req)  # fresh state: a timed-out thread can't pollute the next attempt
                try:
                    from app.agents.runner import run_agent_pipeline  # lazy: crewai is heavy

                    raw = await asyncio.wait_for(asyncio.to_thread(run_agent_pipeline, ctx, self.settings),
                                                 timeout=self.settings.scan_timeout_s)
                    report, extra = reconcile_report(raw, ctx)
                    return report, "agentic", warnings + extra, ctx
                except Exception as exc:  # noqa: BLE001 - any agent-path failure degrades to fallback
                    log.warning("agent_attempt_failed", extra={"ctx": {"attempt": attempt, "error": type(exc).__name__,
                                                                         "detail": str(exc)[:300]}})
                    warnings.append(f"agent attempt {attempt} failed: {type(exc).__name__}")
                    if attempt < self.settings.scan_max_attempts:
                        await asyncio.sleep(min(0.5 * 2 ** attempt, 8))
            warnings.append("LLM agent path failed; deterministic pipeline analysed the scan data instead")
        else:
            warnings.append("LLM agents not used (disabled or no API key); deterministic pipeline analysed the scan data")
        ctx = self._ctx(scan_id, req)
        try:
            report = await asyncio.to_thread(run_deterministic_pipeline, ctx)
        except ScanFailed:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ScanFailed(f"deterministic pipeline failed: {type(exc).__name__}: {exc}") from exc
        return report, "deterministic_fallback", warnings, ctx
