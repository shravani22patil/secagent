"""Ground truth builder + reconciliation guardrail.

Principle: the LLM may add analysis (ordering, narrative), but FACTS (ports, services, which CVEs apply)
are always re-derived from what tools actually observed + the CVE KB. Hallucinated CVEs are dropped.
"""
from __future__ import annotations

from app.core.errors import GroundingError
from app.repositories.cve_repository import CVERepository
from app.schemas.report import (
    IdentifiedCVE, OpenPort, RemediationStep, Severity, ThreatReport, severity_from_cvss,
)
from app.tools.context import ScanContext

_GENERAL_STEP = ("Re-scan the host after remediation and diff against this report; restrict every exposed "
                 "service by firewall to the source ranges that genuinely need it.")


def _plan_for(cves: list[IdentifiedCVE], repo: CVERepository, *, with_general: bool = True) -> list[RemediationStep]:
    grouped: dict[str, list[IdentifiedCVE]] = {}
    for c in cves:  # cves arrive severity-sorted, so insertion order == priority order
        rec = repo.get(c.cve_id)
        grouped.setdefault(rec.remediation if rec else "Apply vendor security updates.", []).append(c)
    steps = [
        RemediationStep(step=i, action=action, priority=severity_from_cvss(max(c.cvss_score for c in grp)),
                        related_cves=sorted({c.cve_id for c in grp}))
        for i, (action, grp) in enumerate(grouped.items(), start=1)
    ]
    if with_general:
        steps.append(RemediationStep(step=len(steps) + 1, action=_GENERAL_STEP,
                                     priority=Severity.LOW if cves else Severity.INFO))
    return steps


def build_report_from_kb(ctx: ScanContext) -> ThreatReport:
    if not ctx.target:
        raise GroundingError("scan target could not be determined")
    services = ctx.snapshot_services()
    cves: list[IdentifiedCVE] = []
    for s in services:
        if not (s.product and s.version):
            continue
        for rec in ctx.cve_repo.find(s.product, s.version):
            cves.append(IdentifiedCVE(
                cve_id=rec.cve_id, severity=severity_from_cvss(rec.cvss_score), cvss_score=rec.cvss_score,
                affected_port=s.port, affected_service=f"{s.product} {s.version}"[:160],
                summary=rec.summary, exploit_path=rec.exploit_path))
    cves.sort(key=lambda c: (-c.cvss_score, c.cve_id, c.affected_port))
    return ThreatReport(
        target_host=ctx.target,
        open_ports=[OpenPort(port=s.port, protocol=s.protocol) for s in services],
        detected_services=services, identified_cves=cves,
        recommended_remediation_plan=_plan_for(cves, ctx.cve_repo))


def reconcile_report(report: ThreatReport, ctx: ScanContext) -> tuple[ThreatReport, list[str]]:
    """Return a report whose facts match tool observations. Raises GroundingError if nothing was observed."""
    if not ctx.observed and not ctx.raw_scan_data:
        raise GroundingError("agent returned a report but no tool call ever observed a port")
    truth = build_report_from_kb(ctx)
    warnings: list[str] = []
    if report.target_host != truth.target_host:
        warnings.append(f"target_host corrected from {report.target_host} to {truth.target_host}")
    if {(p.port, p.protocol) for p in report.open_ports} != {(p.port, p.protocol) for p in truth.open_ports}:
        warnings.append("open_ports differed from tool observations and were replaced")

    truth_cves = {(c.cve_id, c.affected_port): c for c in truth.identified_cves}
    kept: dict[tuple[str, int], IdentifiedCVE] = {}
    for c in report.identified_cves:
        t = truth_cves.get((c.cve_id, c.affected_port))
        if t is None:
            warnings.append(f"dropped ungrounded CVE {c.cve_id} on port {c.affected_port}")
        else:
            kept[(c.cve_id, c.affected_port)] = t.model_copy(update={"exploit_path": c.exploit_path or t.exploit_path})
    for key, t in truth_cves.items():
        if key not in kept:
            warnings.append(f"added {key[0]} on port {key[1]} (present in KB, missed by agent)")
            kept[key] = t
    cves = sorted(kept.values(), key=lambda c: (-c.cvss_score, c.cve_id, c.affected_port))

    valid = {c.cve_id for c in cves}
    steps = [s.model_copy(update={"related_cves": [x for x in s.related_cves if x in valid]})
             for s in report.recommended_remediation_plan]
    covered = {x for s in steps for x in s.related_cves}
    missing = [c for c in cves if c.cve_id not in covered]
    steps += _plan_for(missing, ctx.cve_repo, with_general=False)
    if not steps:
        steps = _plan_for(cves, ctx.cve_repo)
    steps = [s.model_copy(update={"step": i}) for i, s in enumerate(steps, start=1)]

    final = ThreatReport(target_host=truth.target_host, open_ports=truth.open_ports,
                         detected_services=truth.detected_services, identified_cves=cves,
                         recommended_remediation_plan=steps)
    return final, warnings
