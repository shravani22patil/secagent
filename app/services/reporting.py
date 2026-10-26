"""Deterministic executive-report rendering (no LLM involved, so it can never drift)."""
from __future__ import annotations

from collections import Counter

from app.schemas.report import Severity, ThreatReport


def render_markdown(report: ThreatReport, scan_id: str, mode: str, data_source: str = "unknown") -> str:
    counts = Counter(c.severity for c in report.identified_cves)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    summary = ", ".join(f"{counts[s]} {s.value.lower()}" for s in order if counts[s]) or "no known CVEs matched"
    lines = [
        f"# SecAgent-Core Report: {report.target_host}",
        f"_scan `{scan_id}` | pipeline: {mode} | data source: **{data_source}**_",
        "_CVE entries are version-match candidates, not confirmed vulnerabilities._" if data_source != "mock_fixture" else "_DEMO DATA: mock fixture, no real scan was performed._",
        "",
        f"**Executive summary:** {len(report.open_ports)} open port(s); {summary}.",
        "",
        "## Services",
        "| Port | Service | Product | Version |",
        "|---|---|---|---|",
    ]
    for s in report.detected_services:
        lines.append(f"| {s.port}/{s.protocol} | {s.name} | {s.product or '-'} | {s.version or '-'} |")
    lines += ["", "## Vulnerabilities", "| CVE | Severity | CVSS | Port | Service |", "|---|---|---|---|---|"]
    for c in report.identified_cves:
        lines.append(f"| {c.cve_id} | {c.severity.value} | {c.cvss_score} | {c.affected_port} | {c.affected_service} |")
    lines += ["", "## Attack paths"]
    lines += [f"- **{c.cve_id}** ({c.affected_port}): {c.exploit_path}" for c in report.identified_cves] or ["- none identified"]
    lines += ["", "## Remediation plan"]
    for st in report.recommended_remediation_plan:
        refs = f" ({', '.join(st.related_cves)})" if st.related_cves else ""
        lines.append(f"{st.step}. **[{st.priority.value}]** {st.action}{refs}")
    return "\n".join(lines) + "\n"
