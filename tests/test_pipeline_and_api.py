import pytest

from app.core.errors import GroundingError
from app.schemas.report import IdentifiedCVE, RemediationStep, Severity, ThreatReport
from app.services.analysis import build_report_from_kb, reconcile_report
from app.services.fallback import run_deterministic_pipeline
from app.agents.runner import parse_report_fallback
from tests.conftest import HARDENED, LEGACY, MAIL


def body(target, **kw):
    return {"target": target, "authorization_confirmed": True, **kw}


def test_api_legacy_host(client):
    r = client.post("/api/v1/scan", json=body(LEGACY))
    assert r.status_code == 200
    d = r.json()
    assert d["execution_mode"] == "deterministic_fallback" and d["tool_calls"] >= 1
    rep = d["report"]
    assert set(rep) == {"target_host", "open_ports", "detected_services", "identified_cves", "recommended_remediation_plan"}
    cves = {c["cve_id"]: c for c in rep["identified_cves"]}
    assert cves["CVE-2011-2523"]["severity"] == "CRITICAL"
    assert rep["identified_cves"][0]["cvss_score"] >= rep["identified_cves"][-1]["cvss_score"]
    assert [s["step"] for s in rep["recommended_remediation_plan"]] == list(range(1, len(rep["recommended_remediation_plan"]) + 1))


def test_api_mail_and_hardened(client):
    mail = {c["cve_id"] for c in client.post("/api/v1/scan", json=body(MAIL)).json()["report"]["identified_cves"]}
    assert {"CVE-2019-10149", "CVE-2017-7494"} <= mail
    hard = client.post("/api/v1/scan", json=body(HARDENED)).json()["report"]
    assert hard["identified_cves"] == [] and hard["recommended_remediation_plan"]


def test_api_rejects_bad_requests(client):
    assert client.post("/api/v1/scan", json={"target": LEGACY, "authorization_confirmed": False}).status_code == 422
    assert client.post("/api/v1/scan", json=body("example.com")).status_code == 422
    assert client.post("/api/v1/scan", json=body("10.0.0.0/24")).status_code == 422
    assert client.post("/api/v1/scan", json={"authorization_confirmed": True}).status_code == 422
    assert client.post("/api/v1/scan", json=body(LEGACY, ports="22; rm -rf /")).status_code == 422


def test_report_files_written(client, settings):
    sid = client.post("/api/v1/scan", json=body(LEGACY)).json()["scan_id"]
    assert (settings.reports_dir / f"{sid}.json").exists() and (settings.reports_dir / f"{sid}.md").exists()


def test_raw_scan_data_path(client):
    raw = "Nmap scan report for 192.0.2.9\nPORT   STATE SERVICE VERSION\n21/tcp open  ftp     vsftpd 2.3.4\n"
    r = client.post("/api/v1/scan", json={"raw_scan_data": raw, "authorization_confirmed": True})
    assert r.status_code == 200
    assert r.json()["report"]["target_host"] == "192.0.2.9"
    assert r.json()["report"]["identified_cves"][0]["cve_id"] == "CVE-2011-2523"


def test_live_mode_scope_enforced(tmp_path):
    from fastapi.testclient import TestClient
    from app.core.config import Settings
    from app.main import create_app
    s = Settings(agents_enabled=False, tool_mode="live", allowed_cidrs=["10.1.0.0/16"], reports_dir=tmp_path, _env_file=None)
    with TestClient(create_app(s)) as c:
        assert c.post("/api/v1/scan", json=body("8.8.8.8")).status_code == 403


def test_reconcile_drops_hallucinated_cve_and_fixes_facts(ctx):
    run_deterministic_pipeline(ctx)
    truth = build_report_from_kb(ctx)
    fake = IdentifiedCVE(cve_id="CVE-2099-12345", severity=Severity.LOW, cvss_score=9.9, affected_port=22,
                         affected_service="OpenSSH 7.2p2", summary="invented", exploit_path="invented")
    sloppy = ThreatReport(target_host=truth.target_host, open_ports=truth.open_ports,
                          detected_services=truth.detected_services, identified_cves=[fake],
                          recommended_remediation_plan=[RemediationStep(step=1, action="Do something", priority=Severity.LOW,
                                                                        related_cves=["CVE-2099-12345"])])
    fixed, warnings = reconcile_report(sloppy, ctx)
    ids = {c.cve_id for c in fixed.identified_cves}
    assert "CVE-2099-12345" not in ids and "CVE-2011-2523" in ids
    assert any("dropped ungrounded" in w for w in warnings)


def test_reconcile_requires_observations(ctx, ):
    fresh = ctx.__class__(scan_id="x", settings=ctx.settings, cve_repo=ctx.cve_repo, target=LEGACY)
    run_deterministic_pipeline(ctx)
    rep = build_report_from_kb(ctx)
    with pytest.raises(GroundingError):
        reconcile_report(rep, fresh)


def test_structured_parse_fallback(ctx):
    run_deterministic_pipeline(ctx)
    good = build_report_from_kb(ctx).model_dump_json()
    parsed = parse_report_fallback(f"Sure! Here is the report:\n```json\n{good}\n```\nHope that helps.")
    assert parsed.target_host == LEGACY


def test_schema_invariants_enforced(ctx):
    run_deterministic_pipeline(ctx)
    data = build_report_from_kb(ctx).model_dump(mode="json")
    data["recommended_remediation_plan"][0]["step"] = 5
    with pytest.raises(Exception):
        ThreatReport.model_validate(data)
    data2 = build_report_from_kb(ctx).model_dump(mode="json")
    data2["surprise"] = 1
    with pytest.raises(Exception):
        ThreatReport.model_validate(data2)
