"""Nmap integration tests. subprocess is ALWAYS mocked: no real scan, no network."""
import subprocess

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.core.errors import ToolExecutionError
from app.main import create_app
from app.schemas.scan import ScanResponse
from app.tools import nmap_runner
from app.tools.nmap_runner import find_nmap as real_find_nmap  # captured before any test patches it
from app.tools.nmap_xml import NmapXmlError, parse_nmap_xml
from tests.nmap_fixtures import nmap_xml

T = "127.0.0.1"


def live_settings(tmp_path, **kw):
    kw.setdefault("nmap_path", None)  # never inherit a developer's SECAGENT_NMAP_PATH
    return Settings(agents_enabled=False, tool_mode="live", allowed_cidrs=["127.0.0.1/32"],
                    reports_dir=tmp_path / "r", _env_file=None, **kw)


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda s: "/usr/bin/nmap")
    def refuse(*a, **k):
        raise ConnectionRefusedError()
    monkeypatch.setattr("app.tools.recon.socket.create_connection", refuse)  # no real banner grabs


@pytest.fixture
def fake_nmap(monkeypatch):
    """Install a fake subprocess.run; returns a recorder."""
    class Rec:
        calls: list = []
        stdout, returncode, stderr, raises = nmap_xml(), 0, "", None
    rec = Rec(); rec.calls = []

    def run(argv, **kw):
        rec.calls.append((argv, kw))
        if rec.raises:
            raise rec.raises
        return subprocess.CompletedProcess(argv, rec.returncode, stdout=rec.stdout, stderr=rec.stderr)
    monkeypatch.setattr(nmap_runner.subprocess, "run", run)
    return rec


@pytest.fixture
def client(tmp_path, fake_nmap):
    with TestClient(create_app(live_settings(tmp_path))) as c:
        yield c


def post(client, **body):
    return client.post("/api/v1/scan", json={"target": T, "authorization_confirmed": True, **body})


# ------------------------------------------------------------------ XML parsing
def test_parser_keeps_only_open_ports_and_counts_the_rest():
    run = parse_nmap_xml(nmap_xml())
    assert [(s.port, s.product, s.version) for s in run.services] == [(22, "OpenSSH", "7.2p2"), (80, "Apache httpd", "2.4.49")]
    assert run.closed_or_filtered == 2 + 995 and run.host_up and run.nmap_version == "7.94" and run.elapsed_s == 1.52


def test_parser_host_down_and_no_open_ports():
    assert not parse_nmap_xml(nmap_xml(up=False)).host_up
    assert parse_nmap_xml(nmap_xml(ports=(("tcp", 22, "closed", "ssh", None, None),))).services == []


def test_parser_service_without_version_stays_unversioned():
    s = parse_nmap_xml(nmap_xml(ports=(("tcp", 9, "open", "discard", None, None),))).services[0]
    assert s.product is None and s.version is None


@pytest.mark.parametrize("bad", ["", "   ", "<nmaprun><host>", "not xml at all", "<html></html>",
                                 '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun>&a;</nmaprun>'])
def test_parser_rejects_malformed_or_hostile_xml(bad):
    with pytest.raises(NmapXmlError):
        parse_nmap_xml(bad)


# ------------------------------------------------------------------ runner: safety + failure modes
def test_argv_is_a_fixed_list_without_shell_and_with_timeout(tmp_path, fake_nmap):
    nmap_runner.run_nmap(live_settings(tmp_path, tool_timeout_s=30), T, "22,80", "service_detection")
    argv, kw = fake_nmap.calls[0]
    assert argv == ["/usr/bin/nmap", "-oX", "-", "-n", "-sT", "-T3", "--host-timeout", "30s", "-p", "22,80",
                    "-sV", "--version-light", T]
    assert isinstance(argv, list) and kw["shell"] is False and kw["timeout"] == 40


@pytest.mark.parametrize("target,ports", [("127.0.0.1 -oN /tmp/x", "22"), ("127.0.0.1;id", "22"), ("-sS", "22"),
                                          ("127.0.0.1", "22 --script=vuln"), ("127.0.0.1", "22;rm -rf /"), ("127.0.0.1", "-p-")])
def test_arbitrary_arguments_cannot_reach_nmap(tmp_path, fake_nmap, target, ports):
    with pytest.raises(ValueError):
        nmap_runner.run_nmap(live_settings(tmp_path), target, ports, "quick")
    assert fake_nmap.calls == []


def test_timeout_nonzero_exit_bad_xml_and_missing_binary(tmp_path, fake_nmap, monkeypatch):
    s = live_settings(tmp_path)
    fake_nmap.raises = subprocess.TimeoutExpired("nmap", 70)
    with pytest.raises(ToolExecutionError) as e:
        nmap_runner.run_nmap(s, T, "22", "quick")
    assert e.value.code == "TOOL_TIMEOUT" and e.value.retryable
    fake_nmap.raises, fake_nmap.returncode, fake_nmap.stderr = None, 1, "dnet: Failed to open device"
    with pytest.raises(ToolExecutionError) as e:
        nmap_runner.run_nmap(s, T, "22", "quick")
    assert e.value.code == "TOOL_FAILED" and "code 1" in e.value.message
    fake_nmap.returncode, fake_nmap.stdout = 0, "<nmaprun><host>"
    with pytest.raises(ToolExecutionError) as e:
        nmap_runner.run_nmap(s, T, "22", "quick")
    assert e.value.code == "TOOL_BAD_OUTPUT"
    # Real discovery with nmap hidden everywhere it could be found (PATH and default install folders).
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda n: None)
    monkeypatch.setattr(nmap_runner, "_isfile", lambda p: False)
    with pytest.raises(ToolExecutionError) as e:
        real_find_nmap(s)
    assert e.value.code == "TOOL_UNAVAILABLE"


def test_public_or_unlisted_target_never_spawns_a_process(tmp_path, fake_nmap):
    for t in ("8.8.8.8", "192.168.1.5"):
        with pytest.raises(ToolExecutionError) as e:
            nmap_runner.run_nmap(live_settings(tmp_path), t, "22", "quick")
        assert e.value.code == "OUT_OF_SCOPE"
    assert fake_nmap.calls == []


# ------------------------------------------------------------------ API: real vs failed vs mock labelling
def test_successful_real_scan_is_labelled_real_and_uses_only_nmap_data(client, fake_nmap):
    r = post(client)
    assert r.status_code == 200
    d = r.json()
    assert d["data_source"] == "live_nmap" and d["real_scan"] is True
    assert d["scan_evidence"]["tool"] == "nmap" and d["scan_evidence"]["nmap_version"] == "7.94" and "-oX" in d["scan_evidence"]["command"]
    assert [p["port"] for p in d["report"]["open_ports"]] == [22, 80]  # closed/filtered ports excluded
    assert {c["affected_port"] for c in d["report"]["identified_cves"]} <= {22, 80}
    assert "not a confirmed vulnerability" in d["evidence_note"]
    assert len(fake_nmap.calls) == 1


def test_unversioned_service_yields_no_invented_cves(client, fake_nmap):
    fake_nmap.stdout = nmap_xml(ports=(("tcp", 22, "open", "ssh", None, None),))
    d = post(client).json()
    assert d["report"]["identified_cves"] == [] and d["report"]["detected_services"][0]["version"] is None


def test_host_down_returns_empty_result_with_explanation_not_fake_ports(client, fake_nmap):
    fake_nmap.stdout = nmap_xml(up=False)
    d = post(client).json()
    assert d["report"]["open_ports"] == [] and any("down or unreachable" in w for w in d["warnings"]) and d["real_scan"]


def test_time_limit_reached_is_flagged(client, fake_nmap):
    fake_nmap.stdout = nmap_xml(elapsed="60.1")
    assert any("time limit" in w for w in post(client).json()["warnings"])


@pytest.mark.parametrize("mutate,status,code", [
    (lambda f: setattr(f, "raises", subprocess.TimeoutExpired("nmap", 70)), 504, "TOOL_TIMEOUT"),
    (lambda f: (setattr(f, "returncode", 2), setattr(f, "stderr", "boom")), 502, "TOOL_FAILED"),
    (lambda f: setattr(f, "stdout", "<nmaprun><host>"), 502, "TOOL_BAD_OUTPUT"),
])
def test_failed_scans_are_errors_never_substitute_data(client, fake_nmap, mutate, status, code):
    mutate(fake_nmap)
    r = post(client)
    assert r.status_code == status and r.json()["detail"].startswith(code)
    assert "report" not in r.json() and "data_source" not in r.json()


def test_missing_nmap_is_503(tmp_path, fake_nmap, monkeypatch):
    monkeypatch.setattr(nmap_runner, "find_nmap", lambda s: (_ for _ in ()).throw(ToolExecutionError("TOOL_UNAVAILABLE", "nmap executable not found.", retryable=False)))
    with TestClient(create_app(live_settings(tmp_path))) as c:
        assert post(c).status_code == 503


def test_api_refuses_public_unlisted_malformed_and_oversized(client, fake_nmap):
    assert post(client, target="8.8.8.8").status_code == 403
    assert post(client, target="192.168.1.10").status_code == 403
    assert post(client, target="example.com").status_code == 422
    assert post(client, target="127.0.0.1/24").status_code == 422
    assert post(client, ports="22 -sC").status_code == 422
    assert post(client, ports="1-65535").status_code == 422
    assert fake_nmap.calls == []


def test_empty_allowlist_refuses_all_live_scans(tmp_path, fake_nmap):
    s = Settings(agents_enabled=False, tool_mode="live", reports_dir=tmp_path, _env_file=None)
    with TestClient(create_app(s)) as c:
        assert post(c).status_code == 403
    assert fake_nmap.calls == []


# ------------------------------------------------------------------ mock results can never pose as real
def test_mock_mode_never_runs_nmap_and_is_labelled_mock(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("subprocess must not be used in mock mode")
    monkeypatch.setattr(nmap_runner.subprocess, "run", boom)
    s = Settings(agents_enabled=False, tool_mode="mock", reports_dir=tmp_path, _env_file=None)
    with TestClient(create_app(s)) as c:
        d = post(c, target="10.10.10.3").json()
    assert d["data_source"] == "mock_fixture" and d["real_scan"] is False and d["scan_evidence"] is None


def test_provided_scan_data_is_labelled_as_such_not_real(client, fake_nmap):
    d = post(client, raw_scan_data=nmap_xml()).json()
    assert d["data_source"] == "provided_scan_data" and d["real_scan"] is False and fake_nmap.calls == []
    assert [p["port"] for p in d["report"]["open_ports"]] == [22, 80]


def test_response_schema_makes_mislabelling_impossible():
    base = {"scan_id": "x", "execution_mode": "deterministic_fallback", "duration_ms": 1, "tool_calls": 0}
    report = {"target_host": T, "open_ports": [], "detected_services": [], "identified_cves": [],
              "recommended_remediation_plan": [{"step": 1, "action": "Re-scan later", "priority": "INFO"}]}
    with pytest.raises(ValidationError):
        ScanResponse(**base, data_source="mock_fixture", real_scan=True, report=report)
    with pytest.raises(ValidationError):  # claims live but carries no nmap evidence
        ScanResponse(**base, data_source="live_nmap", real_scan=True, report=report)
    ev = {"command": ["nmap"], "exit_code": 0}
    with pytest.raises(ValidationError):  # mock data carrying nmap evidence
        ScanResponse(**base, data_source="mock_fixture", real_scan=False, scan_evidence=ev, report=report)
    assert ScanResponse(**base, data_source="live_nmap", real_scan=True, scan_evidence=ev, report=report).real_scan


def test_secrets_are_redacted_from_logs():
    from app.core.logging import redact
    assert "sk-ant-abcdef123456" not in redact("auth failed for sk-ant-abcdef123456 on call")


def test_blank_api_key_does_not_enable_agents(tmp_path):
    # `.env.example` ships `SECAGENT_LLM_API_KEY=` (blank); that must mean "no key", not "try the LLM".
    assert not Settings(llm_api_key="", _env_file=None).agents_available
    assert not Settings(llm_api_key="   ", _env_file=None).agents_available
    assert Settings(llm_api_key="sk-ant-test", _env_file=None).agents_available
    assert not Settings(llm_api_key="sk-ant-test", agents_enabled=False, _env_file=None).agents_available
