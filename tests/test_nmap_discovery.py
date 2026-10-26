"""Windows executable discovery, simulated with mocks (runs on any OS; no real nmap, no real scan)."""
import subprocess

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.errors import ToolExecutionError
from app.main import create_app
from app.tools import nmap_runner
from tests.nmap_fixtures import nmap_xml

WIN_NMAP = r"C:\Program Files (x86)\Nmap\nmap.exe"


def settings(tmp_path, **kw):
    kw.setdefault("nmap_path", None)
    return Settings(agents_enabled=False, tool_mode="live", allowed_cidrs=["127.0.0.1/32"],
                    reports_dir=tmp_path / "r", _env_file=None, **kw)


@pytest.fixture
def windows(monkeypatch):
    """Pretend to be Windows where nmap is NOT on PATH but IS installed in the default folder."""
    monkeypatch.setattr(nmap_runner, "_is_windows", lambda: True)
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda name: None)
    monkeypatch.setattr(nmap_runner, "_isfile", lambda p: p == WIN_NMAP)
    for var in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def fake_run(monkeypatch):
    calls = []

    def run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, stdout=nmap_xml(), stderr="")
    monkeypatch.setattr(nmap_runner.subprocess, "run", run)
    return calls


def test_finds_default_windows_install_when_path_lookup_fails(tmp_path, windows):
    assert nmap_runner.find_nmap(settings(tmp_path)) == WIN_NMAP


def test_path_lookup_comes_first(tmp_path, windows, monkeypatch):
    monkeypatch.setattr(nmap_runner.shutil, "which", lambda name: r"C:\Tools\nmap.exe")
    monkeypatch.setattr(nmap_runner, "_isfile", lambda p: True)
    assert nmap_runner.find_nmap(settings(tmp_path)) == r"C:\Tools\nmap.exe"


def test_honours_program_files_on_another_drive(tmp_path, windows, monkeypatch):
    monkeypatch.setenv("ProgramFiles(x86)", r"D:\Apps")
    monkeypatch.setattr(nmap_runner, "_isfile", lambda p: p == r"D:\Apps\Nmap\nmap.exe")
    assert nmap_runner.find_nmap(settings(tmp_path)) == r"D:\Apps\Nmap\nmap.exe"


def test_explicit_path_is_used_and_quotes_are_stripped(tmp_path, windows, monkeypatch):
    custom = r"E:\scan\nmap.exe"
    monkeypatch.setattr(nmap_runner, "_isfile", lambda p: p == custom)
    assert nmap_runner.find_nmap(settings(tmp_path, nmap_path=f'"{custom}"')) == custom


def test_dotenv_newline_escape_is_diagnosed_and_does_not_block_discovery(tmp_path, windows):
    mangled = "C:\\Program Files (x86)\\Nmap\nmap.exe"  # what .env produces from "...\Nmap\nmap.exe" in double quotes
    path, checked = nmap_runner.resolve_nmap(settings(tmp_path, nmap_path=mangled))
    assert path == WIN_NMAP and "control character" in checked[0]


def test_tool_unavailable_only_when_really_missing_and_diagnostic_is_useful(tmp_path, windows, monkeypatch):
    monkeypatch.setattr(nmap_runner, "_isfile", lambda p: False)
    monkeypatch.setenv("PATH", "SENTINEL_PATH_CONTENT")
    monkeypatch.setenv("SECAGENT_LLM_API_KEY", "sk-ant-should-never-appear")
    with pytest.raises(ToolExecutionError) as e:
        nmap_runner.find_nmap(settings(tmp_path))
    msg = e.value.message + (e.value.hint or "")
    assert e.value.code == "TOOL_UNAVAILABLE" and not e.value.retryable
    assert WIN_NMAP in msg and "PATH lookup" in msg and "restart" in msg and "SECAGENT_NMAP_PATH" in msg
    assert "SENTINEL_PATH_CONTENT" not in msg and "sk-ant" not in msg


def test_resolved_windows_path_is_used_as_argv0_with_shell_false_and_all_safety_flags(tmp_path, windows, fake_run):
    live = nmap_runner.run_nmap(settings(tmp_path, tool_timeout_s=30), "127.0.0.1", "22,80", "service_detection")
    argv, kw = fake_run[0]
    assert argv[0] == WIN_NMAP and isinstance(argv, list) and kw["shell"] is False and kw["timeout"] == 40
    assert argv[1:] == ["-oX", "-", "-n", "-sT", "-T3", "--host-timeout", "30s", "-p", "22,80", "-sV", "--version-light", "127.0.0.1"]
    assert live.evidence["command"][0] == "nmap.exe"  # exe name only, correct for a Windows path


def test_authorization_and_validation_still_apply_with_windows_path(tmp_path, windows, fake_run):
    for target, ports in (("8.8.8.8", "22"), ("192.168.1.5", "22")):
        with pytest.raises(ToolExecutionError) as e:
            nmap_runner.run_nmap(settings(tmp_path), target, ports, "quick")
        assert e.value.code == "OUT_OF_SCOPE"
    with pytest.raises(ValueError):
        nmap_runner.run_nmap(settings(tmp_path), "127.0.0.1", "22 --script=vuln", "quick")
    assert fake_run == []  # nothing was ever spawned


@pytest.mark.parametrize("exc", [FileNotFoundError(2, "The system cannot find the file specified"),
                                 PermissionError(13, "Access is denied"),
                                 OSError(193, "%1 is not a valid Win32 application")])
def test_executable_that_cannot_be_started_is_tool_unavailable(tmp_path, windows, monkeypatch, exc):
    def boom(argv, **kw):
        raise exc
    monkeypatch.setattr(nmap_runner.subprocess, "run", boom)
    with pytest.raises(ToolExecutionError) as e:
        nmap_runner.run_nmap(settings(tmp_path), "127.0.0.1", "22", "quick")
    assert e.value.code == "TOOL_UNAVAILABLE" and WIN_NMAP in e.value.message


def test_api_scan_succeeds_end_to_end_via_windows_path(tmp_path, windows, fake_run):
    with TestClient(create_app(settings(tmp_path))) as c:
        r = c.post("/api/v1/scan", json={"target": "127.0.0.1", "ports": "22,80", "authorization_confirmed": True})
        h = c.get("/health").json()
    d = r.json()
    assert r.status_code == 200 and d["data_source"] == "live_nmap" and d["scan_evidence"]["command"][0] == "nmap.exe"
    assert fake_run[0][0][0] == WIN_NMAP and h["nmap"] == "found"


def test_api_reports_503_with_diagnostic_and_no_fake_result_when_missing(tmp_path, windows, fake_run, monkeypatch):
    monkeypatch.setattr(nmap_runner, "_isfile", lambda p: False)
    with TestClient(create_app(settings(tmp_path))) as c:
        r = c.post("/api/v1/scan", json={"target": "127.0.0.1", "authorization_confirmed": True})
        h = c.get("/health").json()
    assert r.status_code == 503 and r.json()["detail"].startswith("TOOL_UNAVAILABLE") and WIN_NMAP in r.json()["detail"]
    assert "report" not in r.json() and fake_run == [] and h["nmap"] == "not_found"


def test_health_does_not_look_for_nmap_in_mock_mode(tmp_path):
    s = Settings(agents_enabled=False, tool_mode="mock", reports_dir=tmp_path, _env_file=None)
    with TestClient(create_app(s)) as c:
        assert c.get("/health").json()["nmap"] == "not_used"
