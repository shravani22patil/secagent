import os
import sys
from pathlib import Path

import pytest

# Fail fast with ONE actionable message instead of dozens of FileNotFoundError tracebacks.
_ROOT = Path(__file__).resolve().parents[1]
_REQUIRED = ["app/data/cve_db.json", "app/web/index.html", "app/web/static/app.js", "app/web/static/styles.css"]
_missing = [f for f in _REQUIRED if not (_ROOT / f).is_file()]
if _missing:
    raise SystemExit(
        "\nSecAgent project files are missing from this checkout:\n  - " + "\n  - ".join(_missing) +
        "\nRestore them (re-extract the project zip, or `git checkout -- <file>`). If git does not have them, "
        "check `git check-ignore -v <file>`: a .gitignore rule such as 'data/' or 'static/' may be excluding them.\n")

from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import Settings
from app.main import create_app
from app.repositories.cve_repository import JsonCVERepository
from app.tools.context import ScanContext
from app.tools.recon import build_registry

from app.tools import nmap_runner  # noqa: E402

LEGACY, MAIL, HARDENED = "10.10.10.3", "10.10.10.4", "10.10.10.5"  # scenario = int(ip) % 3


@pytest.fixture(autouse=True)
def hermetic_environment(monkeypatch):
    """Tests must not depend on the developer's machine: no SECAGENT_*/ANTHROPIC_* env vars, and no real
    nmap install being discoverable (a real Windows install would otherwise be found by the fallback)."""
    for key in list(os.environ):
        if key.startswith("SECAGENT_") or key == "ANTHROPIC_API_KEY":
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(nmap_runner, "_isfile", lambda path: False)


@pytest.fixture
def settings(tmp_path):
    return Settings(agents_enabled=False, reports_dir=tmp_path / "reports", nmap_path=None, _env_file=None)


@pytest.fixture
def repo(settings):
    return JsonCVERepository(settings.cve_db_path)


@pytest.fixture
def ctx(settings, repo):
    return ScanContext(scan_id="t", settings=settings, cve_repo=repo, target=LEGACY)


@pytest.fixture
def registry(ctx):
    return build_registry(ctx)


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c
