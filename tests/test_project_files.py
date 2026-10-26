"""Guards against an incomplete checkout (e.g. data/ or static/ dropped by a .gitignore rule)."""
from pathlib import Path

import pytest

from app.core.config import Settings
from app.main import WEB_DIR
from app.repositories.cve_repository import JsonCVERepository

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("rel", ["app/data/cve_db.json", "app/web/index.html", "app/web/static/app.js", "app/web/static/styles.css"])
def test_required_project_file_exists_where_the_app_looks_for_it(rel):
    assert (ROOT / rel).is_file(), rel
    # the app's own configured locations must point at the same files the tests/README refer to
    assert Settings(_env_file=None).cve_db_path == ROOT / "app/data/cve_db.json"
    assert WEB_DIR == ROOT / "app/web"


def test_cve_database_is_valid_and_not_empty():
    repo = JsonCVERepository(Settings(_env_file=None).cve_db_path)
    assert repo.get("CVE-2011-2523") and len(repo.find("vsftpd", "2.3.4")) == 1


def test_missing_cve_database_gives_an_actionable_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="restore it"):
        JsonCVERepository(tmp_path / "nope.json")
