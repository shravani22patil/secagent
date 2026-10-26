"""CVE knowledge-base access behind a Protocol, so the JSON file can be swapped for NVD/OSV."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field

from app.core.validators import version_tuple


class VersionRange(BaseModel):
    min_version: str | None = None  # inclusive
    max_version_exclusive: str | None = None

    def contains(self, version: tuple[int, ...]) -> bool:
        if self.min_version and version < version_tuple(self.min_version):
            return False
        if self.max_version_exclusive and version >= version_tuple(self.max_version_exclusive):
            return False
        return True


class CVERecord(BaseModel):
    cve_id: str
    cvss_score: float
    products: list[str]
    affected: list[VersionRange] = Field(default_factory=list)
    summary: str
    exploit_path: str
    remediation: str


class CVERepository(Protocol):
    def find(self, product: str, version: str) -> list[CVERecord]: ...
    def get(self, cve_id: str) -> CVERecord | None: ...


class JsonCVERepository:
    def __init__(self, path: Path) -> None:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(
                f"CVE database not found at {path}. It ships with the project as app/data/cve_db.json: restore it "
                "(re-extract the project or `git checkout -- app/data/cve_db.json`) or point SECAGENT_CVE_DB_PATH at a valid file.")
        raw = json.loads(path.read_text(encoding="utf-8"))
        self._records = [CVERecord.model_validate(r) for r in raw]
        self._by_id = {r.cve_id: r for r in self._records}

    def get(self, cve_id: str) -> CVERecord | None:
        return self._by_id.get(cve_id)

    def find(self, product: str, version: str) -> list[CVERecord]:
        v = version_tuple(version)
        p = product.lower()
        if not v:
            return []
        hits = [
            r
            for r in self._records
            if any(alias in p for alias in r.products) and any(rng.contains(v) for rng in r.affected)
        ]
        return sorted(hits, key=lambda r: (-r.cvss_score, r.cve_id))
