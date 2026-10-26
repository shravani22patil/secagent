"""Persists reports as JSON + Markdown. Swap for S3/DB by implementing `save`."""
from __future__ import annotations

from pathlib import Path

from app.schemas.report import ThreatReport
from app.services.reporting import render_markdown


class FileReportRepository:
    def __init__(self, directory: Path) -> None:
        self._dir = Path(directory)

    def save(self, scan_id: str, report: ThreatReport, mode: str, data_source: str = "unknown") -> Path:
        self._dir.mkdir(parents=True, exist_ok=True)
        json_path = self._dir / f"{scan_id}.json"
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        (self._dir / f"{scan_id}.md").write_text(render_markdown(report, scan_id, mode, data_source), encoding="utf-8")
        return json_path
