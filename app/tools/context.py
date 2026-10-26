"""Per-scan state shared by every tool call: scope, observations, failure budgets, audit trace."""
from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.core.config import Settings
from app.core.errors import ToolExecutionError
from app.repositories.cve_repository import CVERepository
from app.schemas.report import DetectedService
from app.tools.parsers import infer_product_version


@dataclass
class ScanContext:
    scan_id: str
    settings: Settings
    cve_repo: CVERepository
    target: str | None
    ports: str = "1-1024"
    raw_scan_data: str | None = None
    last_nmap_output: str | None = None
    data_source: str | None = None  # 'live_nmap' | 'mock_fixture' | 'provided_scan_data'
    scan_evidence: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    observed: dict[tuple[int, str], DetectedService] = field(default_factory=dict)
    failures: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    tool_trace: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def assert_in_scope(self, target: str) -> None:
        """The agent may only ever touch the host this scan was authorised for."""
        if self.target is None:
            raise ToolExecutionError(
                "NO_TARGET", "No target is defined for this scan.", retryable=False,
                hint="Use parse_scan_output with source='provided_scan' instead.",
            )
        if target != self.target:
            raise ToolExecutionError(
                "OUT_OF_SCOPE", f"{target} is not authorised for this engagement.",
                hint=f"Only {self.target} is in scope. Re-call with target='{self.target}'.",
            )

    def record_services(self, services: list[DetectedService]) -> None:
        with self._lock:
            for s in services:
                self.observed[(s.port, s.protocol)] = s

    def record_banner(self, port: int, banner: str) -> None:
        with self._lock:
            key = (port, "tcp")
            svc = self.observed.get(key)
            if svc is None:
                return
            update: dict[str, Any] = {"banner": banner[:256]}
            if not (svc.product and svc.version):
                product, version = infer_product_version(banner)
                if product and version:
                    update.update(product=product, version=version)
            self.observed[key] = svc.model_copy(update=update)

    def snapshot_services(self) -> list[DetectedService]:
        with self._lock:
            return sorted(self.observed.values(), key=lambda s: (s.port, s.protocol))
