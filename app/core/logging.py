"""Structured (JSON) logging with a per-scan correlation id."""
from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from typing import Any

scan_id_var: ContextVar[str] = ContextVar("scan_id", default="-")
_SECRET = re.compile(r"(sk-[A-Za-z0-9_\-]{8,}|x-api-key[^\s,;]*)", re.I)


def redact(text: str) -> str:
    return _SECRET.sub("[REDACTED]", text)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
            "scan_id": scan_id_var.get(),
        }
        extra = getattr(record, "ctx", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return redact(json.dumps(payload, default=str))


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
