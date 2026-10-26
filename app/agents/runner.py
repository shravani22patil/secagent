"""Runs the crew and converts its output to a ThreatReport, with a structured-parsing fallback."""
from __future__ import annotations

import json

from pydantic import ValidationError

from app.agents.crew import build_crew
from app.core.config import Settings
from app.core.errors import ReportParseError
from app.schemas.report import ThreatReport
from app.tools.context import ScanContext


def extract_json_object(text: str) -> dict:
    """Find the first balanced {...} in free text (handles ```json fences and chatter)."""
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                esc = (ch == "\\" and not esc)
                if ch == '"' and not esc:
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        pass
                    break
        start = text.find("{", start + 1)
    raise ReportParseError("no JSON object found in agent output")


def parse_report_fallback(raw: str) -> ThreatReport:
    try:
        return ThreatReport.model_validate(extract_json_object(raw))
    except ValidationError as exc:
        raise ReportParseError(f"agent JSON failed schema validation: {exc.error_count()} error(s)") from exc


def run_agent_pipeline(ctx: ScanContext, settings: Settings) -> ThreatReport:
    output = build_crew(ctx, settings).kickoff()
    parsed = getattr(output, "pydantic", None)
    if isinstance(parsed, ThreatReport):
        return parsed
    return parse_report_fallback(getattr(output, "raw", "") or str(output))
