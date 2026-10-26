"""
GuardedTool: the self-correcting tool wrapper (the heart of the error-handling story).

Contract: calling a GuardedTool NEVER raises. Every outcome is a ToolResult serialised to JSON.
On failure the agent receives {error_code, errors[], correction_hint, retryable} so the LLM can
repair its call in-context. A per-tool failure budget stops infinite retry loops.
"""
from __future__ import annotations

import ast
import json
import re
import time
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from app.core.errors import ToolExecutionError
from app.core.logging import get_logger
from app.tools.context import ScanContext

log = get_logger("secagent.tools")
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$")
_BARE = "__bare__"


class ToolResult(BaseModel):
    ok: bool
    tool: str
    data: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    errors: list[dict[str, str]] | None = None
    correction_hint: str | None = None
    retryable: bool | None = None

    def render(self) -> str:
        return self.model_dump_json(exclude_none=True)


def coerce_tool_input(raw: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Tolerant parsing of whatever the LLM emitted: dict, JSON, fenced JSON, python-dict repr, bare value."""
    if kwargs:
        return dict(kwargs)
    if isinstance(raw, dict):
        return dict(raw)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return {}
    if isinstance(raw, str):
        text = _FENCE.sub("", raw.strip()).strip()
        for loader in (json.loads, ast.literal_eval):
            try:
                obj = loader(text)
            except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
                continue
            if isinstance(obj, dict):
                return obj
        return {_BARE: text}
    raise ValueError(f"unsupported tool input type: {type(raw).__name__}")


class GuardedTool:
    def __init__(
        self,
        *,
        name: str,
        description: str,
        args_model: type[BaseModel],
        handler: Callable[[ScanContext, Any], dict[str, Any]],
        ctx: ScanContext,
        example: dict[str, Any],
        aliases: dict[str, str] | None = None,
        primary_field: str | None = None,
    ) -> None:
        self.name, self.description = name, description
        self.args_model, self.handler, self.ctx = args_model, handler, ctx
        self.example, self.aliases, self.primary_field = example, aliases or {}, primary_field

    # -- public ------------------------------------------------------------------
    def __call__(self, raw: Any = None, **kwargs: Any) -> str:
        return self.invoke(raw, **kwargs).render()

    def invoke(self, raw: Any = None, **kwargs: Any) -> ToolResult:
        started = time.perf_counter()
        result = self._run(raw, kwargs)
        self.ctx.tool_trace.append(
            {"tool": self.name, "ok": result.ok, "error_code": result.error_code,
             "ms": int((time.perf_counter() - started) * 1000)}
        )
        log.info("tool_call", extra={"ctx": {"tool": self.name, "ok": result.ok, "error_code": result.error_code}})
        return result

    # -- internals ---------------------------------------------------------------
    def _run(self, raw: Any, kwargs: dict[str, Any]) -> ToolResult:
        if self.ctx.failures[self.name] >= self.ctx.settings.tool_max_failures:
            return ToolResult(
                ok=False, tool=self.name, error_code="RETRY_BUDGET_EXHAUSTED", retryable=False,
                message=f"{self.name} failed {self.ctx.failures[self.name]} times in a row.",
                correction_hint="Do NOT call this tool again. Continue with the data already collected and note the gap.",
            )
        try:
            payload = self._normalise(coerce_tool_input(raw, kwargs))
        except ValueError as exc:
            return self._fail("MALFORMED_INPUT", str(exc), retryable=True, hint=self._schema_hint())
        try:
            args = self.args_model.model_validate(payload)
        except ValidationError as exc:
            errors = [
                {"field": ".".join(map(str, e["loc"])) or "<root>", "problem": e["msg"]}
                for e in exc.errors(include_url=False, include_context=False)
            ]
            return self._fail("INVALID_ARGUMENTS", "Arguments failed validation.", retryable=True,
                              hint=self._schema_hint(), errors=errors)
        try:
            data = self.handler(self.ctx, args)
        except ToolExecutionError as exc:
            return self._fail(exc.code, exc.message, retryable=exc.retryable, hint=exc.hint or self._schema_hint())
        except Exception:  # noqa: BLE001 - tools must never crash the agent loop
            log.exception("tool_crashed", extra={"ctx": {"tool": self.name}})
            return self._fail("INTERNAL_ERROR", "Tool crashed unexpectedly.", retryable=False,
                              hint="Do not retry this call. Continue with data collected so far.")
        self.ctx.failures[self.name] = 0
        return ToolResult(ok=True, tool=self.name, data=data)

    def _normalise(self, payload: dict[str, Any]) -> dict[str, Any]:
        if _BARE in payload:
            if not self.primary_field:
                raise ValueError("Expected a JSON object of named arguments, got a bare value.")
            payload = {self.primary_field: payload[_BARE]}
        out: dict[str, Any] = {}
        for key, value in payload.items():
            canon = self.aliases.get(str(key).strip().lower().replace("-", "_"), str(key).strip())
            out.setdefault(canon, value)
        return out

    def _schema_hint(self) -> str:
        schema = self.args_model.model_json_schema()
        required = set(schema.get("required", []))
        fields = {
            n: f"{'required' if n in required else 'optional'}: {p.get('description', '')}".strip()
            for n, p in schema.get("properties", {}).items()
        }
        return (f"Re-issue the call as ONE JSON object using only these fields {json.dumps(fields)}. "
                f"Valid example: {json.dumps(self.example)}")

    def _fail(self, code: str, message: str, *, retryable: bool, hint: str | None,
              errors: list[dict[str, str]] | None = None) -> ToolResult:
        self.ctx.failures[self.name] += 1
        return ToolResult(ok=False, tool=self.name, error_code=code, message=message,
                          errors=errors, correction_hint=hint, retryable=retryable)
