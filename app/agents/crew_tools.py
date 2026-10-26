"""Adapter: expose GuardedTools to CrewAI with a PERMISSIVE schema so bad args reach our validator
(which returns correction hints) instead of being rejected opaquely by the framework."""
from __future__ import annotations

from typing import Any

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field, create_model

from app.tools.base import GuardedTool


def permissive_schema(model: type[BaseModel]) -> type[BaseModel]:
    fields = {n: (Any, Field(default=None, description=f.description)) for n, f in model.model_fields.items()}
    return create_model(f"{model.__name__}Loose", __config__=ConfigDict(extra="allow"), **fields)


class GuardedCrewTool(BaseTool):
    name: str
    description: str
    args_schema: type[BaseModel]
    guarded: Any = Field(exclude=True)

    def _run(self, **kwargs: Any) -> str:
        return self.guarded(None, **{k: v for k, v in kwargs.items() if v is not None})


def to_crewai(tool: GuardedTool) -> GuardedCrewTool:
    return GuardedCrewTool(name=tool.name, description=tool.description,
                           args_schema=permissive_schema(tool.args_model), guarded=tool)
