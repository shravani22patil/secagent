"""Environment-driven configuration (12-factor). All vars use the SECAGENT_ prefix."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import json
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_APP_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECAGENT_", env_file=".env", extra="ignore", populate_by_name=True)

    log_level: str = "INFO"

    # Tooling
    tool_mode: Literal["mock", "live"] = "mock"
    # Accepts "127.0.0.1/32,192.168.1.0/24" or a JSON list. Empty = every live scan is refused.
    allowed_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=list)
    nmap_path: str | None = None  # explicit nmap executable; otherwise PATH, then common Windows locations
    nmap_skip_host_discovery: bool = False  # True adds -Pn (use when ICMP/ping is filtered)
    max_ports: int = Field(2000, ge=1, le=65535)  # cap on ports per scan to bound duration
    tool_timeout_s: float = Field(60.0, gt=0)
    banner_timeout_s: float = Field(5.0, gt=0)
    tool_max_failures: int = Field(3, ge=1)

    # Agents / LLM
    agents_enabled: bool = True
    llm_model: str = "anthropic/claude-sonnet-5-5"
    # SECAGENT_LLM_API_KEY, or the standard ANTHROPIC_API_KEY. Never logged or returned.
    llm_api_key: SecretStr | None = Field(default=None, validation_alias=AliasChoices("SECAGENT_LLM_API_KEY", "ANTHROPIC_API_KEY", "llm_api_key"))
    llm_timeout_s: float = Field(60.0, gt=0)
    agent_max_iter: int = Field(8, ge=1)

    # Service
    scan_timeout_s: float = Field(180.0, gt=0)
    scan_max_attempts: int = Field(2, ge=1)
    max_concurrent_scans: int = Field(4, ge=1)

    # Persistence
    reports_dir: Path = Path("reports")
    cve_db_path: Path = _APP_DIR / "data" / "cve_db.json"

    @field_validator("allowed_cidrs", mode="before")
    @classmethod
    def _split_cidrs(cls, v):
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            return json.loads(v) if v.startswith("[") else [x.strip() for x in v.split(",") if x.strip()]
        return v

    @property
    def agents_available(self) -> bool:
        """Agents only run when enabled AND an API key is configured."""
        return self.agents_enabled and bool(self.llm_api_key and self.llm_api_key.get_secret_value().strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
