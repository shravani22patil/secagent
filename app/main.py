from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.routes import router as scan_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.repositories.cve_repository import JsonCVERepository
from app.repositories.report_repository import FileReportRepository
from app.services.scan_service import ScanService
from app.tools.nmap_runner import resolve_nmap

WEB_DIR = Path(__file__).resolve().parent / "web"
# The dashboard is same-origin static files, so a strict CSP is possible (no inline code allowed).
_DASHBOARD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.scan_service = ScanService(
            settings, JsonCVERepository(settings.cve_db_path), FileReportRepository(settings.reports_dir))
        yield

    app = FastAPI(title="SecAgent-Core", version="1.0.0", lifespan=lifespan)
    app.include_router(scan_router)
    for needed in (WEB_DIR / "index.html", WEB_DIR / "static" / "app.js", WEB_DIR / "static" / "styles.css"):
        if not needed.is_file():
            raise RuntimeError(f"Dashboard file missing: {needed}. Restore app/web/ from the project zip or Git "
                               "(check `git check-ignore -v` in case a .gitignore rule excludes it).")
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    @app.get("/", include_in_schema=False)
    async def dashboard() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html", headers=_DASHBOARD_HEADERS)

    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        nmap = "not_used" if settings.tool_mode == "mock" else ("found" if resolve_nmap(settings)[0] else "not_found")
        return {"status": "ok", "tool_mode": settings.tool_mode, "nmap": nmap,
                "pipeline": "agentic" if settings.agents_available else "deterministic"}

    return app


app = create_app()
