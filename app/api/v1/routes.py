from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_scan_service
from app.core.errors import InvalidScanRequest, ScanFailed, ScopeViolation
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest, service: ScanService = Depends(get_scan_service)) -> ScanResponse:
    try:
        return await service.run(req)
    except ScopeViolation as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except InvalidScanRequest as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ScanFailed as exc:
        raise HTTPException(status_code=exc.http_status, detail=f"{exc.code}: {exc}") from exc
