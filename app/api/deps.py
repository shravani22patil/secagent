from fastapi import Request

from app.services.scan_service import ScanService


def get_scan_service(request: Request) -> ScanService:
    return request.app.state.scan_service
