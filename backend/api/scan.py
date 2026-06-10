from fastapi import APIRouter, BackgroundTasks, File, UploadFile, Request
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional

from backend.services.scan_service import (
    process_scan_url,
    process_scan_email,
    process_scan_app,
    process_search_app_safety,
    process_scan_health
)

router = APIRouter(prefix="/scan", tags=["scan"])

class URLScanRequest(BaseModel):
    url: HttpUrl
    user_id: Optional[str] = None
    email: Optional[str] = None

class EmailScanRequest(BaseModel):
    email_content: str = Field(..., min_length=1, max_length=50000)
    subject: str = ""
    user_id: Optional[str] = None
    email: Optional[str] = None

class ScanResponse(BaseModel):
    is_malicious: bool
    confidence: float
    threat_type: str
    explanation: str
    indicators: List[str]
    prediction_time_ms: float
    model_version: str
    from_cache: str  
    request_id: str
    timestamp: str

class AppSearchRequest(BaseModel):
    app_name: str

@router.post("/url", response_model=ScanResponse)
async def scan_url(request: URLScanRequest, background_tasks: BackgroundTasks, raw_request: Request):
    return await process_scan_url(request, background_tasks, raw_request)

@router.post("/email", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest, background_tasks: BackgroundTasks, raw_request: Request):
    return await process_scan_email(request, background_tasks, raw_request)

@router.post("/app")
async def scan_app(background_tasks: BackgroundTasks, raw_request: Request, file: UploadFile = File(...), user_id: Optional[str] = None):
    return await process_scan_app(background_tasks, raw_request, file, user_id)

@router.post("/app-name")
async def search_app_safety(request: AppSearchRequest, background_tasks: BackgroundTasks, raw_request: Request, user_id: Optional[str] = None):
    return await process_search_app_safety(request, background_tasks, raw_request, user_id)

@router.get("/health")
async def scan_health():
    return await process_scan_health()