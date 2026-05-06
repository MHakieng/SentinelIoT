from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import Optional
import uuid
from sentinel_iot.services.scanner_service import ScannerService
from sentinel_iot.services.job_manager import JobManager
from sentinel_iot.scanner.network_scan import get_local_network
from sentinel_iot.scanner.vulnerability_scan import PROFILE_ARGUMENTS
from sentinel_iot.api.dependencies import get_scanner_service, get_job_manager, get_devices_db
from sentinel_iot.schemas.job_schema import JobCreateResponse, JobStatus, ScanRuntimeStatus

router = APIRouter(prefix="/scanner", tags=["Scanner"])


def _build_scan_status(service: ScannerService, job_manager: JobManager) -> JobStatus:
    """Return a stable status payload for the active scan state."""
    active_scan = job_manager.get_active_job("scan")

    if active_scan:
        return JobStatus(**active_scan)

    latest_scan = job_manager.get_latest_job("scan")
    if latest_scan:
        return JobStatus(**latest_scan)

    runtime = service.get_runtime_status()
    return JobStatus(
        id="scan-status",
        type="scan",
        status=runtime.get("status", "idle"),
        started_at=runtime.get("started_at") or "N/A",
        updated_at=runtime.get("updated_at") or "N/A",
        progress=100 if runtime.get("status") == "completed" else 0,
        target=runtime.get("target"),
        result=None,
        message=runtime.get("message") or "No active scan job",
        error=runtime.get("error"),
        active_job_id=runtime.get("active_job_id"),
        is_running=runtime.get("is_running", False),
        last_event_at=runtime.get("last_event_at"),
        summary=runtime.get("summary"),
        start_time=runtime.get("started_at") or "N/A",
    )

@router.post("/scans", response_model=JobCreateResponse)
def trigger_scan(
    background_tasks: BackgroundTasks, 
    target_range: Optional[str] = None,
    profile: str = "quick",
    service: ScannerService = Depends(get_scanner_service),
    job_manager: JobManager = Depends(get_job_manager),
    devices_db = Depends(get_devices_db)
):
    """Trigger a non-blocking network scan with Job ID."""
    if profile not in PROFILE_ARGUMENTS:
        supported = ", ".join(sorted(PROFILE_ARGUMENTS))
        raise HTTPException(status_code=400, detail=f"Unsupported scan profile '{profile}'. Supported profiles: {supported}.")

    network = target_range or get_local_network()
    if not network:
        raise HTTPException(status_code=400, detail="Could not determine local network")
    
    if service.get_runtime_status().get("is_running"):
        active_scan = job_manager.get_active_job("scan")
        active_job_id = active_scan["id"] if active_scan else "active"
        return {"message": "Scan already in progress", "job_id": active_job_id, "status": "running"}

    job_id = str(uuid.uuid4())
    job_manager.create_job(job_id, "scan", target=network)
    service.mark_scan_pending(job_id, network, profile)
    
    background_tasks.add_task(service.perform_full_scan, network, job_id, devices_db, profile=profile)
    return {"message": "Scan started", "job_id": job_id, "status": "pending"}


@router.get("/status", response_model=ScanRuntimeStatus)
def get_scan_runtime_status(service: ScannerService = Depends(get_scanner_service)):
    return service.get_runtime_status()

@router.get("/jobs", response_model=JobStatus)
@router.get("/jobs/{job_id}", response_model=JobStatus)
def get_job_status(
    job_id: Optional[str] = None,
    service: ScannerService = Depends(get_scanner_service),
    job_manager: JobManager = Depends(get_job_manager)
):
    if job_id:
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job ID not found")
        return job
    return _build_scan_status(service, job_manager)
