from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
import os
import uuid
from sentinel_iot.services.ml_service import MLService
from sentinel_iot.services.job_manager import JobManager
from sentinel_iot.api.dependencies import get_ml_service, get_job_manager, get_scanner_service
from sentinel_iot.schemas.job_schema import JobCreateResponse
from sentinel_iot.schemas.metrics_schema import MetricsResponse

router = APIRouter(tags=["ML Engine"])

@router.get("/metrics", response_model=MetricsResponse)
def get_ml_metrics(
    service: MLService = Depends(get_ml_service),
    scanner = Depends(get_scanner_service)
):
    """Retrieve model performance metrics, separating real vs synthetic."""
    last_scan_time = scanner.scan_status.get("last_scan")
    return service.get_metrics(last_scan_time)

@router.post("/train", response_model=JobCreateResponse)
def train_model(
    background_tasks: BackgroundTasks, 
    pcap_path: str,
    service: MLService = Depends(get_ml_service),
    job_manager: JobManager = Depends(get_job_manager)
):
    """Train the Anomaly Model using a captured PCAP file (Asynchronous)."""
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail="PCAP file not found")
    
    job_id = str(uuid.uuid4())
    job_manager.create_job(job_id, "train", target=pcap_path)
    
    background_tasks.add_task(service.train_model, pcap_path, job_id)
    return {"message": "Training started", "job_id": job_id, "status": "pending"}
