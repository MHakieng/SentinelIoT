from pydantic import BaseModel, Field
from typing import Optional, Any, Dict


class RuntimeSummary(BaseModel):
    devices_found: int = 0
    devices_scanned: int = 0
    failed_devices: int = 0
    packets_captured: int = 0
    flows_tracked: int = 0
    history_points: int = 0
    last_interval_packets: int = 0


class JobStatus(BaseModel):
    id: str
    type: str
    status: str
    started_at: str
    updated_at: str
    progress: int = 0
    target: Optional[str] = None
    result: Optional[Any] = None
    message: Optional[str] = None
    error: Optional[str] = None
    active_job_id: Optional[str] = None
    is_running: bool = False
    last_event_at: Optional[str] = None
    summary: Optional[RuntimeSummary] = None
    start_time: Optional[str] = Field(default=None, description="Legacy compatibility field")


class JobCreateResponse(BaseModel):
    message: str
    job_id: str
    status: str


class JobControlResponse(BaseModel):
    message: str
    job_id: Optional[str] = None
    status: str


class ScanRuntimeStatus(BaseModel):
    status: str
    active_job_id: Optional[str] = None
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    is_running: bool = False
    last_event_at: Optional[str] = None
    summary: RuntimeSummary = Field(default_factory=RuntimeSummary)
    target: Optional[str] = None
    profile: Optional[str] = None
    last_completed_at: Optional[str] = None


class MonitorRuntimeStatus(BaseModel):
    status: str
    active_job_id: Optional[str] = None
    started_at: Optional[str] = None
    updated_at: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    is_running: bool = False
    last_event_at: Optional[str] = None
    summary: RuntimeSummary = Field(default_factory=RuntimeSummary)
    capture_window_seconds: Optional[int] = None
    last_completed_at: Optional[str] = None
