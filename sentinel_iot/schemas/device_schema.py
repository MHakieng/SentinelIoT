from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class DeviceBase(BaseModel):
    ip: str
    mac: str
    vendor: str = "Unknown"
    asset_type: str = "iot"
    priority: int = 1

class DeviceRisk(BaseModel):
    vuln: float = 0.0
    anomaly: float = 0.0

class DeviceResult(DeviceBase):
    risk_score: float = 0.0
    status: str = "Safe"
    open_ports: List[Dict[str, Any]] = []
    total_cves: int = 0
    risk_breakdown: DeviceRisk = Field(default_factory=lambda: DeviceRisk())
    device_class: Optional[str] = None
    device_class_confidence: Optional[float] = None
    device_class_evidence: Optional[List[str]] = None
    device_class_method: Optional[str] = None

class DeviceHistory(BaseModel):
    timestamp: str
    risk_score: float
    vuln: float
    anomaly: float

class AnomalyLogEntry(BaseModel):
    timestamp: str
    type: str
    score: float
    details: Dict[str, Any]
