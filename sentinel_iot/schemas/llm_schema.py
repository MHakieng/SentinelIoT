from datetime import UTC, datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class DeviceAnalysisSection(str, Enum):
    risk_explanation = "risk_explanation"
    anomaly_summary = "anomaly_summary"
    next_actions = "next_actions"


class DeviceAnalysisRequest(BaseModel):
    device_ip: str
    include_sections: List[DeviceAnalysisSection] = Field(
        default_factory=lambda: [
            DeviceAnalysisSection.risk_explanation,
            DeviceAnalysisSection.anomaly_summary,
            DeviceAnalysisSection.next_actions,
        ]
    )


class DeviceAnalysisSections(BaseModel):
    risk_explanation: Optional[str] = None
    anomaly_summary: Optional[str] = None
    next_actions: List[str] = Field(default_factory=list)


class DeviceAnalysisGroundingSummary(BaseModel):
    risk_score: float = 0.0
    status: str = "Unknown"
    vuln_component: float = 0.0
    anomaly_component: float = 0.0
    total_cves: int = 0
    open_service_count: int = 0
    recent_anomaly_count: int = 0
    risk_history_points: int = 0
    latest_risk_timestamp: Optional[str] = None
    latest_anomaly_timestamp: Optional[str] = None
    monitor_runtime_status: Optional[str] = None


class EvidenceItem(BaseModel):
    source: str
    detail: str


class DeviceAnalysisResponse(BaseModel):
    device_ip: str
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"))
    sections: DeviceAnalysisSections
    grounding_summary: DeviceAnalysisGroundingSummary
    evidence_used: List[EvidenceItem] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class CVEExplanationRequest(BaseModel):
    device_ip: str
    cve_id: str
    port: Optional[int] = None
    service: Optional[str] = None


class CVEExplanationGroundingSummary(BaseModel):
    device_ip: str
    risk_score: float = 0.0
    device_status: str = "Unknown"
    cve_id: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_http_title: Optional[str] = None
    cvss_score: Optional[float] = None
    local_description: Optional[str] = None
    total_cves_on_device: int = 0
    matched_service_cve_count: int = 0
    vuln_component: float = 0.0
    anomaly_component: float = 0.0
    recent_anomaly_count: int = 0


class CVEExplanationResponse(BaseModel):
    cve_id: str
    title: str
    plain_language_summary: str
    why_it_matters_for_this_device: str
    recommended_actions: List[str] = Field(default_factory=list)
    grounding_summary: CVEExplanationGroundingSummary
    evidence_used: List[EvidenceItem] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
