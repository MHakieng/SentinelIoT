from pydantic import BaseModel
from typing import Optional


class TrainingMetrics(BaseModel):
    f1_score: Optional[float] = 0
    precision: Optional[float] = 0
    recall: Optional[float] = 0
    average_precision: Optional[float] = None
    validation_status: str = "unavailable"


class RuntimeMetricsMetadata(BaseModel):
    source: str = "not_available"
    is_placeholder: bool = False
    note: str


class MetricsResponse(BaseModel):
    synthetic_training_metrics: TrainingMetrics
    runtime_detection_metrics: Optional[dict] = None
    runtime_metrics_metadata: RuntimeMetricsMetadata
    model_version: str
    last_training: str
