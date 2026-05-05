from pydantic import BaseModel
from typing import Optional


class TrainingMetrics(BaseModel):
    f1_score: Optional[float] = 0
    precision: Optional[float] = 0
    recall: Optional[float] = 0
    average_precision: Optional[float] = None
    validation_status: str = "unavailable"


class RealWorldMetrics(BaseModel):
    anomalies_detected_24h: int = 0
    true_positives: int = 0
    false_positives: int = 0
    system_uptime: str = "N/A"


class MetricsResponse(BaseModel):
    synthetic_training_metrics: TrainingMetrics
    real_world_metrics: RealWorldMetrics
    model_version: str
    last_training: str
