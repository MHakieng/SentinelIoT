from pydantic import BaseModel
from typing import Optional, List


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


class NbaiotBenchmarkResult(BaseModel):
    model: str
    dataset: str = ""
    sample_count: int = 0
    feature_count: int = 0
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None
    false_negative_rate: Optional[float] = None
    confusion_matrix: Optional[dict] = None


class NbaiotBenchmark(BaseModel):
    available: bool = False
    results: List[NbaiotBenchmarkResult] = []
    note: str = ""


class MetricsResponse(BaseModel):
    synthetic_training_metrics: TrainingMetrics
    runtime_detection_metrics: Optional[dict] = None
    runtime_metrics_metadata: RuntimeMetricsMetadata
    nbaiot_benchmark: Optional[NbaiotBenchmark] = None
    model_version: str
    last_training: str
