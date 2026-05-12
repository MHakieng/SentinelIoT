import os
import json
import threading
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from sentinel_iot.monitor.feature_extractor import extract_features
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.services.job_manager import JobManager

logger = logging.getLogger(__name__)

# N-BaIoT sonuç dosyalarının yolu
# N-BaIoT sonuç dosyalarının yolu (services/ → sentinel_iot/ → v3/)
EVALUATION_RESULTS_DIR = Path(__file__).resolve().parents[2] / "evaluation" / "results"

# Bilinen N-BaIoT model summary dosyaları
NBAIOT_SUMMARY_FILES = [
    "nbaiot_random_forest_summary.json",
    "nbaiot_extra_trees_summary.json",
    "nbaiot_hist_gradient_boosting_summary.json",
    "nbaiot_balanced_random_forest_summary.json",
    "nbaiot_device_split_summary.json",
    "nbaiot_attack_split_summary.json",
    "nbaiot_device_attack_split_summary.json",
]


def _load_nbaiot_benchmark() -> Optional[dict]:
    """Disk üzerindeki N-BaIoT benchmark sonuçlarını oku."""
    if not EVALUATION_RESULTS_DIR.exists():
        return None

    results = []
    for filename in NBAIOT_SUMMARY_FILES:
        filepath = EVALUATION_RESULTS_DIR / filename
        if not filepath.exists():
            continue
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Standard format uses "metrics", split experiments use "mean_metrics"
            metrics = data.get("metrics") or data.get("mean_metrics") or {}
            results.append({
                "model": data.get("model", filename.replace("nbaiot_", "").replace("_summary.json", "")),
                "dataset": os.path.basename(data.get("dataset") or data.get("input") or ""),
                "sample_count": data.get("sample_count", 0),
                "feature_count": data.get("feature_count", 0),
                "accuracy": metrics.get("accuracy"),
                "precision": metrics.get("precision"),
                "recall": metrics.get("recall"),
                "f1_score": metrics.get("f1_score"),
                "false_positive_rate": metrics.get("false_positive_rate"),
                "false_negative_rate": metrics.get("false_negative_rate"),
                "confusion_matrix": metrics.get("confusion_matrix"),
            })
        except Exception as e:
            logger.warning("N-BaIoT summary okunamadı: %s — %s", filepath, e)

    if not results:
        return None

    return {
        "available": True,
        "results": results,
        "note": (
            "N-BaIoT benchmark sonuçları evaluation/results/ dizininden okundu. "
            f"{len(results)} model sonucu mevcut."
        ),
    }


class MLService:
    """Service for managing the ML Anomaly Model training and metrics."""
    
    def __init__(self, anomaly_model: AnomalyModel, job_manager: JobManager):
        self.anomaly_model = anomaly_model
        self.job_manager = job_manager
        self._lock = threading.Lock()
        # N-BaIoT sonuçlarını başlangıçta bir kez yükle (disk I/O optimizasyonu)
        self._nbaiot_cache = _load_nbaiot_benchmark()

    def get_metrics(self, last_scan_time: Optional[str] = None):
        """Retrieve model performance metrics."""
        with self.anomaly_model.metrics_lock:
            m = self.anomaly_model.metrics.copy()

        return {
            "synthetic_training_metrics": m,
            "runtime_detection_metrics": None,
            "runtime_metrics_metadata": {
                "source": "not_available",
                "is_placeholder": False,
                "note": (
                    "Runtime TP/FP/F1 metrics require labelled production events "
                    "and are not available in this prototype."
                ),
            },
            "nbaiot_benchmark": self._nbaiot_cache,
            "model_version": "Isolation Forest v2.0",
            "last_training": last_scan_time or "N/A"
        }

    def train_model(self, pcap_path: str, job_id: str):
        """Background task to extract features and train the model."""
        try:
            self.job_manager.update_job(job_id, status="running")
            
            # Extract features (Potentially long-running)
            features = extract_features(pcap_file=pcap_path)
            if not features:
                self.job_manager.finish_job(job_id, result="No flows found in PCAP", status="failed")
                return
                
            self.anomaly_model.train(features)
            self.job_manager.finish_job(job_id, result=f"Trained on {len(features)} flows")
            
        except Exception as e:
            logger.error("Training Error: %s", e, exc_info=True)
            self.job_manager.update_job(job_id, status="failed", result=str(e), progress=100, message="Training failed", error=str(e))
