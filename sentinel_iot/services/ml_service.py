import os
import threading
import logging
from typing import List, Dict, Any, Optional
from sentinel_iot.monitor.feature_extractor import extract_features
from sentinel_iot.ml.anomaly_model import AnomalyModel
from sentinel_iot.services.job_manager import JobManager

logger = logging.getLogger(__name__)

class MLService:
    """Service for managing the ML Anomaly Model training and metrics."""
    
    def __init__(self, anomaly_model: AnomalyModel, job_manager: JobManager):
        self.anomaly_model = anomaly_model
        self.job_manager = job_manager
        self._lock = threading.Lock()

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
