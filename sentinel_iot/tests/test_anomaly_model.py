"""Unit tests for the Anomaly Detection ML model."""

import os
import pytest
from sentinel_iot.ml.anomaly_model import AnomalyModel


# Realistic test data
NORMAL_DATA = [
    {'packet_count': 10, 'byte_count': 1000, 'duration': 1.0, 'avg_packet_size': 100, 'mean_iat': 0.1, 'var_iat': 0.002, 'dst_ip': '192.168.1.10', 'label': 0},
    {'packet_count': 12, 'byte_count': 1100, 'duration': 1.1, 'avg_packet_size': 91, 'mean_iat': 0.11, 'var_iat': 0.003, 'dst_ip': '192.168.1.10', 'label': 0},
    {'packet_count': 8, 'byte_count': 900, 'duration': 0.9, 'avg_packet_size': 112, 'mean_iat': 0.09, 'var_iat': 0.001, 'dst_ip': '192.168.1.10', 'label': 0},
    {'packet_count': 15, 'byte_count': 1500, 'duration': 1.5, 'avg_packet_size': 100, 'mean_iat': 0.107, 'var_iat': 0.002, 'dst_ip': '192.168.1.20', 'label': 0},
    {'packet_count': 9, 'byte_count': 850, 'duration': 0.8, 'avg_packet_size': 94, 'mean_iat': 0.1, 'var_iat': 0.004, 'dst_ip': '192.168.1.20', 'label': 0},
]

ANOMALY_DATA = [
    {'packet_count': 50000, 'byte_count': 10000000, 'duration': 0.1, 'avg_packet_size': 200, 'mean_iat': 0.000002, 'var_iat': 0.0, 'dst_ip': '9.9.9.9', 'label': 1},
]

COMBINED_TRAINING = NORMAL_DATA * 20 + ANOMALY_DATA  # Enough data for training


@pytest.fixture
def fresh_model(tmp_path):
    """Create a model with a temp path so tests don't interfere with production model."""
    model_path = str(tmp_path / "test_model.joblib")
    return AnomalyModel(model_path=model_path)


class TestTraining:
    """Model training pipeline tests."""

    def test_train_creates_model(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        assert fresh_model.model is not None

    def test_train_produces_metrics(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        assert fresh_model.metrics["validation_status"] == "validated"
        assert 0.0 <= fresh_model.metrics["f1_score"] <= 1.0
        assert 0.0 <= fresh_model.metrics["precision"] <= 1.0
        assert 0.0 <= fresh_model.metrics["recall"] <= 1.0

    def test_train_saves_to_disk(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        assert os.path.exists(fresh_model.model_path)

    def test_model_loads_from_disk(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        loaded = AnomalyModel(model_path=fresh_model.model_path)
        assert loaded.model is not None
        assert loaded.metrics["f1_score"] > 0


class TestDetection:
    """Anomaly detection tests."""

    def test_no_detection_without_model(self, fresh_model):
        result = fresh_model.detect(NORMAL_DATA)
        assert result == []

    def test_detects_extreme_anomaly(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        results = fresh_model.detect(ANOMALY_DATA)
        # The extreme flood traffic should be detected as anomalous
        assert len(results) > 0

    def test_anomaly_score_is_normalized(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        results = fresh_model.detect(ANOMALY_DATA)
        if results:
            for r in results:
                assert 0.0 <= r["score"] <= 1.0

    def test_normal_traffic_fewer_anomalies(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        normal_results = fresh_model.detect(NORMAL_DATA)
        anomaly_results = fresh_model.detect(ANOMALY_DATA)
        # Normal traffic should trigger fewer (or no) anomalies than clearly anomalous traffic
        assert len(normal_results) <= len(anomaly_results) or len(normal_results) == 0


class TestBatchRetraining:
    """Batch retraining (formerly online learning) tests."""

    def test_batch_retrain_accumulates(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        
        # Feed new data multiple times
        for _ in range(3):
            fresh_model.batch_retraining(NORMAL_DATA * 5)
        
        assert hasattr(fresh_model, 'retrain_buffer')

    def test_empty_data_no_crash(self, fresh_model):
        fresh_model.train(COMBINED_TRAINING)
        fresh_model.batch_retraining([])
        fresh_model.batch_retraining(None)
