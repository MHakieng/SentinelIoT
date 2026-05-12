import joblib
import pandas as pd
import pytest
from pathlib import Path

from sentinel_iot.ml.ciciot2023_inference import (
    build_feature_frame,
    build_live_feature_dict,
    clear_ciciot_model_cache,
    load_ciciot_model,
    predict_flow_anomaly,
)
from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA
from sentinel_iot.ml.train_ciciot2023_random_forest import LABEL_MAPPING, build_model_pipeline


def _live_flow(duration=2.0):
    return {
        "packet_count": 10,
        "byte_count": 1000,
        "duration": duration,
        "avg_packet_size": 100.0,
        "mean_iat": 0.1,
        "var_iat": 0.01,
    }


def test_live_feature_dict_and_frame_use_schema_order():
    prepared = build_live_feature_dict(_live_flow())
    frame = build_feature_frame(prepared)

    assert list(prepared.keys()) == LIVE_FEATURE_SCHEMA
    assert list(frame.columns) == LIVE_FEATURE_SCHEMA


def test_packet_rate_is_derived_from_duration():
    prepared = build_live_feature_dict(_live_flow(duration=2.0))
    assert prepared["packet_rate"] == 5.0


def test_packet_rate_is_zero_when_duration_is_zero():
    prepared = build_live_feature_dict(_live_flow(duration=0.0))
    assert prepared["packet_rate"] == 0.0


def test_missing_feature_raises_clear_error():
    incomplete = {
        "packet_count": 10,
        "byte_count": 1000,
        "avg_packet_size": 100.0,
        "mean_iat": 0.1,
        "packet_rate": 5.0,
    }

    with pytest.raises(ValueError, match="Missing live feature"):
        build_feature_frame(incomplete)


def test_missing_model_does_not_crash():
    result = predict_flow_anomaly(_live_flow(), model_path=Path(".pytest_tmp") / "missing_ciciot_rf.joblib")
    assert result["model_available"] is False
    assert result["reason"] == "CICIoT2023 RandomForest model artifact not found"


def test_model_artifact_schema_matches_live_schema():
    artifact = load_ciciot_model("sentinel_iot/ml/models/ciciot2023_random_forest.joblib")
    assert artifact is not None
    assert artifact["feature_schema"] == LIVE_FEATURE_SCHEMA


def test_prediction_response_shape_with_artifact():
    clear_ciciot_model_cache()
    x = pd.DataFrame([
        [10, 1000, 100, 0.10, 0.010, 5],
        [12, 1100, 92, 0.11, 0.012, 6],
        [500, 100000, 200, 0.0001, 0.0, 10000],
        [650, 120000, 185, 0.0001, 0.0, 16250],
    ], columns=LIVE_FEATURE_SCHEMA)
    y = pd.Series([0, 0, 1, 1])
    model = build_model_pipeline(random_state=42)
    model.fit(x, y)
    temp_dir = Path(".pytest_tmp") / "ciciot_live_inference"
    temp_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = temp_dir / "model.joblib"
    joblib.dump({
        "model": model,
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "label_mapping": LABEL_MAPPING,
        "dataset": "CICIoT2023",
        "model_type": "RandomForestClassifier",
    }, artifact_path)

    result = predict_flow_anomaly(_live_flow(), model_path=artifact_path)
    assert result["model_available"] is True
    assert result["model_name"] == "ciciot2023_random_forest"
    assert result["model_type"] == "RandomForestClassifier"
    assert result["dataset"] == "CICIoT2023"
    assert result["threshold"] == 0.5
    assert isinstance(result["attack_probability"], float)


def test_model_loader_caches_artifact(monkeypatch, tmp_path):
    clear_ciciot_model_cache()
    artifact_path = tmp_path / "cached_model.joblib"
    artifact_path.write_bytes(b"placeholder")
    artifact = {
        "model": object(),
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "dataset": "CICIoT2023",
        "model_type": "RandomForestClassifier",
    }
    calls = {"count": 0}

    def fake_load(path):
        calls["count"] += 1
        assert Path(path) == artifact_path.resolve()
        return artifact

    monkeypatch.setattr("sentinel_iot.ml.ciciot2023_inference.joblib.load", fake_load)

    assert load_ciciot_model(artifact_path) is artifact
    assert load_ciciot_model(artifact_path) is artifact
    assert calls["count"] == 1


def test_model_load_failure_returns_controlled_response(monkeypatch, tmp_path):
    clear_ciciot_model_cache()
    artifact_path = tmp_path / "broken_model.joblib"
    artifact_path.write_bytes(b"broken")

    def fake_load(path):
        raise RuntimeError("cannot unpickle")

    monkeypatch.setattr("sentinel_iot.ml.ciciot2023_inference.joblib.load", fake_load)

    result = predict_flow_anomaly(_live_flow(), model_path=artifact_path)
    assert result["model_available"] is False
    assert result["status"] == "unavailable"
    assert "could not be loaded" in result["reason"]
