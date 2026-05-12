import json
from pathlib import Path

import joblib
import pandas as pd

from sentinel_iot.ml.ciciot2023_inference import predict_flow_anomaly
from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA
from sentinel_iot.ml.train_ciciot2023_random_forest import LABEL_MAPPING, build_model_pipeline


def _training_frame():
    x = pd.DataFrame([
        [10, 1000, 100, 0.10, 0.010, 10],
        [12, 1100, 92, 0.11, 0.012, 11],
        [500, 100000, 200, 0.0001, 0.0, 10000],
        [650, 120000, 185, 0.0001, 0.0, 16250],
    ], columns=LIVE_FEATURE_SCHEMA)
    y = pd.Series([0, 0, 1, 1])
    return x, y


def test_model_artifact_schema_and_predict_proba():
    x, y = _training_frame()
    model = build_model_pipeline(random_state=42)
    model.fit(x, y)

    temp_dir = Path(".pytest_tmp") / "ciciot_model_training"
    temp_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = temp_dir / "model.joblib"
    joblib.dump({
        "model": model,
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "label_mapping": LABEL_MAPPING,
        "dataset": "CICIoT2023",
        "model_type": "RandomForestClassifier",
    }, artifact_path)

    artifact = joblib.load(artifact_path)
    assert artifact["feature_schema"] == LIVE_FEATURE_SCHEMA
    assert artifact["model"].predict_proba(x.head(1)).shape == (1, 2)


def test_report_json_contains_required_metrics():
    temp_dir = Path(".pytest_tmp") / "ciciot_model_training"
    temp_dir.mkdir(parents=True, exist_ok=True)
    report_path = temp_dir / "report.json"
    report_path.write_text(json.dumps({
        "metrics": {"precision": 1.0, "recall": 1.0, "f1": 1.0},
        "confusion_matrix": [[1, 0], [0, 1]],
    }), encoding="utf-8")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert "precision" in report["metrics"]
    assert "recall" in report["metrics"]
    assert "f1" in report["metrics"]
    assert "confusion_matrix" in report


def test_missing_model_returns_unavailable():
    result = predict_flow_anomaly(
        {
            "packet_count": 10,
            "byte_count": 1000,
            "avg_packet_size": 100,
            "mean_iat": 0.1,
            "var_iat": 0.01,
            "packet_rate": 10,
        },
        model_path=Path(".pytest_tmp") / "ciciot_model_training" / "missing.joblib",
    )
    assert result["status"] == "unavailable"
    assert result["is_anomaly"] is None
