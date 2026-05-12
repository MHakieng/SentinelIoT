import joblib
import pandas as pd
import pytest
from pathlib import Path

from sentinel_iot.ml.ciciot2023_inference import build_feature_frame, load_ciciot_model
from sentinel_iot.ml.ciciot2023_preprocessing import (
    CICIOT_TO_LIVE_FEATURES,
    infer_binary_label_from_path,
    transform_ciciot_frame,
)
from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA
from sentinel_iot.ml.train_ciciot2023_random_forest import LABEL_MAPPING, build_model_pipeline


def test_live_feature_schema_order_is_fixed():
    assert LIVE_FEATURE_SCHEMA == [
        "packet_count",
        "byte_count",
        "avg_packet_size",
        "mean_iat",
        "var_iat",
        "packet_rate",
    ]


def test_ciciot_column_mapping_matches_live_schema():
    assert list(CICIOT_TO_LIVE_FEATURES.values()) == LIVE_FEATURE_SCHEMA
    assert CICIOT_TO_LIVE_FEATURES == {
        "Number": "packet_count",
        "Tot sum": "byte_count",
        "AVG": "avg_packet_size",
        "IAT": "mean_iat",
        "Variance": "var_iat",
        "Rate": "packet_rate",
    }


def test_label_binary_conversion():
    raw = pd.DataFrame([
        {
            "Number": 10,
            "Tot sum": 1000,
            "AVG": 100,
            "IAT": 0.1,
            "Variance": 0.01,
            "Rate": 10.0,
        },
        {
            "Number": 50,
            "Tot sum": 5000,
            "AVG": 100,
            "IAT": 0.004,
            "Variance": 0.0,
            "Rate": 250.0,
        },
    ])

    X, y, cleaning = transform_ciciot_frame(raw, "C:/data/BenignTraffic/example.csv")

    assert list(X.columns) == LIVE_FEATURE_SCHEMA
    assert y.tolist() == [0, 0]
    assert cleaning["output_rows"] == 2
    assert LABEL_MAPPING == {"BenignTraffic": 0, "Attack": 1}
    assert infer_binary_label_from_path("C:/data/DDoS-ICMP_Flood/example.csv") == 1


def test_inference_missing_feature_raises():
    incomplete = {
        "packet_count": 10,
        "byte_count": 1000,
        "avg_packet_size": 100,
        "mean_iat": 0.1,
        "var_iat": 0.01,
    }

    with pytest.raises(ValueError, match="Missing live feature"):
        build_feature_frame(incomplete)


def test_model_artifact_contains_feature_schema():
    X = pd.DataFrame([
        [10, 1000, 100, 0.10, 0.010, 10],
        [12, 1100, 92, 0.11, 0.012, 11],
        [500, 100000, 200, 0.0001, 0.0, 10000],
        [650, 120000, 185, 0.0001, 0.0, 16250],
    ], columns=LIVE_FEATURE_SCHEMA)
    y = pd.Series([0, 0, 1, 1])

    model = build_model_pipeline(random_state=42)
    model.fit(X, y)
    temp_dir = Path(".pytest_tmp") / "ciciot_feature_schema"
    temp_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = temp_dir / "ciciot2023_random_forest.joblib"
    joblib.dump({
        "model": model,
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "label_mapping": LABEL_MAPPING,
        "dataset": "CICIoT2023",
    }, artifact_path)

    artifact = load_ciciot_model(artifact_path)

    assert artifact["feature_schema"] == LIVE_FEATURE_SCHEMA
    assert artifact["dataset"] == "CICIoT2023"
