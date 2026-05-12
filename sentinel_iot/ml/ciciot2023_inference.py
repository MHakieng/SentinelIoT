"""Inference helpers for the CICIoT2023 RandomForest anomaly model."""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, Mapping, Optional

import joblib
import pandas as pd

from sentinel_iot.ml.live_feature_schema import LIVE_FEATURE_SCHEMA


DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "models" / "ciciot2023_random_forest.joblib"
MODEL_NAME = "ciciot2023_random_forest"
THRESHOLD = 0.5
_MODEL_CACHE: dict[Path, Optional[Dict[str, Any]]] = {}
_MODEL_CACHE_LOCK = Lock()


class CICIOTModelUnavailable(RuntimeError):
    """Raised when the CICIoT2023 model artifact is not available."""


def clear_ciciot_model_cache() -> None:
    """Clear the process-local model cache. Intended for tests and controlled reloads."""
    with _MODEL_CACHE_LOCK:
        _MODEL_CACHE.clear()


def load_ciciot_model(model_path: str | Path = DEFAULT_MODEL_PATH) -> Optional[Dict[str, Any]]:
    """Load a CICIoT2023 model artifact.

    Returns None when the artifact is missing so runtime code can honestly report
    unavailable instead of crashing.
    """
    path = Path(model_path).resolve()
    with _MODEL_CACHE_LOCK:
        if path in _MODEL_CACHE:
            return _MODEL_CACHE[path]

    if not path.exists():
        with _MODEL_CACHE_LOCK:
            _MODEL_CACHE[path] = None
        return None

    artifact = joblib.load(path)
    if not isinstance(artifact, dict) or "model" not in artifact:
        raise ValueError(f"Invalid CICIoT2023 model artifact: {path}")

    feature_schema = artifact.get("feature_schema")
    if feature_schema != LIVE_FEATURE_SCHEMA:
        raise ValueError(
            "CICIoT2023 model feature_schema mismatch. "
            f"Expected {LIVE_FEATURE_SCHEMA}, got {feature_schema}"
        )

    with _MODEL_CACHE_LOCK:
        _MODEL_CACHE[path] = artifact
    return artifact


def build_feature_frame(flow_features: Mapping[str, Any] | Iterable[Mapping[str, Any]]) -> pd.DataFrame:
    """Build a DataFrame in the exact LIVE_FEATURE_SCHEMA order."""
    rows = list(flow_features) if not isinstance(flow_features, Mapping) else [flow_features]
    if not rows:
        raise ValueError("No flow features provided.")

    missing = sorted({
        feature
        for row in rows
        for feature in LIVE_FEATURE_SCHEMA
        if feature not in row
    })
    if missing:
        raise ValueError(f"Missing live feature(s): {missing}")

    frame = pd.DataFrame(rows)
    frame = frame[LIVE_FEATURE_SCHEMA].copy()
    return frame.apply(pd.to_numeric, errors="coerce")


def build_live_feature_dict(flow_features: Mapping[str, Any]) -> Dict[str, Any]:
    """Build a single live feature dict, deriving packet_rate from duration if needed."""
    prepared = dict(flow_features)
    if "packet_rate" not in prepared:
        try:
            duration = float(prepared.get("duration", 0.0) or 0.0)
            packet_count = float(prepared.get("packet_count", 0.0) or 0.0)
        except (TypeError, ValueError):
            duration = 0.0
            packet_count = 0.0
        prepared["packet_rate"] = packet_count / duration if duration > 0 else 0.0
    return {feature: prepared[feature] for feature in LIVE_FEATURE_SCHEMA if feature in prepared}


def predict_flow_anomaly(
    flow_features: Mapping[str, Any],
    model_path: str | Path = DEFAULT_MODEL_PATH,
) -> Dict[str, Any]:
    """Predict whether a live flow is anomalous using the trained RF pipeline."""
    try:
        artifact = load_ciciot_model(model_path)
    except Exception as exc:
        return {
            "model_available": False,
            "is_anomaly": None,
            "attack_probability": None,
            "model_name": MODEL_NAME,
            "model_type": "RandomForestClassifier",
            "dataset": "CICIoT2023",
            "feature_schema": LIVE_FEATURE_SCHEMA,
            "threshold": THRESHOLD,
            "status": "unavailable",
            "reason": f"CICIoT2023 RandomForest model artifact could not be loaded: {exc}",
        }

    if artifact is None:
        return {
            "model_available": False,
            "is_anomaly": None,
            "attack_probability": None,
            "model_name": MODEL_NAME,
            "model_type": "RandomForestClassifier",
            "dataset": "CICIoT2023",
            "feature_schema": LIVE_FEATURE_SCHEMA,
            "threshold": THRESHOLD,
            "status": "unavailable",
            "reason": "CICIoT2023 RandomForest model artifact not found",
        }

    model = artifact["model"]
    try:
        frame = build_feature_frame(build_live_feature_dict(flow_features))
        probabilities = model.predict_proba(frame)[0]
        classes = list(getattr(model, "classes_", []))
        attack_index = classes.index(1) if 1 in classes else 1
        attack_probability = float(probabilities[attack_index])
        prediction = int(attack_probability >= THRESHOLD)
    except Exception as exc:
        return {
            "model_available": False,
            "is_anomaly": None,
            "attack_probability": None,
            "model_name": MODEL_NAME,
            "model_type": artifact.get("model_type", "RandomForestClassifier"),
            "dataset": artifact.get("dataset", "CICIoT2023"),
            "feature_schema": LIVE_FEATURE_SCHEMA,
            "threshold": THRESHOLD,
            "status": "unavailable",
            "reason": f"CICIoT2023 RandomForest prediction failed: {exc}",
        }

    return {
        "model_available": True,
        "is_anomaly": bool(prediction == 1),
        "attack_probability": attack_probability,
        "model_name": MODEL_NAME,
        "model_type": artifact.get("model_type", "RandomForestClassifier"),
        "dataset": artifact.get("dataset", "CICIoT2023"),
        "feature_schema": LIVE_FEATURE_SCHEMA,
        "threshold": THRESHOLD,
        "status": "ok",
    }
