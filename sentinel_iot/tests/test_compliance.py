import pytest
import pandas as pd
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.feature_schema import validate_features, FEATURE_SCHEMA
from ml.anomaly_model import AnomalyModel
from ml.generate_dataset import generate_iot_traffic
from core.risk_engine import RiskEngine

def test_feature_schema_consistency():
    """EMİR: dataset üret, validate_features çalıştır, eksik kolon olmamalı."""
    # 1. Dataset üret (küçük bir örnek)
    data_list = generate_iot_traffic(num_samples=10, anomaly_ratio=0.1)
    
    # 2. validate_features çalıştır
    # validate_features input olarak list of dicts bekliyor
    try:
        validate_features(data_list, source="test_feature_schema_consistency")
    except ValueError as e:
        pytest.fail(f"Feature schema consistency failed: {e}")
    
    # 3. Eksik kolon kontrolü (dataframe üzerinden daha kolay)
    df = pd.DataFrame(data_list)
    for col in FEATURE_SCHEMA:
        assert col in df.columns, f"Eksik kolon: {col}"


def test_anomaly_score_range():
    """EMİR: örnek skor üret, normalize_anomaly_score çalıştır, sonuç 0 ile 1 arasında olmalı."""
    raw_scores = [-1.5, -0.5, 0.0, 0.5, 1.5]
    
    for raw in raw_scores:
        norm = AnomalyModel.normalize_anomaly_score(raw)
        assert 0.0 <= norm <= 1.0, f"Skor aralık dışı: {norm} (raw: {raw})"

def test_risk_engine_input_contract():
    """EMİR: anomaly_score = 60 ver, HATA bekle."""
    engine = RiskEngine()
    
    # anomaly_score 0.0-1.0 arasında olmalı. 60 verilirse ValueError bekliyoruz.
    with pytest.raises(ValueError) as excinfo:
        engine.calculate_device_risk(cvss_score=5.0, anomaly_score=60.0)
    
    assert "gecersiz" in str(excinfo.value)
    print(f"[+] Risk Engine correctly rejected invalid input: {excinfo.value}")

def test_dataset_generator_output():
    """EMİR: dataset generator testini yaz."""
    data = generate_iot_traffic(num_samples=50, anomaly_ratio=0.2)
    df = pd.DataFrame(data)
    assert len(df) == 50
    assert 'label' in df.columns
    # Check if we actually have anomalies (1 in generator means anomaly)
    assert (df['label'] == 1).any() or (df['label'] == 0).any()
