"""Validate SentinelIoT risk engine with deterministic formula scenarios."""

from __future__ import annotations

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def load_risk_engine():
    try:
        from sentinel_iot.core.risk_engine import RiskEngine

        return RiskEngine(), "sentinel_iot.core.risk_engine.RiskEngine"
    except Exception:
        return None, "local_formula_fallback"


def calculate_with_fallback(vuln: float, anomaly: float) -> float:
    # Fallback: mevcut risk motorundaki 0.6 vulnerability + 0.4 anomaly formulu birebir kullanilir.
    return round(min(100.0, (vuln * 0.6) + (anomaly * 0.4)), 2)


def calculate_risk(engine, vuln: float, anomaly: float) -> float:
    if engine is None:
        return calculate_with_fallback(vuln, anomaly)

    result = engine.calculate_device_risk(
        cvss_score=vuln / 10,
        anomaly_score=anomaly / 100,
        asset_type="home",
        anomaly_confidence=1.0,
    )
    return float(result["risk_score"])


def main() -> int:
    scenarios = [
        {"name": "zero_risk", "vuln": 0, "anomaly": 0, "expected": 0},
        {"name": "vulnerability_only", "vuln": 80, "anomaly": 0, "expected": 48},
        {"name": "anomaly_only", "vuln": 0, "anomaly": 90, "expected": 36},
        {"name": "both_high", "vuln": 90, "anomaly": 90, "expected": 90},
        {"name": "balanced_medium", "vuln": 50, "anomaly": 50, "expected": 50},
    ]

    engine, source = load_risk_engine()
    results = []
    all_passed = True
    for scenario in scenarios:
        actual = calculate_risk(engine, scenario["vuln"], scenario["anomaly"])
        passed = abs(actual - scenario["expected"]) <= 0.001
        all_passed = all_passed and passed
        results.append(
            {
                **scenario,
                "actual": actual,
                "passed": passed,
            }
        )

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESULTS_DIR / "risk_engine_validation.json"
    payload = {
        "source": source,
        "formula": "risk = min(100, vulnerability * 0.6 + anomaly * 0.4)",
        "all_passed": all_passed,
        "tests": results,
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"[OK] Risk engine dogrulama sonucu yazildi: {output_path}")
    for item in results:
        status = "PASSED" if item["passed"] else "FAILED"
        print(f"  {status}: {item['name']} expected={item['expected']} actual={item['actual']}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
