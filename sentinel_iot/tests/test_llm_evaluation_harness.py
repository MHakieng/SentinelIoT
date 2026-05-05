from sentinel_iot.evaluation.run_llm_evaluation import build_case_bundle


def test_case_bundle_uses_real_project_data_shape(monkeypatch):
    devices = [
        {
            "ip": "10.0.0.25",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "CameraCo",
            "risk_score": 82.0,
            "status": "High Risk",
            "total_cves": 2,
            "risk_breakdown": {"vuln": 70.0, "anomaly": 28.0},
            "open_ports": [
                {
                    "port": 443,
                    "service": "https",
                    "product": "nginx",
                    "version": "1.24.0",
                    "cves": [
                        {
                            "id": "CVE-2024-9999",
                            "cvss": 9.8,
                            "description": "Known weakness in exposed web service.",
                        }
                    ],
                }
            ],
        }
    ]

    monkeypatch.setattr("sentinel_iot.evaluation.run_llm_evaluation.get_all_devices", lambda: devices)
    monkeypatch.setattr(
        "sentinel_iot.evaluation.run_llm_evaluation.get_device_anomaly_logs",
        lambda device_ip: [{"timestamp": "2026-04-19 21:05:00", "type": "flow_spike", "score": 66.1}],
    )
    monkeypatch.setattr(
        "sentinel_iot.evaluation.run_llm_evaluation.get_device_risk_history",
        lambda device_ip: [{"timestamp": "2026-04-19 21:00:00", "risk_score": 78.0}],
    )

    bundle = build_case_bundle(max_device_cases=2, max_cve_cases=2)

    assert bundle["case_generation_mode"] == "real_project_data"
    assert bundle["data_summary"]["total_devices"] == 1
    assert len(bundle["cases"]) == 2
    assert any(case["task_type"] == "device_analysis" for case in bundle["cases"])
    assert any(case["task_type"] == "cve_explanation" for case in bundle["cases"])


def test_case_bundle_falls_back_cleanly_when_no_devices(monkeypatch):
    monkeypatch.setattr("sentinel_iot.evaluation.run_llm_evaluation.get_all_devices", lambda: [])

    bundle = build_case_bundle()

    assert bundle["case_generation_mode"] == "fallback_sparse_project_data"
    assert bundle["cases"][0]["source_kind"] == "fallback_example"
    assert bundle["cases"][0]["runnable"] is False
