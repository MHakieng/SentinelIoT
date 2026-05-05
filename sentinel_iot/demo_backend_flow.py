"""Backend-only SentinelIoT demo flow.

Run from the v3 project root:
    python -m sentinel_iot.demo_backend_flow

This script uses FastAPI's in-process TestClient. It does not start a real
server and does not trigger an active network scan.
"""

from fastapi.testclient import TestClient

from sentinel_iot.api.main import app


def print_section(title: str):
    print(f"\n=== {title} ===")


def main():
    client = TestClient(app)

    print_section("Health")
    health = client.get("/health").json()
    print(f"API status: {health.get('status')}")
    print(f"Database: {health.get('database', {}).get('path')}")
    llm = health.get("llm", {})
    print(f"LLM enabled: {llm.get('enabled')} ({llm.get('provider')} / {llm.get('model')})")

    print_section("Scan Runtime")
    scan_status = client.get("/scan/status").json()
    print(f"Status: {scan_status.get('status')}")
    print(f"Message: {scan_status.get('message')}")
    print(f"Summary: {scan_status.get('summary')}")

    print_section("Device Inventory")
    devices = client.get("/devices").json()
    print(f"Device count: {len(devices)}")
    for device in devices[:5]:
        print(
            f"- {device.get('ip')} | status={device.get('status')} | "
            f"risk={device.get('risk_score')} | services={len(device.get('open_ports') or [])} | "
            f"cves={device.get('total_cves')}"
        )

    if not devices:
        print("No devices are stored yet. Run a scan from the UI/API before the full demo.")
        return

    selected = devices[0]
    selected_ip = selected["ip"]

    print_section("Risk Context")
    history = client.get(f"/devices/{selected_ip}/risk-history").json()
    anomalies = client.get(f"/devices/{selected_ip}/anomalies").json()
    print(f"Selected device: {selected_ip}")
    print(f"Risk history points: {len(history)}")
    print(f"Anomaly records: {len(anomalies)}")
    print(f"Risk breakdown: {selected.get('risk_breakdown')}")

    print_section("LLM Device Analysis Capability")
    llm_status = client.get("/llm/status").json()
    print(f"Enabled: {llm_status.get('enabled')}")
    if not llm_status.get("enabled"):
        print(f"Missing/config issue: {', '.join(llm_status.get('missing') or [])}")
        print("Set SENTINEL_LLM_API_KEY and SENTINEL_LLM_MODEL to run live LLM analysis.")
        return

    response = client.post(
        "/llm/device-analysis",
        json={
            "device_ip": selected_ip,
            "include_sections": ["risk_explanation", "anomaly_summary", "next_actions"],
        },
    )
    print(f"LLM analysis status code: {response.status_code}")
    if response.status_code != 200:
        print(response.json())
        return

    analysis = response.json()
    print(f"Generated at: {analysis.get('generated_at')}")
    print(f"Evidence items: {len(analysis.get('evidence_used') or [])}")
    print(f"Warnings: {analysis.get('warnings')}")
    print(f"Next actions: {analysis.get('sections', {}).get('next_actions')}")


if __name__ == "__main__":
    main()
