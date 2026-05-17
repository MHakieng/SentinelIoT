from fastapi.testclient import TestClient

from sentinel_iot.api.dependencies import get_llm_analyst_service
from sentinel_iot.api.main import app
from sentinel_iot.schemas.llm_schema import (
    ChatHistoryItem,
    CVEExplanationGroundingSummary,
    CVEExplanationRequest,
    CVEExplanationResponse,
    DeviceAnalysisGroundingSummary,
    DeviceAnalysisRequest,
    DeviceAnalysisResponse,
    DeviceAnalysisSections,
    EvidenceItem,
)
from sentinel_iot.services.llm_context_service import DeviceContextNotFoundError, LLMContextService
from sentinel_iot.services.llm_analyst_service import LLMAnalystService


class FakeAnalystService:
    def analyze_device(self, request: DeviceAnalysisRequest) -> DeviceAnalysisResponse:
        return DeviceAnalysisResponse(
            device_ip=request.device_ip,
            sections=DeviceAnalysisSections(
                direct_answer="Bu cihazda riskin ana nedeni açık servis ve CVE kanıtlarıdır.",
                risk_explanation="Risk is elevated because several exposed services and CVEs are recorded.",
                anomaly_summary="Recent anomaly logs show repeated monitoring events.",
                next_actions=["Review exposed services", "Validate recent monitoring events"],
            ),
            grounding_summary=DeviceAnalysisGroundingSummary(
                risk_score=78.0,
                status="High Risk",
                vuln_component=62.0,
                anomaly_component=44.0,
                total_cves=3,
                open_service_count=4,
                recent_anomaly_count=2,
                risk_history_points=3,
                latest_risk_timestamp="2026-04-19 21:00:00",
                latest_anomaly_timestamp="2026-04-19 21:05:00",
                monitor_runtime_status="running",
            ),
            evidence_used=[
                EvidenceItem(source="device_inventory", detail="Risk score is 78.0 with status High Risk."),
                EvidenceItem(source="anomaly_logs", detail="Recent anomaly logs show repeated monitoring events."),
            ],
            warnings=[],
            limitations=["Recommendations are limited to the available device context."],
        )


class MissingDeviceAnalystService:
    def analyze_device(self, request: DeviceAnalysisRequest) -> DeviceAnalysisResponse:
        raise DeviceContextNotFoundError(f"Device '{request.device_ip}' was not found.")

    def explain_cve(self, request: CVEExplanationRequest) -> CVEExplanationResponse:
        raise DeviceContextNotFoundError(f"Device '{request.device_ip}' was not found.")


client = TestClient(app)


class FakeProvider:
    def __init__(self):
        self.last_system_prompt = None
        self.last_user_prompt = None

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        self.last_system_prompt = system_prompt
        self.last_user_prompt = user_prompt
        return """
        {
          "direct_answer": "Bu cihaz için ana gözlem açık servis ve CVE kaynaklı riskin yüksek olmasıdır.",
          "risk_explanation": "Observed risk is elevated because exposed services and recorded CVEs are present in the current device history.",
          "anomaly_summary": "Observed anomaly logs show repeated monitoring events in recent history.",
          "next_actions": ["Review whether the exposed services are all required.", "Confirm whether the recent monitoring activity matches expected device behavior."],
          "limitations": ["The explanation is limited to the stored device history."]
        }
        """

    def generate_cve(self):
        return """
        {
          "title": "CVE-2024-9999 on the exposed web service",
          "plain_language_summary": "Observed context links this finding to a known weakness in the exposed service.",
          "why_it_matters_for_this_device": "The CVE is tied to a reachable service on this device, so the service exposure and version should be reviewed.",
          "recommended_actions": ["Verify whether the service is required.", "Review the service version and current exposure."],
          "limitations": ["No vendor patch details were provided in the scan context."]
        }
        """


class FakeContextService:
    def build_device_analysis_context(self, device_ip: str):
        return {
            "device": {"ip": device_ip},
            "risk_history": [{"timestamp": "2026-04-19 21:00:00", "risk_score": 78.0}],
            "anomaly_logs": [{"timestamp": "2026-04-19 21:05:00", "type": "flow_spike", "score": 66.1}],
            "monitor_runtime_status": {"status": "running", "message": "Capture is running", "last_event_at": "2026-04-19 21:05:00"},
            "grounding_summary": {
                "risk_score": 78.0,
                "status": "High Risk",
                "vuln_component": 62.0,
                "anomaly_component": 44.0,
                "total_cves": 3,
                "open_service_count": 4,
                "recent_anomaly_count": 1,
                "risk_history_points": 1,
                "latest_risk_timestamp": "2026-04-19 21:00:00",
                "latest_anomaly_timestamp": "2026-04-19 21:05:00",
                "monitor_runtime_status": "running",
            },
            "evidence_used": [
                {"source": "device_inventory", "detail": "Risk score is 78.0 with status High Risk."},
                {"source": "anomaly_logs", "detail": "Most recent anomaly log is flow_spike."},
            ],
            "warnings": [],
        }

    def build_cve_explanation_context(self, device_ip: str, cve_id: str, port=None, service=None):
        return {
            "device": {"ip": device_ip},
            "selected_port": {"port": 443, "service": "https", "cves": [cve_id]},
            "anomaly_logs": [],
            "grounding_summary": {
                "device_ip": device_ip,
                "risk_score": 78.0,
                "device_status": "High Risk",
                "cve_id": cve_id,
                "port": 443,
                "service": "https",
                "service_product": "nginx",
                "service_version": "1.24.0",
                "service_http_title": "Gateway Admin Panel",
                "cvss_score": 9.8,
                "local_description": "A known weakness is associated with the exposed HTTPS service.",
                "total_cves_on_device": 3,
                "matched_service_cve_count": 1,
                "vuln_component": 62.0,
                "anomaly_component": 44.0,
                "recent_anomaly_count": 0,
            },
            "evidence_used": [
                {"source": "service_exposure", "detail": f"CVE {cve_id} is associated with port 443 (https)."},
            ],
            "warnings": ["Patch availability is not included in the scan context."],
        }
    

def test_llm_analyst_service_parses_mocked_provider_response():
    provider = FakeProvider()
    service = LLMAnalystService(provider, FakeContextService())
    response = service.analyze_device(DeviceAnalysisRequest(device_ip="10.0.0.25", user_question="Bu cihaz neden riskli?"))

    assert response.device_ip == "10.0.0.25"
    assert response.sections.direct_answer.startswith("Bu cihaz")
    assert "observed" in response.sections.risk_explanation.lower()
    assert len(response.sections.next_actions) == 2
    assert response.grounding_summary.total_cves == 3
    assert len(response.evidence_used) == 2
    assert "Bu cihaz neden riskli?" in provider.last_user_prompt
    assert "Device-class confidence is classification confidence only" in provider.last_system_prompt


def test_device_analysis_prompt_is_grounded_and_metric_safe():
    provider = FakeProvider()
    service = LLMAnalystService(provider, FakeContextService())
    service.analyze_device(
        DeviceAnalysisRequest(
            device_ip="10.0.0.25",
            user_question="Canlı doğruluk oranı kaç?",
            include_sections=["risk_explanation"],
        )
    )

    assert "Canlı doğruluk oranı kaç?" in provider.last_user_prompt
    assert '"direct_answer": string' in provider.last_user_prompt
    assert "Return exactly this JSON object shape" in provider.last_user_prompt
    assert "Do not present live runtime accuracy" in provider.last_system_prompt


def test_chat_prompt_defaults_to_question_specific_answer():
    provider = FakeProvider()
    service = LLMAnalystService(provider, FakeContextService())
    service.analyze_device(
        DeviceAnalysisRequest(
            device_ip="10.0.0.25",
            user_question="Bu port gerekli mi?",
            include_sections=["risk_explanation"],
        )
    )

    assert "direct_answer should be enough for a chat response" in provider.last_user_prompt
    assert "avoid adding unnecessary operational checklist language" in provider.last_system_prompt


def test_device_analysis_prompt_includes_conversation_history():
    provider = FakeProvider()
    service = LLMAnalystService(provider, FakeContextService())
    service.analyze_device(
        DeviceAnalysisRequest(
            device_ip="10.0.0.25",
            user_question="Peki SNMP için ne yapmalıyım?",
            include_sections=["risk_explanation", "next_actions"],
            conversation_history=[
                ChatHistoryItem(role="user", content="Bu cihazda hangi portlar önemli?"),
                ChatHistoryItem(role="assistant", content="SSH ve SNMP daha dikkatli incelenmeli."),
            ],
        )
    )

    assert "conversation_history" in provider.last_user_prompt
    assert "SSH ve SNMP" in provider.last_user_prompt
    assert "Treat this as a multi-turn chat" in provider.last_user_prompt


def test_llm_analyst_service_builds_cve_explanation():
    provider = FakeProvider()
    provider.generate = lambda system_prompt, user_prompt: provider.generate_cve()
    service = LLMAnalystService(provider, FakeContextService())
    response = service.explain_cve(CVEExplanationRequest(device_ip="10.0.0.25", cve_id="CVE-2024-9999", port=443))

    assert response.cve_id == "CVE-2024-9999"
    assert "observed" in response.plain_language_summary.lower()
    assert response.grounding_summary.port == 443
    assert response.grounding_summary.cvss_score == 9.8
    assert len(response.recommended_actions) == 2


def test_device_analysis_endpoint_returns_typed_payload():
    app.dependency_overrides[get_llm_analyst_service] = lambda: FakeAnalystService()
    response = client.post(
        "/llm/device-analysis",
        json={
            "device_ip": "10.0.0.25",
            "include_sections": ["risk_explanation", "anomaly_summary", "next_actions"],
        },
    )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["device_ip"] == "10.0.0.25"
    assert body["sections"]["risk_explanation"]
    assert body["sections"]["anomaly_summary"]
    assert len(body["sections"]["next_actions"]) == 2
    assert body["grounding_summary"]["risk_score"] == 78.0
    assert len(body["evidence_used"]) == 2


def test_device_analysis_endpoint_returns_404_for_missing_device():
    app.dependency_overrides[get_llm_analyst_service] = lambda: MissingDeviceAnalystService()
    response = client.post(
        "/llm/device-analysis",
        json={"device_ip": "10.0.0.250", "include_sections": ["risk_explanation"]},
    )
    app.dependency_overrides.clear()

    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_cve_explanation_endpoint_returns_typed_payload():
    class FakeCVEAnalystService(FakeAnalystService):
        def explain_cve(self, request: CVEExplanationRequest) -> CVEExplanationResponse:
            return CVEExplanationResponse(
                cve_id=request.cve_id,
                title=f"{request.cve_id} on https",
                plain_language_summary="This CVE indicates a known weakness in the exposed web service.",
                why_it_matters_for_this_device="The affected service is reachable on this device.",
                recommended_actions=["Confirm whether the service is required.", "Review the exposed version."],
                grounding_summary=CVEExplanationGroundingSummary(
                    device_ip=request.device_ip,
                    risk_score=78.0,
                    device_status="High Risk",
                    cve_id=request.cve_id,
                    port=request.port,
                    service=request.service or "https",
                    service_product="nginx",
                    service_version="1.24.0",
                    service_http_title="Gateway Admin Panel",
                    cvss_score=9.8,
                    local_description="A known weakness is associated with the exposed HTTPS service.",
                    total_cves_on_device=3,
                    matched_service_cve_count=1,
                    vuln_component=62.0,
                    anomaly_component=44.0,
                    recent_anomaly_count=2,
                ),
                evidence_used=[
                    EvidenceItem(source="service_exposure", detail="CVE is associated with the HTTPS service."),
                ],
                limitations=["Patch details are not included in the current scan context."],
            )

    app.dependency_overrides[get_llm_analyst_service] = lambda: FakeCVEAnalystService()
    response = client.post(
        "/llm/cve-explanation",
        json={"device_ip": "10.0.0.25", "cve_id": "CVE-2024-9999", "port": 443, "service": "https"},
    )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["cve_id"] == "CVE-2024-9999"
    assert body["grounding_summary"]["port"] == 443
    assert body["grounding_summary"]["cvss_score"] == 9.8
    assert len(body["recommended_actions"]) == 2


def test_cve_context_service_extracts_cvss_and_description_from_nested_scan_data(monkeypatch):
    device = {
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
                "http_title": "Gateway Admin Panel",
                "cves": ["CVE-2024-9999"],
                "scripts": {
                    "vulners": {
                        "findings": [
                            {
                                "id": "CVE-2024-9999",
                                "cvss": "9.8",
                                "description": "Remote attackers may reach sensitive logic through the exposed web service.",
                            }
                        ]
                    }
                },
            }
        ],
    }

    monkeypatch.setattr("sentinel_iot.services.llm_context_service.get_device_by_ip", lambda _: device)
    monkeypatch.setattr("sentinel_iot.services.llm_context_service.get_device_anomaly_logs", lambda _: [])

    class DummyMonitorService:
        def get_runtime_status(self):
            return {"status": "idle", "message": "Idle", "last_event_at": None}

    service = LLMContextService(DummyMonitorService())
    context = service.build_cve_explanation_context("10.0.0.25", "CVE-2024-9999", port=443, service="https")

    assert context["grounding_summary"]["cvss_score"] == 9.8
    assert "Remote attackers may reach sensitive logic" in context["grounding_summary"]["local_description"]
    assert any(item["source"] == "cve_score" for item in context["evidence_used"])
    assert any(item["source"] == "cve_description" for item in context["evidence_used"])
