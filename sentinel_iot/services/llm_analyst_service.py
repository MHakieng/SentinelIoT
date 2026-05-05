import json
from typing import Any, Dict

from sentinel_iot.schemas.llm_schema import (
    CVEExplanationRequest,
    CVEExplanationResponse,
    DeviceAnalysisRequest,
    DeviceAnalysisResponse,
    DeviceAnalysisSections,
    EvidenceItem,
)
from sentinel_iot.services.llm_context_service import LLMContextService
from sentinel_iot.services.llm_prompts import (
    CVE_EXPLANATION_SYSTEM_PROMPT,
    DEVICE_ANALYSIS_SYSTEM_PROMPT,
    build_cve_explanation_user_prompt,
    build_device_analysis_user_prompt,
)
from sentinel_iot.services.llm_provider import LLMProvider


class LLMAnalystService:
    def __init__(self, provider: LLMProvider, context_service: LLMContextService):
        self.provider = provider
        self.context_service = context_service

    def analyze_device(self, request: DeviceAnalysisRequest) -> DeviceAnalysisResponse:
        include_sections = [section.value for section in request.include_sections]
        context = self.context_service.build_device_analysis_context(request.device_ip)
        raw_response = self.provider.generate(
            DEVICE_ANALYSIS_SYSTEM_PROMPT,
            build_device_analysis_user_prompt(context, include_sections),
        )
        parsed = self._parse_json_response(raw_response)

        sections = DeviceAnalysisSections(
            risk_explanation=parsed.get("risk_explanation") if "risk_explanation" in include_sections else None,
            anomaly_summary=parsed.get("anomaly_summary") if "anomaly_summary" in include_sections else None,
            next_actions=self._normalize_string_list(parsed.get("next_actions")) if "next_actions" in include_sections else [],
        )

        return DeviceAnalysisResponse(
            device_ip=request.device_ip,
            sections=sections,
            grounding_summary=context["grounding_summary"],
            evidence_used=[EvidenceItem(**item) for item in context["evidence_used"]],
            warnings=context["warnings"],
            limitations=self._normalize_string_list(parsed.get("limitations")),
        )

    def explain_cve(self, request: CVEExplanationRequest) -> CVEExplanationResponse:
        context = self.context_service.build_cve_explanation_context(
            device_ip=request.device_ip,
            cve_id=request.cve_id,
            port=request.port,
            service=request.service,
        )
        raw_response = self.provider.generate(
            CVE_EXPLANATION_SYSTEM_PROMPT,
            build_cve_explanation_user_prompt(context, request.cve_id),
        )
        parsed = self._parse_json_response(raw_response)

        return CVEExplanationResponse(
            cve_id=request.cve_id,
            title=parsed.get("title") or request.cve_id,
            plain_language_summary=parsed.get("plain_language_summary") or "Ozet dondurulmedi.",
            why_it_matters_for_this_device=parsed.get("why_it_matters_for_this_device") or "Cihaza ozel aciklama dondurulmedi.",
            recommended_actions=self._normalize_string_list(parsed.get("recommended_actions")),
            grounding_summary=context["grounding_summary"],
            evidence_used=[EvidenceItem(**item) for item in context["evidence_used"]],
            limitations=context["warnings"] + self._normalize_string_list(parsed.get("limitations")),
        )

    def _parse_json_response(self, raw_response: str) -> Dict[str, Any]:
        candidate = raw_response.strip()
        if candidate.startswith("```"):
            parts = candidate.split("```")
            candidate = next((part for part in parts if part.strip().startswith("{")), candidate)

        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end == -1 or end < start:
            raise ValueError("LLM provider returned a non-JSON response.")

        try:
            return json.loads(candidate[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ValueError("LLM provider returned invalid JSON.") from exc

    def _normalize_string_list(self, value: Any):
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()]
