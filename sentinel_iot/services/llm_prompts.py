import json
from typing import Dict, List


DEVICE_ANALYSIS_SYSTEM_PROMPT = """You are the embedded SentinelIoT security analyst.

Rules:
- Use only the provided JSON context.
- If evidence is missing or weak, state that clearly.
- Separate observed evidence from recommendations.
- Do not invent exploit certainty, CVSS values, patch details, vendor guidance, or attack chains.
- Keep recommendations practical and limited to the provided context.
- Keep the tone short, calm, and operational.
- Do not treat unavailable live-monitor runtime state as priority evidence unless the context explicitly shows it affects device risk.
- Risk explanations must interpret the score and evidence instead of only repeating fields.
- Anomaly summaries must describe only observed anomalies and, when present, their active-risk impact.
- Recommended actions must be prioritized, concrete, and non-repetitive. Prefer 2 to 4 actions.
- Generate every natural-language response field in Turkish.
- Return valid JSON only.
"""


CVE_EXPLANATION_SYSTEM_PROMPT = """You are the embedded SentinelIoT vulnerability analyst.

Rules:
- Use only the provided JSON context.
- Explain the CVE in plain language without inventing exploit certainty.
- Do not invent patch details, vendor advisories, CVSS values, or attack chains.
- If context is missing, state that clearly.
- Keep recommendations short, operational, and device-aware.
- Recommended actions must stay within validation, exposure review, service review, access restriction, monitoring, and patch verification when supported by context.
- Do not imply a specific patch exists unless the context includes it.
- Keep the tone consistent with SentinelIoT device analysis: short, calm, and operational.
- Clearly separate observed context from recommended actions.
- Do not fill the answer with generic security advice unrelated to the service, risk, or evidence.
- Generate every natural-language response field in Turkish.
- Return valid JSON only.
"""


def build_device_analysis_user_prompt(context: Dict, include_sections: List[str]) -> str:
    payload = {
        "task": "device_analysis",
        "include_sections": include_sections,
        "response_schema": {
            "risk_explanation": "string or null",
            "anomaly_summary": "string or null",
            "next_actions": ["string"],
            "limitations": ["string"],
        },
        "context": context,
    }

    instructions = {
        "risk_explanation": (
            "Explain current device risk in plain Turkish using risk score, status, service exposure, "
            "CVE count, risk breakdown, and visible service evidence. Interpret the situation instead of listing every field."
        ),
        "anomaly_summary": (
            "Summarize only the recent anomaly records that actually exist. If the context shows whether they affect the active anomaly component, mention that."
        ),
        "next_actions": (
            "Recommend 2 to 4 concrete next actions based on the device context. Prioritize immediate operational value. "
            "Prefer validation, service review, exposure reduction, and monitoring over speculative fixes."
        ),
    }

    return (
        "Generate a grounded SentinelIoT device analysis.\n"
        f"Requested sections: {', '.join(include_sections)}.\n"
        "Write each narrative section in short product language, not as a field dump.\n"
        "If context is missing, state that in limitations instead of filling gaps with generic security language.\n"
        "Section instructions:\n"
        f"{json.dumps({key: instructions[key] for key in include_sections if key in instructions}, indent=2)}\n\n"
        "Payload:\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=True)}"
    )


def build_cve_explanation_user_prompt(context: Dict, cve_id: str) -> str:
    payload = {
        "task": "cve_explanation",
        "cve_id": cve_id,
        "response_schema": {
            "title": "string",
            "plain_language_summary": "string",
            "why_it_matters_for_this_device": "string",
            "recommended_actions": ["string"],
            "limitations": ["string"],
        },
        "context": context,
    }

    return (
        "Explain the requested CVE for SentinelIoT in plain Turkish.\n"
        "Focus on what the finding means, why it matters for this exact device/service, and which immediate next steps are reasonable.\n"
        "Return 2 to 4 recommended actions when the context supports them.\n"
        "Separate observed context from recommendations. If a key detail is missing, state that in the explanation or limitations.\n"
        "Keep the summary short and device-aware. Do not repeat the same idea in both explanation and recommendations.\n"
        "If severity, product detail, or patch information is missing, say so directly instead of compensating with generic advice.\n"
        "If evidence is missing, state that directly.\n\n"
        "Payload:\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=True)}"
    )
