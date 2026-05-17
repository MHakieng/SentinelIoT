import json
from typing import Any, Dict, List


PROJECT_BRIEF = {
    "product": "SentinelIoT",
    "purpose": "IoT ve yerel ağ cihazlarını keşfetmek, açık servis/CVE kanıtlarını toplamak, canlı paketlerden flow çıkarmak ve açıklanabilir risk önceliği üretmek.",
    "main_pipeline": [
        "scanner device discovery",
        "service and CVE evidence",
        "device-class-aware context",
        "live packet capture and flow extraction",
        "ML inference",
        "reward/penalty explainable flow scoring",
        "risk dashboard",
    ],
    "important_limits": [
        "Live trafikte etiketli ground-truth yoksa runtime accuracy/F1/precision/recall hesaplanmaz.",
        "Device-class confidence başarı metriği değildir; sadece sınıflandırma güvenidir.",
        "Reward/penalty katmanı reinforcement learning değildir; inference sonrası açıklanabilir kalibrasyondur.",
        "Asistan internette arama yapmaz; verilen SentinelIoT bağlamına ve proje bilgisine dayanır.",
    ],
}


DEVICE_ANALYSIS_SYSTEM_PROMPT = """You are the embedded SentinelIoT security analyst.

Rules:
- Use only the provided JSON context.
- Answer the user's exact question first when it is present.
- Always write a question-specific `direct_answer` first. It must not be a generic reusable risk paragraph.
- If the user asks a narrow question, `direct_answer` should answer that narrow question even if the requested sections also include broader context.
- Use the conversation history to resolve follow-up questions and pronouns.
- Do not repeat the previous answer unless the user asks for a recap. Continue the conversation with new, targeted information.
- If the user asks about how SentinelIoT works as a project, answer from the provided project brief and device context.
- If the user did not explicitly ask for actions, anomaly history, or a full report, keep `direct_answer` self-contained and avoid adding unnecessary operational checklist language.
- Prefer the strongest observed evidence in this order: device risk score and status, risk breakdown, exposed services, CVE count, device class metadata, recent anomaly records, risk history, live monitor runtime status.
- If evidence is missing or weak, state that clearly.
- Separate observed evidence from recommendations.
- Do not invent exploit certainty, CVSS values, patch details, vendor guidance, or attack chains.
- Keep recommendations practical and limited to the provided context.
- Keep the tone short, calm, and operational.
- Do not treat unavailable live-monitor runtime state as priority evidence unless the context explicitly shows it affects device risk.
- Do not present live runtime accuracy, F1, precision, recall, TP, FP, TN, or FN. SentinelIoT does not have live labelled ground truth in this context.
- Device-class confidence is classification confidence only; never describe it as model accuracy or detection success.
- Risk explanations must interpret the score and evidence instead of only repeating fields.
- Anomaly summaries must describe only observed anomalies and, when present, their active-risk impact.
- If there are no recent anomaly records, say that no stored recent anomaly evidence was found. Do not invent live attacks.
- Recommended actions must be prioritized, concrete, and non-repetitive. Prefer 2 to 4 actions.
- For a normal/low-risk device, recommend verification and monitoring rather than urgent remediation.
- Every output array must contain strings only. Use null for unrequested text sections.
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
- Do not present exploitability as certain unless the provided context explicitly says so.
- Every output array must contain strings only.
- Generate every natural-language response field in Turkish.
- Return valid JSON only.
"""


def _clean_history(conversation_history: List[Dict[str, Any]] | None) -> List[Dict[str, str]]:
    cleaned: List[Dict[str, str]] = []
    for item in conversation_history or []:
        role = str(item.get("role", "")).strip().lower()
        if role not in {"user", "assistant"}:
            continue
        content = " ".join(str(item.get("content", "")).split())[:700]
        if content:
            cleaned.append({"role": role, "content": content})
    return cleaned[-8:]


def build_device_analysis_user_prompt(
    context: Dict,
    include_sections: List[str],
    user_question: str | None = None,
    conversation_history: List[Dict[str, Any]] | None = None,
) -> str:
    clean_question = " ".join(str(user_question or "").split())[:500] or None
    clean_history = _clean_history(conversation_history)
    payload = {
        "task": "device_analysis",
        "user_question": clean_question,
        "conversation_history": clean_history,
        "project_brief": PROJECT_BRIEF,
        "include_sections": include_sections,
        "response_schema": {
            "direct_answer": "string",
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
        "The answer must be consistent with the provided context and must not contradict the grounding summary.\n"
        f"Requested sections: {', '.join(include_sections)}.\n"
        f"User question: {clean_question or 'No specific user question; produce the requested operational sections.'}\n"
        "Conversation behavior:\n"
        "- Treat this as a multi-turn chat, not a static report generator.\n"
        "- If the question is a follow-up, use conversation_history and avoid restating everything from earlier turns.\n"
        "- If the user asks 'neden', 'nasıl düzeltirim', 'hangisi önemli', or similar, answer that exact intent with concrete reasoning.\n"
        "- Keep direct_answer conversational and short, usually 1 paragraph.\n"
        "First produce `direct_answer`: 1 to 3 Turkish sentences that directly answer the user question. "
        "Do not copy the risk_explanation text into direct_answer; make it question-specific.\n"
        "If the requested sections only include risk_explanation, direct_answer should be enough for a chat response; keep risk_explanation short and do not include recommendations there.\n"
        "Write each narrative section in short product language, not as a field dump.\n"
        "Use these interpretation rules:\n"
        "- If risk_score is high but evidence is mostly service/CVE exposure, explain it as exposure risk, not as a confirmed active attack.\n"
        "- If recent_anomaly_count is 0, anomaly_summary must say no stored recent anomaly evidence was found.\n"
        "- If monitor_runtime_status is unavailable, mention that live state is unavailable only in limitations.\n"
        "- If device_class is present, use it as context; do not call device_class_confidence an accuracy metric.\n"
        "- Recommendations must directly follow from open services, CVE count, risk breakdown, anomaly records, or classification evidence.\n"
        "If context is missing, state that in limitations instead of filling gaps with generic security language.\n"
        "Return exactly this JSON object shape, with no markdown and no extra keys:\n"
        "{\n"
        '  "direct_answer": string,\n'
        '  "risk_explanation": string or null,\n'
        '  "anomaly_summary": string or null,\n'
        '  "next_actions": [string],\n'
        '  "limitations": [string]\n'
        "}\n"
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
        "Return exactly this JSON object shape, with no markdown and no extra keys:\n"
        "{\n"
        '  "title": string,\n'
        '  "plain_language_summary": string,\n'
        '  "why_it_matters_for_this_device": string,\n'
        '  "recommended_actions": [string],\n'
        '  "limitations": [string]\n'
        "}\n"
        "Payload:\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=True)}"
    )
