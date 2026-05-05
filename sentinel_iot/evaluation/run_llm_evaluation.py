from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_PARENT = PACKAGE_ROOT.parent

if str(PROJECT_PARENT) not in sys.path:
    sys.path.insert(0, str(PROJECT_PARENT))

from sentinel_iot.database.db import get_all_devices, get_device_anomaly_logs, get_device_risk_history
from sentinel_iot.schemas.llm_schema import CVEExplanationRequest, DeviceAnalysisRequest
from sentinel_iot.services.llm_analyst_service import LLMAnalystService
from sentinel_iot.services.llm_context_service import LLMContextService
from sentinel_iot.services.llm_provider import ProviderConfigError, ProviderExecutionError, build_llm_provider_from_env

EVALUATION_ROOT = PACKAGE_ROOT / "evaluation"
CASES_DIR = EVALUATION_ROOT / "cases"
RESULTS_DIR = EVALUATION_ROOT / "results"
DEFAULT_CASE_FILE = CASES_DIR / "real_data_cases.json"
DEFAULT_REVIEW_TEMPLATE = EVALUATION_ROOT / "review_rubric.md"


class EvaluationMonitorStub:
    """Minimal monitor context provider for evaluation-only LLM runs."""

    def get_runtime_status(self) -> Dict[str, Any]:
        return {
            "status": "evaluation_unavailable",
            "message": "Live monitor runtime was not loaded by the evaluation harness.",
            "last_event_at": None,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_dirs() -> None:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def normalize_cve_id(entry: Any) -> str | None:
    if isinstance(entry, str):
        value = entry.strip().upper()
        return value or None

    if isinstance(entry, dict):
        value = (
            entry.get("id")
            or entry.get("cve")
            or entry.get("cve_id")
            or entry.get("name")
            or ""
        )
        value = str(value).strip().upper()
        return value or None

    value = str(entry).strip().upper()
    return value or None


def preview_cve_details(entry: Any) -> Dict[str, Any]:
    if not isinstance(entry, dict):
        return {"cvss_score": None, "has_local_description": False}

    cvss_raw = (
        entry.get("cvss")
        or entry.get("cvss_score")
        or entry.get("cvss_base")
        or entry.get("score")
    )
    try:
        cvss_score = round(float(cvss_raw), 1) if cvss_raw not in (None, "") else None
    except (TypeError, ValueError):
        cvss_score = None

    description = (
        entry.get("description")
        or entry.get("summary")
        or entry.get("title")
        or ""
    )
    return {
        "cvss_score": cvss_score,
        "has_local_description": bool(str(description).strip()),
    }


def extract_cve_candidates_from_scripts(port: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    scripts = port.get("scripts") or {}
    if not isinstance(scripts, dict):
        return []

    found: Dict[str, Dict[str, Any]] = {}

    def walk(payload: Any) -> None:
        if isinstance(payload, dict):
            entry_id = normalize_cve_id(payload)
            if entry_id:
                found.setdefault(entry_id, preview_cve_details(payload))

            for key, value in payload.items():
                key_id = normalize_cve_id(key)
                if key_id and key_id.startswith("CVE-"):
                    if isinstance(value, dict):
                        found.setdefault(key_id, preview_cve_details(value))
                    else:
                        found.setdefault(key_id, {"cvss_score": None, "has_local_description": bool(str(value).strip())})
                walk(value)
            return

        if isinstance(payload, list):
            for item in payload:
                walk(item)
            return

        if isinstance(payload, str):
            for match in re.findall(r"CVE-\d{4}-\d{4,7}", payload.upper()):
                found.setdefault(match, {"cvss_score": None, "has_local_description": False})

    walk(scripts)
    return list(found.items())


def count_detectable_cves(device: Dict[str, Any]) -> int:
    seen: set[Tuple[int | None, str]] = set()
    for port in device.get("open_ports") or []:
        for entry in port.get("cves") or []:
            cve_id = normalize_cve_id(entry)
            if cve_id:
                seen.add((port.get("port"), cve_id))
        for cve_id, _details in extract_cve_candidates_from_scripts(port):
            seen.add((port.get("port"), cve_id))
    return len(seen)


def build_data_summary(devices: List[Dict[str, Any]], device_context: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    devices_with_cves = 0
    devices_with_script_cve_signals = 0
    devices_with_anomalies = 0
    devices_with_history = 0
    total_cve_rows = 0
    total_script_detectable_cves = 0

    for device in devices:
        ip = device["ip"]
        context = device_context[ip]
        normalized_cve_count = sum(len(port.get("cves") or []) for port in (device.get("open_ports") or []))
        script_detectable_cves = count_detectable_cves(device)
        has_cve = normalized_cve_count > 0
        if has_cve:
            devices_with_cves += 1
        if script_detectable_cves > 0:
            devices_with_script_cve_signals += 1
        if context["anomaly_count"] > 0:
            devices_with_anomalies += 1
        if context["risk_history_count"] > 0:
            devices_with_history += 1

        total_cve_rows += normalized_cve_count
        total_script_detectable_cves += script_detectable_cves

    return {
        "total_devices": len(devices),
        "devices_with_cves": devices_with_cves,
        "devices_with_script_cve_signals": devices_with_script_cve_signals,
        "devices_with_anomalies": devices_with_anomalies,
        "devices_with_risk_history": devices_with_history,
        "total_cve_entries": total_cve_rows,
        "total_script_detectable_cves": total_script_detectable_cves,
    }


def build_device_case(device: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    ip = device["ip"]
    expected_strengths = [
        "Uses the stored risk score, status, and risk breakdown to explain current device risk.",
        "Keeps the tone calm and operational rather than conversational.",
        "Stays grounded in the recorded device context and avoids unsupported claims.",
    ]

    context_notes = [
        f"Real project device record for {ip}.",
        f"Open services recorded: {len(device.get('open_ports') or [])}.",
        f"Total CVEs recorded on device: {int(device.get('total_cves', 0))}.",
        f"Recent anomaly logs available: {context['anomaly_count']}.",
        f"Risk history points available: {context['risk_history_count']}.",
    ]

    if int(device.get("total_cves", 0)) > 0:
        expected_strengths.append("Connects elevated risk to recorded service exposure and CVE presence.")
    else:
        expected_strengths.append("Does not invent CVE-related risk evidence when no CVEs are recorded.")

    if context["anomaly_count"] > 0:
        expected_strengths.append("Summarizes recent anomaly evidence without overclaiming attack certainty.")
    else:
        expected_strengths.append("Clearly says anomaly context is sparse or absent when no anomaly logs are recorded.")

    expected_strengths.append("Next actions remain practical: verification, service review, monitoring, or containment-oriented steps.")

    return {
        "case_id": f"device_analysis__{ip.replace('.', '_')}",
        "task_type": "device_analysis",
        "source_kind": "real_project_data",
        "input_payload": {
            "device_ip": ip,
            "include_sections": ["risk_explanation", "anomaly_summary", "next_actions"],
        },
        "grounding_preview": {
            "risk_score": float(device.get("risk_score", 0.0)),
            "status": device.get("status", "Unknown"),
            "vuln_component": float((device.get("risk_breakdown") or {}).get("vuln", 0.0)),
            "anomaly_component": float((device.get("risk_breakdown") or {}).get("anomaly", 0.0)),
            "total_cves": int(device.get("total_cves", 0)),
            "open_service_count": len(device.get("open_ports") or []),
            "risk_history_count": context["risk_history_count"],
            "anomaly_count": context["anomaly_count"],
            "monitor_runtime_context_used": True,
        },
        "expected_strengths": expected_strengths,
        "context_notes": context_notes,
    }


def iter_cve_candidates(device: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    for port in device.get("open_ports") or []:
        seen_for_port: set[str] = set()
        for entry in port.get("cves") or []:
            cve_id = normalize_cve_id(entry)
            if not cve_id:
                continue
            seen_for_port.add(cve_id)
            yield cve_id, port, preview_cve_details(entry)
        for cve_id, preview in extract_cve_candidates_from_scripts(port):
            if cve_id in seen_for_port:
                continue
            yield cve_id, port, preview


def build_cve_case(device: Dict[str, Any], port: Dict[str, Any], cve_id: str, cve_preview: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    service_label = port.get("service") or "unknown"
    cve_sources = {normalize_cve_id(entry) for entry in (port.get("cves") or [])}
    cve_visibility = "normalized cve list" if cve_id in cve_sources else "raw script evidence only"
    expected_strengths = [
        "Explains the CVE in plain language without sounding like a general chat answer.",
        f"Connects the finding to port {port.get('port')} and service {service_label} on this device.",
        "Recommended actions stay within verification, exposure review, monitoring, access restriction, or patch-validation guidance.",
        "Does not invent vendor advisories, exploit certainty, or patch details.",
    ]

    if cve_preview.get("cvss_score") is not None:
        expected_strengths.append("Uses available severity context carefully if a stored CVSS score exists.")
    else:
        expected_strengths.append("Acknowledges incomplete severity context if no stored CVSS score is available.")

    if not cve_preview.get("has_local_description"):
        expected_strengths.append("States clearly when local vulnerability description context is incomplete.")

    return {
        "case_id": f"cve_explanation__{device['ip'].replace('.', '_')}__{port.get('port', 'na')}__{cve_id.replace('-', '_')}",
        "task_type": "cve_explanation",
        "source_kind": "real_project_data",
        "input_payload": {
            "device_ip": device["ip"],
            "cve_id": cve_id,
            "port": port.get("port"),
            "service": port.get("service"),
        },
        "grounding_preview": {
            "device_risk_score": float(device.get("risk_score", 0.0)),
            "device_status": device.get("status", "Unknown"),
            "port": port.get("port"),
            "service": port.get("service"),
            "service_product": port.get("product") or None,
            "service_version": port.get("version") or None,
            "device_total_cves": int(device.get("total_cves", 0)),
            "recent_anomaly_count": context["anomaly_count"],
            "stored_cvss_score": cve_preview.get("cvss_score"),
            "has_local_description": cve_preview.get("has_local_description", False),
            "cve_visibility": cve_visibility,
        },
        "expected_strengths": expected_strengths,
        "context_notes": [
            f"Real project CVE entry for device {device['ip']}.",
            f"Service fingerprint preview: {' '.join([part for part in [port.get('product'), port.get('version'), port.get('extrainfo')] if part]) or 'limited'}.",
            f"Recent anomaly logs available for device: {context['anomaly_count']}.",
            f"CVE source visibility: {cve_visibility}.",
        ],
    }


def build_fallback_case_bundle() -> Dict[str, Any]:
    return {
        "generated_at": utc_now(),
        "case_generation_mode": "fallback_sparse_project_data",
        "data_summary": {
            "total_devices": 0,
            "devices_with_cves": 0,
            "devices_with_script_cve_signals": 0,
            "devices_with_anomalies": 0,
            "devices_with_risk_history": 0,
            "total_cve_entries": 0,
            "total_script_detectable_cves": 0,
        },
        "notes": [
            "No real stored device records were available when the case file was generated.",
            "This bundle is review scaffolding only and is not runnable until real project data exists.",
        ],
        "cases": [
            {
                "case_id": "fallback_device_analysis_example",
                "task_type": "device_analysis",
                "source_kind": "fallback_example",
                "runnable": False,
                "input_payload": {
                    "device_ip": "REPLACE_WITH_REAL_DEVICE_IP",
                    "include_sections": ["risk_explanation", "anomaly_summary", "next_actions"],
                },
                "grounding_preview": {
                    "note": "Replace this placeholder with a real stored device before running the harness."
                },
                "expected_strengths": [
                    "Uses only provided device context.",
                    "Explains risk and anomaly context calmly and clearly.",
                    "Keeps next actions concrete and grounded.",
                ],
                "context_notes": [
                    "Fallback example only because no real project data was found."
                ],
            }
        ],
    }


def build_case_bundle(max_device_cases: int = 4, max_cve_cases: int = 6) -> Dict[str, Any]:
    devices = sorted(
        get_all_devices(),
        key=lambda item: (
            float(item.get("risk_score", 0.0)),
            int(item.get("total_cves", 0)),
            len(item.get("open_ports") or []),
        ),
        reverse=True,
    )

    if not devices:
        return build_fallback_case_bundle()

    device_context: Dict[str, Dict[str, Any]] = {}
    for device in devices:
        ip = device["ip"]
        anomaly_logs = get_device_anomaly_logs(ip)
        risk_history = get_device_risk_history(ip)
        device_context[ip] = {
            "anomaly_count": len(anomaly_logs),
            "risk_history_count": len(risk_history),
        }

    selected_device_cases: List[Dict[str, Any]] = []
    selected_device_ids: set[str] = set()

    for device in devices:
        if len(selected_device_cases) >= max_device_cases:
            break
        ip = device["ip"]
        context = device_context[ip]
        has_signal = (
            int(device.get("total_cves", 0)) > 0
            or context["anomaly_count"] > 0
            or context["risk_history_count"] > 0
        )
        if not has_signal or ip in selected_device_ids:
            continue
        selected_device_cases.append(build_device_case(device, context))
        selected_device_ids.add(ip)

    for device in devices:
        if len(selected_device_cases) >= max_device_cases:
            break
        ip = device["ip"]
        if ip in selected_device_ids:
            continue
        selected_device_cases.append(build_device_case(device, device_context[ip]))
        selected_device_ids.add(ip)

    selected_cve_cases: List[Dict[str, Any]] = []
    selected_cve_keys: set[Tuple[str, int | None, str]] = set()
    for device in devices:
        context = device_context[device["ip"]]
        for cve_id, port, cve_preview in iter_cve_candidates(device):
            key = (device["ip"], port.get("port"), cve_id)
            if key in selected_cve_keys:
                continue
            selected_cve_cases.append(build_cve_case(device, port, cve_id, cve_preview, context))
            selected_cve_keys.add(key)
            if len(selected_cve_cases) >= max_cve_cases:
                break
        if len(selected_cve_cases) >= max_cve_cases:
            break

    notes = []
    data_summary = build_data_summary(devices, device_context)
    if not selected_cve_cases:
        if data_summary["devices_with_script_cve_signals"] > 0:
            notes.append("Raw scan script data appears to contain CVE-like signals, but no stable CVE case could be selected from the stored project data.")
        else:
            notes.append("No recorded CVE-bearing services were found in the current project database.")
    else:
        notes.append(f"Generated {len(selected_cve_cases)} CVE evaluation case(s) from stored project data.")
    if not any(device_context[device["ip"]]["anomaly_count"] > 0 for device in devices):
        notes.append("No anomaly logs were found in the current project database, so anomaly-summary evaluation coverage is sparse.")

    return {
        "generated_at": utc_now(),
        "case_generation_mode": "real_project_data",
        "data_summary": data_summary,
        "notes": notes,
        "cases": selected_device_cases + selected_cve_cases,
    }


def dump_model(model: Any) -> Dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    if hasattr(model, "dict"):
        return model.dict()
    return dict(model)


def evaluate_case(service: Any, case: Dict[str, Any]) -> Dict[str, Any]:
    task_type = case["task_type"]
    payload = case["input_payload"]

    if not case.get("runnable", True):
        return {
            "status": "skipped",
            "reason": "Case is marked as non-runnable fallback scaffolding.",
        }

    try:
        if task_type == "device_analysis":
            response = service.analyze_device(DeviceAnalysisRequest(**payload))
        elif task_type == "cve_explanation":
            response = service.explain_cve(CVEExplanationRequest(**payload))
        else:
            raise ValueError(f"Unsupported task type '{task_type}'.")
        return {
            "status": "ok",
            "response": dump_model(response),
        }
    except ProviderConfigError as exc:
        return {
            "status": "provider_config_error",
            "error_type": exc.__class__.__name__,
            "error_message": str(exc),
            "review_blocker": True,
            "review_blocker_reason": "LLM provider is not configured correctly for evaluation.",
        }
    except ProviderExecutionError as exc:
        classification = classify_provider_error(str(exc))
        return {
            "status": classification["status"],
            "error_type": exc.__class__.__name__,
            "error_message": str(exc),
            "review_blocker": classification["review_blocker"],
            "review_blocker_reason": classification["review_blocker_reason"],
        }
    except Exception as exc:  # pragma: no cover - runtime harness behavior
        return {
            "status": "error",
            "error_type": exc.__class__.__name__,
            "error_message": str(exc),
        }


def classify_provider_error(message: str) -> Dict[str, Any]:
    lowered = message.lower()

    if "http 429" in lowered or "resource_exhausted" in lowered or "quota exceeded" in lowered:
        return {
            "status": "provider_quota_blocked",
            "review_blocker": True,
            "review_blocker_reason": "The provider rejected the request because quota or billing is unavailable.",
        }

    if "http 404" in lowered or "not found" in lowered:
        return {
            "status": "provider_model_not_found",
            "review_blocker": True,
            "review_blocker_reason": "The configured model name is invalid or unsupported for this provider endpoint.",
        }

    if "http 503" in lowered or "http 502" in lowered or "could not be reached" in lowered:
        return {
            "status": "provider_unavailable",
            "review_blocker": True,
            "review_blocker_reason": "The provider was unavailable, so the case could not be reviewed.",
        }

    return {
        "status": "provider_execution_error",
        "review_blocker": True,
        "review_blocker_reason": "The provider failed before a model answer was returned.",
    }


def review_table() -> str:
    rows = [
        "groundedness",
        "correctness",
        "usefulness",
        "clarity",
        "actionability",
        "hallucination_risk",
        "calm_product_tone",
    ]
    lines = ["| Dimension | Score (1-5) | Reviewer Notes |", "| --- | --- | --- |"]
    lines.extend(f"| {row} |  |  |" for row in rows)
    return "\n".join(lines)


def build_markdown_report(result_bundle: Dict[str, Any]) -> str:
    lines = [
        "# SentinelIoT LLM Evaluation Results",
        "",
        f"- Generated at: `{result_bundle['generated_at']}`",
        f"- Case file: `{result_bundle['case_file']}`",
        f"- Provider: `{result_bundle['provider_summary']}`",
        f"- Manual rubric reference: `{DEFAULT_REVIEW_TEMPLATE.relative_to(PACKAGE_ROOT)}`",
        "",
        "## Data Coverage",
        "",
        "```json",
        json.dumps(result_bundle["data_summary"], indent=2),
        "```",
        "",
    ]

    if result_bundle.get("notes"):
        lines.append("## Case Notes")
        lines.append("")
        lines.extend(f"- {note}" for note in result_bundle["notes"])
        lines.append("")

    lines.append("## Case Reviews")
    lines.append("")

    for item in result_bundle["results"]:
        case = item["case"]
        outcome = item["outcome"]
        lines.extend(
            [
                f"### {case['case_id']}",
                "",
                f"- Task type: `{case['task_type']}`",
                f"- Source kind: `{case['source_kind']}`",
                "",
                "Expected checkpoints:",
            ]
        )
        lines.extend(f"- {strength}" for strength in case.get("expected_strengths", []))
        lines.append("")
        lines.append("Input payload:")
        lines.append("```json")
        lines.append(json.dumps(case["input_payload"], indent=2))
        lines.append("```")
        lines.append("")
        lines.append("Grounding preview:")
        lines.append("```json")
        lines.append(json.dumps(case.get("grounding_preview", {}), indent=2))
        lines.append("```")
        lines.append("")

        if case.get("context_notes"):
            lines.append("Context notes:")
            lines.extend(f"- {note}" for note in case["context_notes"])
            lines.append("")

        lines.append("Model outcome:")
        lines.append("```json")
        lines.append(json.dumps(outcome, indent=2))
        lines.append("```")
        lines.append("")
        if outcome.get("review_blocker"):
            lines.append("Review blocker:")
            lines.append(f"- {outcome.get('review_blocker_reason')}")
            lines.append("")
        lines.append("Manual review:")
        lines.append(review_table())
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def build_provider_summary() -> str:
    provider = os.getenv("SENTINEL_LLM_PROVIDER", "openai").strip().lower() or "openai"
    model = os.getenv("SENTINEL_LLM_MODEL", "").strip() or "not_configured"
    return f"{provider}:{model}"


def build_evaluation_service() -> LLMAnalystService:
    provider = build_llm_provider_from_env()
    context_service = LLMContextService(EvaluationMonitorStub())
    return LLMAnalystService(provider, context_service)


def run_evaluation(case_bundle: Dict[str, Any], case_file: Path) -> Dict[str, Any]:
    service = build_evaluation_service()
    results = []

    for case in case_bundle["cases"]:
        results.append(
            {
                "case": case,
                "outcome": evaluate_case(service, case),
            }
        )

    return {
        "generated_at": utc_now(),
        "case_file": str(case_file.relative_to(PACKAGE_ROOT)),
        "provider_summary": build_provider_summary(),
        "data_summary": case_bundle.get("data_summary", {}),
        "notes": case_bundle.get("notes", []),
        "results": results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run lightweight real-data evaluation for SentinelIoT LLM flows.")
    parser.add_argument("--case-file", default=str(DEFAULT_CASE_FILE), help="Path to the JSON case file.")
    parser.add_argument("--cases-only", action="store_true", help="Generate or refresh the case file and stop.")
    parser.add_argument("--use-existing-cases", action="store_true", help="Use an existing case file instead of regenerating from the current database.")
    parser.add_argument("--max-device-cases", type=int, default=4, help="Maximum number of device-analysis cases to include.")
    parser.add_argument("--max-cve-cases", type=int, default=6, help="Maximum number of CVE explanation cases to include.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_dirs()
    case_file = Path(args.case_file)
    if not case_file.is_absolute():
        case_file = PACKAGE_ROOT / case_file

    if args.use_existing_cases and case_file.exists():
        case_bundle = json.loads(case_file.read_text(encoding="utf-8"))
    else:
        case_bundle = build_case_bundle(
            max_device_cases=args.max_device_cases,
            max_cve_cases=args.max_cve_cases,
        )
        write_json(case_file, case_bundle)

    print(f"Case file ready: {case_file}")

    if args.cases_only:
        print("Case generation only. Evaluation run skipped.")
        return 0

    result_bundle = run_evaluation(case_bundle, case_file)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_json = RESULTS_DIR / f"llm_eval_{timestamp}.json"
    result_md = RESULTS_DIR / f"llm_eval_{timestamp}.md"
    latest_json = RESULTS_DIR / "latest.json"
    latest_md = RESULTS_DIR / "latest.md"

    write_json(result_json, result_bundle)
    latest_json.write_text(result_json.read_text(encoding="utf-8"), encoding="utf-8")

    markdown = build_markdown_report(result_bundle)
    result_md.write_text(markdown, encoding="utf-8")
    latest_md.write_text(markdown, encoding="utf-8")

    print(f"Evaluation JSON written to: {result_json}")
    print(f"Evaluation Markdown written to: {result_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
