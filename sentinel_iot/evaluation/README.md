# SentinelIoT LLM Evaluation

This folder contains a lightweight evaluation harness for the current narrow LLM flows:

- device-scoped AI analysis
- CVE explanation and remediation advice

It is intentionally simple. The goal is product validation against real stored project data, not benchmark infrastructure.

## Files

- `run_llm_evaluation.py`: generates reviewable cases from the current SQLite-backed project data and can execute the LLM flows.
- `review_rubric.md`: manual scoring rubric for reviewing outputs.
- `cases/`: generated case bundles.
- `results/`: generated JSON and Markdown evaluation outputs.

## How To Run

Run from the project root:

```powershell
py -3 evaluation\run_llm_evaluation.py --cases-only
```

This refreshes the reviewable case file using the current stored project data.

To execute the cases against the configured LLM provider:

```powershell
py -3 evaluation\run_llm_evaluation.py
```

Example Gemini environment setup in PowerShell:

```powershell
$env:SENTINEL_LLM_PROVIDER="gemini"
$env:SENTINEL_LLM_API_KEY="<your_gemini_api_key>"
$env:SENTINEL_LLM_MODEL="gemini-2.0-flash"
```

To rerun only the prompts against an existing case file after prompt edits:

```powershell
py -3 evaluation\run_llm_evaluation.py --use-existing-cases
```

## Expected Outputs

- `evaluation/cases/real_data_cases.json`
- `evaluation/results/latest.json`
- `evaluation/results/latest.md`

The Markdown output is designed for manual review in a final-project workflow.

## Notes

- The harness prefers real stored device, CVE, anomaly, and risk-history data.
- If the local database is sparse, the generated case file says so explicitly.
- If no real records exist, the harness writes clearly-labeled fallback scaffolding instead of pretending it ran on real data.
