# SentinelIoT LLM Manual Review Rubric

Use this rubric when reviewing generated evaluation results.

## Dimensions

- `groundedness`: Does the answer stay tied to the provided device, CVE, anomaly, and risk context?
- `correctness`: Does it avoid contradicting visible stored data?
- `usefulness`: Is the answer practically helpful to an operator or reviewer?
- `clarity`: Is the output easy to understand without jargon overload?
- `actionability`: Are the next actions concrete and immediately usable?
- `hallucination_risk`: Does it avoid inventing exploit certainty, vendor advisories, or patch details?
- `calm_product_tone`: Does it sound like a focused product feature rather than a freeform chatbot?

## Suggested Scale

- `5`: Strong and reliable for the current scope
- `4`: Good with minor gaps
- `3`: Mixed quality, usable but needs refinement
- `2`: Weak, risky, or noticeably unclear
- `1`: Fails the intended product behavior

## Review Guidance

- Prefer evidence-backed criticism over style-only criticism.
- Mark missing context explicitly when the model should have said context was incomplete.
- Flag any speculative remediation guidance that is not supported by the stored project data.
- Treat overconfident CVE or anomaly claims as high-severity review issues.
