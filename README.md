# Sentinel-IoT

**Sentinel-IoT: IoT Security Vulnerability and Anomaly Analysis Platform**

Sentinel-IoT is a capstone security analysis platform for small IoT networks. It combines device discovery, service and vulnerability scanning, live packet/flow monitoring, ML-based anomaly inference, device-class-aware scoring, and explainable hybrid risk prioritization in a React dashboard.

This repository is prepared for academic demo/submission use. It is not a production IDS/IPS and it does not claim to block attacks, inspect traffic outside the visible capture interface, or compute live accuracy/F1 without labelled runtime events.

## Features

- Network device discovery
- Port and vulnerability scanning with Nmap-based evidence
- Device fingerprinting and rule-based device classification
- Live packet and 5-tuple flow monitoring
- CICIoT2023/RandomForest-style ML anomaly inference support
- Explainable reward/penalty flow scoring
- Device-class-aware flow risk calibration
- Hybrid risk scoring for device prioritization
- Device detail analysis and evidence views
- Offline validation vs live runtime scoring separation
- React + Vite dashboard for final demo

## Architecture

Sentinel-IoT is organized as a FastAPI backend and a React/Vite frontend:

- `sentinel_iot/api/`: FastAPI application and routers
- `sentinel_iot/scanner/`: host discovery, service probing, fingerprinting helpers
- `sentinel_iot/services/`: scanner, monitor, LLM analyst, and orchestration services
- `sentinel_iot/monitor/`: packet/flow feature extraction helpers
- `sentinel_iot/ml/`: anomaly inference, flow scoring, device classifier, validation/training helpers
- `sentinel_iot/database/`: SQLite persistence models and database access
- `sentinel_iot/schemas/`: Pydantic API schemas
- `sentinel_iot/dashboard/react_app/`: final React dashboard
- `sentinel_iot/tests/`: backend/unit/regression tests
- `evaluation/`: offline validation utilities and report generation scripts
- `docs/`: final delivery notes, validation summaries, and defense-readiness documents

Recommended final docs:

- `docs/final_acceptance_criteria.md`
- `docs/final_acceptance_test_report.md`
- `docs/demo_readiness_checklist.md`
- `docs/remaining_risks_before_defense.md`
- `docs/model_validation_summary.md`
- `docs/device_class_aware_detection.md`
- `docs/ciciot2023_model_integration.md`

## Tech Stack

- Backend: Python, FastAPI, Pydantic, SQLAlchemy
- Scanner/monitor: Nmap, Scapy
- ML: scikit-learn, joblib, pandas
- Frontend: React, Vite, Recharts, Lucide React
- Database: SQLite
- Tests: pytest, httpx

## Installation

Backend setup on Windows:

```powershell
cd sentinel_iot
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

Frontend setup:

```powershell
cd sentinel_iot\dashboard\react_app
npm install
```

Optional root helper:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

## Running

Backend:

```powershell
cd sentinel_iot
.\.venv\Scripts\activate
uvicorn sentinel_iot.api.main:app --reload
```

Frontend:

```powershell
cd sentinel_iot\dashboard\react_app
npm run dev
```

Default URLs:

- API: `http://127.0.0.1:8000`
- Dashboard: `http://127.0.0.1:5173`

Root helper:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_dev.ps1
```

## Testing

Backend syntax and tests:

```powershell
cd sentinel_iot
.\.venv\Scripts\python.exe -m compileall sentinel_iot
.\.venv\Scripts\python.exe -m pytest
```

Frontend production build:

```powershell
cd sentinel_iot\dashboard\react_app
npm run build
```

Root helper:

```powershell
powershell -ExecutionPolicy Bypass -File .\verify_release.ps1
```

## Demo Notes

- Nmap and Scapy operations may require administrator/root privileges.
- Packet capture only sees traffic visible to the selected host/interface. Switched networks, Wi-Fi isolation, loopback visibility, or missing Npcap support can limit what is captured.
- Live runtime traffic normally has no ground-truth labels. Therefore runtime precision, recall, F1, TP, FP, TN, and FN are not reported as real runtime metrics.
- Offline validation metrics come from labelled datasets or controlled validation scripts and must be interpreted separately from live runtime scoring.
- Device-class confidence is a rule-based classification confidence, not model accuracy.
- Reward/penalty flow scoring is not reinforcement learning. It is an explainable calibration layer over inference output and flow context.

## Offline Validation

Offline model validation and dataset preparation live under `evaluation/` and `docs/`. Large datasets and generated model artifacts are intentionally excluded from Git.

Important distinction:

- Offline validation: labelled dataset evaluation, such as CICIoT2023 report outputs.
- Live runtime scoring: current network inference, flow risk, decision, and explanation without labelled ground truth.

Do not present offline validation metrics as live runtime detection success.

## Model Artifacts

Model artifacts such as `.joblib` and `.pkl` files are ignored by default to avoid committing large binaries. If a demo model is required, place it locally at the expected path described in the docs, for example:

```text
sentinel_iot/ml/models/ciciot2023_random_forest.joblib
```

If the model artifact is missing, the application should return an honest unavailable/fallback response instead of producing fake predictions.

## Final Project Scope

The final submission includes:

- Working FastAPI backend
- Working React/Vite dashboard
- Device inventory and scanner flow
- Vulnerability and evidence presentation
- Live packet/flow monitoring endpoints
- Explainable flow scoring
- Device-class-aware detection context
- Offline validation documentation
- Regression tests and final delivery notes

Out of scope for this final academic MVP:

- Production IDS/IPS blocking
- SIEM deployment
- Multi-user authentication/authorization
- Guaranteed full-network capture without correct network setup
- Runtime accuracy/F1 without labelled live events

## Repository Hygiene

The repository intentionally excludes:

- `.env` and local secrets
- SQLite runtime databases and WAL/SHM files
- PCAP/PCAPNG captures
- Raw datasets and generated dataset CSV files
- Large model artifacts
- Python and frontend caches
- `node_modules/`, `dist/`, and build output

Use `.env.example` as the template for local configuration.

## License

Academic/capstone project. License: TBD.
