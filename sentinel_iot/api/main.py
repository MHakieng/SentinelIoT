from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sys
import os

# Add the project root (v3) to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sentinel_iot.database.db import init_db
from sentinel_iot.api.routers import devices, scanner, monitor, ml, llm, health

app = FastAPI(title="SentinelIoT API", version="3.0.0")

# Enable CORS for React Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Modular Routers (Unified Path Strategy)
app.include_router(devices.router)
app.include_router(scanner.router)
app.include_router(monitor.router)
app.include_router(ml.router)
app.include_router(llm.router)
app.include_router(health.router)

@app.on_event("startup")
def startup_event():
    """Initialize DB tables."""
    init_db()

@app.get("/")
def read_root():
    return {
        "app": "SentinelIoT API",
        "version": "3.0.0 (Refactored)",
        "status": "online",
        "architecture": "Service Layer + DI"
    }

if __name__ == "__main__":
    import uvicorn
    # Use full path for uvicorn to support absolute imports correctly on Windows/Reload
    uvicorn.run("sentinel_iot.api.main:app", host="127.0.0.1", port=8000, reload=True)
