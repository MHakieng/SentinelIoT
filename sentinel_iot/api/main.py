from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sys
import os
from contextlib import asynccontextmanager

# Add the project root (v3) to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from sentinel_iot.database.db import init_db
from sentinel_iot.api.routers import devices, scanner, monitor, ml, llm, health, settings, traffic


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application resources on startup."""
    init_db()
    yield


app = FastAPI(title="SentinelIoT API", version="3.0.0", lifespan=lifespan)

# Enable CORS for React Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Modular Routers (Unified Path Strategy)
app.include_router(devices.router)
app.include_router(scanner.router)
app.include_router(monitor.router)
app.include_router(traffic.router)
app.include_router(ml.router)
app.include_router(llm.router)
app.include_router(health.router)
app.include_router(settings.router)

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
    uvicorn.run(
        "sentinel_iot.api.main:app", 
        host="127.0.0.1", 
        port=8000, 
        reload=True,
        reload_excludes=["*.db", "*.db-wal", "*.db-shm", "*.sqlite", "*.csv"]
    )
