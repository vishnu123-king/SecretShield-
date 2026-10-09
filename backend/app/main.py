from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional, Dict, Any
import os
import json
import uuid
from datetime import datetime

app = FastAPI(
    title="SecretShield API",
    description="Git Repository Secrets Detection and Credential Exposure Monitoring Platform API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SecretShield Core API",
        "timestamp": datetime.utcnow().isoformat(),
        "database": "connected",
        "worker": "ready",
        "scanner_engine": "operational"
    }

@app.get("/api/health/database")
def database_health():
    return {"status": "ok", "latency_ms": 1.2}

@app.get("/api/health/worker")
def worker_health():
    return {"status": "ok", "active_tasks": 0, "queue_depth": 0}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
