#!/usr/bin/env python3
"""
AdGuard Home Log Summary Web Service

Provides REST API endpoints for:
- Fetching logs from router
- Building log summaries
- Querying and filtering summary data
"""

import json
import re
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from pathlib import Path

# Load .env configuration
ENV_FILE = Path(__file__).parent / ".env"


def load_env() -> dict:
    """Load environment variables from .env file."""
    env = {}
    if ENV_FILE.exists():
        with open(ENV_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env[key.strip()] = value.strip()
    return env


ENV = load_env()
WEB_HOST = ENV.get("WEB_HOST", "0.0.0.0")
WEB_PORT = int(ENV.get("WEB_PORT", "8080"))

# Import functions from existing scripts
from fetch_logs import run_fetch
from build_log_summary import run_build_summary

# Directories
SCRIPT_DIR = Path(__file__).parent
APP_DATA_DIR = SCRIPT_DIR / "AppData"
CURRENT_DIR = APP_DATA_DIR / "Current"
STATIC_DIR = SCRIPT_DIR / "static"

app = FastAPI(
    title="AdGuard Home Log Summary API",
    description="API for managing and querying AdGuard Home DNS logs",
    version="1.0.0"
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Response models
class OperationResponse(BaseModel):
    success: bool
    message: str


class FetchResponse(OperationResponse):
    entries_fetched: int = 0


class BuildResponse(OperationResponse):
    client_records: int = 0
    domain_records: int = 0
    base_domain_records: int = 0


# API Endpoints

@app.post("/api/update-logs", response_model=FetchResponse)
async def update_logs():
    """
    Fetch new logs from the router.
    Executes fetch_logs.py with confirmation bypassed.
    """
    try:
        result = run_fetch(skip_confirmation=True)
        return FetchResponse(
            success=result["success"],
            message=result["message"],
            entries_fetched=result["entries_fetched"]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/build-summary", response_model=BuildResponse)
async def build_summary(from_date: Optional[str] = Query(None, description="Filter entries from this date (YYYY-MM-DD)")):
    """
    Build log summaries from querylog.ndjson.
    Optionally filter to entries >= from_date.
    """
    try:
        # Validate date format if provided
        if from_date:
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', from_date):
                raise HTTPException(status_code=400, detail="from_date must be in YYYY-MM-DD format")

        result = run_build_summary(from_date=from_date)
        return BuildResponse(
            success=result["success"],
            message=result["message"],
            client_records=result["client_records"],
            domain_records=result["domain_records"],
            base_domain_records=result["base_domain_records"]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def load_json_file(filename: str) -> list[dict]:
    """Load a JSON file from the Current directory."""
    file_path = CURRENT_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {filename}")
    with open(file_path, "r") as f:
        return json.load(f)


def filter_records(
    records: list[dict],
    qh: Optional[str] = None,
    qt: Optional[str] = None,
    cp: Optional[str] = None,
    ip: Optional[str] = None,
    client: Optional[str] = None,
    is_filtered: Optional[bool] = None,
    count_gte: Optional[int] = None,
    count_lte: Optional[int] = None,
    max_count_gte: Optional[int] = None,
    max_count_lte: Optional[int] = None,
) -> list[dict]:
    """
    Filter records based on query parameters.

    - QH: wildcard case-insensitive search (contains)
    - Other text fields: case-insensitive exact match
    - IsFiltered: boolean match
    - count/maxCount: >= or <= comparisons
    """
    filtered = records

    # QH - wildcard case-insensitive (contains)
    if qh is not None:
        qh_lower = qh.lower()
        filtered = [r for r in filtered if qh_lower in r.get("QH", "").lower()]

    # QT - case-insensitive exact match
    if qt is not None:
        qt_lower = qt.lower()
        filtered = [r for r in filtered if r.get("QT", "").lower() == qt_lower]

    # CP - case-insensitive exact match
    if cp is not None:
        cp_lower = cp.lower()
        filtered = [r for r in filtered if r.get("CP", "").lower() == cp_lower]

    # IP - case-insensitive exact match
    if ip is not None:
        ip_lower = ip.lower()
        filtered = [r for r in filtered if r.get("IP", "").lower() == ip_lower]

    # client - case-insensitive exact match
    if client is not None:
        client_lower = client.lower()
        filtered = [r for r in filtered if r.get("client", "").lower() == client_lower]

    # IsFiltered - boolean match
    if is_filtered is not None:
        filtered = [r for r in filtered if r.get("IsFiltered") == is_filtered]

    # count >=
    if count_gte is not None:
        filtered = [r for r in filtered if r.get("count", 0) >= count_gte]

    # count <=
    if count_lte is not None:
        filtered = [r for r in filtered if r.get("count", 0) <= count_lte]

    # maxCount >=
    if max_count_gte is not None:
        filtered = [r for r in filtered if r.get("maxCount", 0) >= max_count_gte]

    # maxCount <=
    if max_count_lte is not None:
        filtered = [r for r in filtered if r.get("maxCount", 0) <= max_count_lte]

    return filtered


@app.get("/api/query-log-summary")
async def get_query_log_summary(
    qh: Optional[str] = Query(None, description="Domain (wildcard case-insensitive search)"),
    qt: Optional[str] = Query(None, description="Query type (exact match)"),
    cp: Optional[str] = Query(None, description="Client protocol (exact match)"),
    ip: Optional[str] = Query(None, description="IP address (exact match)"),
    client: Optional[str] = Query(None, description="Client name (exact match)"),
    is_filtered: Optional[bool] = Query(None, description="Filter status"),
    count_gte: Optional[int] = Query(None, description="Count >= value"),
    count_lte: Optional[int] = Query(None, description="Count <= value"),
    max_count_gte: Optional[int] = Query(None, description="Max count >= value"),
    max_count_lte: Optional[int] = Query(None, description="Max count <= value"),
):
    """
    Get query log summary data (queryLogSummary.json).
    Contains IP/client + domain combinations.
    """
    records = load_json_file("queryLogSummary.json")
    filtered = filter_records(
        records, qh=qh, qt=qt, cp=cp, ip=ip, client=client,
        is_filtered=is_filtered, count_gte=count_gte, count_lte=count_lte,
        max_count_gte=max_count_gte, max_count_lte=max_count_lte
    )
    return {"total": len(filtered), "records": filtered}


@app.get("/api/domain-summary")
async def get_domain_summary(
    qh: Optional[str] = Query(None, description="Domain (wildcard case-insensitive search)"),
    qt: Optional[str] = Query(None, description="Query type (exact match)"),
    cp: Optional[str] = Query(None, description="Client protocol (exact match)"),
    is_filtered: Optional[bool] = Query(None, description="Filter status"),
    count_gte: Optional[int] = Query(None, description="Count >= value"),
    count_lte: Optional[int] = Query(None, description="Count <= value"),
    max_count_gte: Optional[int] = Query(None, description="Max count >= value"),
    max_count_lte: Optional[int] = Query(None, description="Max count <= value"),
):
    """
    Get domain summary data (queryLogDomainSummary.json).
    Contains full domain combinations.
    """
    records = load_json_file("queryLogDomainSummary.json")
    filtered = filter_records(
        records, qh=qh, qt=qt, cp=cp,
        is_filtered=is_filtered, count_gte=count_gte, count_lte=count_lte,
        max_count_gte=max_count_gte, max_count_lte=max_count_lte
    )
    return {"total": len(filtered), "records": filtered}


@app.get("/api/base-domain-summary")
async def get_base_domain_summary(
    qh: Optional[str] = Query(None, description="Base domain (wildcard case-insensitive search)"),
    qt: Optional[str] = Query(None, description="Query type (exact match)"),
    cp: Optional[str] = Query(None, description="Client protocol (exact match)"),
    is_filtered: Optional[bool] = Query(None, description="Filter status"),
    count_gte: Optional[int] = Query(None, description="Count >= value"),
    count_lte: Optional[int] = Query(None, description="Count <= value"),
    max_count_gte: Optional[int] = Query(None, description="Max count >= value"),
    max_count_lte: Optional[int] = Query(None, description="Max count <= value"),
):
    """
    Get base domain summary data (queryLogBaseDomainSummary.json).
    Contains base domain (e.g., amazonaws.com) combinations.
    """
    records = load_json_file("queryLogBaseDomainSummary.json")
    filtered = filter_records(
        records, qh=qh, qt=qt, cp=cp,
        is_filtered=is_filtered, count_gte=count_gte, count_lte=count_lte,
        max_count_gte=max_count_gte, max_count_lte=max_count_lte
    )
    return {"total": len(filtered), "records": filtered}


# Serve static files and frontend
@app.get("/")
async def serve_frontend():
    """Serve the main frontend page."""
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Frontend not found")
    return FileResponse(index_path)


# Mount static files directory
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT)
