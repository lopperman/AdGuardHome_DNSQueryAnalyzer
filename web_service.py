#!/usr/bin/env python3
"""
AdGuard Home Log Summary Web Service

Provides REST API endpoints for:
- Fetching logs from router
- Querying raw logs and aggregated summaries via DuckDB
"""

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Import database module
from database import (
    init_database, query_client_summary,
    query_domain_summary, query_base_domain_summary, get_database_stats
)

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

# Directories
SCRIPT_DIR = Path(__file__).parent
STATIC_DIR = SCRIPT_DIR / "static"

app = FastAPI(
    title="AdGuard Home Log Summary API",
    description="API for managing and querying AdGuard Home DNS logs",
    version="2.0.0"
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


# Pagination defaults
DEFAULT_PAGE_SIZE = 500
MAX_PAGE_SIZE = 2000


# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_database()


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


@app.get("/api/stats")
async def get_stats():
    """Get database statistics."""
    try:
        stats = get_database_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/query-log-summary")
async def get_query_log_summary(
    date: Optional[str] = Query(None, description="Date (exact match, YYYY-MM-DD)"),
    date_from: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    qh: Optional[str] = Query(None, description="Domain (wildcard search)"),
    qt: Optional[str] = Query(None, description="Query type (wildcard search)"),
    cp: Optional[str] = Query(None, description="Client protocol (exact match)"),
    ip: Optional[str] = Query(None, description="IP address (exact match)"),
    client: Optional[str] = Query(None, description="Client name (wildcard search)"),
    is_filtered: Optional[bool] = Query(None, description="Filter status"),
    filter_rule: Optional[str] = Query(None, description="Filter rule (wildcard search)"),
    count_gte: Optional[int] = Query(None, description="Count >= value"),
    count_lte: Optional[int] = Query(None, description="Count <= value"),
    sort_by: str = Query("count", description="Column to sort by"),
    sort_asc: bool = Query(False, description="Sort ascending"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Records per page"),
):
    """
    Get client summary data (aggregated by Date/IP/Client/Domain/Type/Protocol/Filtered/FilterRule).
    """
    try:
        result = query_client_summary(
            date=date,
            date_from=date_from,
            date_to=date_to,
            ip=ip,
            client=client,
            domain=qh,
            query_type=qt,
            client_protocol=cp,
            is_filtered=is_filtered,
            filter_rule=filter_rule,
            count_gte=count_gte,
            count_lte=count_lte,
            sort_by=sort_by,
            sort_asc=sort_asc,
            page=page,
            page_size=page_size,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/domain-summary")
async def get_domain_summary(
    date: Optional[str] = Query(None, description="Date (exact match, YYYY-MM-DD)"),
    qh: Optional[str] = Query(None, description="Domain (wildcard search)"),
    qt: Optional[str] = Query(None, description="Query type (exact match)"),
    cp: Optional[str] = Query(None, description="Client protocol (exact match)"),
    is_filtered: Optional[bool] = Query(None, description="Filter status"),
    count_gte: Optional[int] = Query(None, description="Count >= value"),
    count_lte: Optional[int] = Query(None, description="Count <= value"),
    sort_by: str = Query("count", description="Column to sort by"),
    sort_asc: bool = Query(False, description="Sort ascending"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Records per page"),
):
    """
    Get domain summary data (aggregated by Date/Domain/Type/Protocol/Filtered).
    Each row represents a unique combination of these fields with a count.
    """
    try:
        result = query_domain_summary(
            date=date,
            domain=qh,
            query_type=qt,
            client_protocol=cp,
            is_filtered=is_filtered,
            count_gte=count_gte,
            count_lte=count_lte,
            sort_by=sort_by,
            sort_asc=sort_asc,
            page=page,
            page_size=page_size,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/base-domain-summary")
async def get_base_domain_summary(
    qh: Optional[str] = Query(None, description="Base domain (wildcard search)"),
    qt: Optional[str] = Query(None, description="Query type (exact match)"),
    cp: Optional[str] = Query(None, description="Client protocol (exact match)"),
    is_filtered: Optional[bool] = Query(None, description="Filter status"),
    count_gte: Optional[int] = Query(None, description="Count >= value"),
    count_lte: Optional[int] = Query(None, description="Count <= value"),
    max_count_gte: Optional[int] = Query(None, description="Max count >= value"),
    max_count_lte: Optional[int] = Query(None, description="Max count <= value"),
    sort_by: str = Query("count", description="Column to sort by"),
    sort_asc: bool = Query(False, description="Sort ascending"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE, description="Records per page"),
):
    """
    Get base domain summary data (aggregated by BaseDomain/Type/Protocol/Filtered).
    Includes total count and max count per day.
    """
    try:
        result = query_base_domain_summary(
            domain=qh,
            query_type=qt,
            client_protocol=cp,
            is_filtered=is_filtered,
            count_gte=count_gte,
            count_lte=count_lte,
            max_count_gte=max_count_gte,
            max_count_lte=max_count_lte,
            sort_by=sort_by,
            sort_asc=sort_asc,
            page=page,
            page_size=page_size,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
