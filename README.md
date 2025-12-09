# AdGuard Home Log Analyzer

A toolkit for fetching, storing, and analyzing DNS query logs from AdGuard Home running on a remote router. Features a DuckDB-powered backend for fast queries and a web dashboard for exploring log data.

## Features

- **Incremental Log Fetching**: Retrieves DNS query logs from AdGuard Home via SSH, tracking byte offsets to only transfer new data
- **DuckDB Storage**: All logs stored in a local DuckDB database for fast analytical queries
- **Real-time Aggregations**: Summary views computed on-the-fly via SQL - no pre-processing needed
- **Client Name Resolution**: Automatically maps IP addresses to hostnames using DHCP lease data
- **Web Dashboard**: Interactive UI with four views:
  - **Client Summary**: Query counts grouped by date/IP/client/domain
  - **Domain Summary**: Query counts grouped by full domain with max daily counts
  - **Base Domain Summary**: Query counts grouped by base domain (e.g., `amazonaws.com`)
  - **Raw Logs**: Browse individual log entries with full details
- **REST API**: FastAPI-based endpoints for programmatic access

![Client Summary](https://github.com/lopperman/AdGuardHome_DNSQueryAnalyzer/blob/main/images/ClientSummary.png?raw=true)

![Fetch Logs](https://github.com/lopperman/AdGuardHome_DNSQueryAnalyzer/blob/main/images/fetch_logs.png?raw=true)

## Prerequisites

- Python 3.10+
- SSH access to the router running AdGuard Home
- AdGuard Home query log files accessible on the router

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd AdguardHomeLogs
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file with your configuration:
   ```
   # Router SSH connection
   ROUTER_SSH_HOST=192.168.1.1
   ROUTER_SSH_PORT=22
   ROUTER_SSH_USER=admin

   # AdGuard Home paths on router
   ADGUARD_QUERY_LOG=/opt/AdGuardHome/data/querylog.json
   DHCP_LEASES_PATH=/var/lib/misc/dnsmasq.leases

   # Web server settings (optional)
   WEB_HOST=0.0.0.0
   WEB_PORT=8080

   # Fetch settings (optional)
   FETCH_CHUNK_SIZE=1048576
   ```

## Usage

### Web Dashboard

Start the web server:

```bash
# Using the start script (recommended)
./start.sh

# Or run directly
python web_service.py
```

The `start.sh` script will:
- Check if the service is already running
- Find an available port (8080-8099) if the default is in use
- Start the service and open the dashboard in your browser

To stop the service:
```bash
./stop.sh
```

Access the dashboard at http://localhost:8080

### Fetching Logs

Click **Update Logs** in the web UI, or run from command line:

```bash
# Interactive mode (prompts for confirmation)
python fetch_logs.py

# Non-interactive mode
python fetch_logs.py -y
```

The fetcher:
- Uses byte offset tracking to only transfer new data since last fetch
- Stores entries directly into DuckDB
- Updates client name mappings from DHCP leases
- Handles log rotation automatically

# API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Database statistics (total entries, date range, unique IPs/domains) |
| `/api/update-logs` | POST | Fetch new logs from router |
| `/api/raw-logs` | GET | Query individual log entries |
| `/api/query-log-summary` | GET | Query client summary (aggregated by date/IP/domain) |
| `/api/domain-summary` | GET | Query domain summary |
| `/api/base-domain-summary` | GET | Query base domain summary |

### Query Parameters

**All endpoints support pagination:**
- `page` - Page number (default: 1)
- `page_size` - Records per page (default: 500, max: 2000)
- `sort_by` - Column to sort by
- `sort_asc` - Sort ascending (default: false)

**Raw Logs filters:**
- `date_from` / `date_to` - Date range (YYYY-MM-DD)
- `ip` - IP address (exact match)
- `qh` - Domain name (wildcard search)
- `qt` - Query type (A, AAAA, HTTPS, etc.)
- `cp` - Client protocol (dns, doh, dot)
- `is_filtered` - Filter status (true/false)
- `filter_rule` - Filter rule (wildcard search)
- `cached` - Cached status (true/false)

**Summary filters:**
- `qh` - Domain name (wildcard search)
- `qt` - Query type (exact match)
- `cp` - Client protocol (exact match)
- `is_filtered` - Filter status (true/false)
- `count_gte` / `count_lte` - Count range filters
- `max_count_gte` / `max_count_lte` - Max daily count filters (domain summaries only)

**Client summary additional filters:**
- `date` - Exact date (YYYY-MM-DD)
- `date_from` / `date_to` - Date range
- `ip` - IP address (exact match)
- `client` - Client hostname (exact match)

## Directory Structure

```
AdguardHomeLogs/
├── database.py            # DuckDB database module
├── fetch_logs.py          # Log fetcher script
├── web_service.py         # FastAPI web service
├── start.sh               # Start web service
├── stop.sh                # Stop web service
├── requirements.txt       # Python dependencies
├── static/
│   └── index.html         # Web dashboard
├── AppData/
│   ├── adguard_logs.duckdb   # DuckDB database
│   └── logFetchHistory.json  # Fetch state (offsets, timestamps)
└── .env                   # Configuration (not committed)
```

## Data Schema

### Raw Log Fields

| Field | Description |
|-------|-------------|
| `timestamp` | Query timestamp with timezone |
| `date` | Query date (YYYY-MM-DD) |
| `ip` | Client IP address |
| `client` | Client hostname (from DHCP) |
| `domain` | Query domain name |
| `query_type` | DNS record type (A, AAAA, HTTPS, etc.) |
| `query_class` | DNS class (usually IN) |
| `client_protocol` | Protocol used (dns, doh, dot) |
| `upstream` | DNS upstream server used |
| `answer` | Raw DNS answer (base64 encoded) |
| `is_filtered` | Whether the query was blocked |
| `filter_rule` | Blocking rule (if filtered) |
| `filter_reason` | Reason code for filtering |
| `elapsed_ns` | Query time in nanoseconds |
| `cached` | Whether response was cached |

### Summary Fields

| Field | Description |
|-------|-------------|
| `Date` | Query date (client summary only) |
| `IP` | Client IP address (client summary only) |
| `client` | Client hostname (client summary only) |
| `QH` | Query host (domain or base domain) |
| `QT` | Query type |
| `CP` | Client protocol |
| `IsFiltered` | Whether queries were blocked |
| `count` | Total query count |
| `maxCount` | Maximum queries in a single day |

## AdGuard Home Configuration Notes

### Query Log Buffering

AdGuard Home buffers queries in memory before writing to disk. The `size_memory` setting in `AdGuardHome.yaml` controls the buffer size (default: 1000). Queries won't appear in the log file until the buffer fills or the service restarts.

| size_memory | Approx. flush time (at ~90 queries/min) |
|-------------|----------------------------------------|
| 1000 | ~11 minutes |
| 500 | ~5.5 minutes |
| 100 | ~1 minute |

### Log Rotation

AdGuard keeps one backup file (`querylog.json.1`). This tool handles rotation automatically by tracking file timestamps and detecting when rotation occurs.

## License

MIT
