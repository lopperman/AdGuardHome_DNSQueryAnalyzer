# AdGuard Home Log Summary

A toolkit for fetching, aggregating, and analyzing DNS query logs from AdGuard Home running on a remote router. Includes a web-based dashboard for exploring and filtering log data.

## Features

- **Incremental Log Fetching**: Retrieves DNS query logs from AdGuard Home via SSH, tracking the last fetch timestamp to avoid duplicates
- **Byte Offset Optimization**: Only transfers new data since last fetch using `tail -c +OFFSET`, dramatically reducing bandwidth for large log files
- **Chunked Reading**: Large files are read in configurable chunks (default 1 MB) to avoid memory issues on the router
- **Rotation Detection**: Automatically detects when AdGuard rotates log files and adjusts accordingly
- **Summary Generation**: Aggregates logs into three summary views:
  - **Client Summary**: Query counts grouped by IP/client + domain
  - **Domain Summary**: Query counts grouped by full domain
  - **Base Domain Summary**: Query counts grouped by base domain (e.g., `amazonaws.com`)
- **Web Dashboard**: Interactive UI for browsing and filtering summary data with sortable tables
- **REST API**: FastAPI-based endpoints for programmatic access

![](https://github.com/lopperman/AdGuardHome_DNSQueryAnalyzer/blob/main/images/ClientSummary.png?raw=true)

![](https://github.com/lopperman/AdGuardHome_DNSQueryAnalyzer/blob/main/images/fetch_logs.png?raw=true)



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
   ROUTER_SSH_HOST=[Router IP]
   ROUTER_SSH_PORT=[Router SSH Port]
   ROUTER_SSH_USER=[Router Username]

   # AdGuard Home paths on router
   ADGUARD_QUERY_LOG=[Path to AdGuard querylog.json on router]
   DHCP_LEASES_PATH=/var/lib/misc/dnsmasq.leases

   # Web server settings (optional)
   WEB_HOST=0.0.0.0
   WEB_PORT=8080

   # Fetch settings (optional)
   # Maximum bytes to read in a single SSH operation (default: 1MB)
   FETCH_CHUNK_SIZE=1048576
   ```

## Usage

### Fetching Logs

Fetch new log entries from the router:

```bash
# Interactive mode (prompts for confirmation)
python fetch_logs.py

# Non-interactive mode
python fetch_logs.py -y
```

Logs are stored incrementally in `LogData/querylog.ndjson`.

The fetcher uses byte offset tracking to only transfer new data since the last fetch. For example, if a 50 MB log file has grown by 500 KB since the last fetch, only the new 500 KB is transferred. The fetch state is stored in `AppData/logFetchHistory.json`.

### Building Summaries

Generate summary files from the fetched logs:

```bash
# Process all logs
python build_log_summary.py

# Process logs from a specific date onwards
python build_log_summary.py --from-date 2025-12-01
```

Summaries are written to `AppData/Current/` and timestamped copies in `AppData/`.

### Web Dashboard

Start the web server:

```bash
# Using the start script (recommended)
./start.sh

# Or run directly
python web_service.py
```

The `start.sh` script will:
- Check if the service is already running (and open browser if so)
- Find an available port (8080-8099) if the default is in use
- Start the service and open the dashboard in your browser

To run in the background:
```bash
./start.sh &
```

To stop the service:
```bash
./stop.sh
```

Access the dashboard at http://localhost:8080 (or the port shown at startup)

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/update-logs` | POST | Fetch new logs from router |
| `/api/build-summary` | POST | Build summary files (optional `from_date` param) |
| `/api/query-log-summary` | GET | Query client+domain summary data |
| `/api/domain-summary` | GET | Query domain summary data |
| `/api/base-domain-summary` | GET | Query base domain summary data |

### Query Parameters

All summary endpoints support these filters:
- `qh` - Domain name (wildcard search)
- `qt` - Query type (exact match, e.g., `A`, `AAAA`)
- `cp` - Client protocol (exact match, e.g., `dns`)
- `is_filtered` - Filter status (`true`/`false`)
- `count_gte` / `count_lte` - Count range filters
- `max_count_gte` / `max_count_lte` - Max daily count range filters

The client summary endpoint also supports:
- `ip` - IP address (exact match)
- `client` - Client hostname (exact match)

## Directory Structure

```
AdguardHomeLogs/
├── fetch_logs.py          # Log fetcher script
├── build_log_summary.py   # Summary builder script
├── web_service.py         # FastAPI web service
├── start.sh               # Start web service (handles port conflicts)
├── stop.sh                # Stop web service
├── requirements.txt       # Python dependencies
├── static/
│   └── index.html         # Web dashboard
├── LogData/               # Raw log storage (created automatically)
│   └── querylog.ndjson
├── AppData/               # Application data (created automatically)
│   ├── Current/           # Latest summaries
│   ├── logFetchHistory.json  # Fetch state (offsets, timestamps)
│   └── *.json             # Timestamped summaries
└── .env                   # Configuration (not committed)
```

## Summary Data Fields

| Field | Description |
|-------|-------------|
| `IP` | Client IP address (client summary only) |
| `client` | Client hostname from DHCP (client summary only) |
| `QH` | Query host (domain name) |
| `QT` | Query type (A, AAAA, HTTPS, etc.) |
| `CP` | Client protocol (dns, doh, dot) |
| `IsFiltered` | Whether the query was blocked |
| `count` | Total query count |
| `maxCount` | Maximum queries in a single day |

## AdGuard Home Configuration Notes

### Query Log Buffering

AdGuard Home buffers queries in memory before writing to disk. The `size_memory` setting in `AdGuardHome.yaml` controls how many entries are buffered (default: 1000). Queries won't appear in `querylog.json` until the buffer fills or the service restarts.

With ~90 queries/minute, a 1000-entry buffer takes ~11 minutes to flush. Lower `size_memory` for faster disk writes:

| size_memory | Approx. flush time |
|-------------|-------------------|
| 1000 | ~11 minutes |
| 500 | ~5.5 minutes |
| 100 | ~1 minute |

### Log Rotation

AdGuard keeps one backup file (`querylog.json.1`). The `interval` setting controls rotation frequency. Actual retention is ~2x the interval (current + backup).

This tool handles rotation automatically by tracking the first timestamp in each file to detect when rotation occurs.

## License

MIT
