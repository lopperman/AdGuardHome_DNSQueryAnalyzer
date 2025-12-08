# AdGuard Home Log Summary

A toolkit for fetching, aggregating, and analyzing DNS query logs from AdGuard Home running on a remote router. Includes a web-based dashboard for exploring and filtering log data.

## Features

- **Incremental Log Fetching**: Retrieves DNS query logs from AdGuard Home via SSH, tracking the last fetch timestamp to avoid duplicates
- **Summary Generation**: Aggregates logs into three summary views:
  - **Client Summary**: Query counts grouped by IP/client + domain
  - **Domain Summary**: Query counts grouped by full domain
  - **Base Domain Summary**: Query counts grouped by base domain (e.g., `amazonaws.com`)
- **Web Dashboard**: Interactive UI for browsing and filtering summary data with sortable tables
- **REST API**: FastAPI-based endpoints for programmatic access

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
python web_service.py
```

Access the dashboard at http://localhost:8080

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
├── requirements.txt       # Python dependencies
├── static/
│   └── index.html         # Web dashboard
├── LogData/               # Raw log storage (created automatically)
│   └── querylog.ndjson
├── AppData/               # Summary files (created automatically)
│   ├── Current/           # Latest summaries
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

## License

MIT
