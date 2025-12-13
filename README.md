# AdGuard Home Log Analyzer

A toolkit for fetching, storing, and analyzing DNS query logs from AdGuard Home running on a remote router. Features a DuckDB-powered backend for fast queries and a web dashboard for exploring log data.

## Features

- [test](/images.UpdateLogs.png){:target="_blank" rel="noopener"}

- **Incremental Log Fetching**: [Retrieves DNS query logs](/images/UpdateLogs.png) from AdGuard Home via SSH, tracking byte offsets to only transfer new data
- **DuckDB Storage**: All logs stored in a local DuckDB database for fast analytical queries
- **Real-time Aggregations**: Summary views computed on-the-fly via SQL - no pre-processing needed
- **Client Name Resolution**: Automatically maps IP addresses to hostnames using DHCP lease data
- **Condensed Storage**: Log entries are aggregated by unique combinations of date/IP/client/domain/type/protocol/upstream/filtered/filter_rule with a count field, dramatically reducing storage requirements
- **Web Dashboard**: Interactive UI with four views:
  - **[Client Summary](https://github.com/lopperman/AdGuardHome_DNSQueryAnalyzer/blob/main/images/ClientSummary.png)**: Query counts grouped by date/IP/client/domain with row actions (delete logs, add to ignore list)
  - **[Domain Summary](https://github.com/lopperman/AdGuardHome_DNSQueryAnalyzer/blob/main/images/DomainSummary.png)**: Query counts grouped by date/domain/type/protocol/filtered
  - **[Base Domain Summary](https://github.com/lopperman/AdGuardHome_DNSQueryAnalyzer/blob/main/images/BaseDomainSummary.png)**: Query counts grouped by base domain (e.g., `amazonaws.com`) with max daily counts
  - **[Ignored Domains](https://github.com/lopperman/AdGuardHome_DNSQueryAnalyzer/blob/main/images/IgnoredDomains.png)**: Manage domains to exclude from future log imports, with ability to delete existing logs
- **REST API**: FastAPI-based endpoints for programmatic access

![Client Summary](/images/ClientSummary.png?raw=true)

## Domain Research and Imported Log Management

### - **Research Domains**
- Click 'search' icon to lookup information about privacy & trackers, security, general domain

- - ![**](/images/ResearchDomain.png)

### - **Manage Imported Data**
- Click 'gear' icon for imported data options

- - ![**](/images/RowActions.png)


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
| `/api/stats` | GET | Database statistics (total records, total requests, date range) |
| `/api/update-logs` | POST | Fetch new logs from router |
| `/api/query-log-summary` | GET | Query client summary (aggregated by date/IP/client/domain) |
| `/api/domain-summary` | GET | Query domain summary (aggregated by date/domain) |
| `/api/base-domain-summary` | GET | Query base domain summary |
| `/api/logs/before-date/{date}` | DELETE | Delete all logs before specified date |
| `/api/logs/by-domain/{domain}` | DELETE | Delete all logs for specified domain |
| `/api/ignored-domains` | GET | List ignored domains (with optional search filter) |
| `/api/ignored-domains` | POST | Add domain to ignore list |
| `/api/ignored-domains/{domain}` | DELETE | Remove domain from ignore list |

### Query Parameters

**All summary endpoints support pagination:**
- `page` - Page number (default: 1)
- `page_size` - Records per page (default: 500, max: 2000)
- `sort_by` - Column to sort by
- `sort_asc` - Sort ascending (default: false)

**Common filters (all summary endpoints):**
- `qh` - Domain name (wildcard search)
- `qt` - Query type (wildcard search)
- `cp` - Client protocol (exact match)
- `is_filtered` - Filter status (true/false)
- `count_gte` / `count_lte` - Count range filters

**Client summary additional filters:**
- `date` - Exact date (YYYY-MM-DD)
- `date_from` / `date_to` - Date range
- `ip` - IP address (exact match)
- `client` - Client hostname (wildcard search)
- `filter_rule` - Filter rule (wildcard search)

**Domain summary additional filters:**
- `date` - Exact date (YYYY-MM-DD)

**Base domain summary additional filters:**
- `max_count_gte` / `max_count_lte` - Max daily count filters

**Ignored domains filters:**
- `search` - Domain name (wildcard search)

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

### Query Logs Table (Condensed)

Log entries are stored in a condensed format where each row represents a unique combination of attributes with a count field. This dramatically reduces storage compared to storing individual queries.

| Field | Description |
|-------|-------------|
| `date` | Query date (YYYY-MM-DD) |
| `ip` | Client IP address |
| `client` | Client hostname (from DHCP) |
| `domain` | Query domain name |
| `query_type` | DNS record type (A, AAAA, HTTPS, etc.) |
| `client_protocol` | Protocol used (dns, doh, dot) |
| `upstream` | DNS upstream server used |
| `is_filtered` | Whether the query was blocked |
| `filter_rule` | Blocking rule (if filtered) |
| `count` | Number of matching queries |

### Ignored Domains Table

| Field | Description |
|-------|-------------|
| `domain` | Domain name to ignore (primary key) |
| `added_at` | Timestamp when added |
| `notes` | Optional notes |

### Summary Fields (API Response)

| Field | Description |
|-------|-------------|
| `Date` | Query date (client/domain summary) |
| `IP` | Client IP address (client summary only) |
| `client` | Client hostname (client summary only) |
| `QH` | Query host (domain or base domain) |
| `QT` | Query type |
| `CP` | Client protocol |
| `IsFiltered` | Whether queries were blocked |
| `filterRule` | Filter rule (client summary only) |
| `count` | Total query count |
| `maxCount` | Maximum queries in a single day (base domain only) |

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
