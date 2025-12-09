"""
DuckDB database module for AdGuard Home Log storage and querying.

This module provides:
- Database initialization and schema management
- Functions to insert raw log entries
- Query functions for raw logs and aggregated summaries
"""

import duckdb
import json
from pathlib import Path
from typing import Optional
from datetime import datetime

# Database file location
SCRIPT_DIR = Path(__file__).parent
DB_FILE = SCRIPT_DIR / "AppData" / "adguard_logs.duckdb"

# Public suffix list for base domain extraction (common TLDs)
MULTI_PART_TLDS = {
    'co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.kr', 'co.in',
    'org.uk', 'net.au', 'org.au', 'ac.uk', 'gov.uk', 'com.mx', 'com.cn',
    'cloudfront.net', 'amazonaws.com', 'azurewebsites.net', 'blob.core.windows.net',
    'cloudapp.azure.com', 's3.amazonaws.com', 'elasticbeanstalk.com',
    'herokuapp.com', 'appspot.com', 'firebaseapp.com', 'web.app',
    'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
    'github.io', 'gitlab.io', 'bitbucket.io',
}


def get_connection() -> duckdb.DuckDBPyConnection:
    """Get a connection to the DuckDB database."""
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    return duckdb.connect(str(DB_FILE))


def init_database():
    """Initialize the database schema."""
    conn = get_connection()

    # Create the raw logs table (no explicit id - use rowid)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS query_logs (
            timestamp TIMESTAMPTZ NOT NULL,
            date DATE NOT NULL,
            ip VARCHAR NOT NULL,
            domain VARCHAR NOT NULL,
            query_type VARCHAR,
            query_class VARCHAR,
            client_protocol VARCHAR,
            upstream VARCHAR,
            answer TEXT,
            is_filtered BOOLEAN DEFAULT FALSE,
            filter_rule TEXT,
            filter_reason INTEGER,
            elapsed_ns BIGINT,
            cached BOOLEAN DEFAULT FALSE
        )
    """)

    # Create indexes for common query patterns
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_date ON query_logs(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON query_logs(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON query_logs(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON query_logs(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_is_filtered ON query_logs(is_filtered)")

    # Create a table to track last fetch timestamp
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fetch_metadata (
            key VARCHAR PRIMARY KEY,
            value VARCHAR
        )
    """)

    # Create client names table (IP to hostname mapping)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS client_names (
            ip VARCHAR PRIMARY KEY,
            hostname VARCHAR NOT NULL,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.close()
    print(f"Database initialized: {DB_FILE}")


def extract_base_domain(domain: str) -> str:
    """
    Extract the base domain from a full domain name.
    e.g., 'sub.example.co.uk' -> 'example.co.uk'
         'api.example.com' -> 'example.com'
    """
    if not domain:
        return domain

    domain = domain.lower().rstrip('.')
    parts = domain.split('.')

    if len(parts) <= 2:
        return domain

    # Check for multi-part TLDs
    for i in range(len(parts) - 1):
        potential_tld = '.'.join(parts[i:])
        if potential_tld in MULTI_PART_TLDS:
            if i > 0:
                return '.'.join(parts[i-1:])
            return potential_tld

    # Default: return last two parts
    return '.'.join(parts[-2:])


def parse_timestamp(ts_str: str) -> tuple[datetime, str]:
    """
    Parse AdGuard timestamp string to datetime and date string.
    Handles nanosecond precision by truncating to microseconds.

    Returns: (datetime, date_str)
    """
    # Format: 2025-12-03T20:51:20.119085476-06:00
    # Python only handles microseconds (6 digits), so truncate nanoseconds (9 digits)
    try:
        # Find the decimal point and timezone
        if '.' in ts_str:
            base, rest = ts_str.split('.', 1)
            # Find where the timezone starts (+ or - after the decimal)
            tz_pos = -1
            for i, c in enumerate(rest):
                if c in '+-' and i > 0:
                    tz_pos = i
                    break

            if tz_pos > 0:
                fractional = rest[:tz_pos][:6]  # Truncate to 6 digits (microseconds)
                tz = rest[tz_pos:]
                ts_str = f"{base}.{fractional}{tz}"

        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        date_str = dt.strftime('%Y-%m-%d')
        return dt, date_str
    except Exception:
        # Fallback: try to extract date from string
        date_str = ts_str[:10] if len(ts_str) >= 10 else 'unknown'
        return datetime.now(), date_str


def insert_log_entries(entries: list[dict], conn: Optional[duckdb.DuckDBPyConnection] = None) -> int:
    """
    Insert raw log entries into the database.

    Args:
        entries: List of log entry dictionaries from AdGuard
        conn: Optional existing connection (creates new one if not provided)

    Returns:
        Number of entries inserted
    """
    should_close = conn is None
    if conn is None:
        conn = get_connection()

    rows = []
    for entry in entries:
        ts_str = entry.get('T', '')
        dt, date_str = parse_timestamp(ts_str)

        result = entry.get('Result', {})
        rules = result.get('Rules', [])
        filter_rule = rules[0].get('Text', '') if rules else None

        rows.append((
            dt,                                    # timestamp
            date_str,                              # date
            entry.get('IP', ''),                   # ip
            entry.get('QH', ''),                   # domain
            entry.get('QT', ''),                   # query_type
            entry.get('QC', ''),                   # query_class
            entry.get('CP', ''),                   # client_protocol
            entry.get('Upstream', ''),             # upstream
            entry.get('Answer', ''),               # answer
            result.get('IsFiltered', False),       # is_filtered
            filter_rule,                           # filter_rule
            result.get('Reason'),                  # filter_reason
            entry.get('Elapsed'),                  # elapsed_ns
            entry.get('Cached', False),            # cached
        ))

    if rows:
        conn.executemany("""
            INSERT INTO query_logs
            (timestamp, date, ip, domain, query_type, query_class, client_protocol,
             upstream, answer, is_filtered, filter_rule, filter_reason, elapsed_ns, cached)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)

    if should_close:
        conn.close()

    return len(rows)


def update_client_names(ip_to_hostname: dict[str, str]):
    """Update the client names table with IP to hostname mappings."""
    conn = get_connection()

    for ip, hostname in ip_to_hostname.items():
        conn.execute("""
            INSERT OR REPLACE INTO client_names (ip, hostname, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        """, [ip, hostname])

    conn.close()


def get_last_entry_timestamp() -> Optional[str]:
    """Get the timestamp of the last log entry in the database."""
    conn = get_connection()
    result = conn.execute("""
        SELECT MAX(timestamp) as max_ts FROM query_logs
    """).fetchone()
    conn.close()

    if result and result[0]:
        return result[0].isoformat()
    return None


def set_metadata(key: str, value: str):
    """Set a metadata value."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO fetch_metadata (key, value) VALUES (?, ?)
    """, [key, value])
    conn.close()


def get_metadata(key: str) -> Optional[str]:
    """Get a metadata value."""
    conn = get_connection()
    result = conn.execute("""
        SELECT value FROM fetch_metadata WHERE key = ?
    """, [key]).fetchone()
    conn.close()
    return result[0] if result else None


# ============================================================================
# Query Functions for Web Service
# ============================================================================

def query_raw_logs(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    ip: Optional[str] = None,
    domain: Optional[str] = None,
    query_type: Optional[str] = None,
    client_protocol: Optional[str] = None,
    is_filtered: Optional[bool] = None,
    filter_rule: Optional[str] = None,
    cached: Optional[bool] = None,
    sort_by: str = 'timestamp',
    sort_asc: bool = False,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """
    Query raw log entries with filtering, sorting, and pagination.

    Returns dict with: total, page, page_size, total_pages, records
    """
    conn = get_connection()

    # Build WHERE clause
    conditions = []
    params = []

    if date_from:
        conditions.append("date >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("date <= ?")
        params.append(date_to)
    if ip:
        conditions.append("LOWER(ip) = LOWER(?)")
        params.append(ip)
    if domain:
        conditions.append("LOWER(domain) LIKE LOWER(?)")
        params.append(f"%{domain}%")
    if query_type:
        conditions.append("LOWER(query_type) = LOWER(?)")
        params.append(query_type)
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)
    if filter_rule:
        conditions.append("LOWER(filter_rule) LIKE LOWER(?)")
        params.append(f"%{filter_rule}%")
    if cached is not None:
        conditions.append("cached = ?")
        params.append(cached)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Valid sort columns
    valid_sort = ['timestamp', 'date', 'ip', 'domain', 'query_type', 'client_protocol',
                  'is_filtered', 'elapsed_ns', 'cached']
    if sort_by not in valid_sort:
        sort_by = 'timestamp'

    sort_dir = 'ASC' if sort_asc else 'DESC'

    # Get total count
    count_result = conn.execute(f"""
        SELECT COUNT(*) FROM query_logs WHERE {where_clause}
    """, params).fetchone()
    total = count_result[0]

    # Calculate pagination
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size

    # Get paginated results with client names
    results = conn.execute(f"""
        SELECT
            q.timestamp,
            q.date,
            q.ip,
            COALESCE(c.hostname, '') as client,
            q.domain,
            q.query_type,
            q.query_class,
            q.client_protocol,
            q.upstream,
            q.answer,
            q.is_filtered,
            q.filter_rule,
            q.filter_reason,
            q.elapsed_ns,
            q.cached
        FROM query_logs q
        LEFT JOIN client_names c ON q.ip = c.ip
        WHERE {where_clause}
        ORDER BY {sort_by} {sort_dir}
        LIMIT ? OFFSET ?
    """, params + [page_size, offset]).fetchall()

    conn.close()

    # Convert to list of dicts
    records = []
    for row in results:
        records.append({
            'timestamp': row[0].isoformat() if row[0] else '',
            'date': str(row[1]) if row[1] else '',
            'IP': row[2],
            'client': row[3],
            'QH': row[4],
            'QT': row[5],
            'QC': row[6],
            'CP': row[7],
            'upstream': row[8],
            'answer': row[9],
            'IsFiltered': row[10],
            'filterRule': row[11],
            'filterReason': row[12],
            'elapsedNs': row[13],
            'cached': row[14],
        })

    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'records': records,
    }


def query_client_summary(
    date: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    ip: Optional[str] = None,
    client: Optional[str] = None,
    domain: Optional[str] = None,
    query_type: Optional[str] = None,
    client_protocol: Optional[str] = None,
    is_filtered: Optional[bool] = None,
    count_gte: Optional[int] = None,
    count_lte: Optional[int] = None,
    sort_by: str = 'count',
    sort_asc: bool = False,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """
    Query client summary (aggregated by date/IP/domain/type/protocol/filtered).
    """
    conn = get_connection()

    # Build WHERE clause for raw data
    conditions = []
    params = []

    if date:
        conditions.append("q.date = ?")
        params.append(date)
    if date_from:
        conditions.append("q.date >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("q.date <= ?")
        params.append(date_to)
    if ip:
        conditions.append("LOWER(q.ip) = LOWER(?)")
        params.append(ip)
    if domain:
        conditions.append("LOWER(q.domain) LIKE LOWER(?)")
        params.append(f"%{domain}%")
    if query_type:
        conditions.append("LOWER(q.query_type) = LOWER(?)")
        params.append(query_type)
    if client_protocol:
        conditions.append("LOWER(q.client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("q.is_filtered = ?")
        params.append(is_filtered)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # HAVING clause for count filters
    having_conditions = []
    having_params = []
    if count_gte is not None:
        having_conditions.append("COUNT(*) >= ?")
        having_params.append(count_gte)
    if count_lte is not None:
        having_conditions.append("COUNT(*) <= ?")
        having_params.append(count_lte)

    # Client name filter needs to be in HAVING since it's joined
    if client:
        having_conditions.append("LOWER(COALESCE(c.hostname, '')) = LOWER(?)")
        having_params.append(client)

    having_clause = " AND ".join(having_conditions) if having_conditions else "1=1"

    # Valid sort columns (prefixed with table alias to avoid ambiguity)
    sort_map = {
        'Date': 'q.date', 'IP': 'q.ip', 'client': 'client', 'QH': 'q.domain',
        'QT': 'q.query_type', 'CP': 'q.client_protocol', 'IsFiltered': 'q.is_filtered',
        'count': 'count'
    }
    sort_col = sort_map.get(sort_by, 'count')
    sort_dir = 'ASC' if sort_asc else 'DESC'

    # Count total groups
    count_query = f"""
        SELECT COUNT(*) FROM (
            SELECT 1
            FROM query_logs q
            LEFT JOIN client_names c ON q.ip = c.ip
            WHERE {where_clause}
            GROUP BY q.date, q.ip, q.domain, q.query_type, q.client_protocol, q.is_filtered
            HAVING {having_clause}
        ) subq
    """
    count_result = conn.execute(count_query, params + having_params).fetchone()
    total = count_result[0]

    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size

    # Get aggregated results
    results = conn.execute(f"""
        SELECT
            q.date,
            q.ip,
            COALESCE(c.hostname, '') as client,
            q.domain,
            q.query_type,
            q.client_protocol,
            q.is_filtered,
            COUNT(*) as count
        FROM query_logs q
        LEFT JOIN client_names c ON q.ip = c.ip
        WHERE {where_clause}
        GROUP BY q.date, q.ip, c.hostname, q.domain, q.query_type, q.client_protocol, q.is_filtered
        HAVING {having_clause}
        ORDER BY {sort_col} {sort_dir}
        LIMIT ? OFFSET ?
    """, params + having_params + [page_size, offset]).fetchall()

    conn.close()

    records = []
    for row in results:
        records.append({
            'Date': str(row[0]) if row[0] else '',
            'IP': row[1],
            'client': row[2],
            'QH': row[3],
            'QT': row[4],
            'CP': row[5],
            'IsFiltered': row[6],
            'count': row[7],
        })

    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'records': records,
    }


def query_domain_summary(
    domain: Optional[str] = None,
    query_type: Optional[str] = None,
    client_protocol: Optional[str] = None,
    is_filtered: Optional[bool] = None,
    count_gte: Optional[int] = None,
    count_lte: Optional[int] = None,
    max_count_gte: Optional[int] = None,
    max_count_lte: Optional[int] = None,
    sort_by: str = 'count',
    sort_asc: bool = False,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """
    Query domain summary (aggregated by domain/type/protocol/filtered).
    Includes total count and max count per day.
    """
    conn = get_connection()

    # Build WHERE clause
    conditions = []
    params = []

    if domain:
        conditions.append("LOWER(domain) LIKE LOWER(?)")
        params.append(f"%{domain}%")
    if query_type:
        conditions.append("LOWER(query_type) = LOWER(?)")
        params.append(query_type)
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # HAVING clause for count/maxCount filters
    having_conditions = []
    having_params = []
    if count_gte is not None:
        having_conditions.append("SUM(daily_count) >= ?")
        having_params.append(count_gte)
    if count_lte is not None:
        having_conditions.append("SUM(daily_count) <= ?")
        having_params.append(count_lte)
    if max_count_gte is not None:
        having_conditions.append("MAX(daily_count) >= ?")
        having_params.append(max_count_gte)
    if max_count_lte is not None:
        having_conditions.append("MAX(daily_count) <= ?")
        having_params.append(max_count_lte)

    having_clause = " AND ".join(having_conditions) if having_conditions else "1=1"

    # Sort mapping
    sort_map = {
        'QH': 'domain', 'QT': 'query_type', 'CP': 'client_protocol',
        'IsFiltered': 'is_filtered', 'count': 'total_count', 'maxCount': 'max_count'
    }
    sort_col = sort_map.get(sort_by, 'total_count')
    sort_dir = 'ASC' if sort_asc else 'DESC'

    # Use CTE to first get daily counts, then aggregate
    base_query = f"""
        WITH daily_counts AS (
            SELECT
                domain,
                query_type,
                client_protocol,
                is_filtered,
                date,
                COUNT(*) as daily_count
            FROM query_logs
            WHERE {where_clause}
            GROUP BY domain, query_type, client_protocol, is_filtered, date
        )
        SELECT
            domain,
            query_type,
            client_protocol,
            is_filtered,
            SUM(daily_count) as total_count,
            MAX(daily_count) as max_count
        FROM daily_counts
        GROUP BY domain, query_type, client_protocol, is_filtered
        HAVING {having_clause}
    """

    # Count total
    count_result = conn.execute(f"SELECT COUNT(*) FROM ({base_query}) subq",
                                 params + having_params).fetchone()
    total = count_result[0]

    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size

    # Get paginated results
    results = conn.execute(f"""
        {base_query}
        ORDER BY {sort_col} {sort_dir}
        LIMIT ? OFFSET ?
    """, params + having_params + [page_size, offset]).fetchall()

    conn.close()

    records = []
    for row in results:
        records.append({
            'QH': row[0],
            'QT': row[1],
            'CP': row[2],
            'IsFiltered': row[3],
            'count': row[4],
            'maxCount': row[5],
        })

    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'records': records,
    }


def query_base_domain_summary(
    domain: Optional[str] = None,
    query_type: Optional[str] = None,
    client_protocol: Optional[str] = None,
    is_filtered: Optional[bool] = None,
    count_gte: Optional[int] = None,
    count_lte: Optional[int] = None,
    max_count_gte: Optional[int] = None,
    max_count_lte: Optional[int] = None,
    sort_by: str = 'count',
    sort_asc: bool = False,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """
    Query base domain summary (aggregated by base domain/type/protocol/filtered).
    """
    conn = get_connection()

    # DuckDB doesn't have our extract_base_domain function, so we need to do this differently
    # We'll create a temporary table or use a subquery with the base domain calculation

    # For now, let's fetch domains and compute base domain in Python
    # This is less efficient but works correctly

    conditions = []
    params = []

    if query_type:
        conditions.append("LOWER(query_type) = LOWER(?)")
        params.append(query_type)
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Get daily counts per domain first
    results = conn.execute(f"""
        SELECT
            domain,
            query_type,
            client_protocol,
            is_filtered,
            date,
            COUNT(*) as daily_count
        FROM query_logs
        WHERE {where_clause}
        GROUP BY domain, query_type, client_protocol, is_filtered, date
    """, params).fetchall()

    conn.close()

    # Aggregate by base domain in Python
    from collections import defaultdict
    base_domain_data = defaultdict(lambda: {'total': 0, 'daily': defaultdict(int)})

    for row in results:
        full_domain = row[0]
        qt = row[1]
        cp = row[2]
        is_filt = row[3]
        date = row[4]
        count = row[5]

        base = extract_base_domain(full_domain)
        key = (base, qt, cp, is_filt)

        base_domain_data[key]['total'] += count
        base_domain_data[key]['daily'][date] += count

    # Convert to records with filtering
    records = []
    for (base, qt, cp, is_filt), data in base_domain_data.items():
        total_count = data['total']
        max_count = max(data['daily'].values()) if data['daily'] else 0

        # Apply domain filter
        if domain and domain.lower() not in base.lower():
            continue
        # Apply count filters
        if count_gte is not None and total_count < count_gte:
            continue
        if count_lte is not None and total_count > count_lte:
            continue
        if max_count_gte is not None and max_count < max_count_gte:
            continue
        if max_count_lte is not None and max_count > max_count_lte:
            continue

        records.append({
            'QH': base,
            'QT': qt,
            'CP': cp,
            'IsFiltered': is_filt,
            'count': total_count,
            'maxCount': max_count,
        })

    # Sort
    sort_map = {'QH': 'QH', 'QT': 'QT', 'CP': 'CP', 'IsFiltered': 'IsFiltered',
                'count': 'count', 'maxCount': 'maxCount'}
    sort_key = sort_map.get(sort_by, 'count')
    records.sort(key=lambda x: (x[sort_key] is None, x[sort_key]), reverse=not sort_asc)

    # Paginate
    total = len(records)
    total_pages = max(1, (total + page_size - 1) // page_size)
    offset = (page - 1) * page_size
    paginated = records[offset:offset + page_size]

    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'records': paginated,
    }


def get_database_stats() -> dict:
    """Get statistics about the database."""
    conn = get_connection()

    stats = {}

    # Total log entries
    result = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()
    stats['total_entries'] = result[0]

    # Date range
    result = conn.execute("SELECT MIN(date), MAX(date) FROM query_logs").fetchone()
    stats['date_min'] = str(result[0]) if result[0] else None
    stats['date_max'] = str(result[1]) if result[1] else None

    # Unique IPs
    result = conn.execute("SELECT COUNT(DISTINCT ip) FROM query_logs").fetchone()
    stats['unique_ips'] = result[0]

    # Unique domains
    result = conn.execute("SELECT COUNT(DISTINCT domain) FROM query_logs").fetchone()
    stats['unique_domains'] = result[0]

    # Filtered percentage
    result = conn.execute("""
        SELECT
            SUM(CASE WHEN is_filtered THEN 1 ELSE 0 END) as filtered,
            COUNT(*) as total
        FROM query_logs
    """).fetchone()
    stats['filtered_count'] = result[0]
    stats['filtered_percentage'] = round(result[0] / result[1] * 100, 2) if result[1] > 0 else 0

    conn.close()
    return stats


if __name__ == "__main__":
    # Initialize database when run directly
    init_database()
    print("Database schema created successfully.")
