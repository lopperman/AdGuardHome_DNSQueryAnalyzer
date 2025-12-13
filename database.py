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

    # Create the condensed query logs table
    # Each row is unique by: date, ip, client, domain, query_type, client_protocol, upstream, is_filtered, filter_rule
    conn.execute("""
        CREATE TABLE IF NOT EXISTS query_logs (
            date DATE NOT NULL,
            ip VARCHAR NOT NULL,
            client VARCHAR NOT NULL DEFAULT '',
            domain VARCHAR NOT NULL,
            query_type VARCHAR,
            client_protocol VARCHAR,
            upstream VARCHAR,
            is_filtered BOOLEAN DEFAULT FALSE,
            filter_rule TEXT,
            count INTEGER NOT NULL DEFAULT 1
        )
    """)

    # Create indexes for common query patterns
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_date ON query_logs(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON query_logs(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON query_logs(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_is_filtered ON query_logs(is_filtered)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_query_type ON query_logs(query_type)")

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


def get_client_names_map(conn: duckdb.DuckDBPyConnection) -> dict[str, str]:
    """Get a mapping of IP addresses to client names."""
    results = conn.execute("SELECT ip, hostname FROM client_names").fetchall()
    return {row[0]: row[1] for row in results}


def insert_log_entries(entries: list[dict], conn: Optional[duckdb.DuckDBPyConnection] = None) -> int:
    """
    Insert log entries into the database (uncondensed, with count=1 each).
    Call condense_logs() after to aggregate duplicates.

    Args:
        entries: List of log entry dictionaries from AdGuard
        conn: Optional existing connection (creates new one if not provided)

    Returns:
        Number of entries inserted
    """
    should_close = conn is None
    if conn is None:
        conn = get_connection()

    # Get client name mapping
    client_map = get_client_names_map(conn)

    rows = []
    for entry in entries:
        ts_str = entry.get('T', '')
        _, date_str = parse_timestamp(ts_str)

        result = entry.get('Result', {})
        rules = result.get('Rules', [])
        filter_rule = rules[0].get('Text', '') if rules else ''

        ip = entry.get('IP', '')
        client = client_map.get(ip, '')

        rows.append((
            date_str,                              # date
            ip,                                    # ip
            client,                                # client
            entry.get('QH', ''),                   # domain
            entry.get('QT', ''),                   # query_type
            entry.get('CP', ''),                   # client_protocol
            entry.get('Upstream', ''),             # upstream
            result.get('IsFiltered', False),       # is_filtered
            filter_rule,                           # filter_rule
            1,                                     # count
        ))

    if rows:
        conn.executemany("""
            INSERT INTO query_logs
            (date, ip, client, domain, query_type, client_protocol,
             upstream, is_filtered, filter_rule, count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)

    if should_close:
        conn.close()

    return len(rows)


def condense_logs(conn: Optional[duckdb.DuckDBPyConnection] = None) -> dict:
    """
    Condense query_logs by aggregating duplicate rows.

    Groups by: date, ip, client, domain, query_type, client_protocol, upstream, is_filtered, filter_rule
    Sums the count column for each group.

    Returns:
        dict with 'rows_before', 'rows_after', 'total_count' for verification
    """
    should_close = conn is None
    if conn is None:
        conn = get_connection()

    # Get stats before
    rows_before = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()[0]
    total_count_before = conn.execute("SELECT SUM(count) FROM query_logs").fetchone()[0] or 0

    # Create condensed version in a temp table
    conn.execute("""
        CREATE TEMP TABLE query_logs_condensed AS
        SELECT
            date,
            ip,
            client,
            domain,
            query_type,
            client_protocol,
            upstream,
            is_filtered,
            filter_rule,
            SUM(count) as count
        FROM query_logs
        GROUP BY date, ip, client, domain, query_type, client_protocol, upstream, is_filtered, filter_rule
    """)

    # Replace original table
    conn.execute("DELETE FROM query_logs")
    conn.execute("""
        INSERT INTO query_logs
        SELECT * FROM query_logs_condensed
    """)
    conn.execute("DROP TABLE query_logs_condensed")

    # Get stats after
    rows_after = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()[0]
    total_count_after = conn.execute("SELECT SUM(count) FROM query_logs").fetchone()[0] or 0

    if should_close:
        conn.close()

    return {
        'rows_before': rows_before,
        'rows_after': rows_after,
        'total_count_before': total_count_before,
        'total_count_after': total_count_after,
        'count_match': total_count_before == total_count_after,
    }


def migrate_to_condensed_schema():
    """
    One-time migration from old schema (with timestamp, answer, etc.) to new condensed schema.
    """
    conn = get_connection()

    # Check if old schema exists (has 'timestamp' column)
    columns = conn.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'query_logs'
    """).fetchall()
    column_names = [c[0] for c in columns]

    if 'timestamp' not in column_names:
        print("Already using new schema, no migration needed.")
        conn.close()
        return

    print("Migrating to condensed schema...")

    # Get stats before
    rows_before = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()[0]
    print(f"Rows before migration: {rows_before:,}")

    # Create new condensed table from old data, joining with client_names
    conn.execute("""
        CREATE TABLE query_logs_new AS
        SELECT
            q.date,
            q.ip,
            COALESCE(c.hostname, '') as client,
            q.domain,
            q.query_type,
            q.client_protocol,
            q.upstream,
            q.is_filtered,
            COALESCE(q.filter_rule, '') as filter_rule,
            COUNT(*) as count
        FROM query_logs q
        LEFT JOIN client_names c ON q.ip = c.ip
        GROUP BY q.date, q.ip, c.hostname, q.domain, q.query_type, q.client_protocol,
                 q.upstream, q.is_filtered, q.filter_rule
    """)

    # Get stats for new table
    rows_after = conn.execute("SELECT COUNT(*) FROM query_logs_new").fetchone()[0]
    total_count = conn.execute("SELECT SUM(count) FROM query_logs_new").fetchone()[0]

    print(f"Rows after condensing: {rows_after:,}")
    print(f"Total count (should match rows_before): {total_count:,}")
    print(f"Compression ratio: {rows_before/rows_after:.1f}x")

    if total_count != rows_before:
        print("WARNING: Count mismatch! Aborting migration.")
        conn.execute("DROP TABLE query_logs_new")
        conn.close()
        return

    # Drop old table and rename new one
    conn.execute("DROP TABLE query_logs")
    conn.execute("ALTER TABLE query_logs_new RENAME TO query_logs")

    # Recreate indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_date ON query_logs(date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON query_logs(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON query_logs(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_is_filtered ON query_logs(is_filtered)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_query_type ON query_logs(query_type)")

    print("Migration complete!")
    conn.close()


def update_client_names(ip_to_hostname: dict[str, str]):
    """Update the client names table with IP to hostname mappings."""
    conn = get_connection()

    for ip, hostname in ip_to_hostname.items():
        conn.execute("""
            INSERT OR REPLACE INTO client_names (ip, hostname, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        """, [ip, hostname])

    conn.close()


def get_last_entry_date() -> Optional[str]:
    """Get the most recent date in the database."""
    conn = get_connection()
    result = conn.execute("""
        SELECT MAX(date) as max_date FROM query_logs
    """).fetchone()
    conn.close()

    if result and result[0]:
        return str(result[0])
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
    filter_rule: Optional[str] = None,
    count_gte: Optional[int] = None,
    count_lte: Optional[int] = None,
    sort_by: str = 'count',
    sort_asc: bool = False,
    page: int = 1,
    page_size: int = 500,
) -> dict:
    """
    Query client summary (aggregated by date/IP/client/domain/type/protocol/filtered/filter_rule).
    Uses the condensed query_logs table which already has counts.
    """
    conn = get_connection()

    # Build WHERE clause
    conditions = []
    params = []

    if date:
        conditions.append("date = ?")
        params.append(date)
    if date_from:
        conditions.append("date >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("date <= ?")
        params.append(date_to)
    if ip:
        conditions.append("LOWER(ip) = LOWER(?)")
        params.append(ip)
    if client:
        conditions.append("LOWER(client) LIKE LOWER(?)")
        params.append(f"%{client}%")
    if domain:
        conditions.append("LOWER(domain) LIKE LOWER(?)")
        params.append(f"%{domain}%")
    if query_type:
        conditions.append("LOWER(query_type) LIKE LOWER(?)")
        params.append(f"%{query_type}%")
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)
    if filter_rule:
        conditions.append("LOWER(filter_rule) LIKE LOWER(?)")
        params.append(f"%{filter_rule}%")

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # HAVING clause for count filters (applied after SUM)
    having_conditions = []
    having_params = []
    if count_gte is not None:
        having_conditions.append("SUM(count) >= ?")
        having_params.append(count_gte)
    if count_lte is not None:
        having_conditions.append("SUM(count) <= ?")
        having_params.append(count_lte)

    having_clause = " AND ".join(having_conditions) if having_conditions else "1=1"

    # Sort mapping
    sort_map = {
        'Date': 'date', 'IP': 'ip', 'client': 'client', 'QH': 'domain',
        'QT': 'query_type', 'CP': 'client_protocol', 'IsFiltered': 'is_filtered',
        'filterRule': 'filter_rule', 'count': 'total_count'
    }
    sort_col = sort_map.get(sort_by, 'total_count')
    sort_dir = 'ASC' if sort_asc else 'DESC'

    # Base query - aggregate by the display grouping
    # Group by date/ip/client/domain/type/protocol/filtered/filter_rule
    base_query = f"""
        SELECT
            date,
            ip,
            client,
            domain,
            query_type,
            client_protocol,
            is_filtered,
            filter_rule,
            SUM(count) as total_count
        FROM query_logs
        WHERE {where_clause}
        GROUP BY date, ip, client, domain, query_type, client_protocol, is_filtered, filter_rule
        HAVING {having_clause}
    """

    # Count total groups
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
            'Date': str(row[0]) if row[0] else '',
            'IP': row[1],
            'client': row[2],
            'QH': row[3],
            'QT': row[4],
            'CP': row[5],
            'IsFiltered': row[6],
            'filterRule': row[7] or '',
            'count': row[8],
        })

    return {
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': total_pages,
        'records': records,
    }


def query_domain_summary(
    date: Optional[str] = None,
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
    Query domain summary (aggregated by date/domain/type/protocol/filtered).
    Each row represents a unique combination of (Date, Domain, Type, Protocol, Filtered).
    Uses the condensed query_logs table which already has counts.
    """
    conn = get_connection()

    # Build WHERE clause
    conditions = []
    params = []

    if date:
        conditions.append("date = ?")
        params.append(date)
    if domain:
        conditions.append("LOWER(domain) LIKE LOWER(?)")
        params.append(f"%{domain}%")
    if query_type:
        conditions.append("LOWER(query_type) LIKE LOWER(?)")
        params.append(f"%{query_type}%")
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # HAVING clause for count filters (applied after SUM)
    having_conditions = []
    having_params = []
    if count_gte is not None:
        having_conditions.append("SUM(count) >= ?")
        having_params.append(count_gte)
    if count_lte is not None:
        having_conditions.append("SUM(count) <= ?")
        having_params.append(count_lte)

    having_clause = " AND ".join(having_conditions) if having_conditions else "1=1"

    # Sort mapping
    sort_map = {
        'Date': 'date', 'QH': 'domain', 'QT': 'query_type', 'CP': 'client_protocol',
        'IsFiltered': 'is_filtered', 'count': 'total_count'
    }
    sort_col = sort_map.get(sort_by, 'total_count')
    sort_dir = 'ASC' if sort_asc else 'DESC'

    # Query aggregated by date/domain/type/protocol/filtered
    base_query = f"""
        SELECT
            date,
            domain,
            query_type,
            client_protocol,
            is_filtered,
            SUM(count) as total_count
        FROM query_logs
        WHERE {where_clause}
        GROUP BY date, domain, query_type, client_protocol, is_filtered
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
            'Date': str(row[0]) if row[0] else '',
            'QH': row[1],
            'QT': row[2],
            'CP': row[3],
            'IsFiltered': row[4],
            'count': row[5],
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
    Uses the condensed query_logs table which already has counts.
    """
    conn = get_connection()

    # DuckDB doesn't have our extract_base_domain function, so we need to do this differently
    # Fetch domains and compute base domain in Python

    conditions = []
    params = []

    if query_type:
        conditions.append("LOWER(query_type) LIKE LOWER(?)")
        params.append(f"%{query_type}%")
    if client_protocol:
        conditions.append("LOWER(client_protocol) = LOWER(?)")
        params.append(client_protocol)
    if is_filtered is not None:
        conditions.append("is_filtered = ?")
        params.append(is_filtered)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # Get daily counts per domain (using SUM since data is already condensed)
    results = conn.execute(f"""
        SELECT
            domain,
            query_type,
            client_protocol,
            is_filtered,
            date,
            SUM(count) as daily_count
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

    # Total queries (sum of counts from condensed table)
    result = conn.execute("SELECT SUM(count) FROM query_logs").fetchone()
    stats['total_queries'] = result[0] or 0

    # Total rows (condensed)
    result = conn.execute("SELECT COUNT(*) FROM query_logs").fetchone()
    stats['total_rows'] = result[0]

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
