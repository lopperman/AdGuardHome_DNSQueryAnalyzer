#!/usr/bin/env python3
"""
AdGuard Home Log Summary Builder

Reads the local querylog.ndjson file and generates summary JSON files
with aggregated statistics by domain and by client+domain.
"""

import argparse
import json
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# Directories
SCRIPT_DIR = Path(__file__).parent
LOG_DATA_DIR = SCRIPT_DIR / "LogData"
APP_DATA_DIR = SCRIPT_DIR / "AppData"
CURRENT_DIR = APP_DATA_DIR / "Current"
ENV_FILE = SCRIPT_DIR / ".env"
QUERYLOG_FILE = LOG_DATA_DIR / "querylog.ndjson"


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


def prepare_current_directory():
    """
    Prepare the Current directory for fresh summary files.

    Creates the directory if it doesn't exist, and removes any existing .json files.
    """
    # Create directory if it doesn't exist
    CURRENT_DIR.mkdir(parents=True, exist_ok=True)

    # Delete any existing .json files
    deleted_count = 0
    for json_file in CURRENT_DIR.glob("*.json"):
        json_file.unlink()
        deleted_count += 1

    if deleted_count > 0:
        print(f"  Removed {deleted_count} existing JSON file(s) from {CURRENT_DIR}")


# Load configuration from .env
ENV = load_env()

# SSH configuration
SSH_HOST = ENV.get("ROUTER_SSH_HOST", "")
SSH_PORT = int(ENV.get("ROUTER_SSH_PORT", "22"))
SSH_USER = ENV.get("ROUTER_SSH_USER", "")
DHCP_LEASES_PATH = ENV.get("DHCP_LEASES_PATH", "/var/lib/misc/dnsmasq.leases")


def fetch_dhcp_leases() -> dict[str, str]:
    """
    Fetch DHCP leases from router and build IP-to-hostname mapping.

    Returns:
        Dictionary mapping IP addresses to hostnames
    """
    ip_to_hostname = {}

    if not SSH_HOST or not SSH_USER:
        print("Warning: SSH configuration missing, cannot fetch DHCP leases")
        return ip_to_hostname

    try:
        ssh_cmd = [
            "ssh", "-p", str(SSH_PORT),
            f"{SSH_USER}@{SSH_HOST}",
            f"cat {DHCP_LEASES_PATH}"
        ]
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    # Format: lease_time mac ip hostname [client_id]
                    ip = parts[2]
                    hostname = parts[3]
                    if hostname != "*":
                        ip_to_hostname[ip] = hostname
            print(f"  Loaded {len(ip_to_hostname)} IP-to-hostname mappings from DHCP leases")
        else:
            print(f"Warning: Failed to fetch DHCP leases: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("Warning: SSH command timed out")
    except Exception as e:
        print(f"Warning: Error fetching DHCP leases: {e}")

    return ip_to_hostname


def parse_date(timestamp: str) -> str:
    """Extract date (YYYY-MM-DD) from ISO timestamp."""
    try:
        # Handle timezone offset format like "2025-12-05T21:37:05.339028433-06:00"
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except (ValueError, AttributeError):
        return "unknown"


# Common multi-part TLDs that should be kept together
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "net.za",
    "com.br", "net.br", "org.br",
    "com.mx", "org.mx", "net.mx",
    "co.in", "net.in", "org.in",
    "com.cn", "net.cn", "org.cn",
    "co.kr", "or.kr", "ne.kr",
}


def extract_base_domain(domain: str) -> str:
    """
    Extract the base domain from a full domain name.

    Examples:
        r-0595b96f.kinesisvideo.us-west-2.amazonaws.com -> amazonaws.com
        www.google.com -> google.com
        api.example.co.uk -> example.co.uk
    """
    if not domain or domain == "unknown":
        return domain

    # Remove trailing dot if present
    domain = domain.rstrip(".")

    parts = domain.lower().split(".")

    if len(parts) <= 2:
        return domain.lower()

    # Check for multi-part TLDs
    if len(parts) >= 3:
        potential_tld = f"{parts[-2]}.{parts[-1]}"
        if potential_tld in MULTI_PART_TLDS:
            # Return domain + multi-part TLD (e.g., example.co.uk)
            return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"

    # Default: return last two parts
    return f"{parts[-2]}.{parts[-1]}"


def build_summaries(
    ip_to_hostname: dict[str, str],
    from_date: Optional[str] = None
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Build summary data from querylog.

    Args:
        ip_to_hostname: Dictionary mapping IP addresses to hostnames
        from_date: Optional date string (YYYY-MM-DD) to filter entries >= this date

    Returns:
        Tuple of (queryLogSummary records, queryLogDomainSummary records, queryLogBaseDomainSummary records)
    """
    if not QUERYLOG_FILE.exists():
        print(f"Error: Querylog file not found: {QUERYLOG_FILE}")
        return [], [], []

    # Aggregation dictionaries
    # Key: (IP, QH, QT, CP, IsFiltered) -> {count, daily_counts: {date: count}}
    client_summary = defaultdict(lambda: {"count": 0, "daily_counts": defaultdict(int)})
    # Key: (QH, QT, CP, IsFiltered) -> {count, daily_counts: {date: count}}
    domain_summary = defaultdict(lambda: {"count": 0, "daily_counts": defaultdict(int)})
    # Key: (base_domain, QT, CP, IsFiltered) -> {count, daily_counts: {date: count}}
    base_domain_summary = defaultdict(lambda: {"count": 0, "daily_counts": defaultdict(int)})

    if from_date:
        print(f"\n  Processing {QUERYLOG_FILE} (from {from_date})...")
    else:
        print(f"\n  Processing {QUERYLOG_FILE}...")
    entry_count = 0
    skipped_count = 0
    error_count = 0

    with open(QUERYLOG_FILE, "r") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)

                # Get timestamp and check from_date filter
                timestamp = entry.get("T", "")
                date = parse_date(timestamp)

                # Skip entries before from_date
                if from_date and date < from_date:
                    skipped_count += 1
                    continue

                # Extract fields
                ip = entry.get("IP", "unknown")
                qh = entry.get("QH", "unknown")  # Query Host (domain)
                qt = entry.get("QT", "unknown")  # Query Type
                cp = entry.get("CP", "unknown")  # Client Protocol

                # Get IsFiltered from Result
                result = entry.get("Result", {})
                is_filtered = result.get("IsFiltered", False)

                # Update client summary
                client_key = (ip, qh, qt, cp, is_filtered)
                client_summary[client_key]["count"] += 1
                client_summary[client_key]["daily_counts"][date] += 1

                # Update domain summary
                domain_key = (qh, qt, cp, is_filtered)
                domain_summary[domain_key]["count"] += 1
                domain_summary[domain_key]["daily_counts"][date] += 1

                # Update base domain summary
                base_domain = extract_base_domain(qh)
                base_domain_key = (base_domain, qt, cp, is_filtered)
                base_domain_summary[base_domain_key]["count"] += 1
                base_domain_summary[base_domain_key]["daily_counts"][date] += 1

                entry_count += 1

                if entry_count % 50000 == 0:
                    print(f"    Processed {entry_count:,} entries...")

            except json.JSONDecodeError:
                error_count += 1
                if error_count <= 5:
                    print(f"    Warning: Skipped malformed entry at line {line_num}")

    if skipped_count > 0:
        print(f"  Processed {entry_count:,} entries, skipped {skipped_count:,} (before from_date), {error_count} errors")
    else:
        print(f"  Processed {entry_count:,} entries ({error_count} errors)")

    # Convert to flat records
    client_records = []
    for (ip, qh, qt, cp, is_filtered), data in client_summary.items():
        max_count = max(data["daily_counts"].values()) if data["daily_counts"] else 0
        client_name = ip_to_hostname.get(ip, "")

        client_records.append({
            "IP": ip,
            "client": client_name,
            "QH": qh,
            "QT": qt,
            "CP": cp,
            "IsFiltered": is_filtered,
            "count": data["count"],
            "maxCount": max_count
        })

    domain_records = []
    for (qh, qt, cp, is_filtered), data in domain_summary.items():
        max_count = max(data["daily_counts"].values()) if data["daily_counts"] else 0

        domain_records.append({
            "QH": qh,
            "QT": qt,
            "CP": cp,
            "IsFiltered": is_filtered,
            "count": data["count"],
            "maxCount": max_count
        })

    base_domain_records = []
    for (base_domain, qt, cp, is_filtered), data in base_domain_summary.items():
        max_count = max(data["daily_counts"].values()) if data["daily_counts"] else 0

        base_domain_records.append({
            "QH": base_domain,
            "QT": qt,
            "CP": cp,
            "IsFiltered": is_filtered,
            "count": data["count"],
            "maxCount": max_count
        })

    # Sort by count descending
    client_records.sort(key=lambda x: x["count"], reverse=True)
    domain_records.sort(key=lambda x: x["count"], reverse=True)
    base_domain_records.sort(key=lambda x: x["count"], reverse=True)

    return client_records, domain_records, base_domain_records


def run_build_summary(from_date: Optional[str] = None) -> dict:
    """
    Run the summary build operation.

    Args:
        from_date: Optional date string (YYYY-MM-DD) to filter entries >= this date

    Returns:
        Dictionary with build results
    """
    result = {
        "success": False,
        "message": "",
        "client_records": 0,
        "domain_records": 0,
        "base_domain_records": 0
    }

    print("\n" + "=" * 60)
    print("AdGuard Home Log Summary Builder")
    print("=" * 60)

    # Ensure directories exist
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Prepare Current directory (create if needed, clear existing JSON files)
    print("\nPreparing Current directory...")
    prepare_current_directory()

    # Fetch IP-to-hostname mapping
    print("\nFetching client names from router...")
    ip_to_hostname = fetch_dhcp_leases()

    # Build summaries
    print("\nBuilding summaries...")
    client_records, domain_records, base_domain_records = build_summaries(ip_to_hostname, from_date)

    if not client_records and not domain_records:
        print("\nNo data to summarize.")
        result["message"] = "No data to summarize"
        return result

    # Generate timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Write client summary
    client_file = APP_DATA_DIR / f"queryLogSummary_{timestamp}.json"
    client_file_current = CURRENT_DIR / "queryLogSummary.json"
    with open(client_file, "w") as f:
        json.dump(client_records, f, indent=2)
    with open(client_file_current, "w") as f:
        json.dump(client_records, f, indent=2)
    print(f"\n  Created: {client_file}")
    print(f"  Created: {client_file_current}")
    print(f"    {len(client_records):,} unique IP/domain combinations")

    # Write domain summary
    domain_file = APP_DATA_DIR / f"queryLogDomainSummary_{timestamp}.json"
    domain_file_current = CURRENT_DIR / "queryLogDomainSummary.json"
    with open(domain_file, "w") as f:
        json.dump(domain_records, f, indent=2)
    with open(domain_file_current, "w") as f:
        json.dump(domain_records, f, indent=2)
    print(f"\n  Created: {domain_file}")
    print(f"  Created: {domain_file_current}")
    print(f"    {len(domain_records):,} unique domain combinations")

    # Write base domain summary
    base_domain_file = APP_DATA_DIR / f"queryLogBaseDomainSummary_{timestamp}.json"
    base_domain_file_current = CURRENT_DIR / "queryLogBaseDomainSummary.json"
    with open(base_domain_file, "w") as f:
        json.dump(base_domain_records, f, indent=2)
    with open(base_domain_file_current, "w") as f:
        json.dump(base_domain_records, f, indent=2)
    print(f"\n  Created: {base_domain_file}")
    print(f"  Created: {base_domain_file_current}")
    print(f"    {len(base_domain_records):,} unique base domains")

    # Show top entries
    print("\n" + "-" * 60)
    print("Top 10 domains by query count:")
    print("-" * 60)
    for i, record in enumerate(domain_records[:10], 1):
        filtered_str = " [BLOCKED]" if record["IsFiltered"] else ""
        print(f"  {i:2}. {record['QH'][:50]:<50} {record['count']:>8,}{filtered_str}")

    print("\n" + "=" * 60)
    print("Summary complete!")
    print("=" * 60)

    result["success"] = True
    result["message"] = "Summary built successfully"
    result["client_records"] = len(client_records)
    result["domain_records"] = len(domain_records)
    result["base_domain_records"] = len(base_domain_records)
    return result


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Build AdGuard Home log summaries")
    parser.add_argument(
        "--from-date",
        type=str,
        help="Only include entries from this date onwards (YYYY-MM-DD)"
    )
    args = parser.parse_args()

    run_build_summary(from_date=args.from_date)


if __name__ == "__main__":
    main()
