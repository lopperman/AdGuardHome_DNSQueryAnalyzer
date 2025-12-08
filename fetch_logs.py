#!/usr/bin/env python3
"""
AdGuard Home Log Fetcher

Retrieves DNS query logs from AdGuard Home running on a remote router.
Supports incremental fetching to avoid duplicate entries.
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

# Directories
SCRIPT_DIR = Path(__file__).parent
LOG_DATA_DIR = SCRIPT_DIR / "LogData"
APP_DATA_DIR = SCRIPT_DIR / "AppData"
FETCH_HISTORY_FILE = APP_DATA_DIR / "logFetchHistory.json"
ENV_FILE = SCRIPT_DIR / ".env"


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


# Load configuration from .env
ENV = load_env()

# SSH configuration
SSH_HOST = ENV.get("ROUTER_SSH_HOST", "")
SSH_PORT = int(ENV.get("ROUTER_SSH_PORT", "22"))
SSH_USER = ENV.get("ROUTER_SSH_USER", "")

# AdGuard Home paths from .env
ADGUARD_QUERY_LOG = ENV.get("ADGUARD_QUERY_LOG", "")


def validate_config() -> bool:
    """Validate that required configuration is present."""
    missing = []
    if not SSH_HOST:
        missing.append("ROUTER_SSH_HOST")
    if not SSH_USER:
        missing.append("ROUTER_SSH_USER")
    if not ADGUARD_QUERY_LOG:
        missing.append("ADGUARD_QUERY_LOG")

    if missing:
        print("Error: Missing required configuration in .env file:")
        for var in missing:
            print(f"  - {var}")
        return False
    return True

# AdGuard Home log files on router
ADGUARD_LOGS = {
    "querylog": {
        "description": "DNS Query Log",
        "remote_files": [
            ADGUARD_QUERY_LOG,
            f"{ADGUARD_QUERY_LOG}.1"
        ],
        "timestamp_field": "T",
        "local_file": "querylog.ndjson"
    }
}


def load_fetch_history() -> dict:
    """Load the fetch history from JSON file."""
    if FETCH_HISTORY_FILE.exists():
        with open(FETCH_HISTORY_FILE, "r") as f:
            return json.load(f)
    return {}


def save_fetch_history(history: dict) -> None:
    """Save the fetch history to JSON file."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(FETCH_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def format_timestamp(ts: Optional[str]) -> str:
    """Format an ISO timestamp for display."""
    if not ts:
        return "Never"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    except (ValueError, AttributeError):
        return ts


def ssh_command(cmd: str) -> tuple[int, str, str]:
    """Execute a command on the remote router via SSH."""
    ssh_cmd = ["ssh", "-p", str(SSH_PORT), f"{SSH_USER}@{SSH_HOST}", cmd]
    result = subprocess.run(ssh_cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def fetch_remote_file(remote_path: str) -> Optional[str]:
    """Fetch contents of a remote file via SSH."""
    returncode, stdout, _ = ssh_command(f"cat '{remote_path}' 2>/dev/null")
    if returncode == 0:
        return stdout
    return None


def parse_ndjson_entries(
    content: str,
    timestamp_field: str,
    after_timestamp: Optional[str] = None
) -> list[dict]:
    """
    Parse NDJSON content and filter entries after a given timestamp.
    Safely discards partial last records that may result from reading during writes.

    Args:
        content: NDJSON string (one JSON object per line)
        timestamp_field: Field name containing the timestamp
        after_timestamp: Only include entries after this timestamp (ISO format)

    Returns:
        List of parsed JSON objects, filtered and sorted by timestamp
    """
    entries = []
    lines = content.strip().split("\n")

    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            entry_ts = entry.get(timestamp_field, "")

            # Filter by timestamp if specified
            if after_timestamp and entry_ts <= after_timestamp:
                continue

            entries.append(entry)
        except json.JSONDecodeError:
            # If the last line fails to parse, it's likely a partial record
            # from reading during an active write - discard it safely
            if i == len(lines) - 1:
                print(f"      Discarded partial last record (truncated during read)")
            else:
                print(f"      Warning: Skipped malformed entry at line {i + 1}")
            continue

    # Sort by timestamp
    entries.sort(key=lambda x: x.get(timestamp_field, ""))
    return entries


def fetch_log(log_name: str, log_config: dict, history: dict) -> tuple[int, Optional[str]]:
    """
    Fetch a specific log type from the router.

    Returns:
        Tuple of (new_entry_count, latest_timestamp)
    """
    print(f"\nFetching {log_config['description']}...")

    # Get last fetch timestamp
    last_fetch = history.get(log_name, {}).get("last_entry_timestamp")
    if last_fetch:
        print(f"  Last entry timestamp: {format_timestamp(last_fetch)}")
        print(f"  Fetching entries after this time...")
    else:
        print("  First fetch - retrieving all available entries...")

    # Fetch all remote log files
    all_entries = []
    for remote_file in log_config["remote_files"]:
        print(f"  Reading {remote_file}...")
        content = fetch_remote_file(remote_file)
        if content:
            entries = parse_ndjson_entries(
                content,
                log_config["timestamp_field"],
                after_timestamp=last_fetch
            )
            print(f"    Found {len(entries)} new entries")
            all_entries.extend(entries)
        else:
            print(f"    File not found or empty")

    if not all_entries:
        print("  No new entries found.")
        return 0, None

    # Sort all entries by timestamp
    all_entries.sort(key=lambda x: x.get(log_config["timestamp_field"], ""))

    # Remove duplicates (same timestamp)
    seen_timestamps = set()
    unique_entries = []
    for entry in all_entries:
        ts = entry.get(log_config["timestamp_field"], "")
        if ts not in seen_timestamps:
            seen_timestamps.add(ts)
            unique_entries.append(entry)

    print(f"  Total new unique entries: {len(unique_entries)}")

    # Append to local file
    LOG_DATA_DIR.mkdir(parents=True, exist_ok=True)
    local_file = LOG_DATA_DIR / log_config["local_file"]

    with open(local_file, "a") as f:
        for entry in unique_entries:
            f.write(json.dumps(entry) + "\n")

    print(f"  Appended to {local_file}")

    # Get latest timestamp
    latest_ts = unique_entries[-1].get(log_config["timestamp_field"]) if unique_entries else None

    return len(unique_entries), latest_ts


def display_status(history: dict) -> None:
    """Display the current status of all log types."""
    print("\n" + "=" * 60)
    print("AdGuard Home Log Fetcher")
    print("=" * 60)
    print("\nAvailable log types:\n")

    for log_name, log_config in ADGUARD_LOGS.items():
        log_history = history.get(log_name, {})
        last_fetch_time = log_history.get("last_fetch_time")
        last_entry_ts = log_history.get("last_entry_timestamp")
        total_entries = log_history.get("total_entries_fetched", 0)

        print(f"  [{log_name}] {log_config['description']}")
        print(f"      Last fetch:      {format_timestamp(last_fetch_time)}")
        print(f"      Last entry:      {format_timestamp(last_entry_ts)}")
        print(f"      Total fetched:   {total_entries:,} entries")
        print()


def run_fetch(skip_confirmation: bool = False) -> dict:
    """
    Run the log fetch operation.

    Args:
        skip_confirmation: If True, skip the user confirmation prompt

    Returns:
        Dictionary with fetch results
    """
    result = {"success": False, "message": "", "entries_fetched": 0}

    # Validate configuration
    if not validate_config():
        result["message"] = "Invalid configuration"
        return result

    # Ensure directories exist
    LOG_DATA_DIR.mkdir(parents=True, exist_ok=True)
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Load history
    history = load_fetch_history()

    # Display current status
    display_status(history)

    # Prompt user unless skipping confirmation
    if not skip_confirmation:
        print("-" * 60)
        response = input("Do you want to fetch logs now? [y/N]: ").strip().lower()

        if response not in ("y", "yes"):
            print("Cancelled.")
            result["message"] = "Cancelled by user"
            return result

    # Fetch each log type
    fetch_time = datetime.now().isoformat()
    total_new_entries = 0

    for log_name, log_config in ADGUARD_LOGS.items():
        new_count, latest_ts = fetch_log(log_name, log_config, history)
        total_new_entries += new_count

        if new_count > 0:
            # Update history
            if log_name not in history:
                history[log_name] = {"total_entries_fetched": 0}

            history[log_name]["last_fetch_time"] = fetch_time
            history[log_name]["last_entry_timestamp"] = latest_ts
            history[log_name]["total_entries_fetched"] = (
                history[log_name].get("total_entries_fetched", 0) + new_count
            )

    # Save history
    save_fetch_history(history)

    print("\n" + "=" * 60)
    print("Fetch complete!")
    print("=" * 60)

    # Show updated status
    display_status(history)

    result["success"] = True
    result["message"] = f"Fetched {total_new_entries} new entries"
    result["entries_fetched"] = total_new_entries
    return result


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Fetch AdGuard Home logs from router")
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompt and fetch immediately"
    )
    args = parser.parse_args()

    run_fetch(skip_confirmation=args.yes)


if __name__ == "__main__":
    main()
