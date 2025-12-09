#!/usr/bin/env python3
"""
AdGuard Home Log Fetcher

Retrieves DNS query logs from AdGuard Home running on a remote router.
Supports incremental fetching to avoid duplicate entries.
Stores logs in DuckDB database for efficient querying.
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

# Import database module
from database import (
    init_database, insert_log_entries, get_last_entry_timestamp,
    update_client_names, set_metadata, get_metadata
)

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

# Fetch settings
# Default 5MB chunk size for reading remote files
FETCH_CHUNK_SIZE = int(ENV.get("FETCH_CHUNK_SIZE", "5242880"))


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
    if returncode == 0 and stdout.strip():
        return stdout
    return None


def check_remote_file_exists(remote_path: str) -> bool:
    """Check if a remote file exists via SSH."""
    returncode, _, _ = ssh_command(f"test -f '{remote_path}'")
    return returncode == 0


def get_remote_file_size(remote_path: str) -> Optional[int]:
    """Get the size of a remote file in bytes via SSH."""
    returncode, stdout, _ = ssh_command(f"wc -c < '{remote_path}' 2>/dev/null")
    if returncode == 0 and stdout.strip():
        try:
            return int(stdout.strip())
        except ValueError:
            pass
    return None


def get_remote_first_line(remote_path: str) -> Optional[str]:
    """Get the first line of a remote file via SSH."""
    returncode, stdout, _ = ssh_command(f"head -1 '{remote_path}' 2>/dev/null")
    if returncode == 0 and stdout.strip():
        return stdout.strip()
    return None


def get_first_timestamp(line: str, timestamp_field: str) -> Optional[str]:
    """Extract timestamp from a JSON line."""
    try:
        entry = json.loads(line)
        return entry.get(timestamp_field)
    except json.JSONDecodeError:
        return None


def fetch_remote_file_from_offset(remote_path: str, offset: int) -> Optional[str]:
    """Fetch contents of a remote file starting from a byte offset via SSH."""
    returncode, stdout, _ = ssh_command(f"tail -c +{offset + 1} '{remote_path}' 2>/dev/null")
    if returncode == 0 and stdout:
        return stdout
    return None


def fetch_remote_chunk(remote_path: str, offset: int, size: int) -> Optional[str]:
    """
    Fetch a chunk of a remote file via SSH.

    Args:
        remote_path: Path to the remote file
        offset: Byte offset to start reading from
        size: Number of bytes to read

    Returns:
        The chunk content as a string, or None if read failed
    """
    # tail -c +N gives bytes from position N to end
    # head -c M limits output to M bytes
    cmd = f"tail -c +{offset + 1} '{remote_path}' 2>/dev/null | head -c {size}"
    returncode, stdout, _ = ssh_command(cmd)
    if returncode == 0 and stdout:
        return stdout
    return None


def fetch_file_in_chunks(
    remote_path: str,
    offset: int,
    file_size: int,
    timestamp_field: str,
    after_timestamp: Optional[str],
    chunk_size: int = FETCH_CHUNK_SIZE
) -> tuple[list[dict], int]:
    """
    Fetch a remote file in chunks, handling partial lines at boundaries.

    Args:
        remote_path: Path to the remote file
        offset: Byte offset to start reading from
        file_size: Total size of the remote file
        timestamp_field: JSON field containing the timestamp
        after_timestamp: Only include entries after this timestamp
        chunk_size: Maximum bytes to read per chunk

    Returns:
        Tuple of (list of parsed entries, total bytes consumed)
    """
    all_entries = []
    current_offset = offset
    total_bytes_consumed = 0
    partial_line = ""  # Carries incomplete line between chunks
    is_first_chunk = True
    bytes_to_read = file_size - offset

    chunk_num = 0
    total_chunks = (bytes_to_read + chunk_size - 1) // chunk_size  # Ceiling division

    while current_offset < file_size:
        chunk_num += 1
        read_size = min(chunk_size, file_size - current_offset)

        if total_chunks > 1:
            print(f"      Reading chunk {chunk_num}/{total_chunks} ({read_size:,} bytes)")

        chunk = fetch_remote_chunk(remote_path, current_offset, read_size)
        if chunk is None:
            print(f"      Error reading chunk at offset {current_offset}")
            break

        # Prepend any partial line from previous chunk
        content = partial_line + chunk
        partial_line = ""

        # Split into lines
        lines = content.split("\n")

        # If chunk doesn't end with newline, last element is partial
        # (unless we're at end of file)
        is_last_chunk = (current_offset + read_size >= file_size)
        if not is_last_chunk and lines:
            partial_line = lines[-1]
            lines = lines[:-1]

        # Parse lines
        for i, line in enumerate(lines):
            if not line.strip():
                continue

            try:
                entry = json.loads(line)
                entry_ts = entry.get(timestamp_field, "")

                # Filter by timestamp
                if after_timestamp and entry_ts <= after_timestamp:
                    continue

                all_entries.append(entry)
            except json.JSONDecodeError:
                # First line of first chunk may be partial (resumed mid-line)
                if is_first_chunk and i == 0:
                    print(f"      Discarded partial first record (resumed mid-line)")
                # Last line of last chunk may be partial (write in progress)
                elif is_last_chunk and i == len(lines) - 1:
                    print(f"      Discarded partial last record (truncated during read)")
                else:
                    print(f"      Warning: Skipped malformed entry in chunk {chunk_num}")
                continue

        # Update position
        chunk_bytes = len(chunk.encode('utf-8'))
        current_offset += chunk_bytes
        total_bytes_consumed += chunk_bytes - len(partial_line.encode('utf-8'))
        is_first_chunk = False

    # Sort by timestamp
    all_entries.sort(key=lambda x: x.get(timestamp_field, ""))

    return all_entries, total_bytes_consumed


def parse_ndjson_entries(
    content: str,
    timestamp_field: str,
    after_timestamp: Optional[str] = None,
    from_offset: bool = False
) -> tuple[list[dict], int]:
    """
    Parse NDJSON content and filter entries after a given timestamp.
    Safely discards partial first/last records that may result from reading
    during writes or resuming from a byte offset.

    Args:
        content: NDJSON string (one JSON object per line)
        timestamp_field: Field name containing the timestamp
        after_timestamp: Only include entries after this timestamp (ISO format)
        from_offset: If True, first line may be partial and should be discarded if malformed

    Returns:
        Tuple of (list of parsed JSON objects filtered and sorted by timestamp,
                  bytes consumed including all complete lines)
    """
    entries = []
    lines = content.split("\n")
    bytes_consumed = 0

    for i, line in enumerate(lines):
        line_bytes = len(line.encode('utf-8')) + 1  # +1 for newline

        if not line.strip():
            bytes_consumed += line_bytes
            continue

        try:
            entry = json.loads(line)
            entry_ts = entry.get(timestamp_field, "")

            # Filter by timestamp if specified
            if after_timestamp and entry_ts <= after_timestamp:
                bytes_consumed += line_bytes
                continue

            entries.append(entry)
            bytes_consumed += line_bytes
        except json.JSONDecodeError:
            # Handle malformed lines
            is_first = (i == 0)
            is_last = (i == len(lines) - 1)

            if is_first and from_offset:
                # Expected: partial first line when reading from offset
                print(f"      Discarded partial first record (resumed mid-line)")
                bytes_consumed += line_bytes
            elif is_last:
                # Expected: partial last line from reading during active write
                # Don't count these bytes - we'll re-read them next time
                print(f"      Discarded partial last record (truncated during read)")
            else:
                # Unexpected: malformed entry in the middle
                print(f"      Warning: Skipped malformed entry at line {i + 1}")
                bytes_consumed += line_bytes
            continue

    # Sort by timestamp
    entries.sort(key=lambda x: x.get(timestamp_field, ""))
    return entries, bytes_consumed


def fetch_log(log_name: str, log_config: dict, history: dict) -> tuple[int, Optional[str], dict]:
    """
    Fetch a specific log type from the router.

    Returns:
        Tuple of (new_entry_count, latest_timestamp, file_states)
        where file_states is a dict of {filename: {first_timestamp, byte_offset}}
    """
    print(f"\nFetching {log_config['description']}...")

    # Get last fetch timestamp
    last_fetch = history.get(log_name, {}).get("last_entry_timestamp")
    if last_fetch:
        print(f"  Last entry timestamp: {format_timestamp(last_fetch)}")
        print(f"  Fetching entries after this time...")
    else:
        print("  First fetch - retrieving all available entries...")

    # Get stored file states for offset optimization
    stored_file_states = history.get(log_name, {}).get("files", {})
    new_file_states = {}

    # Check which remote files exist
    primary_file = log_config["remote_files"][0]
    rotated_file = log_config["remote_files"][1] if len(log_config["remote_files"]) > 1 else None

    primary_exists = check_remote_file_exists(primary_file)
    rotated_exists = rotated_file and check_remote_file_exists(rotated_file)

    # Provide diagnostic info if primary file doesn't exist
    if not primary_exists:
        if rotated_exists:
            print(f"  Note: {primary_file} does not exist (only rotated file found)")
            print(f"        AdGuard Home may have recently restarted and is buffering")
            print(f"        new queries in memory (flushes after ~1000 queries).")
        else:
            print(f"  Warning: No querylog files found on router!")

    # Fetch all remote log files
    all_entries = []
    timestamp_field = log_config["timestamp_field"]

    for remote_file in log_config["remote_files"]:
        file_key = Path(remote_file).name
        print(f"  Reading {remote_file}...")

        # Check if file exists and get its size
        file_size = get_remote_file_size(remote_file)
        if file_size is None:
            print(f"    File not found or empty")
            continue

        # Get first line to detect rotation
        first_line = get_remote_first_line(remote_file)
        if not first_line:
            print(f"    File not found or empty")
            continue

        current_first_ts = get_first_timestamp(first_line, timestamp_field)

        # Check if we can use offset optimization
        stored_state = stored_file_states.get(file_key, {})
        stored_first_ts = stored_state.get("first_timestamp")
        stored_offset = stored_state.get("byte_offset", 0)

        use_offset = False
        offset = 0

        if stored_first_ts and current_first_ts == stored_first_ts and stored_offset > 0:
            # File hasn't rotated, we can resume from offset
            if stored_offset < file_size:
                use_offset = True
                offset = stored_offset
                bytes_to_read = file_size - offset
                print(f"    Resuming from byte {offset:,} (reading {bytes_to_read:,} of {file_size:,} bytes)")
            else:
                # No new data since last fetch
                print(f"    No new data (file size unchanged)")
                new_file_states[file_key] = {
                    "first_timestamp": current_first_ts,
                    "byte_offset": stored_offset
                }
                continue
        else:
            if stored_first_ts and current_first_ts != stored_first_ts:
                print(f"    File rotated, reading from beginning")
            print(f"    Reading full file ({file_size:,} bytes)")

        # Fetch the file content using chunked reading
        entries, bytes_consumed = fetch_file_in_chunks(
            remote_file,
            offset,
            file_size,
            timestamp_field,
            after_timestamp=last_fetch,
            chunk_size=FETCH_CHUNK_SIZE
        )

        if entries or bytes_consumed > 0:
            print(f"    Found {len(entries)} new entries")
            all_entries.extend(entries)

            # Update file state for next fetch
            new_offset = offset + bytes_consumed
            new_file_states[file_key] = {
                "first_timestamp": current_first_ts,
                "byte_offset": new_offset
            }
        else:
            print(f"    File not found or empty")

    if not all_entries:
        print("  No new entries found.")
        if not primary_exists and rotated_exists:
            print("  Tip: Wait for more DNS queries or restart AdGuard Home to flush buffer.")
        return 0, None, new_file_states

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

    # Insert into DuckDB
    if unique_entries:
        inserted = insert_log_entries(unique_entries)
        print(f"  Inserted {inserted} entries into database")

    # Get latest timestamp
    latest_ts = unique_entries[-1].get(log_config["timestamp_field"]) if unique_entries else None

    return len(unique_entries), latest_ts, new_file_states


def fetch_client_names_from_router() -> dict[str, str]:
    """
    Fetch client name mappings from router DHCP leases.
    Returns dict mapping IP addresses to hostnames.
    """
    ip_to_hostname = {}

    # Try to fetch DHCP leases
    returncode, stdout, _ = ssh_command("cat /var/lib/misc/dnsmasq.leases 2>/dev/null")
    if returncode == 0 and stdout.strip():
        for line in stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[2]
                hostname = parts[3]
                if hostname != "*":
                    ip_to_hostname[ip] = hostname

    # Also try nvram dhcp_staticlist for static assignments
    returncode, stdout, _ = ssh_command("nvram get dhcp_staticlist 2>/dev/null")
    if returncode == 0 and stdout.strip():
        entries = stdout.strip().split("<")
        for entry in entries:
            if ">" in entry:
                parts = entry.split(">")
                if len(parts) >= 3:
                    mac, ip, hostname = parts[0], parts[1], parts[2]
                    if hostname and ip:
                        ip_to_hostname[ip] = hostname

    return ip_to_hostname


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

    # Initialize database
    init_database()

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

    # Fetch client names from router and update database
    print("\nFetching client names from router...")
    client_names = fetch_client_names_from_router()
    if client_names:
        update_client_names(client_names)
        print(f"  Updated {len(client_names)} client name mappings")
    else:
        print("  No client names found")

    # Fetch each log type
    fetch_time = datetime.now().isoformat()
    total_new_entries = 0

    for log_name, log_config in ADGUARD_LOGS.items():
        new_count, latest_ts, file_states = fetch_log(log_name, log_config, history)
        total_new_entries += new_count

        # Update history (always update file states for offset tracking)
        if log_name not in history:
            history[log_name] = {"total_entries_fetched": 0}

        # Always update file states for offset optimization
        if file_states:
            history[log_name]["files"] = file_states

        if new_count > 0:
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
