#!/bin/bash
# stop.sh - Stop the AdGuard Home Log Summary web service

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="AdGuardHomeLogs"
PID_FILE="$SCRIPT_DIR/.web_service.pid"
PORT_FILE="$SCRIPT_DIR/.web_service.port"

if [[ ! -f "$PID_FILE" ]]; then
    echo "✓ $APP_NAME is not running (no PID file)"
    exit 0
fi

pid=$(cat "$PID_FILE")
port=$(cat "$PORT_FILE" 2>/dev/null || echo "unknown")

# Check if process is actually running
if ! ps -p "$pid" > /dev/null 2>&1; then
    echo "✓ $APP_NAME is not running (stale PID file)"
    rm -f "$PID_FILE" "$PORT_FILE"
    exit 0
fi

# Kill the process
echo "Stopping $APP_NAME (PID: $pid, Port: $port)..."
kill "$pid" 2>/dev/null

# Wait briefly for graceful shutdown
sleep 1

# Check if it stopped
if ps -p "$pid" > /dev/null 2>&1; then
    echo "⚠ Process still running, sending SIGKILL..."
    kill -9 "$pid" 2>/dev/null
    sleep 1
fi

# Final check and cleanup
if ps -p "$pid" > /dev/null 2>&1; then
    echo "✗ Failed to stop $APP_NAME"
    exit 1
else
    echo "✓ $APP_NAME stopped successfully"
    rm -f "$PID_FILE" "$PORT_FILE"
    exit 0
fi
