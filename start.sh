#!/bin/bash
# start.sh - Start the AdGuard Home Log Summary web service
# Handles port conflicts by finding the next available port

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="AdGuardHomeLogs"
PID_FILE="$SCRIPT_DIR/.web_service.pid"
PORT_FILE="$SCRIPT_DIR/.web_service.port"
DEFAULT_PORT=8080
MAX_PORT=8099  # Will try ports 8080-8099

# Check if our specific service is already running
is_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if ps -p "$pid" > /dev/null 2>&1; then
            # Verify it's actually our uvicorn process
            if ps -p "$pid" -o command= | grep -q "web_service"; then
                return 0  # Running
            fi
        fi
        # Stale PID file, remove it
        rm -f "$PID_FILE" "$PORT_FILE"
    fi
    return 1  # Not running
}

# Check if a port is in use
port_in_use() {
    local port=$1
    lsof -i :"$port" > /dev/null 2>&1
}

# Find an available port starting from default
find_available_port() {
    local port=$DEFAULT_PORT
    while [[ $port -le $MAX_PORT ]]; do
        if ! port_in_use "$port"; then
            echo "$port"
            return 0
        fi
        ((port++))
    done
    return 1  # No available port found
}

# Main logic
cd "$SCRIPT_DIR"

# Check if already running
if is_running; then
    pid=$(cat "$PID_FILE")
    port=$(cat "$PORT_FILE" 2>/dev/null || echo "$DEFAULT_PORT")
    echo "✓ $APP_NAME is already running (PID: $pid, Port: $port)"
    open "http://localhost:$port"
    exit 0
fi

# Find available port
PORT=$(find_available_port)
if [[ -z "$PORT" ]]; then
    echo "✗ No available port found in range $DEFAULT_PORT-$MAX_PORT"
    exit 1
fi

if [[ "$PORT" -ne "$DEFAULT_PORT" ]]; then
    echo "⚠ Default port $DEFAULT_PORT in use, using port $PORT"
fi

# Start the service
echo "Starting $APP_NAME on port $PORT..."
python3 -c "
import uvicorn
from web_service import app
uvicorn.run(app, host='0.0.0.0', port=$PORT)
" &

# Save PID and port
echo $! > "$PID_FILE"
echo "$PORT" > "$PORT_FILE"
sleep 1

# Verify it started
if is_running; then
    echo "✓ $APP_NAME started successfully"
    echo "  URL: http://localhost:$PORT"
    echo "  PID: $(cat "$PID_FILE")"

    # Open in default browser
    open "http://localhost:$PORT"
else
    echo "✗ Failed to start $APP_NAME"
    rm -f "$PID_FILE" "$PORT_FILE"
    exit 1
fi
