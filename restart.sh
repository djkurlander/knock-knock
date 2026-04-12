#!/bin/bash

# --- Configuration ---
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_DIR="${DB_DIR:-$PROJECT_DIR/data}"
DC="docker compose --project-directory $PROJECT_DIR"

# --- Parse flags ---
RESET=false
MODE=""
for arg in "$@"; do
    case "$arg" in
        --reset-all) RESET=true ;;
        --build)     BUILD=true ;;
        --docker)    MODE="docker" ;;
        --systemd)   MODE="systemd" ;;
    esac
done

# --- Auto-detect mode if not specified ---
if [ -z "$MODE" ]; then
    if docker compose version &>/dev/null && [ -f "$PROJECT_DIR/docker-compose.yml" ]; then
        # Check if containers are running or if there are no systemd units installed
        if $DC ps --quiet 2>/dev/null | grep -q . \
           || ! systemctl list-unit-files knock-monitor.service &>/dev/null; then
            MODE="docker"
        else
            MODE="systemd"
        fi
    else
        MODE="systemd"
    fi
fi

echo "Refreshing Knock-Knock Infrastructure (mode: $MODE)..."

# --- Stop ---
echo "Stopping services..."
if [ "$MODE" = "docker" ]; then
    $DC down
else
    systemctl stop knock-monitor knock-web 2>/dev/null
fi

# --- Reset (optional) ---
if [ "$RESET" = true ]; then
    echo "Performing data wipe..."
    BLOCKLIST_FILE="$DB_DIR/blocklist.txt"

    # Delete SQLite databases
    for db in "$DB_DIR/knock_knock.db" "$DB_DIR/visitors.db"; do
        if [ -f "$db" ]; then
            rm "$db"
            echo "  [+] Deleted $db"
        fi
    done

    # Determine redis-cli command (host may differ per mode)
    if [ "$MODE" = "docker" ]; then
        REDIS_CMD="$DC run --rm redis redis-cli -h redis"
        # Need redis running to flush it
        $DC up -d redis
        sleep 1
    else
        REDIS_CMD="redis-cli"
    fi

    $REDIS_CMD keys 'knock:*' | grep -v '^knock:blocked$' | grep -v '^knock:alerted:' | xargs -r $REDIS_CMD del > /dev/null
    echo "  [+] Cleared Redis keys"

    # Clear persisted blocklist so monitor doesn't reload banned IPs on boot
    : > "$BLOCKLIST_FILE"
    echo "  [+] Cleared $BLOCKLIST_FILE"
fi

# --- Start ---
echo "Starting services..."
if [ "$MODE" = "docker" ]; then
    if [ "${BUILD:-false}" = true ]; then
        $DC up -d --build
        echo "  [+] Docker containers built and started"
    else
        $DC up -d
        echo "  [+] Docker containers started"
    fi
    $DC ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
else
    systemctl daemon-reload

    systemctl start knock-monitor
    echo "  [+] Honeypot + Monitor online (ports 21/FTP 22/SSH 23/Telnet 25/SMTP 587/SMTP 80/HTTP 443/HTTPS 445/SMB 3389/RDP 5060/SIP, log parsing active)"

    systemctl start knock-web
    echo "  [+] Web server online (WebSockets active)"
fi

echo "System restored."
