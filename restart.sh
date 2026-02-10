#!/bin/bash

# --- Configuration ---
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_DIR="${DB_DIR:-$PROJECT_DIR/data}"

# --- Parse flags ---
RESET=false
MODE=""
for arg in "$@"; do
    case "$arg" in
        --reset-all) RESET=true ;;
        --docker)    MODE="docker" ;;
        --systemd)   MODE="systemd" ;;
    esac
done

# --- Auto-detect mode if not specified ---
if [ -z "$MODE" ]; then
    if docker compose version &>/dev/null && [ -f "$PROJECT_DIR/docker-compose.yml" ]; then
        # Check if containers are running or if there are no systemd units installed
        if docker compose -f "$PROJECT_DIR/docker-compose.yml" ps --quiet 2>/dev/null | grep -q . \
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
    docker compose -f "$PROJECT_DIR/docker-compose.yml" down
else
    systemctl stop knock-monitor knock-web 2>/dev/null
fi

# --- Reset (optional) ---
if [ "$RESET" = true ]; then
    echo "Performing data wipe..."

    # Delete SQLite databases
    for db in "$DB_DIR/knock_knock.db" "$DB_DIR/visitors.db"; do
        if [ -f "$db" ]; then
            rm "$db"
            echo "  [+] Deleted $db"
        fi
    done

    # Determine redis-cli command (host may differ per mode)
    if [ "$MODE" = "docker" ]; then
        REDIS_CMD="docker compose -f $PROJECT_DIR/docker-compose.yml run --rm redis redis-cli -h redis"
        # Need redis running to flush it
        docker compose -f "$PROJECT_DIR/docker-compose.yml" up -d redis
        sleep 1
    else
        REDIS_CMD="redis-cli"
    fi

    $REDIS_CMD del knock:total_global knock:last_time knock:last_lat knock:last_lng knock:recent > /dev/null
    echo "  [+] Cleared Redis keys"
fi

# --- Start ---
echo "Starting services..."
if [ "$MODE" = "docker" ]; then
    docker compose -f "$PROJECT_DIR/docker-compose.yml" up -d --build
    echo "  [+] Docker containers built and started"
    docker compose -f "$PROJECT_DIR/docker-compose.yml" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
else
    systemctl daemon-reload

    systemctl start knock-monitor
    echo "  [+] Honeypot + Monitor online (port 22, log parsing active)"

    systemctl start knock-web
    echo "  [+] Web server online (WebSockets active)"
fi

echo "System restored."
