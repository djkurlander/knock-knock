#!/bin/bash
# knock-watch.sh — lightweight health check for knock-knock servers
#
# Run via cron every 5 minutes:
#   */5 * * * * /root/knock-knock/knock-watch.sh
#   */5 * * * * /root/knock-knock/knock-watch.sh --central  # on one server only
#
# Usage:
#   ./knock-watch.sh              # local checks only
#   ./knock-watch.sh --central    # local checks + remote server checks
#
# Environment variables:
#   NTFY_TOPIC       push notification topic (required — change the default!)
#   THRESHOLD        seconds since last knock before alerting (default: 1200 = 20 min)
#   ALERT_COOLDOWN   seconds before re-alerting same issue (default: 1800 = 30 min)
#   CENTRAL_MODE     set to "true" instead of using --central flag
#   COMPOSE_PROJECT  Docker Compose project name (default: knock-knock)

NTFY_TOPIC="${NTFY_TOPIC:-your-private-topic-change-me}"
THRESHOLD="${THRESHOLD:-1200}"
ALERT_COOLDOWN="${ALERT_COOLDOWN:-1800}"
HOSTNAME=$(hostname)

CENTRAL_MODE="${CENTRAL_MODE:-false}"
[ "$1" = "--central" ] && CENTRAL_MODE="true"

# Remote servers to check in central mode (space-separated)
REMOTE_SERVERS="${REMOTE_SERVERS:-knock-knock.net}"

# === AUTO-DETECT DEPLOYMENT MODE ===

COMPOSE_PROJECT="${COMPOSE_PROJECT:-knock-knock}"

if systemctl list-unit-files knock-monitor.service &>/dev/null | grep -q knock-monitor; then
    MODE=systemd
elif docker compose ls 2>/dev/null | grep -q "$COMPOSE_PROJECT"; then
    MODE=docker
else
    MODE=unknown
fi

# === FUNCTIONS ===

redis_cmd() {
    if [ "$MODE" = "docker" ]; then
        docker exec "${COMPOSE_PROJECT}-redis-1" redis-cli "$@" 2>/dev/null
    else
        redis-cli "$@" 2>/dev/null
    fi
}

alert() {
    local tag="$1"
    local msg="$2"
    local tags="${3:-warning}"
    local cooldown_key="knock:alerted:${tag}"
    local alerted=$(redis_cmd GET "$cooldown_key")
    if [ -z "$alerted" ]; then
        curl -s -X POST "https://ntfy.sh/${NTFY_TOPIC}" \
            -H "Title: Knock-Knock Alert (${HOSTNAME})" \
            -H "Priority: urgent" \
            -H "Tags: ${tags}" \
            -d "$msg" > /dev/null 2>&1
        redis_cmd SET "$cooldown_key" 1 EX "$ALERT_COOLDOWN" > /dev/null 2>&1
    fi
}

clear_alert() {
    local tag="$1"
    local msg="$2"
    local cooldown_key="knock:alerted:${tag}"
    if [ -n "$(redis_cmd GET "$cooldown_key")" ]; then
        curl -s -X POST "https://ntfy.sh/${NTFY_TOPIC}" \
            -H "Title: Knock-Knock Recovered (${HOSTNAME})" \
            -H "Priority: default" \
            -H "Tags: white_check_mark" \
            -d "$msg" > /dev/null 2>&1
    fi
    redis_cmd DEL "$cooldown_key" > /dev/null 2>&1
}

# === LOCAL CHECKS ===

# Check Redis
if ! redis_cmd PING > /dev/null 2>&1; then
    curl -s -X POST "https://ntfy.sh/${NTFY_TOPIC}" \
        -H "Title: Knock-Knock Alert (${HOSTNAME})" \
        -H "Priority: urgent" \
        -H "Tags: rotating_light" \
        -d "Redis is down on ${HOSTNAME}" > /dev/null 2>&1
    exit 1
fi

# Check services
if [ "$MODE" = "systemd" ]; then
    for svc in knock-monitor knock-web; do
        if ! systemctl is-active --quiet "$svc"; then
            alert "$svc" "${svc} is not running on ${HOSTNAME}" "rotating_light"
        else
            clear_alert "$svc" "${svc} is back on ${HOSTNAME}"
        fi
    done
elif [ "$MODE" = "docker" ]; then
    for ctr in honeypot-monitor web; do
        full="${COMPOSE_PROJECT}-${ctr}-1"
        status=$(docker inspect --format='{{.State.Status}}' "$full" 2>/dev/null)
        if [ "$status" != "running" ]; then
            alert "$ctr" "${full} is not running on ${HOSTNAME} (status: ${status:-not found})" "rotating_light"
        else
            clear_alert "$ctr" "${full} is back on ${HOSTNAME}"
        fi
    done
else
    curl -s -X POST "https://ntfy.sh/${NTFY_TOPIC}" \
        -H "Title: Knock-Knock Alert (${HOSTNAME})" \
        -H "Priority: urgent" \
        -H "Tags: rotating_light" \
        -d "Could not detect deployment mode on ${HOSTNAME} (neither systemd nor Docker found)" > /dev/null 2>&1
    exit 1
fi

# Check knock flow
last=$(redis_cmd GET knock:last_time)
if [ -n "$last" ]; then
    now=$(date +%s)
    age=$(( now - last ))
    if [ "$age" -gt "$THRESHOLD" ]; then
        mins=$(( age / 60 ))
        alert "stale" "No knocks for ${mins} min on ${HOSTNAME} (monitor may be stuck)"
    else
        clear_alert "stale" "Knocks are flowing again on ${HOSTNAME}"
    fi
fi

# === CENTRAL MODE: CHECK REMOTE SERVERS ===

if [ "$CENTRAL_MODE" = "true" ]; then
    for server in $REMOTE_SERVERS; do
        if ! curl -sf --max-time 10 "https://${server}/" > /dev/null 2>&1; then
            alert "down:${server}" "${server} is not responding (checked by ${HOSTNAME})" "rotating_light"
        else
            clear_alert "down:${server}" "${server} is back online"
        fi
    done
fi
