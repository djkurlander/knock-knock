#!/bin/bash

# --- Configuration ---
PROJECT_DIR="/root/knock-knock"
DB_PATH="$PROJECT_DIR/knock_knock.db"

# Check for reset flag
RESET=false
if [[ "$1" == "--reset-all" ]]; then
    RESET=true
fi

echo "🚀 Refreshing Knock-Knock Infrastructure..."

# 1. Stop services (using your actual service names)
echo "🛑 Stopping services..."
systemctl stop knock-honeypot knock-monitor knock-web

if [ "$RESET" = true ]; then
    echo "🧹 Performing Data Wipe..."
    # Delete SQLite DB
    if [ -f "$DB_PATH" ]; then
        rm "$DB_PATH"
        echo "   [+] Deleted $DB_PATH"
    fi
    # Clear Redis keys for the dashboard
    redis-cli del knock:total_global knock:wall_of_shame knock:ip_hits > /dev/null
    echo "   [+] Cleared Redis keys from memory"
fi

# 1b. Reload the service info just in case
systemctl daemon-reload

# 2. Restart in dependency order
echo "🟢 Re-engaging services..."

systemctl start knock-honeypot
echo "   [+] Honeypot online (Port 22)"
sleep 1 

systemctl start knock-monitor
echo "   [+] Monitor online (Log parsing active)"

systemctl start knock-web
echo "   [+] Web Server online (WebSockets active)"

echo "✅ System Restored."
