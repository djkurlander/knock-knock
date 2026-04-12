#!/bin/bash
# Fetches latest Cloudflare IP ranges and updates UFW rules for ports 80 and 443.
# Intended to run daily via cron.

PORTS="80 8080"
COMMENT="Cloudflare"
TMPFILE=$(mktemp)
trap "rm -f $TMPFILE" EXIT

# Fetch current Cloudflare IP ranges (echo ensures newline between v4 and v6)
curl -sf https://www.cloudflare.com/ips-v4 > "$TMPFILE"
echo >> "$TMPFILE"
curl -sf https://www.cloudflare.com/ips-v6 >> "$TMPFILE"

# Strip carriage returns and blank lines
sed -i 's/\r//; /^$/d' "$TMPFILE"

if [ ! -s "$TMPFILE" ]; then
    echo "ERROR: Failed to fetch Cloudflare IPs. Leaving rules unchanged."
    exit 1
fi

for PORT in $PORTS; do
    echo "Syncing port $PORT..."

    # Get current Cloudflare rules from UFW for this port (extract CIDR ranges)
    CURRENT=$(ufw status | grep "$PORT/tcp.*# $COMMENT" | awk '{print $3}')

    # Remove rules that are no longer in Cloudflare's list
    for cidr in $CURRENT; do
        if ! grep -q "^${cidr}$" "$TMPFILE"; then
            echo "y" | ufw delete allow from "$cidr" to any port $PORT proto tcp 2>/dev/null && echo "Removed: $cidr (port $PORT)" || true
        fi
    done

    # Add any new ranges not already in UFW
    for cidr in $(cat "$TMPFILE"); do
        if ! echo "$CURRENT" | grep -q "^${cidr}$"; then
            ufw allow from "$cidr" to any port $PORT proto tcp comment "$COMMENT" && echo "Added: $cidr (port $PORT)"
        fi
    done
done

echo "Cloudflare UFW rules updated at $(date)"

# --- Optional: regenerate nginx Cloudflare allow list ---
# If NGINX_CONF is set to a file path, rewrite the allow/deny block in that file.
# Usage: NGINX_CONF=/etc/nginx/sites-enabled/knock-knock ./update-cloudflare-ufw.sh
if [ -n "$NGINX_CONF" ] && [ -f "$NGINX_CONF" ]; then
    echo "Updating nginx Cloudflare allow list in $NGINX_CONF..."
    ALLOW_BLOCK=$(while IFS= read -r cidr; do echo "    allow $cidr;"; done < "$TMPFILE"; echo "    deny all;")
    # Replace everything between '# Cloudflare IPs only' and 'deny all;' (inclusive)
    awk -v block="$ALLOW_BLOCK" '
        /# Cloudflare IPs only/ { print; print block; skip=1; next }
        skip && /deny all;/     { skip=0; next }
        skip                    { next }
        { print }
    ' "$NGINX_CONF" > "${NGINX_CONF}.tmp" && mv "${NGINX_CONF}.tmp" "$NGINX_CONF"
    nginx -t && systemctl reload nginx && echo "nginx reloaded."
fi
