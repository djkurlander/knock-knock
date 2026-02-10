#!/bin/bash
# Fetches latest Cloudflare IP ranges and updates UFW rules for port 443.
# Intended to run daily via cron.

PORT=443
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

# Get current Cloudflare rules from UFW (extract CIDR ranges)
CURRENT=$(ufw status | grep "# $COMMENT" | awk '{print $3}')

# Remove rules that are no longer in Cloudflare's list
for cidr in $CURRENT; do
    if ! grep -q "^${cidr}$" "$TMPFILE"; then
        echo "y" | ufw delete allow from "$cidr" to any port $PORT proto tcp 2>/dev/null && echo "Removed: $cidr" || true
    fi
done

# Add any new ranges not already in UFW
for cidr in $(cat "$TMPFILE"); do
    if ! echo "$CURRENT" | grep -q "^${cidr}$"; then
        ufw allow from "$cidr" to any port $PORT proto tcp comment "$COMMENT" && echo "Added: $cidr"
    fi
done

echo "Cloudflare UFW rules updated at $(date)"
