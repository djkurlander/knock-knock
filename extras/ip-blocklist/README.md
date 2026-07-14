# IP Blocklist Generator + Consumer Guide

Generates plain-text IP blocklist files from honeypot data for public download, and shows how to
plug them into common firewalls. Web version of the consumer guide: <https://knock-knock.net/blocklist>.

## Output

- `static/ip-blocklist-year.txt` — attacker IPs seen in the last **365 days** (100k+; **recommended**)
- `static/ip-blocklist-month.txt` — attacker IPs seen in the last **30 days** (~tens of thousands; conservative —
  for public, user-facing services)

**Format:** one IPv4 address per line, no comments/headers, sorted most-recently-seen first. Served via
the `/static` mount (`main.py`). Downloads are logged to `visitors.db` (page `/static/ip-blocklist-*.txt`)
and broken out under "BLOCKLIST FEED CONSUMERS" in the visitor report.

## Generate

```bash
python extras/ip-blocklist/generate.py
```

## Cron (rebuild hourly)

```
0 * * * * /root/knock-knock/.venv/bin/python /root/knock-knock/extras/ip-blocklist/generate.py
```

## Public URLs

```
https://knock-knock.net/static/ip-blocklist-year.txt    # 365-day, recommended for most
https://knock-knock.net/static/ip-blocklist-month.txt   # 30-day, conservative
```

---

## Consumers — plug the feed into your firewall

Rebuilt **hourly**; fetch up to hourly. The **365-day** list is the default; use the 30-day for public,
user-facing services, always with a finite ban time. CSF and pfSense self-refresh once configured — only the
CrowdSec / ipset / nftables snippets run from cron (or a systemd timer). Examples use the 365-day list (swap `-year` → `-month`).

### CSF (ConfigServer Security & Firewall)
Add one line to `/etc/csf/csf.blocklists` — format `NAME|refresh_secs|max_ips(0=all)|URL` — then reload.
Set `LF_IPSET = "1"` in `csf.conf` so a large list lands in ipset, not raw iptables.

```
# /etc/csf/csf.blocklists
KNOCKKNOCK|3600|0|https://knock-knock.net/static/ip-blocklist-year.txt
```
```bash
csf -ra
```

### CrowdSec
Import as decisions from cron; match the duration to your fetch interval so entries expire.

```bash
curl -sf https://knock-knock.net/static/ip-blocklist-year.txt \
  | cscli decisions import -i - --format values --duration 25h --reason "knock-knock-honeypot"
```

### ipset + iptables (works anywhere)
Universal recipe with an atomic swap (no gap). Safe to run whole from cron — the set refreshes each time and
the DROP rule is added only if missing.

```bash
URL=https://knock-knock.net/static/ip-blocklist-year.txt
ipset create knockknock hash:ip -exist
ipset create knockknock_tmp hash:ip -exist; ipset flush knockknock_tmp
curl -sf "$URL" | sed 's/^/add knockknock_tmp /' | ipset restore -exist
ipset swap knockknock_tmp knockknock
ipset destroy knockknock_tmp

# add the DROP rule only if it's not already present (so re-running is harmless):
iptables -C INPUT -m set --match-set knockknock src -j DROP 2>/dev/null \
  || iptables -I INPUT -m set --match-set knockknock src -j DROP
```

### nftables
Create the table/set/rule once (or keep them in `nftables.conf`); only the refresh block at the bottom runs from cron.

```bash
nft add table inet filter
nft add set inet filter knockknock '{ type ipv4_addr; flags interval; }'
nft add rule inet filter input ip saddr @knockknock drop

# refresh (hourly):
IPS=$(curl -sf https://knock-knock.net/static/ip-blocklist-year.txt | paste -sd,)
nft flush set inet filter knockknock
nft add element inet filter knockknock "{ $IPS }"
```

### pfSense / OPNsense
No shell needed: **Firewall → Aliases → add a "URL Table (IPs)" alias** pointing at the list URL with a
1-day refresh, then add a WAN/floating rule that blocks the alias.

### Why not fail2ban?
fail2ban parses *your* logs for bad behaviour — it isn't built to import a static IP list. Use the **ipset**
recipe above (fail2ban sits on iptables/nftables anyway).

## Use responsibly
Observed attackers, not a verdict. Use a finite ban time and keep an allowlist for anything user-facing.
