# IP Blocklist Generator

Generates plain-text IP blocklist files from honeypot data for public download.

## Output

- `static/ip-blocklist-month.txt` — IPs seen in the last 30 days
- `static/ip-blocklist-year.txt` — IPs seen in the last 365 days

One IP per line, sorted by hit count (most active first).

## Usage

```bash
python extras/ip-blocklist/generate.py
```

## Cron

```
0 4 * * * /root/knock-knock/.venv/bin/python /root/knock-knock/extras/ip-blocklist/generate.py
```

## Public URLs

```
https://knock-knock.net/static/ip-blocklist-month.txt
https://knock-knock.net/static/ip-blocklist-year.txt
```
