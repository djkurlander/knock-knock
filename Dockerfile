FROM python:3.14-slim

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app
# Root Python modules. self_redaction.py is a RUNTIME import of monitor.py — keep this list in
# sync when adding root modules. ip_ban/dbtool/stats are management CLIs (run via `docker compose
# exec`), not imported at runtime, but shipped for operational parity with systemd installs.
COPY monitor.py main.py constants.py protocol_api.py self_redaction.py ip_ban.py dbtool.py stats.py \
     index.html summary.html sitemap.xml robots.txt ./
COPY honeypots/ honeypots/
COPY protocols/ protocols/
COPY extras/ extras/
COPY static/ static/
