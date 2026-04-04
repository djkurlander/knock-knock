FROM python:3.12-slim

RUN pip install --no-cache-dir \
    paramiko \
    asyncssh==2.22.0 \
    impacket \
    geoip2 \
    redis \
    fastapi \
    "uvicorn[standard]" \
    phonenumbers

WORKDIR /app
COPY monitor.py main.py constants.py index.html summary.html sitemap.xml robots.txt ./
COPY honeypots/ honeypots/
COPY static/ static/
