FROM python:3.12-slim

RUN pip install --no-cache-dir \
    paramiko \
    geoip2 \
    redis \
    fastapi \
    "uvicorn[standard]"

WORKDIR /app
COPY honeypot.py monitor.py main.py index.html server.key ./
COPY static/ static/
