FROM python:3.12-slim

RUN pip install --no-cache-dir \
    paramiko \
    impacket \
    geoip2 \
    redis \
    fastapi \
    "uvicorn[standard]" \
    phonenumbers

WORKDIR /app
COPY monitor.py main.py constants.py index.html ./
COPY honeypots/ honeypots/
COPY static/ static/
