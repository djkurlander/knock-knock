FROM python:3.12-slim

RUN pip install --no-cache-dir \
    asyncssh==2.23.0 \
    impacket==0.13.1 \
    geoip2==5.2.0 \
    redis==7.4.0 \
    fastapi==0.136.1 \
    "uvicorn[standard]==0.47.0" \
    phonenumbers==9.0.30

WORKDIR /app
COPY monitor.py main.py constants.py protocol_api.py index.html summary.html sitemap.xml robots.txt ./
COPY honeypots/ honeypots/
COPY protocols/ protocols/
COPY static/ static/
