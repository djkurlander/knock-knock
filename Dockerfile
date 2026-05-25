FROM python:3.14-slim

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app
COPY monitor.py main.py constants.py protocol_api.py index.html summary.html sitemap.xml robots.txt ./
COPY honeypots/ honeypots/
COPY protocols/ protocols/
COPY static/ static/
