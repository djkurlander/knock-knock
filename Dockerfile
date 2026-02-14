FROM python:3.12-slim

RUN pip install --no-cache-dir \
    paramiko \
    geoip2 \
    redis \
    fastapi \
    "uvicorn[standard]"

WORKDIR /app
COPY honeypot.py monitor.py main.py index.html ./
COPY static/ static/
RUN python -c "import paramiko; paramiko.RSAKey.generate(2048).write_private_key_file('server.key')"
