FROM python:3.12-slim

LABEL org.opencontainers.image.title="zoraxy-guard"
LABEL org.opencontainers.image.description="Zoraxy log monitor with threat list alerts"
LABEL org.opencontainers.image.source="https://github.com/PaulG67/zoraxy-guard"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ZORAXY_GUARD_CONFIG=/config/config.yaml

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY config.example.yaml /config.example.yaml

RUN mkdir -p /data/lists /data/feed-cache /config /logs

VOLUME ["/config", "/data", "/logs"]

CMD ["python", "-m", "app.main"]
