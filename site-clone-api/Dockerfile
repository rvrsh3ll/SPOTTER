FROM debian:bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        httrack \
        proxychains4 \
        python3 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py /app/app.py

# scripts/ is bind-mounted at runtime to /data/scripts (same pattern as n8n).
ENV SPOTTER_SCRIPTS_DIR=/data/scripts \
    SITE_CLONE_DATA=/data/clones \
    SITE_CLONE_PORT=7052

EXPOSE 7052

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7052/health')"

CMD ["python3", "/app/app.py"]
