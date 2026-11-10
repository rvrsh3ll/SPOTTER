# Node 22 is required by webcrack's isolated-vm addon (odd Node releases break it).
# Compile tools live only in the builder; the final image keeps the runtime.
FROM node:22-bookworm-slim AS webcrack

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && npm install -g webcrack@2.16.0 \
 && npm cache clean --force \
 && rm -rf /var/lib/apt/lists/* /root/.npm /tmp/*

FROM debian:bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NODE_ENV=production

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        httrack \
        proxychains4 \
        python3 \
        ca-certificates \
        libstdc++6 \
        util-linux \
 && rm -rf /var/lib/apt/lists/*
# util-linux provides unshare (per-job resolv.conf via a user+mount namespace,
# and a network-less namespace for webcrack). DoH uses the in-tree Python stub
# (scripts/site_clone_dns_stub.py): Debian bookworm has no maintained
# lightweight DoH package (no cloudflared, no AdGuard dnsproxy, no doh-client).
# No SYS_ADMIN is required; see docker-compose.flowsint.yml for AppArmor.

COPY --from=webcrack /usr/local /usr/local

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
