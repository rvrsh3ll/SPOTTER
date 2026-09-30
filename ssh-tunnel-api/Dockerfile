FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# tor ships the geoip/geoip6 tables the country selector reads; without them
# EntryNodes/ExitNodes {cc} expressions match nothing and circuits never build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    ca-certificates \
    tor \
    tor-geoipdb \
    && rm -rf /var/lib/apt/lists/*

# Nothing starts the packaged tor service in a container (no init), and every
# launch here passes an explicit `-f`, so /etc/tor/torrc is never consulted.

# requests[socks] pulls PySocks, which is what makes socks5h:// usable — the
# egress check has to traverse the same proxy the workflows will.
RUN pip install --no-cache-dir \
    flask>=3.0 \
    gunicorn>=21 \
    "requests[socks]>=2.31"

WORKDIR /app
COPY app.py .

# Written at Tor start-up; owned by the account tor drops to.
RUN mkdir -p /var/lib/spotter-tor \
    && chown -R debian-tor:debian-tor /var/lib/spotter-tor \
    && chmod 700 /var/lib/spotter-tor

EXPOSE 7060
# Tor SOCKS. Never published to the host — reachable only from the compose
# network, e.g. socks5h://ssh-tunnel-api:9050.
EXPOSE 9050

# Single worker keeps tunnel process state in one Python process.
CMD ["gunicorn", "--bind", "0.0.0.0:7060", "--workers", "1", "--timeout", "120", "app:app"]
