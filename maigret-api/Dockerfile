FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# maigret + flask + gunicorn; pin maigret to avoid breaking API changes.
#
# socid-extractor is deliberately NOT listed: maigret depends on it (it drives
# maigret's own recursive extraction, the --no-extracting flag), so it arrives
# pinned to a version maigret is tested against. Naming it here would create a
# second constraint that can drift from maigret's and silently downgrade one of
# the two tools.
#
# requests[socks] IS named explicitly even though it currently arrives
# transitively: /extract sends socks5h:// proxy URLs, and without PySocks a
# proxied fetch raises inside our per-candidate try/except and reads as
# "profile had nothing to extract" rather than as a broken proxy.
RUN pip install --no-cache-dir \
        "maigret>=0.4.4" \
        "flask>=3.0" \
        "gunicorn>=21" \
        "requests[socks]>=2.31"

WORKDIR /app
COPY app.py .

EXPOSE 7050

# 5-min gunicorn timeout so long Maigret scans don't get cut off. 4 workers, not
# 2: /extract is called in batches of up to a dozen right after a /search, and on
# 2 workers those short calls would queue behind a 6-minute regional scan.
CMD ["gunicorn", "--bind", "0.0.0.0:7050", "--workers", "4", "--timeout", "360", "app:app"]
