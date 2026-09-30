FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir \
    flask>=3.0 \
    gunicorn>=21 \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin spotter

WORKDIR /app
COPY app.py .

# Same uid as the n8n task runner, so a staged file written here can be read
# and unlinked by WF06. The staging directory on the host must be writable by
# uid 1000 (bootstrap creates it).
USER 1000

EXPOSE 7053

# A slow 16 MB chunk over the managed tunnel can take longer than the default
# 30s worker timeout. State is on disk, so two workers do not split an upload.
CMD ["gunicorn", "--bind", "0.0.0.0:7053", "--workers", "2", "--timeout", "120", "app:app"]
