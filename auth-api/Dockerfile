FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir \
    flask>=3.0 \
    gunicorn>=21

WORKDIR /app
COPY spotter_auth_db.py .
COPY app.py .

EXPOSE 7052

# /auth/verify runs on every proxied request, so a couple of workers keeps the
# gate off the critical path. SQLite is opened in WAL mode (see
# spotter_auth_db.connect) which is safe across processes.
CMD ["gunicorn", "--bind", "0.0.0.0:7052", "--workers", "2", "--timeout", "30", "app:app"]
