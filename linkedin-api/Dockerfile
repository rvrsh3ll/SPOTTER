FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    flask==3.0.3 \
    gunicorn==22.0.0 \
    requests==2.32.3 \
    beautifulsoup4==4.12.3 \
    lxml==5.2.2

COPY app.py .

EXPOSE 7051

CMD ["gunicorn", "--bind", "0.0.0.0:7051", "--workers", "2", "--timeout", "60", "app:app"]
