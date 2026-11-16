FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng \
        tesseract-ocr-rus \
        tesseract-ocr-ukr \
        tesseract-ocr-ara \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        fastapi \
        uvicorn \
        python-multipart \
        pypdf \
        python-docx \
        requests

COPY main.py /app/main.py
WORKDIR /app
EXPOSE 8052
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8052"]
