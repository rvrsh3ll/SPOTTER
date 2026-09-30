FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git
RUN go install github.com/praetorian-inc/titus/cmd/titus@latest

FROM python:3.12-slim
COPY --from=builder /go/bin/titus /usr/local/bin/titus
RUN pip install --no-cache-dir fastapi uvicorn python-multipart
COPY main.py /app/main.py
WORKDIR /app
EXPOSE 8051
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8051"]
