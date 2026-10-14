FROM golang:1.27-alpine AS builder
RUN apk add --no-cache git
# titus v1.2.9 declares go >= 1.27. golang:1.25-alpine sets GOTOOLCHAIN=local,
# so `go install @latest` fails instead of fetching a newer toolchain.
# CGO_ENABLED=0 avoids a Vectorscan/CGO build on Alpine.
ENV GOTOOLCHAIN=auto
RUN CGO_ENABLED=0 go install -trimpath github.com/praetorian-inc/titus/cmd/titus@v1.2.9

FROM python:3.12-slim
COPY --from=builder /go/bin/titus /usr/local/bin/titus
RUN pip install --no-cache-dir fastapi uvicorn python-multipart
COPY main.py /app/main.py
WORKDIR /app
EXPOSE 8051
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8051"]
