# Build context: Code/DevSecOps. Base ghim theo digest, cập nhật bằng digest thật.
FROM python:3.13.18-slim-trixie@sha256:76baad6037690d6e8c4397fbcaef17bca6f19eecef822b708fe8fa3417d30bb5 AS builder

WORKDIR /build
COPY src/requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade "pip==26.2.2" \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.13.18-slim-trixie@sha256:76baad6037690d6e8c4397fbcaef17bca6f19eecef822b708fe8fa3417d30bb5 AS runtime

# Pip thuộc base image nằm ngoài virtualenv; cập nhật vì ứng dụng không dùng bản pip cũ.
RUN python -m pip install --no-cache-dir --upgrade "pip==26.2.2" \
    && rm -rf /root/.cache/pip

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY src/app ./app

# Chạy bằng UID số, không phải root (N06: bind 0.0.0.0 bên trong container)
USER 10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
