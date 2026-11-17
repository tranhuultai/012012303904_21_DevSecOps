# Build context: Code/DevSecOps. Base ghim theo digest, cập nhật bằng digest thật.
FROM python:3.13.18-slim-trixie@sha256:76baad6037690d6e8c4397fbcaef17bca6f19eecef822b708fe8fa3417d30bb5 AS builder

WORKDIR /build
COPY src/requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade "pip==26.3" \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.13.18-slim-trixie@sha256:76baad6037690d6e8c4397fbcaef17bca6f19eecef822b708fe8fa3417d30bb5 AS runtime

# Patch CVE-2026-109518 (APT) and CVE-2026-76844/CVE-2026-85091 (zlib)
# in the pinned Debian base. Use HTTPS and disable retries while bootstrapping
# the fixed APT version; fail the build until the security floor is available.
RUN set -eux; \
    sed -i 's#http://deb.debian.org/#https://deb.debian.org/#g' /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::Retries=0 update; \
    apt-get -o Acquire::Retries=0 install -y --no-install-recommends --only-upgrade apt zlib1g; \
    apt_version="$(dpkg-query -W -f='${Version}' apt)"; \
    zlib_version="$(dpkg-query -W -f='${Version}' zlib1g)"; \
    dpkg --compare-versions "$apt_version" ge "3.0.4"; \
    dpkg --compare-versions "$zlib_version" ge "1:1.3.dfsg+really1.3.1-1+deb13u1"; \
    echo "Security package versions: apt=$apt_version zlib1g=$zlib_version"; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
# pip chỉ cần lúc build. Bỏ package manager khỏi runtime để loại các bản vendored
# msgpack/urllib3/setuptools đi kèm và giảm bề mặt tấn công của image phát hành.
RUN set -eux; \
    rm -rf \
      /usr/local/lib/python3.13/site-packages/pip \
      /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
      /opt/venv/lib/python3.13/site-packages/pip \
      /opt/venv/lib/python3.13/site-packages/pip-*.dist-info; \
    rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 \
      /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.13
COPY src/app ./app

# Chạy bằng UID số, không phải root (N06: bind 0.0.0.0 bên trong container)
USER 10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status == 200 else 1)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
