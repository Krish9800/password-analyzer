# ==============================================================================
# Multi-Stage Hardened Dockerfile: Password Intelligence Analyzer
# Security Posture: Non-root execution (UID 10001), minimal dependencies, zero-cache
# ==============================================================================

# Stage 1: Build & Wheel Creation
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ src/
COPY data/ data/

RUN pip install --no-cache-dir --upgrade pip build \
 && python -m build --wheel

# Stage 2: Minimal Hardened Runtime
FROM python:3.12-slim AS runtime

LABEL maintainer="Cybersecurity Engineering Portfolio"
LABEL description="Defensive Password Intelligence Analyzer"

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

# Create dedicated unprivileged user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /usr/sbin/nologin -d /app appuser

WORKDIR /app

# Copy wheel from builder and install production dependencies only
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Copy wordlist data assets ensuring read-only permissions for non-root user
COPY data/ /app/data/
RUN chown -R appuser:appgroup /app && \
    chmod -R 555 /app

# Switch to unprivileged non-root user
USER 10001:10001

EXPOSE 8000

# Health check using standard Python urllib (no curl/wget attack surface)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/health")' || exit 1

ENTRYPOINT ["password-analyzer"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
