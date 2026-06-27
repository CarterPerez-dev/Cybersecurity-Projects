# Prompt Scan — Dockerfile
#
# ⚠️  WARNING: This container is intentionally insecure for security testing.
#     Do not expose beyond localhost.

FROM python:3.11-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy dependency manifest first for layer caching
COPY pyproject.toml .

# Install dependencies with uv
RUN uv sync --no-dev

# Copy application source
COPY . .

# Create data directory
RUN mkdir -p data/chat_history

EXPOSE 5000

ENV FLASK_APP=app/main.py
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

CMD ["uv", "run", "python", "app/main.py"]
