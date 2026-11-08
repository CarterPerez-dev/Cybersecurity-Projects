# ©AngelaMos | 2026
# fastapi.dev.dockerfile
#
# Development Dockerfile for the FastAPI backend
#
# Based on python:3.14-slim with uv from the astral-sh
# image. Installs build-essential, libpq-dev, curl and git,
# then installs the project with dev and ml extras via uv
# pip install --system -e. Copies the backend source and
# entrypoint script, creates the model data directory, and
# runs uvicorn with --reload for live code changes.
# Connects to dev.compose.yml, entrypoint.sh

FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    git && \
    rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml ./
RUN uv pip install --system -e ".[dev,ml]"

COPY backend/ .
COPY infra/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && \
    mkdir -p /app/data/models

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app.factory:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--reload"]
