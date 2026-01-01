# ©AngelaMos | 2025
# Development FastAPI Dockerfile
# Hot reload with uvicorn, volume mounts for code

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl && \
    rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml ./
RUN uv pip install --system -e .[dev]

COPY backend/ .

EXPOSE 8000

CMD ["uvicorn", "app.factory:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--reload"]
