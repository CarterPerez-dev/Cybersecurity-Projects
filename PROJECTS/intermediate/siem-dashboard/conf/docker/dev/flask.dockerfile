# ©AngelaMos | 2026
# flask.dockerfile

FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_SYSTEM_PYTHON=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install uv

COPY backend/pyproject.toml .

RUN uv pip install -e ".[dev]"

COPY backend/ .

EXPOSE 5000

CMD ["flask", "run", "--host", "0.0.0.0", "--port", "5000", "--reload"]
