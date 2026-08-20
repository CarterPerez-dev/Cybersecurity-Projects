# ©AngelaMos | 2026
# Dockerfile

FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

COPY src/ ./src/
RUN uv sync --frozen --no-dev

EXPOSE 8000

ENV PATH="/app/.venv/bin:${PATH}"

CMD ["uvicorn", \
     "not_sandboxed.arena.app:build_arena", \
     "--factory", "--host", "0.0.0.0", "--port", "8000"]
