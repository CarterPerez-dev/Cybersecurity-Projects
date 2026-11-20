# ©AngelaMos | 2026
# api.dockerfile

FROM python:3.15-slim

COPY --from=ghcr.io/astral-sh/uv:0.10.2 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY src ./src
COPY challenges ./challenges
RUN uv sync --frozen --no-dev

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["uv", "run", "--no-sync", "python", "-c", \
        "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/challenges')"]

CMD ["uv", "run", "--no-sync", "uvicorn", "rveng.api.server:app", \
    "--host", "0.0.0.0", "--port", "8000"]
