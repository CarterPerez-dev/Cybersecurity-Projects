# ©AngelaMos | 2026
# Dockerfile
#
# Container image for the dev-log FastAPI target application
#
# Based on python:3.14-slim with uv copied from the official
# astral-sh image. Installs fastapi and uvicorn system-wide,
# copies app.py, and runs uvicorn on port 8000. Sits behind
# the nginx reverse proxy defined in compose.yml

FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/
RUN uv pip install --system fastapi uvicorn

WORKDIR /app
COPY app.py .

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
