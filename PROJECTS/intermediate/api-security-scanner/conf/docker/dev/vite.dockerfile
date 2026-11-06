# ©AngelaMos | 2026
# vite.dockerfile
# syntax=docker/dockerfile:1

FROM node:25-slim

RUN corepack enable && corepack prepare pnpm@10.29.1 --activate

WORKDIR /app

COPY frontend/package.json frontend/pnpm-lock.yaml ./

RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile

COPY frontend/ .

EXPOSE 5173

CMD ["pnpm", "dev", "--host", "0.0.0.0"]
