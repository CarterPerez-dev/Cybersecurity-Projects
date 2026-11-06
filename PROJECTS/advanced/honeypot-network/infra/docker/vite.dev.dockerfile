# ©AngelaMos | 2026
# vite.dev.dockerfile

FROM node:25-alpine

RUN corepack enable && corepack prepare pnpm@10.29.1 --activate

WORKDIR /app

COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY frontend/ .

EXPOSE 5173

CMD ["pnpm", "dev", "--host"]
