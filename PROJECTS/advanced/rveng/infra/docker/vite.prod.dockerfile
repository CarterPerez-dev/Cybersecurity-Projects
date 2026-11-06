# ©AngelaMos | 2026
# vite.prod.dockerfile

FROM node:25-slim AS build

RUN corepack enable && corepack prepare pnpm@10.29.1 --activate

WORKDIR /app

COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY frontend/ ./
RUN pnpm build

FROM nginx:1.29-alpine

COPY infra/nginx/prod.nginx /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
