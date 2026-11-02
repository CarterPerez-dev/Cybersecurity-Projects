# ©AngelaMos | 2026
# vite.prod.dockerfile

FROM node:25-alpine AS builder

RUN corepack enable && corepack prepare pnpm@10.29.1 --activate

WORKDIR /build

COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY frontend/ .

RUN pnpm build

FROM nginx:1.29-alpine

COPY --from=builder /build/dist /usr/share/nginx/html
COPY infra/nginx/hive.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
