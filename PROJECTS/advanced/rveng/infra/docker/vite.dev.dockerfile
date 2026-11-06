# ©AngelaMos | 2026
# vite.dev.dockerfile

FROM node:25-slim

RUN corepack enable && corepack prepare pnpm@10.29.1 --activate

WORKDIR /app

EXPOSE 5173

CMD ["sh", "-c", "pnpm install && exec pnpm dev --host 0.0.0.0"]
