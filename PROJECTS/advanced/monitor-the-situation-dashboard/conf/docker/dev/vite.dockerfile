# ©AngelaMos | 2026
# vite.dockerfile

FROM node:24-alpine

RUN corepack enable && corepack prepare pnpm@10.29.1 --activate

WORKDIR /app

ENV NODE_ENV=development

EXPOSE 5173

CMD ["sh", "-c", "pnpm install && pnpm dev --host 0.0.0.0"]
