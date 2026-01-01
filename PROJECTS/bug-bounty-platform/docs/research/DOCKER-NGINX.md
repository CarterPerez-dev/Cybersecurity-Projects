# Production Docker stack for FastAPI and React in 2025

The modern Docker Compose ecosystem has matured significantly, with **the Compose Specification replacing legacy v2/v3 syntax** and BuildKit becoming the default engine. Your proposed architecture is sound, but several optimizations can dramatically improve performance, security, and developer experience. The key shifts for 2025: adopt **uv** as your Python package manager (10-100× faster than pip), consider **Granian** as an alternative ASGI server for maximum throughput, leverage **Compose Watch** for superior hot-reload without bind mounts, and structure your Dockerfiles with multi-stage builds using BuildKit cache mounts.

This guide provides senior-level patterns addressing your specific stack: FastAPI with async SQLAlchemy, React/Vite frontend, Nginx reverse proxy with WebSocket support, and proper dev/prod separation.

## Modern Compose architecture eliminates version confusion

The **`version` field is now deprecated and should be omitted** entirely. Since Compose v1.27.0+, the unified Compose Specification auto-detects behavior. Your file naming convention is correct—prefer `compose.yml` over the legacy `docker-compose.yml`.

For your proposed structure, the recommended override pattern maximizes code reuse while maintaining clear separation:

```yaml
# compose.yml (Base/shared configuration - no version field)
name: myproject

services:
  api:
    build:
      context: ./backend
      dockerfile: ../conf/docker/fastapi.Dockerfile
      target: ${BUILD_TARGET:-production}
    networks:
      - backend
      - frontend
    depends_on:
      db:
        condition: service_healthy
        restart: true  # Compose 2.17.0+ restarts api if db restarts

  frontend:
    build:
      context: ./frontend
      dockerfile: ../conf/docker/frontend.Dockerfile
      target: ${BUILD_TARGET:-production}
    networks:
      - frontend

  nginx:
    image: nginx:1.27-alpine
    volumes:
      - ./conf/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./conf/nginx/${NGINX_CONFIG:-prod}.nginx:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "80:80"
    depends_on:
      api:
        condition: service_healthy
    networks:
      - frontend
      - backend

  db:
    image: postgres:16-alpine
    volumes:
      - db_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - backend

networks:
  backend:
  frontend:

volumes:
  db_data:
```

Custom networks are essential for security—your database sits only on the `backend` network, inaccessible to the frontend container. Services resolve each other by name automatically (`http://api:8000`).

**Compose Watch** (GA in Compose 2.22.0+) provides superior hot-reload compared to traditional bind mounts, with granular control over sync, rebuild, and restart actions. For development, your override file would include:

```yaml
# compose.dev.yml
services:
  api:
    build:
      target: development
    develop:
      watch:
        - action: sync
          path: ./backend
          target: /app
          ignore:
            - __pycache__/
            - .venv/
        - action: rebuild
          path: ./backend/pyproject.toml
    ports:
      - "8000:8000"
    environment:
      - NGINX_CONFIG=dev

  frontend:
    build:
      target: development
    develop:
      watch:
        - action: sync
          path: ./frontend/src
          target: /app/src
        - action: rebuild
          path: ./frontend/package.json
```

Execute with `docker compose watch` for development. For production: `docker compose -f compose.yml up -d`.

**Resource limits now work without Swarm** using the `deploy.resources` syntax. Always set these in production to prevent runaway containers:

```yaml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
```

## FastAPI containers need uv, multi-stage builds, and careful ASGI selection

**Use `python:3.12-slim` as your base image.** Alpine's musl libc causes package compatibility issues and can make builds 50× slower when compiling native extensions. The slim variant offers the best balance at ~130MB.

**uv is now production-ready** with 16+ million monthly downloads. Created by Astral (the Ruff team), it provides 10-100× faster dependency installation with proper lock file support. Here's the complete production Dockerfile pattern:

```dockerfile
# conf/docker/fastapi.Dockerfile
# syntax=docker/dockerfile:1

# ============ BUILD STAGE ============
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Install dependencies first (cached layer)
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev

# Install project
COPY . .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable

# ============ DEVELOPMENT STAGE ============
FROM python:3.12-slim AS development
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen

COPY . .
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ============ PRODUCTION STAGE ============
FROM python:3.12-slim AS production

# Security: non-root user
RUN groupadd -g 1001 appgroup && \
    useradd -u 1001 -g appgroup -m -s /bin/false appuser

WORKDIR /app
COPY --from=builder --chown=appuser:appgroup /app/.venv /app/.venv
COPY --from=builder --chown=appuser:appgroup /app /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

The `--mount=type=cache` directive is a BuildKit feature that caches pip/uv downloads between builds—essential for CI/CD speed. The `UV_COMPILE_BYTECODE=1` flag pre-compiles Python files for faster startup in production.

**ASGI server selection in 2025** presents interesting choices. Uvicorn remains the safe default, but **Granian** (Rust-based) delivers higher throughput with more consistent latency:

| Server | Requests/sec | Latency Gap (avg/max) | Best For |
|--------|-------------|----------------------|----------|
| Granian | ~50,000 | 2.8× | Maximum performance |
| Uvicorn (httptools) | ~45,000 | 6.8× | General production |
| Gunicorn + Uvicorn | ~45,000 | 6.5× | Process management |
| Hypercorn | ~35,000 | 5.2× | HTTP/2, HTTP/3 |

For Uvicorn with multiple workers: `uvicorn app.main:app --workers 4`. The worker formula for async I/O-bound apps is `(2 × CPU_COUNT) + 1`. For Gunicorn with process management benefits, use `gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --max-requests 1000 --max-requests-jitter 100`.

**Async SQLAlchemy connection pooling** requires attention in containers:

```python
from sqlalchemy.ext.asyncio import create_async_engine

engine = create_async_engine(
    "postgresql+asyncpg://user:pass@db:5432/dbname",
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,   # Recycle after 1 hour
)
```

## Frontend builds require HMR fixes and strategic caching

Vite in Docker requires specific configuration to enable Hot Module Replacement through container networking. Your `vite.config.ts` must bind to all interfaces and enable polling for file system events:

```typescript
export default defineConfig({
  server: {
    host: "0.0.0.0",
    port: 5173,
    watch: { usePolling: true },
    hmr: { clientPort: 5173 },
  },
});
```

**Use `node:22-slim` for production builds**—it provides glibc compatibility and lower CVE counts than Alpine. The multi-stage frontend Dockerfile should separate dependency installation from build for optimal caching:

```dockerfile
# conf/docker/frontend.Dockerfile
# ========== DEVELOPMENT ==========
FROM node:22-slim AS development
WORKDIR /app
COPY package*.json ./
RUN npm ci
EXPOSE 5173
CMD ["npm", "run", "dev"]

# ========== BUILD STAGE ==========
FROM node:22-slim AS builder
WORKDIR /app
COPY package*.json ./
ENV NODE_ENV=production
RUN npm ci --only=production
COPY . .
RUN npm run build

# ========== PRODUCTION ==========
FROM nginx:1.27-alpine AS production
COPY --from=builder /app/dist /usr/share/nginx/html
RUN chown -R nginx:nginx /usr/share/nginx/html
USER nginx
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

The **node_modules handling** question has a definitive answer for Docker: install in the container, not on the host. Use an anonymous volume to preserve container modules when bind-mounting source:

```yaml
volumes:
  - ./frontend:/app
  - /app/node_modules  # Preserves container's node_modules
```

**pnpm is the 2025 recommendation** for new projects—it provides significant disk space savings through a shared store and faster installs. Enable it in your Dockerfile with `RUN corepack enable && corepack prepare pnpm@latest --activate`.

**Vite environment variables are statically replaced at build time**—they become hardcoded strings. For runtime configuration, use the placeholder pattern:

```dockerfile
ENV VITE_API_URL="__VITE_API_URL__"
RUN npm run build
CMD ["/bin/sh", "-c", \
  "find /usr/share/nginx/html -type f -name '*.js' -exec sed -i 's|__VITE_API_URL__|'$VITE_API_URL'|g' {} + && \
   nginx -g 'daemon off;'"]
```

## Nginx configuration balances performance, security, and WebSocket support

Your nginx.conf should establish global settings while environment-specific server blocks handle routing differences. The critical pattern for FastAPI reverse proxying includes **upstream keepalive for connection pooling** and proper header forwarding:

```nginx
# conf/nginx/nginx.conf
user nginx;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log warn;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    server_tokens off;
    
    # Compression
    gzip on;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml image/svg+xml;
    
    # Rate limiting zones
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=1r/s;
    limit_req_status 429;
    
    # WebSocket upgrade map
    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }
    
    # Upstream with connection pooling
    upstream fastapi {
        server api:8000;
        keepalive 32;
        keepalive_requests 1000;
        keepalive_timeout 60s;
    }
    
    include /etc/nginx/conf.d/*.conf;
}
```

The production server block handles API proxying, WebSocket connections, and static file serving with proper cache headers:

```nginx
# conf/nginx/prod.nginx
server {
    listen 80;
    root /usr/share/nginx/html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # API proxy with rate limiting
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://fastapi/;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 32k;
        proxy_connect_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # WebSocket endpoint
    location /api/ws {
        proxy_pass http://fastapi;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;
        proxy_buffering off;
    }
    
    # Hashed assets - cache forever
    location /assets/ {
        add_header Cache-Control "public, max-age=31536000, immutable";
        try_files $uri =404;
    }
    
    # SPA fallback - never cache index.html
    location / {
        add_header Cache-Control "no-cache";
        try_files $uri $uri/ /index.html;
    }
}
```

**WebSocket configuration requires specific attention**: the `Upgrade` and `Connection` headers are hop-by-hop and must be explicitly forwarded. The `map` directive dynamically sets the Connection header based on whether an upgrade is requested. The **86400-second timeout** prevents Nginx from closing idle WebSocket connections.

**Keep proxy_buffering ON for regular API requests**—this protects FastAPI from slow clients by letting Nginx accept the full response and free the uvicorn worker immediately. Only disable buffering for WebSocket and Server-Sent Events endpoints.

For development, your dev.nginx proxies to the Vite dev server instead of serving static files:

```nginx
# conf/nginx/dev.nginx
server {
    listen 80;
    access_log /var/log/nginx/access.log detailed;
    
    add_header Cache-Control "no-store" always;
    
    location / {
        proxy_pass http://frontend:5173;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
    
    location /api/ {
        proxy_pass http://api:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## Security hardening requires layered defenses

Container security follows defense-in-depth principles. **Never run containers as root**—this is the single most important security measure. Combine with capability dropping and read-only filesystems:

```yaml
services:
  api:
    user: "1001:1001"
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

**Docker secrets provide secure credential handling** without exposing values in environment variables or compose files:

```yaml
services:
  db:
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password

secrets:
  db_password:
    file: ./secrets/db_password.txt  # Git-ignored
```

Your FastAPI app reads secrets from the mounted file:

```python
def get_secret(name: str) -> str:
    secret_path = Path(f"/run/secrets/{name}")
    if secret_path.exists():
        return secret_path.read_text().strip()
    return os.environ.get(name.upper(), "")
```

**Handle CORS at the FastAPI level**, not Nginx—this allows dynamic origin handling and proper credential support. Never configure CORS in both layers simultaneously.

For zero-downtime deployments with Docker Compose, the **docker-rollout** plugin provides seamless rolling updates:

```bash
curl https://raw.githubusercontent.com/wowu/docker-rollout/main/docker-rollout \
  -o ~/.docker/cli-plugins/docker-rollout
chmod +x ~/.docker/cli-plugins/docker-rollout
docker rollout api  # Instead of docker compose up -d
```

**Health checks are mandatory for reliable orchestration**. Implement both liveness (is the process running?) and readiness (can we serve traffic?) endpoints:

```python
@router.get("/health")
async def liveness():
    return {"status": "alive"}

@router.get("/health/ready")
async def readiness(db: AsyncSession = Depends(get_db)):
    await db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "connected"}
```

Database migrations should be decoupled from application startup in production. Run them as a separate step: `docker compose run --rm api alembic upgrade head`, then deploy with `docker compose up -d`.

## Conclusion

The 2025 Docker ecosystem offers substantial improvements over previous patterns. The unified Compose Specification eliminates version confusion, BuildKit cache mounts dramatically accelerate CI/CD builds, and tools like uv transform Python dependency management. Your architecture is well-structured—the key refinements are adopting multi-stage Dockerfiles with explicit development/production targets, leveraging Compose Watch for superior hot-reload, and ensuring proper security hardening with non-root users, capability dropping, and secrets management.

For maximum performance, consider Granian as your ASGI server—its Rust-based implementation delivers 10-15% higher throughput with more consistent latency than Uvicorn. The upstream keepalive configuration in Nginx is often overlooked but critical for reducing TCP handshake overhead between your reverse proxy and FastAPI workers.

The anti-patterns to actively avoid: bind-mounting code in production, using the `version` field in compose files, running containers as root, hardcoding secrets anywhere, and configuring CORS in both Nginx and FastAPI simultaneously. These patterns cause subtle production issues that are difficult to debug.
