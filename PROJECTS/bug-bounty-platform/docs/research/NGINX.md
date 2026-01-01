# Production-Grade Nginx Configuration: 2025 Best Practices

**Complete guide for modern full-stack applications (FastAPI + Frontend) with emphasis on WebSocket support, configuration organization, and dev/prod architectures.**

## Table of Contents
1. [Configuration File Organization](#configuration-file-organization)
2. [WebSocket Proxying](#websocket-proxying)
3. [Shared Configuration (http.conf)](#shared-configuration-httpconf)
4. [Development Configuration](#development-configuration-devnginx)
5. [Production Configuration](#production-configuration-prodnginx)
6. [Performance Optimization](#performance-optimization)
7. [Security Headers](#security-headers)
8. [Static File Serving](#static-file-serving-production)
9. [Vite Dev Server Integration](#vite-dev-server-integration-development)
10. [Load Balancing & Upstreams](#load-balancing--upstreams)
11. [Rate Limiting](#rate-limiting)
12. [Logging & Monitoring](#logging--monitoring)
13. [Complete Configuration Examples](#complete-configuration-examples)

---

## Configuration File Organization

### Recommended Structure

```
conf/nginx/
├── http.conf           # Shared: upstreams, maps, global http settings
├── dev.nginx          # Full nginx.conf for development
└── prod.nginx         # Full nginx.conf for production
```

### What Goes Where

**http.conf (Shared Configurations)**:
- Upstream definitions (backend, frontend servers)
- Map directives for WebSocket connection upgrades
- Shared rate limit zones
- Common proxy settings
- MIME type definitions
- Log formats

**dev.nginx (Development-Specific)**:
- Full nginx.conf structure
- Includes http.conf
- Proxies to Vite dev server (port 5173)
- Proxies API/WebSocket to backend (port 8000)
- Verbose logging
- CORS permissive settings
- No caching
- No SSL (typically)

**prod.nginx (Production-Specific)**:
- Full nginx.conf structure
- Includes http.conf
- Serves static files from `/usr/share/nginx/html`
- Proxies API/WebSocket to Gunicorn workers
- SSL/TLS configuration
- Security headers
- Gzip/Brotli compression
- Static file caching
- Error logging only

---

## WebSocket Proxying

WebSocket connections require explicit handling because the "Upgrade" and "Connection" headers are hop-by-hop and not automatically passed to the proxied server. The modern approach uses a `map` directive to handle connections conditionally.

### Core WebSocket Configuration Pattern

```nginx
# In http.conf (shared configuration)
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
```

This sophisticated approach sets the Connection header to "close" when there's no Upgrade header, and to "upgrade" when WebSocket upgrade is requested.

### WebSocket Location Block

```nginx
location /ws/ {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    
    # WebSocket-specific headers
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    
    # Standard proxy headers
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Timeout settings for long-lived connections
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_connect_timeout 75s;
    
    # Disable buffering for real-time data
    proxy_buffering off;
    proxy_cache_bypass $http_upgrade;
}
```

### Critical WebSocket Settings Explained

For WebSocket session persistence with multiple backend servers, use `ip_hash` to ensure clients always connect to the same backend:

```nginx
upstream websocket_backend {
    ip_hash;  # Session persistence
    server backend1:8000;
    server backend2:8000;
    server backend3:8000;
}
```

**Timeout Configuration**: By default, connections close if the proxied server doesn't transmit data within 60 seconds. For WebSockets:
- `proxy_read_timeout`: Set to 3600s (1 hour) or higher
- `proxy_send_timeout`: Set to 3600s (1 hour) or higher
- `proxy_connect_timeout`: Usually 75s is sufficient

---

## Shared Configuration (http.conf)

This file contains settings used by both dev and prod environments.

```nginx
# conf/nginx/http.conf

# WebSocket upgrade handling
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

# Upstream definitions
upstream backend {
    # Development: single uvicorn instance
    # Production: multiple gunicorn workers (override in prod.nginx)
    server backend:8000 max_fails=3 fail_timeout=30s;
    keepalive 32;  # Connection pooling
}

upstream frontend_dev {
    # Only used in development
    server frontend:5173;
}

# Custom log format with timing information
log_format main_timed '$remote_addr - $remote_user [$time_local] '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent" '
                      'rt=$request_time uct="$upstream_connect_time" '
                      'uht="$upstream_header_time" urt="$upstream_response_time"';

# Rate limit zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=1r/s;

# Connection limits
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

# Common proxy settings
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

---

## Development Configuration (dev.nginx)

Full nginx.conf optimized for local development with hot module replacement.

```nginx
# conf/nginx/dev.nginx

user nginx;
worker_processes 1;  # Single worker sufficient for dev
error_log /var/log/nginx/error.log debug;  # Verbose logging
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Include shared configuration
    include /etc/nginx/http.conf;
    
    # Development-specific settings
    access_log /var/log/nginx/access.log main_timed;
    sendfile off;  # Disable for file system changes
    tcp_nopush off;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    # Disable caching in development
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0";
    
    # CORS permissive for development
    add_header 'Access-Control-Allow-Origin' '*' always;
    add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, PATCH, OPTIONS' always;
    add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
    
    server {
        listen 80;
        server_name localhost;
        
        # Handle preflight requests
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' '*';
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization';
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
        
        # API routes to backend
        location /api/ {
            limit_req zone=api_limit burst=20 nodelay;
            limit_conn conn_limit 10;
            
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            
            # Proxy buffering settings
            proxy_buffering off;
            proxy_request_buffering off;
        }
        
        # WebSocket route
        location /ws/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_buffering off;
        }
        
        # Vite dev server (with HMR WebSocket support)
        location / {
            proxy_pass http://frontend_dev;
            proxy_http_version 1.1;
            
            # Required for Vite HMR
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $host;
            
            # Vite-specific timeout
            proxy_read_timeout 60s;
            proxy_buffering off;
        }
        
        # Health check endpoint
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
```

### Key Development Features:

1. **Verbose Logging**: `error_log debug` for troubleshooting
2. **No Caching**: Ensures fresh content on every request
3. **Permissive CORS**: Allows frontend to call backend freely
4. **HMR Support**: WebSocket headers (Upgrade and Connection) are required for Vite's Hot Module Replacement to function properly
5. **Disabled Optimizations**: `sendfile off` to catch file changes immediately

---

## Production Configuration (prod.nginx)

Optimized for performance, security, and reliability.

```nginx
# conf/nginx/prod.nginx

user nginx;
worker_processes auto;  # One per CPU core
worker_rlimit_nofile 100000;
error_log /var/log/nginx/error.log warn;  # Only warnings and errors
pid /var/run/nginx.pid;

events {
    worker_connections 4096;  # High concurrency support
    use epoll;  # Efficient connection handling on Linux
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Include shared configuration
    include /etc/nginx/http.conf;
    
    # Logging with buffering
    access_log /var/log/nginx/access.log main_timed buffer=32k flush=5s;
    
    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 100;
    types_hash_max_size 2048;
    server_tokens off;  # Hide nginx version
    
    # File cache
    open_file_cache max=10000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
    
    # Buffer sizes
    client_body_buffer_size 128k;
    client_header_buffer_size 16k;
    client_max_body_size 10m;
    large_client_header_buffers 4 16k;
    
    # Timeouts
    client_body_timeout 12s;
    client_header_timeout 12s;
    send_timeout 10s;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;
    gzip_disable "msie6";
    gzip_min_length 256;
    
    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name yourdomain.com;
        return 301 https://$host$request_uri;
    }
    
    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name yourdomain.com;
        
        # SSL configuration
        ssl_certificate /etc/nginx/ssl/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:50m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;
        ssl_stapling on;
        ssl_stapling_verify on;
        
        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
        
        # Content Security Policy
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss://yourdomain.com" always;
        
        # Root directory for static files
        root /usr/share/nginx/html;
        index index.html;
        
        # API routes with rate limiting
        location /api/ {
            limit_req zone=api_limit burst=20 nodelay;
            limit_conn conn_limit 20;
            
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            
            # Proxy buffering optimized for API
            proxy_buffering on;
            proxy_buffers 8 24k;
            proxy_buffer_size 2k;
            
            # Timeouts
            proxy_connect_timeout 75s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;
        }
        
        # Auth endpoints with stricter rate limiting
        location /api/auth/ {
            limit_req zone=auth_limit burst=5 nodelay;
            
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
        
        # WebSocket route
        location /ws/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_connect_timeout 75s;
            proxy_buffering off;
        }
        
        # Static files with aggressive caching
        location ~* \.(jpg|jpeg|png|gif|ico|svg|webp)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
        }
        
        location ~* \.(css|js)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
        }
        
        location ~* \.(woff|woff2|ttf|eot|otf)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            access_log off;
        }
        
        # SPA fallback - all non-matching routes to index.html
        location / {
            try_files $uri $uri/ /index.html;
            add_header Cache-Control "no-cache, must-revalidate";
        }
        
        # Health check
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
        
        # Deny access to hidden files
        location ~ /\. {
            deny all;
            access_log off;
            log_not_found off;
        }
    }
}
```

---

## Performance Optimization

### Worker Configuration

Running one worker process per CPU core works well in most cases, and setting worker_processes to auto achieves this:

```nginx
worker_processes auto;
worker_rlimit_nofile 100000;  # File descriptor limit

events {
    worker_connections 4096;
    use epoll;  # Most efficient on Linux
    multi_accept on;  # Accept multiple connections at once
}
```

### Connection and Request Handling

The default worker_connections is 512, but most systems can support higher values. The optimal setting depends on server resources and traffic patterns.

**Formula**: `max_clients = worker_processes * worker_connections`

### Buffer Optimization

If buffer sizes are too low, Nginx will write to temporary files, causing excessive disk I/O:

```nginx
client_body_buffer_size 128k;
client_header_buffer_size 16k;
client_max_body_size 10m;
large_client_header_buffers 4 16k;
```

### Keepalive Connections

Keepalive connections reduce CPU and network overhead by keeping connections open longer:

```nginx
keepalive_timeout 65;
keepalive_requests 100;

upstream backend {
    server backend:8000;
    keepalive 32;  # Idle connections to upstream
}
```

### Sendfile and TCP Optimizations

The sendfile() system call enables zero-copy data transfer, speeding up TCP transmissions without consuming CPU cycles:

```nginx
sendfile on;
tcp_nopush on;  # Send headers in one packet
tcp_nodelay on;  # Disable Nagle's algorithm
```

### File Caching

```nginx
open_file_cache max=10000 inactive=20s;
open_file_cache_valid 30s;
open_file_cache_min_uses 2;
open_file_cache_errors on;
```

### Compression

```nginx
gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;  # Balance between CPU and compression
gzip_min_length 256;
gzip_types
    text/plain
    text/css
    text/xml
    text/javascript
    application/json
    application/javascript
    application/xml+rss
    application/atom+xml
    image/svg+xml;
```

**Important**: Don't increase compression level too high, as it costs CPU effort without proportional throughput gains.

---

## Security Headers

### Essential Security Headers (2025)

Security headers are levers that slash XSS risk, lock browsers to HTTPS, tame third-party scripts, and protect users without touching app code.

```nginx
# HTTP Strict Transport Security (HSTS)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Prevent clickjacking
add_header X-Frame-Options "SAMEORIGIN" always;

# Prevent MIME sniffing
add_header X-Content-Type-Options "nosniff" always;

# XSS Protection (legacy but still useful)
add_header X-XSS-Protection "1; mode=block" always;

# Referrer Policy
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Disable dangerous browser features
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Content Security Policy (CSP)

CSP controls where scripts, styles, images, frames, and connections can load from. Start with a restrictive policy:

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss://yourdomain.com" always;
```

**Best Practice**: Roll out CSP in Report-Only mode first, sending violation reports to an endpoint you control:

```nginx
# Test mode
add_header Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report" always;
```

### HSTS Explained

HSTS forces browsers to only use HTTPS by caching this policy for the max-age period. The `includeSubDomains` directive applies the policy to all subdomains.

**Preloading**: To add your domain to the browser preload list, include "preload" in the header and submit to hstspreload.org. This is a one-way decision—removal is difficult.

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

### SSL/TLS Best Practices

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:50m;
ssl_session_timeout 1d;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
```

---

## Static File Serving (Production)

### Cache Headers Strategy

Use Cache-Control on static files so that CDNs and browsers can cache them effectively. The modern approach favors `Cache-Control` over `Expires`.

```nginx
# Images, fonts, media - long cache
location ~* \.(jpg|jpeg|png|gif|ico|svg|webp|avif|woff|woff2|ttf|eot|otf|mp4|mp3|ogg|webm)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# CSS and JavaScript - long cache with versioning
location ~* \.(css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# HTML files - no caching
location ~* \.html$ {
    expires -1;
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0";
}
```

### Cache Busting

When files are updated, use cache-busting by appending version numbers to filenames (e.g., `style.css?v=2` or `style.v2.css`).

### SPA Routing

For Single Page Applications, route all non-file requests to index.html:

```nginx
location / {
    try_files $uri $uri/ /index.html;
    add_header Cache-Control "no-cache, must-revalidate";
}
```

---

## Vite Dev Server Integration (Development)

### HMR WebSocket Support

Vite's HMR requires WebSocket support with Upgrade and Connection headers set for the WebSocket connection to function:

```nginx
location / {
    proxy_pass http://frontend:5173;
    proxy_http_version 1.1;
    
    # Critical for Vite HMR
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    
    # Timeouts
    proxy_read_timeout 60s;
    proxy_buffering off;
}
```

### Vite HMR Path Handling

If Vite uses a custom HMR path:

```nginx
location ~* /__vite_hmr {
    proxy_pass http://frontend:5173;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
    proxy_set_header Host $host;
}
```

### Common Vite + Nginx Issues

1. **HMR not working**: Ensure WebSocket headers are set correctly
2. **Too many redirects**: Use `proxy_pass http://host;` without trailing slash to avoid path manipulation
3. **Connection timeout**: Default proxy timeouts may be too short; increase to 30-60 seconds for WebSocket connections

---

## Load Balancing & Upstreams

### Upstream Configuration

```nginx
upstream backend {
    least_conn;  # Route to server with fewest connections
    
    server backend1:8000 max_fails=3 fail_timeout=30s;
    server backend2:8000 max_fails=3 fail_timeout=30s;
    server backend3:8000 backup;  # Fallback server
    
    keepalive 32;  # Connection pooling
    keepalive_requests 100;
    keepalive_timeout 60s;
}
```

### Load Balancing Methods

- `round_robin` (default): Distribute requests evenly
- `least_conn`: Route to server with fewest active connections
- `ip_hash`: Consistent routing based on client IP (session persistence)
- `hash $request_uri consistent`: Route based on URI

### Health Checks (Nginx Plus)

```nginx
upstream backend {
    zone backend 64k;
    
    server backend1:8000;
    server backend2:8000;
    
    health_check interval=5s fails=3 passes=2;
}
```

---

## Rate Limiting

### Zone Definitions

```nginx
# In http block
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=1r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
```

### Application in Locations

```nginx
# General API rate limiting
location /api/ {
    limit_req zone=api_limit burst=20 nodelay;
    limit_conn conn_limit 20;
    proxy_pass http://backend;
}

# Stricter for authentication
location /api/auth/ {
    limit_req zone=auth_limit burst=5 nodelay;
    proxy_pass http://backend;
}
```

**Parameters**:
- `rate`: Requests per second (or `r/m` for per minute)
- `burst`: Allow temporary burst above rate
- `nodelay`: Process burst requests immediately
- `limit_conn`: Max simultaneous connections

---

## Logging & Monitoring

### Custom Log Format with Timing

```nginx
log_format main_timed '$remote_addr - $remote_user [$time_local] '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent" '
                      'rt=$request_time uct="$upstream_connect_time" '
                      'uht="$upstream_header_time" urt="$upstream_response_time"';
```

### Buffered Logging for Performance

Logging every request directly to disk is expensive; buffering reduces write operations:

```nginx
access_log /var/log/nginx/access.log main_timed buffer=32k flush=5s;
```

### Conditional Logging

```nginx
# Don't log health checks
location /health {
    access_log off;
    return 200 "healthy\n";
}

# Log only errors for static files
location ~* \.(jpg|png|css|js)$ {
    access_log off;
    error_log /var/log/nginx/static_error.log;
}
```

---

## Complete Configuration Examples

### Docker Compose Integration

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./conf/nginx/http.conf:/etc/nginx/http.conf:ro
      - ./conf/nginx/prod.nginx:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
      - nginx_cache:/var/cache/nginx
    depends_on:
      - backend
    networks:
      - app_network

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    expose:
      - "8000"
    networks:
      - app_network

volumes:
  nginx_cache:

networks:
  app_network:
```

### Minimal Dev Configuration

```nginx
# Absolute minimum for development
http {
    include mime.types;
    
    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }
    
    upstream backend {
        server backend:8000;
    }
    
    server {
        listen 80;
        
        location /api/ {
            proxy_pass http://backend;
        }
        
        location /ws/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_read_timeout 3600s;
        }
        
        location / {
            proxy_pass http://frontend:5173;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
        }
    }
}
```

---

## Key Takeaways

### WebSocket Requirements
1. Map `$http_upgrade` to `$connection_upgrade`
2. Set `proxy_http_version 1.1`
3. Set headers: `Upgrade $http_upgrade` and `Connection $connection_upgrade`
4. Increase timeouts: `proxy_read_timeout 3600s`
5. Disable buffering: `proxy_buffering off`

### Dev vs Prod Differences
- **Dev**: Verbose logging, no caching, permissive CORS, proxy to Vite
- **Prod**: Error logging only, aggressive caching, strict security headers, serve static files

### File Organization
- **http.conf**: Upstreams, maps, shared settings
- **dev.nginx**: Full config optimized for development
- **prod.nginx**: Full config optimized for production

### Performance Priorities
1. Worker processes = CPU cores (`worker_processes auto`)
2. High worker connections (4096+)
3. Enable `sendfile`, `tcp_nopush`, `tcp_nodelay`
4. Buffer optimization to avoid disk I/O
5. Keepalive connections for upstreams

### Security Essentials
1. HSTS with preload for HTTPS enforcement
2. Comprehensive CSP to prevent XSS
3. X-Frame-Options to prevent clickjacking
4. Rate limiting on API endpoints
5. Hide server version (`server_tokens off`)

### Static File Serving
1. Long cache for assets (1 year with `immutable`)
2. No cache for HTML files
3. Use cache busting with versioned filenames
4. SPA fallback with `try_files $uri /index.html`
