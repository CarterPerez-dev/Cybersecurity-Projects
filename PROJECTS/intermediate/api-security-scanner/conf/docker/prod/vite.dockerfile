# ⒸAngelaMos | 2025
# Production Vite Dockerfile (Multi-stage build)
# Stage 1: Build the React app with Vite
# Stage 2: Serve static files with Nginx


# Stage 1: Build
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY frontend/ .

# Build the app (creates dist/ folder with static files)
RUN npm run build



# Stage 2: Serve with Nginx
FROM nginx:alpine

# Copy built static files from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy nginx configurations
COPY conf/nginx/prod.nginx /etc/nginx/nginx.conf
COPY conf/nginx/http.conf /etc/nginx/http.conf

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
