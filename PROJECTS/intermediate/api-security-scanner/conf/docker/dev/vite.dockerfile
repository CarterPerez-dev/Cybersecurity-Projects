# ⒸAngelaMos | 2025
# Development Vite Dockerfile
# Runs Vite dev server with HMR (Hot Module Replacement)
# Uses volume mounts for code (defined in docker-compose.dev.yml)

FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files first (for layer caching)
COPY frontend/package*.json ./

# Install dependencies
RUN npm ci

# Copy application code (in dev this is overridden by volume mount)
COPY frontend/ .

# Expose port
EXPOSE 5173

# Run Vite dev server with --host to allow external connections
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
