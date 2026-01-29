FROM node:18.19.0-alpine3.19

# Best practices Dockerfile with all security features

# Install dependencies as root
RUN apk add --no-cache \
    ca-certificates \
    curl \
    tini

# Create non-root user with specific UID/GID
RUN addgroup -g 1001 nodejs && \
    adduser -D -u 1001 -G nodejs nodejs

WORKDIR /app

# Copy package files
COPY --chown=nodejs:nodejs package*.json ./

# Install production dependencies only
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application code
COPY --chown=nodejs:nodejs . .

# Remove write permissions from application code
RUN chmod -R 555 /app

# Switch to non-root user
USER nodejs

EXPOSE 3000

# Add health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node healthcheck.js || exit 1

# Use tini as init process (handles signals properly)
ENTRYPOINT ["/sbin/tini", "--"]

CMD ["node", "server.js"]
