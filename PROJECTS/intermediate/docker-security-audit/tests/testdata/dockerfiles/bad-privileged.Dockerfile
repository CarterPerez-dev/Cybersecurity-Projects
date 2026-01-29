FROM alpine:latest

# CRITICAL: Using latest tag
# INFO: Should use specific version like alpine:3.19

RUN apk add --no-cache curl bash docker-cli

# HIGH: Installing Docker CLI inside container (likely needs docker.sock)
# This pattern usually means they'll mount docker socket

# MEDIUM: Running as root
WORKDIR /app

COPY entrypoint.sh /app/
RUN chmod 777 /app/entrypoint.sh

# MEDIUM: World-writable permissions

# Note: The "privileged" part would be in docker run or compose
# This Dockerfile enables that pattern

EXPOSE 9000

CMD ["/app/entrypoint.sh"]
