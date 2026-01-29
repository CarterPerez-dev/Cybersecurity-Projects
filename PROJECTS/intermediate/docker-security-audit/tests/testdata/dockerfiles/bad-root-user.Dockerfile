FROM ubuntu:22.04

# MEDIUM: No USER directive - runs as root
# MEDIUM: Using latest tag implicitly (ubuntu:22.04 is ok, but shows pattern)

RUN apt-get update && \
    apt-get install -y nginx curl && \
    rm -rf /var/lib/apt/lists/*

# HIGH: Installing sudo (not needed in containers)
RUN apt-get update && apt-get install -y sudo

# Creating files as root
RUN mkdir -p /app/data && \
    echo "config" > /app/config.txt

COPY app.sh /app/
RUN chmod +x /app/app.sh

WORKDIR /app

# MEDIUM: No HEALTHCHECK defined
EXPOSE 8080

# Running as root (uid 0)
CMD ["/app/app.sh"]
