FROM node:18

# MEDIUM: Using ADD instead of COPY (can extract archives, execute URLs)
ADD https://example.com/config.tar.gz /app/
ADD ./local-files.tar.gz /app/

# LOW: Could use COPY instead unless extraction is intended

# MEDIUM: No USER directive
WORKDIR /app

# HIGH: npm install as root
RUN npm install -g yarn
RUN npm install

# MEDIUM: No --production flag, installs dev dependencies

# MEDIUM: Exposing unnecessary ports
EXPOSE 3000 9229 9230

# MEDIUM: No HEALTHCHECK
CMD ["node", "server.js"]
