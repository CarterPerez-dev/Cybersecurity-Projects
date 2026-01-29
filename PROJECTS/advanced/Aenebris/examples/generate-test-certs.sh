#!/bin/bash

# Generate self-signed certificates for testing Ᾰenebris TLS

set -e

echo "Generating test certificates for Ᾰenebris..."

# Create certs directory if it doesn't exist
mkdir -p examples/certs

# Generate single certificate for localhost
echo "→ Generating single certificate for localhost..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/certs/localhost.key \
  -out examples/certs/localhost.crt \
  -days 365 \
  -subj "/CN=localhost/O=Aenebris Test/C=US"

# Generate SNI certificate for api.localhost
echo "→ Generating SNI certificate for api.localhost..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/certs/api.localhost.key \
  -out examples/certs/api.localhost.crt \
  -days 365 \
  -subj "/CN=api.localhost/O=Aenebris Test/C=US"

# Generate SNI certificate for web.localhost
echo "→ Generating SNI certificate for web.localhost..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/certs/web.localhost.key \
  -out examples/certs/web.localhost.crt \
  -days 365 \
  -subj "/CN=web.localhost/O=Aenebris Test/C=US"

# Generate default SNI certificate
echo "→ Generating default SNI certificate..."
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/certs/default.key \
  -out examples/certs/default.crt \
  -days 365 \
  -subj "/CN=default.localhost/O=Aenebris Test/C=US"

echo "✓ All test certificates generated successfully!"
echo ""
echo "Files created:"
echo "  examples/certs/localhost.{crt,key}        - Single cert for localhost"
echo "  examples/certs/api.localhost.{crt,key}    - SNI cert for api.localhost"
echo "  examples/certs/web.localhost.{crt,key}    - SNI cert for web.localhost"
echo "  examples/certs/default.{crt,key}          - Default SNI cert"
echo ""
echo "These are self-signed certificates for testing only!"
echo "Use curl -k or --insecure to test HTTPS endpoints."
