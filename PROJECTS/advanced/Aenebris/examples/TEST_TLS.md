# TLS Testing Guide for Ᾰenebris

This document describes how to test all TLS/SSL features in Ᾰenebris.

## Prerequisites

1. Generate test certificates:
```bash
./examples/generate-test-certs.sh
```

2. Start test backend servers:
```bash
# Terminal 1: Main backend on port 8000
python examples/test_backend_multi.py 8000

# Terminal 2 (for SNI testing): API backend on port 8001
python examples/test_backend_multi.py 8001

# Terminal 3 (for SNI testing): Web backend on port 8002
python examples/test_backend_multi.py 8002
```

## Test 1: Single Certificate HTTPS

**Config:** `examples/config-https.yaml`

**Start proxy:**
```bash
./aenebris examples/config-https.yaml
```

**Tests:**

### Test HTTP → HTTPS Redirect
```bash
# Should return 301 redirect to HTTPS
curl -v http://localhost:8080/

# Expected: Location: https://localhost:8080/
```

### Test HTTPS Connection
```bash
# Make HTTPS request (-k ignores self-signed cert)
curl -k https://localhost:8443/

# Expected: Response from backend server
```

### Test TLS 1.3
```bash
# Verify TLS 1.3 is available
openssl s_client -connect localhost:8443 -tls1_3

# Expected: Should succeed with "Protocol  : TLSv1.3"
```

### Test TLS 1.2
```bash
# Verify TLS 1.2 is also supported
openssl s_client -connect localhost:8443 -tls1_2

# Expected: Should succeed with "Protocol  : TLSv1.2"
```

### Test TLS 1.1 Rejected
```bash
# Verify old TLS is rejected
openssl s_client -connect localhost:8443 -tls1_1 2>&1 | grep -i "error\|alert"

# Expected: Should fail with "no protocols available" or similar
```

### Test Security Headers
```bash
# Check security headers are present
curl -k -I https://localhost:8443/

# Expected headers:
# - Strict-Transport-Security: max-age=2592000; includeSubDomains
# - Content-Security-Policy: default-src 'self'; ...
# - X-Frame-Options: DENY
# - X-Content-Type-Options: nosniff
# - Referrer-Policy: strict-origin-when-cross-origin
# - Permissions-Policy: geolocation=(), ...
# - Expect-CT: max-age=86400, enforce
# - Server: Aenebris
```

### Test HTTP/2
```bash
# Verify HTTP/2 is negotiated via ALPN
curl -k --http2 -v https://localhost:8443/ 2>&1 | grep "ALPN"

# Expected: "ALPN, server accepted to use h2"
```

### Test Cipher Suites
```bash
# List negotiated cipher suite
openssl s_client -connect localhost:8443 -tls1_3 2>&1 | grep "Cipher"

# Expected: Strong cipher like:
# - TLS_AES_128_GCM_SHA256
# - TLS_AES_256_GCM_SHA384
# - TLS_CHACHA20_POLY1305_SHA256
```

## Test 2: SNI (Server Name Indication)

**Config:** `examples/config-sni.yaml`

**Start proxy:**
```bash
./aenebris examples/config-sni.yaml
```

**Tests:**

### Test SNI for api.localhost
```bash
# Request with Host: api.localhost
curl -k -H "Host: api.localhost" https://localhost:8443/

# Verify correct certificate
openssl s_client -connect localhost:8443 -servername api.localhost 2>&1 | grep "subject"

# Expected: subject=CN = api.localhost
```

### Test SNI for web.localhost
```bash
# Request with Host: web.localhost
curl -k -H "Host: web.localhost" https://localhost:8443/

# Verify correct certificate
openssl s_client -connect localhost:8443 -servername web.localhost 2>&1 | grep "subject"

# Expected: subject=CN = web.localhost
```

### Test Default Certificate
```bash
# Request with unknown hostname
curl -k -H "Host: unknown.localhost" https://localhost:8443/

# Verify default certificate is used
openssl s_client -connect localhost:8443 -servername unknown.localhost 2>&1 | grep "subject"

# Expected: subject=CN = default.localhost
```

### Test SNI Routing
```bash
# Verify api.localhost routes to port 8001 backend
curl -k -H "Host: api.localhost" https://localhost:8443/

# Verify web.localhost routes to port 8002 backend
curl -k -H "Host: web.localhost" https://localhost:8443/

# Check backend logs to confirm correct routing
```

## Test 3: Security Validation

### Test Strong Ciphers Only
```bash
# Try to connect with weak cipher (should fail)
openssl s_client -connect localhost:8443 -cipher DES-CBC3-SHA 2>&1 | grep -i "error\|alert"

# Expected: Connection should fail, 3DES not allowed
```

### Test HSTS Enforcement
```bash
# Check HSTS header prevents downgrade
curl -k -I https://localhost:8443/ | grep -i "strict-transport"

# Expected: Strict-Transport-Security: max-age=2592000; includeSubDomains
```

### Test X-Powered-By Removal
```bash
# Verify X-Powered-By is stripped
curl -k -I https://localhost:8443/ | grep -i "powered-by"

# Expected: No X-Powered-By header present
```

### Test Server Header Customization
```bash
# Check Server header
curl -k -I https://localhost:8443/ | grep -i "server:"

# Expected: Server: Aenebris (not revealing version)
```

## Test 4: Performance

### Test Connection Reuse
```bash
# Make multiple requests with keep-alive
for i in {1..10}; do
  curl -k -s -o /dev/null -w "Time: %{time_total}s\n" https://localhost:8443/
done

# Expected: First request slower (handshake), subsequent faster (reuse)
```

### Test Concurrent Connections
```bash
# Benchmark with multiple concurrent connections
# Using 'hey' tool (install: go install github.com/rakyll/hey@latest)
hey -n 1000 -c 10 -disable-keepalive https://localhost:8443/

# Or using Apache Bench:
ab -n 1000 -c 10 -k https://localhost:8443/

# Expected: Should handle concurrent requests without errors
```

## Test 5: Error Handling

### Test Invalid Certificate Path
Edit config with invalid cert path, should see clear error:
```yaml
tls:
  cert: /nonexistent/cert.pem
  key: /nonexistent/key.pem
```

**Expected:**
```
ERROR: Failed to load TLS certificate
  CertFileNotFound "/nonexistent/cert.pem"
```

### Test Mismatched Cert/Key
Use wrong key for certificate, should fail gracefully with clear error.

### Test Missing SNI Default
Remove `default_cert` from SNI config, should fail validation:
```
SNI configuration error: sni, default_cert, and default_key required
```

## Success Criteria

✅ All tests pass
✅ TLS 1.2 and TLS 1.3 work
✅ TLS 1.0/1.1 rejected
✅ HTTP → HTTPS redirect works
✅ SNI correctly routes to different backends
✅ Strong ciphers only
✅ All security headers present
✅ HTTP/2 negotiated via ALPN
✅ No X-Powered-By leakage
✅ Clear error messages for misconfigurations

## SSL Labs Testing (Optional)

For production deployments, test with SSL Labs:

1. Deploy to public server with real domain
2. Visit https://www.ssllabs.com/ssltest/
3. Enter your domain
4. **Target: A+ rating**

Key requirements for A+:
- TLS 1.2 minimum
- Strong cipher suites
- HSTS with long max-age
- No vulnerabilities (BEAST, POODLE, Heartbleed, etc.)
- Perfect Forward Secrecy
- HTTP Strict Transport Security
