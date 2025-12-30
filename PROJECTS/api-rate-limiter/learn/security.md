# Security Considerations and Common Mistakes

Rate limiting seems simple until you realize how many ways it can fail. This doc covers real vulnerabilities, attack vectors, and the mistakes that show up in CVEs over and over again.

## Real CVEs: What Goes Wrong

### CVE-2023-2531 (AzuraCast) - X-Forwarded-For Spoofing

CVSS 7.5. The `getIp()` method trusted the X-Forwarded-For header without validation.

```python
# What they did (broken)
def get_ip(request):
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0]
    return request.remote_addr
```

An attacker just sends:
```
X-Forwarded-For: 1.2.3.4
```

Now every request looks like it comes from a different IP. Rate limiting completely bypassed.

The fix is to only trust X-Forwarded-For from known proxy IPs:

```python
TRUSTED_PROXIES = {'10.0.0.1', '10.0.0.2'}

def get_ip(request):
    if request.remote_addr in TRUSTED_PROXIES:
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
    return request.remote_addr
```

This package has `TRUST_X_FORWARDED_FOR=False` by default. You have to explicitly enable it and should also configure `TRUSTED_PROXIES`.

### CVE-2023-46745 (LibreNMS) - Inconsistent Limit Application

Rate limiting was applied to POST `/login` but not GET `/login`. The login form could be submitted via GET with query parameters, bypassing limits entirely.

```
POST /login  <- rate limited
GET /login?username=x&password=y  <- not rate limited
```

The lesson: rate limit the action, not just a specific method. This package includes the HTTP method in the endpoint key by default (`GET:/api/data` vs `POST:/api/data`), but you need to make sure all paths to sensitive operations are covered.

### GHSA-984p-xq9m-4rjw (express-brute) - Race Conditions

Non-atomic counter updates allowed concurrent requests to bypass limits. Classic TOCTOU (time of check to time of use) bug.

```javascript
// Broken: gap between read and write
const count = await store.get(key);
if (count < limit) {
    await store.set(key, count + 1);  // Race condition here
    next();
}
```

Between the get and set, dozens of requests can sneak through. Under load, this completely defeats rate limiting.

This is why we use Redis Lua scripts. The entire check-and-increment runs atomically.

## Attack Vectors to Understand

### Header Spoofing

Any header can be spoofed. X-Forwarded-For, X-Real-IP, CF-Connecting-IP. Attackers know which headers your reverse proxy sets.

The only safe approach:
1. Know exactly which proxies sit in front of your app
2. Only trust forwarded headers from those specific IPs
3. Take the rightmost IP added by your trusted proxy, not the leftmost (which the client controls)

```
X-Forwarded-For: attacker-spoofed, real-proxy-added
                 ^                 ^
                 client controls   proxy controls
```

### GraphQL Batching

This one catches people off guard. GraphQL lets you batch multiple operations in one HTTP request:

```json
[
  {"query": "mutation { login(user: \"x\", pass: \"a\") }"},
  {"query": "mutation { login(user: \"x\", pass: \"b\") }"},
  {"query": "mutation { login(user: \"x\", pass: \"c\") }"}
]
```

That is one HTTP request but three login attempts. If you rate limit by request, you are letting 100 password guesses through per "request."

GraphQL endpoints need operation-level limiting:
- Count mutations, not requests
- Limit query depth and complexity
- Cap batch sizes (5-10 operations max)

### Slowloris and Connection Exhaustion

Rate limiting usually focuses on completed requests. But what about requests that never complete?

Slowloris attacks open many connections and send data very slowly, tying up server resources without triggering request-based limits.

This is outside the scope of application-level rate limiting. You need:
- Connection timeouts at the reverse proxy level
- Per-IP connection limits in nginx/haproxy
- Request body size limits

### IPv6 Address Rotation

Covered in the architecture doc, but worth repeating: a single residential IPv6 user controls 18 quintillion addresses in their /64 prefix.

```
2001:db8:abcd:1234::1
2001:db8:abcd:1234::2
2001:db8:abcd:1234::ffff:ffff:ffff:ffff
```

All controlled by the same person. If you rate limit per IP, they just rotate.

Normalize to /64 prefix before rate limiting:
```python
2001:db8:abcd:1234::1  ->  2001:db8:abcd:1234::
```

## Redis Security

Redis is a common target. Default installations often have no authentication and listen on all interfaces.

### CVE-2025-49844 (RediShell) - CVSS 10.0

Remote code execution through Lua sandbox escape. Affected around 330,000 exposed instances.

Protection:
1. Always require authentication (`requirepass`)
2. Bind to localhost only unless you specifically need network access
3. Use ACLs to restrict what the rate limiter can do
4. Disable dangerous commands

```redis
# Create a restricted user for rate limiting
ACL SETUSER ratelimiter on >strongpassword ~rl:* +EVALSHA +GET +SET +INCR +EXPIRE +TTL
```

This user can only:
- Run EVALSHA (our Lua scripts)
- Access keys starting with `rl:`
- Do basic counter operations

They cannot FLUSHALL, CONFIG, DEBUG, or do anything administrative.

### Key Expiration

Every rate limit key must have a TTL. Without expiration:
- Memory grows forever
- Old keys from users who never return pile up
- Attackers can create millions of keys by rotating identifiers

We set TTL to 2x the window size. A 60 second window gets a 120 second TTL. This ensures the key lives long enough for the sliding window to work, but expires after.

## Common Implementation Mistakes

### 1. Not Testing Under Load

Unit tests pass. Integration tests pass. Production gets slammed and requests slip through.

Race conditions only appear under concurrent load. You need to actually test with hundreds of simultaneous requests:

```python
async def test_concurrent_limit():
    tasks = [make_request() for _ in range(200)]
    results = await asyncio.gather(*tasks)

    allowed = sum(1 for r in results if r.status == 200)
    blocked = sum(1 for r in results if r.status == 420)

    # With limit of 100, should see ~100 allowed, ~100 blocked
    assert 95 <= allowed <= 105
```

### 2. Blocking Logging

```python
# Bad: blocks the event loop
logger.info(f"Rate limited {ip}")  # Synchronous I/O
```

Under attack, you might rate limit thousands of requests per second. Synchronous logging blocks the event loop and slows everything down.

Use async logging, batch writes, or background tasks:

```python
# Better: non-blocking
background_tasks.add_task(log_violation, ip, endpoint)
```

### 3. Forgetting TTLs

```python
# Bad: key lives forever
await redis.incr(key)

# Good: key expires
await redis.incr(key)
await redis.expire(key, window_seconds * 2)
```

Actually even better, do it atomically in Lua so there is no gap where the key exists without a TTL.

### 4. Integer Overflow

At extreme scale, counters can overflow. Python handles big integers fine, but Redis stores numbers as 64-bit signed integers. Max value is about 9.2 quintillion.

You probably will not hit this, but if you are doing high volume with long windows, consider it.

### 5. Clock Drift

Distributed systems with multiple app servers can have clock skew. Server A thinks it is 10:00:00, Server B thinks it is 10:00:02.

For sliding window, use Redis server time instead of local time:

```python
server_time = await redis.time()  # Returns (seconds, microseconds)
```

Now all servers agree on what time it is.

### 6. Fail Closed Without Monitoring

If you choose to fail closed (block all requests when Redis is down), you absolutely need monitoring and alerting on Redis availability.

Otherwise Redis goes down at 3am, your API becomes completely unavailable, and you do not find out until customers complain.

### 7. Overly Strict Fingerprinting

STRICT fingerprinting mode includes Accept headers and auth tokens. But this can cause problems:

- Same user on different browsers gets different fingerprints
- API clients with slightly different Accept headers look like different users
- Token rotation creates new fingerprints

Start with NORMAL (IP + User-Agent) and only go stricter if you have a specific problem to solve.

## OWASP API4:2023 - Unrestricted Resource Consumption

Rate limiting directly addresses OWASP API4, which identifies these failure modes:

- Missing or inadequate rate limiting
- Lack of payload size limits
- No execution timeouts
- Unlimited resource allocation per request

A complete defense includes:
- Request rate limits (what this package does)
- Payload size limits (configure in your web server)
- Execution timeouts (configure in your ASGI server)
- Memory limits (configure at the container/process level)

Rate limiting is one layer. You need the others too.

## Testing Your Implementation

### Verify limits actually work

```bash
# Send 110 requests, expect ~100 to succeed
for i in {1..110}; do
    curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/api/test
done | sort | uniq -c
```

Should see roughly 100 responses of 200 and 10 responses of 420.

### Verify headers are present

```bash
curl -i http://localhost:8000/api/test
```

Look for:
```
RateLimit-Limit: 100
RateLimit-Remaining: 99
RateLimit-Reset: 58
```

### Test concurrent requests

```python
import asyncio
import httpx

async def blast():
    async with httpx.AsyncClient() as client:
        tasks = [client.get("http://localhost:8000/api/test") for _ in range(200)]
        responses = await asyncio.gather(*tasks)

        codes = [r.status_code for r in responses]
        print(f"200: {codes.count(200)}, 420: {codes.count(420)}")

asyncio.run(blast())
```

### Test failover

```bash
# Stop Redis
docker stop redis

# Requests should still work (fail open)
curl http://localhost:8000/api/test

# Check logs for fallback warning
```

## Reporting Security Issues

If you find a security vulnerability in this package, do not open a public issue. Email the maintainer directly so it can be fixed before disclosure.
