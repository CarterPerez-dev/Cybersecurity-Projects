# Architecture and Design Decisions

This doc explains why the package is built the way it is. Not how to use it, but why certain decisions were made.

## The Three Layer Defense Model

The limiter uses three layers of protection that work together:

1. **Per user, per endpoint** - Each user gets their own limit for each endpoint
2. **Per endpoint global** - Each endpoint has an overall limit across all users
3. **Circuit breaker** - Global kill switch when things go really wrong

Why three layers? Because different attacks hit different surfaces.

A credential stuffing attack hammers one endpoint (`/login`) from many IPs. Per user limits do not help because each IP only tries a few times. You need a global endpoint limit.

A single abusive user with a valid account might scrape your entire API. Global limits do not help because they are lost in normal traffic. You need per user limits.

A massive DDoS might overwhelm everything. Individual limits cannot keep up with the volume. You need a circuit breaker that just shuts things down temporarily.

```
Request
   │
   ▼
┌─────────────────────┐
│ Per User/Endpoint   │ ─── Stops individual abuse
└─────────────────────┘
   │
   ▼
┌─────────────────────┐
│ Per Endpoint Global │ ─── Stops coordinated attacks
└─────────────────────┘
   │
   ▼
┌─────────────────────┐
│ Circuit Breaker     │ ─── Emergency stop
└─────────────────────┘
   │
   ▼
 Allowed
```

## Why Fail Open is the Default

When Redis goes down, you have two choices:

1. **Fail closed** - Block all requests until Redis comes back
2. **Fail open** - Allow all requests until Redis comes back

This package defaults to fail open. Here is why.

Rate limiting is a protective measure, not a core business function. If your rate limiter fails, the worst case is some extra load for a few minutes. If you fail closed, your entire API goes down.

Think about it from an attacker's perspective. If they know you fail closed, they just need to DoS your Redis instance and your whole API dies. You turned a rate limiting dependency into a single point of failure.

The fail open approach includes an in-memory fallback. When Redis is unreachable, the limiter switches to local memory storage. It is not perfect (each server instance counts separately) but it is better than nothing and way better than blocking everything.

```python
# What happens internally
try:
    return await redis_storage.check(key, limit)
except RedisConnectionError:
    logger.warning("Redis down, using memory fallback")
    return await memory_storage.check(key, limit)
```

You can change this behavior with `FAIL_OPEN=False` if your use case genuinely requires fail closed semantics. But think hard about whether you actually need that.

## Why Redis Needs Lua Scripts

Rate limiting seems simple: read counter, increment, check limit. But there is a race condition hiding in plain sight.

```python
# This looks fine but it is broken
count = await redis.get(key)
if count < limit:
    await redis.incr(key)
    return allowed
return denied
```

The problem: between the GET and INCR, another request can sneak in.

```
Request A: GET key -> 99
Request B: GET key -> 99
Request A: 99 < 100, so INCR -> 100
Request B: 99 < 100, so INCR -> 101  # Limit bypassed!
```

This is not theoretical. Under load, this happens constantly. Attackers can deliberately time requests to exploit it.

The fix is atomic operations. Redis Lua scripts run as a single atomic unit. Nothing can interleave.

```lua
local count = tonumber(redis.call('GET', key)) or 0
if count < limit then
    redis.call('INCR', key)
    return 1  -- allowed
end
return 0  -- denied
```

We also use EVALSHA instead of EVAL. EVAL sends the entire script text every time. EVALSHA sends a 40 byte hash and Redis looks up the cached script. Saves bandwidth on every single request.

## Composite Fingerprinting

IP based rate limiting has an obvious problem: attackers can rotate IPs.

Botnets have millions of IPs. Cloud providers give you a new IP every few seconds. IPv6 lets you control billions of addresses from a single allocation.

Composite fingerprinting combines multiple signals to identify clients:

```
IP Address
    +
User-Agent
    +
Accept Headers
    +
Auth Token (hashed)
    =
Fingerprint
```

The idea is that while IPs are easy to rotate, the combination of browser characteristics is harder to fake consistently. A real browser has a specific User-Agent, accepts specific encodings and languages, and generally looks consistent across requests.

An attacker scripting requests often:
- Uses a generic or missing User-Agent
- Has inconsistent or minimal Accept headers
- Changes these values between requests (which itself is a signal)

The fingerprint levels:

| Level | What it uses | When to use |
|-------|--------------|-------------|
| RELAXED | Just IP | High volume public APIs, CDN cached content |
| NORMAL | IP + User-Agent | Most APIs (default) |
| STRICT | IP + User-Agent + Accept + Auth | Sensitive endpoints, auth flows |

Stricter is not always better. STRICT mode might accidentally rate limit legitimate users behind corporate proxies who share an IP but have different auth tokens.

## IPv6 Requires Special Handling

Most rate limiters treat each IP as unique. This is fine for IPv4 where addresses are scarce.

IPv6 is different. ISPs typically allocate a /64 prefix to each customer, which means one user controls 18 quintillion addresses. They can rotate through a new IP for every single request and never repeat.

The fix is to normalize IPv6 addresses to their /64 prefix before using them as rate limit keys.

```python
from ipaddress import ip_address, ip_network

def normalize_ip(ip: str) -> str:
    addr = ip_address(ip)
    if addr.version == 6:
        # Treat entire /64 as one "user"
        network = ip_network(f"{ip}/64", strict=False)
        return str(network.network_address)
    return ip
```

Now `2001:db8::1` and `2001:db8::ffff:ffff:ffff:ffff` become the same key: `2001:db8::`.

The /64 choice is not arbitrary. It matches how ISPs actually allocate addresses to end users. Smaller prefixes risk grouping unrelated users. Larger prefixes miss the attack surface.

## Key Naming Strategy

Rate limit keys need to be:
- Unique per client/endpoint/window combination
- Predictable (so you can debug)
- Namespaced (so they do not collide with other Redis usage)

The format:
```
{prefix}:{version}:{layer}:{endpoint}:{identifier}:{window}
```

Example:
```
rl:v1:user:GET:/api/users:a1b2c3d4:60
```

Breaking it down:
- `rl` - Key prefix, configurable, avoids collision with other Redis keys
- `v1` - Version, lets you migrate key formats without clearing everything
- `user` - Layer (user, endpoint, or global)
- `GET:/api/users` - Endpoint including method (GET and POST are separate limits)
- `a1b2c3d4` - First 16 chars of fingerprint hash
- `60` - Window size in seconds

The version field is important for migrations. If you change how keys are structured, bump the version and old keys will naturally expire while new keys use the new format.

## Response Headers

The package adds standard rate limit headers to responses:

```
RateLimit-Limit: 100
RateLimit-Remaining: 67
RateLimit-Reset: 45
```

These follow the IETF draft standard (draft-ietf-httpapi-ratelimit-headers). Using standard headers means clients do not need custom code to handle your API.

When a request is blocked:

```
HTTP/1.1 420 Enhance Your Calm
Retry-After: 45
RateLimit-Limit: 100
RateLimit-Remaining: 0
RateLimit-Reset: 45
```

The Retry-After header tells clients exactly how long to wait. Good clients respect this. Bad clients ignore it and get blocked again.

## Why HTTP 420

The spec says to use 429 Too Many Requests. We use 420 instead.

Twitter invented 420 "Enhance Your Calm" for their rate limiting before the 429 standard existed. It is technically non-standard now but it is more memorable and honestly more fun.

The code works the same either way. We just return a different number and a message telling you to calm down.

If you genuinely need 429 for compatibility, you can catch `EnhanceYourCalm` and return your own response. But where is the fun in that?

## Storage Abstraction

The storage layer is abstracted so you can swap backends:

```python
class Storage(Protocol):
    async def increment(self, key: str, window: int, limit: int) -> Result
    async def get_window_state(self, key: str, window: int) -> State
    async def consume_token(self, key: str, capacity: int, rate: float) -> Result
    async def health_check(self) -> bool
    async def close(self) -> None
```

Currently implemented:
- **MemoryStorage** - Dict based, good for dev and single instance deployments
- **RedisStorage** - Lua script based, required for distributed deployments

The abstraction means you can add new backends (Memcached, DynamoDB, whatever) without touching the limiter logic.

MemoryStorage includes LRU eviction when you hit max keys. This prevents unbounded memory growth from attackers creating millions of unique fingerprints. The default is 100k keys which is about 2.4MB for sliding window counters.
