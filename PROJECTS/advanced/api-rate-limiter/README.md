# fastapi-420

Production rate limiting for FastAPI. Uses HTTP code 420 "Enhance Your Calm" because 429 is boring.

## Installation

```bash
pip install fastapi-420
```

For Redis support:

```bash
pip install fastapi-420[redis]
```

## Quick Start

Three ways to add rate limiting. Pick what fits your app.

### Middleware (global)

Limits all routes automatically.

```python
from fastapi import FastAPI
from fastapi_420 import RateLimiter, RateLimitMiddleware

app = FastAPI()
limiter = RateLimiter()

app.add_middleware(
    RateLimitMiddleware,
    limiter=limiter,
    default_limit="100/minute",
)

@app.get("/")
async def root():
    return {"message": "hello"}
```

### Decorator (per route)

Fine grained control on specific endpoints.

```python
from fastapi import FastAPI, Request
from fastapi_420 import RateLimiter

app = FastAPI()
limiter = RateLimiter()

@app.get("/search")
@limiter.limit("30/minute")
async def search(request: Request, q: str):
    return {"results": []}

@app.post("/upload")
@limiter.limit("5/minute", "20/hour")
async def upload(request: Request):
    return {"status": "ok"}
```

### Dependency (FastAPI style)

Works with FastAPI's dependency injection.

```python
from fastapi import FastAPI, Depends
from fastapi_420 import RateLimiter, RateLimitDep, set_global_limiter

app = FastAPI()
limiter = RateLimiter()
set_global_limiter(limiter)

@app.get("/api/data", dependencies=[Depends(RateLimitDep("50/minute"))])
async def get_data():
    return {"data": []}
```

## Common Patterns

### Different limits for different endpoints

Auth endpoints get strict limits. Public endpoints stay relaxed.

```python
from fastapi_420 import ScopedRateLimiter

auth_limiter = ScopedRateLimiter(
    prefix="/auth",
    default_rules=["5/minute"],
    endpoint_rules={
        "POST:/auth/login": ["3/minute", "10/hour"],
        "POST:/auth/register": ["2/minute"],
    },
)

@app.post("/auth/login", dependencies=[Depends(auth_limiter)])
async def login():
    ...
```

### Using Redis

Memory storage works fine for single instances. Redis for distributed apps.

```python
from fastapi_420 import RateLimiter, RateLimiterSettings, StorageSettings

settings = RateLimiterSettings(
    storage=StorageSettings(
        REDIS_URL="redis://localhost:6379/0",
    ),
)

limiter = RateLimiter(settings=settings)
```

If Redis goes down, the limiter falls back to memory automatically.

### Trusting proxy headers

Behind nginx or a load balancer? Trust the forwarded headers.

```python
from fastapi_420 import FingerprintSettings, RateLimiterSettings

settings = RateLimiterSettings(
    fingerprint=FingerprintSettings(
        TRUST_X_FORWARDED_FOR=True,
    ),
)
```

### Custom identification

Rate limit by user ID instead of IP.

```python
def get_user_id(request):
    return request.state.user_id or request.client.host

@app.get("/api/resource")
@limiter.limit("100/minute", key_func=get_user_id)
async def resource(request: Request):
    ...
```

## Configuration Reference

All settings with their defaults.

### RateLimiterSettings

```python
from fastapi_420 import RateLimiterSettings
from fastapi_420.types import Algorithm

RateLimiterSettings(
    # Algorithm
    ALGORITHM=Algorithm.SLIDING_WINDOW,  # SLIDING_WINDOW | TOKEN_BUCKET | FIXED_WINDOW

    # Defaults applied when no rules specified
    DEFAULT_LIMIT="100/minute",
    DEFAULT_LIMITS=["100/minute"],       # list form, multiple rules

    # Storage key configuration
    KEY_PREFIX="rl",
    KEY_VERSION="v1",

    # Response behavior
    INCLUDE_HEADERS=True,                # add RateLimit-* headers
    HTTP_420_MESSAGE="Enhance Your Calm",
    HTTP_420_DETAIL={"error": "rate_limit_exceeded", "message": "Enhance Your Calm"},

    # Failure handling
    FAIL_OPEN=True,                      # allow requests if storage fails
    LOG_VIOLATIONS=True,                 # log when limits exceeded

    # Nested settings (see below)
    storage=StorageSettings(...),
    fingerprint=FingerprintSettings(...),
)
```

### StorageSettings

```python
from fastapi_420 import StorageSettings

StorageSettings(
    # Redis (optional, falls back to memory if not set or unavailable)
    REDIS_URL=None,                      # "redis://localhost:6379/0"
    REDIS_KEY_PREFIX="rl",
    REDIS_SOCKET_TIMEOUT=5.0,
    REDIS_SOCKET_CONNECT_TIMEOUT=5.0,
    REDIS_MAX_CONNECTIONS=50,
    REDIS_RETRY_ON_TIMEOUT=True,
    REDIS_HEALTH_CHECK_INTERVAL=30,

    # Memory storage
    MEMORY_MAX_KEYS=100_000,             # max keys before LRU eviction
    MEMORY_CLEANUP_INTERVAL=60,          # seconds between expired key cleanup
)
```

### FingerprintSettings

Controls how clients are identified. Higher levels are stricter but may cause issues with legitimate users behind proxies.

```python
from fastapi_420 import FingerprintSettings
from fastapi_420.types import FingerprintLevel

FingerprintSettings(
    LEVEL=FingerprintLevel.NORMAL,       # RELAXED | NORMAL | STRICT

    # What to trust
    TRUST_X_FORWARDED_FOR=False,         # trust X-Forwarded-For header
    TRUSTED_PROXIES=[],                  # IPs that can set forwarded headers

    # IPv6 handling
    IPV6_PREFIX_LENGTH=64,               # normalize IPv6 to /64 prefix
)
```

**Fingerprint Levels:**

| Level | What it uses |
|-------|-------------|
| RELAXED | IP only |
| NORMAL | IP + User-Agent |
| STRICT | IP + User-Agent + Accept headers + Auth token hash |

### Algorithms

| Algorithm | Behavior | Best for |
|-----------|----------|----------|
| SLIDING_WINDOW | Smooth, accurate limits | Most cases (default) |
| TOKEN_BUCKET | Allows short bursts | APIs with bursty traffic |
| FIXED_WINDOW | Simple, less accurate at window edges | High performance needs |

## Rate Limit Format

Rules follow the pattern `{requests}/{period}`:

```
100/minute
50/hour
1000/day
10/second
```

Multiple rules stack. The most restrictive one applies:

```python
@limiter.limit("10/second", "100/minute", "1000/hour")
async def endpoint(request: Request):
    ...
```

## Running the Example

```bash
cd examples
docker compose up -d
pip install fastapi uvicorn
python app.py
```

Then hit http://localhost:8000/docs to see the API.

## Why 420?

Twitter used HTTP 420 "Enhance Your Calm" for rate limiting before switching to 429. It is more fun.

The exception is called `EnhanceYourCalm` and the response tells clients to chill out.

## License

MIT
