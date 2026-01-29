# How The Scanner Is Built

This doc explains the architecture decisions. Not how to use it, but why it works the way it does.

## The Layer Cake

The application follows a standard layered architecture.

```
┌─────────────────────────────────────┐
│            Routes (API)             │  FastAPI endpoints
├─────────────────────────────────────┤
│           Services                  │  Business logic
├─────────────────────────────────────┤
│     Repositories / Scanners         │  Data access / Scanning
├─────────────────────────────────────┤
│             Models                  │  SQLAlchemy ORM
├─────────────────────────────────────┤
│            Database                 │  PostgreSQL
└─────────────────────────────────────┘
```

**Routes** handle HTTP requests, validate input with Pydantic, and return responses. They do not contain business logic.

**Services** orchestrate operations. ScanService coordinates which scanners to run and saves results. AuthService handles user registration and login.

**Repositories** abstract database operations. This keeps SQL queries out of services and makes testing easier.

**Scanners** are the security testing engines. Each scanner inherits from BaseScanner and implements a scan() method.

## The Scanner Pattern

All scanners inherit from BaseScanner which provides common functionality.

```python
class BaseScanner(ABC):
    def __init__(self, target_url, auth_token, max_requests):
        self.target_url = target_url
        self.session = self._create_session()
        # ...

    def make_request(self, method, endpoint, **kwargs):
        # Rate limiting, retries, timing
        pass

    @abstractmethod
    def scan(self) -> TestResultCreate:
        # Implemented by each scanner
        pass
```

This design means:
- Common HTTP logic lives in one place
- Request spacing and retry logic is consistent
- Each scanner focuses only on its detection logic
- Adding a new scanner is straightforward

### Request Spacing

Scanners do not blast requests at targets. Each request is spaced to avoid overwhelming the target or triggering defensive rate limits.

```python
required_delay = 1.0 / (max_requests / window_seconds)
```

With default settings of 100 requests per 60 second window, that is about 600ms between requests. Random jitter is added to avoid predictable patterns.

This matters because:
1. You do not want to DoS your own production systems during testing
2. Aggressive scanning triggers alerts and gets you blocked
3. Some timing attacks need consistent baseline measurements

### Retry Logic

Requests that fail get retried with exponential backoff.

```python
retry_count = 0
backoff_factor = 2.0

while retry_count <= max_retries:
    response = session.request(method, url)

    if response.status_code == 429:
        wait_time = int(response.headers.get("Retry-After", default_wait))
        time.sleep(wait_time)
        retry_count += 1
        continue

    if response.status_code >= 500:
        wait_time = backoff_factor ** retry_count
        time.sleep(wait_time)
        retry_count += 1
        continue

    return response
```

429 responses respect the Retry-After header. 5xx errors trigger exponential backoff. This keeps the scanner resilient against temporary failures.

## Evidence Collection

Every scan result includes evidence. This is not just for debugging. Proper evidence is required for professional security reports.

```python
evidence = {
    "status_code": response.status_code,
    "response_time_ms": elapsed * 1000,
    "response_length": len(response.text),
    "headers": self._redact_sensitive_headers(dict(response.headers)),
    "payload": str(payload),
}
```

Sensitive headers are automatically redacted. You do not want authorization tokens showing up in scan reports.

```python
sensitive_headers = [
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
]
```

## The Service Layer

ScanService coordinates scans. It maps test types to scanner classes and handles the workflow.

```python
scanner_mapping = {
    TestType.RATE_LIMIT: RateLimitScanner,
    TestType.AUTH: AuthScanner,
    TestType.SQLI: SQLiScanner,
    TestType.IDOR: IDORScanner,
}

for test_type in scan_request.tests_to_run:
    scanner_class = scanner_mapping.get(test_type)
    scanner = scanner_class(target_url, auth_token, max_requests)
    result = scanner.scan()
    results.append(result)
```

If a scanner throws an exception, the service catches it and creates an error result. One failing scanner does not kill the entire scan.

```python
except Exception as e:
    results.append(
        TestResultCreate(
            test_name=test_type,
            status="error",
            details=f"Scanner error: {str(e)}",
        )
    )
```

## Database Design

Three main tables.

**users**: Account information. Passwords are bcrypt hashed.

**scans**: Metadata about each scan (who ran it, when, target URL).

**test_results**: Individual test outcomes linked to scans.

```
users (1) ──── (*) scans (1) ──── (*) test_results
```

Cascade deletes are configured so deleting a user removes their scans, and deleting a scan removes its test results.

## Rate Limiting The Scanner API

The scanner API itself is rate limited using slowapi.

```python
limiter = Limiter(key_func=get_remote_address)

@router.post("/")
@limiter.limit("5/minute")
async def create_scan(...):
    pass
```

Running security scans is expensive. Without rate limiting, someone could hammer your scanner with requests and either run up your bills or use it to attack third parties.

The scan endpoint has stricter limits than read endpoints. Creating a scan triggers potentially hundreds of requests to the target.

## Authentication Flow

JWT tokens with bcrypt password hashing.

```
1. User registers with email/password
2. Password is hashed with bcrypt (cost factor 12)
3. User logs in with credentials
4. Server validates password against hash
5. Server issues JWT with user ID and expiration
6. Client sends JWT in Authorization header
7. Server validates JWT on each request
```

The JWT contains minimal claims. Just enough to identify the user.

```python
{
    "sub": "user_id",
    "exp": expiration_timestamp
}
```

No roles or permissions in the token. Those are checked against the database on each request. This means you can revoke permissions instantly without waiting for token expiration.

## Error Handling Strategy

The application uses HTTPException for expected errors and lets unexpected errors bubble up.

```python
if not scan:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Scan not found",
    )

if scan.user_id != user_id:
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Not authorized to access this scan",
    )
```

FastAPI catches HTTPException and returns proper JSON error responses. Unhandled exceptions return 500 with minimal details (no stack traces in production).

## Configuration

Settings are loaded from environment variables with pydantic_settings.

```python
class Settings(BaseSettings):
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    DEBUG: bool = False
    DATABASE_URL: str
    JWT_SECRET_KEY: str
    # ...

    model_config = SettingsConfigDict(env_file=".env")
```

Defaults exist for development convenience but secrets like JWT_SECRET_KEY have no default. The application fails fast if required settings are missing.

## Why This Structure

The layered approach might seem like overkill for a scanner, but it pays off.

**Testing**: Each layer can be tested independently. Mock the repository to test services. Mock services to test routes.

**Extensibility**: Adding a new scanner means creating one file that inherits from BaseScanner. No changes to services or routes needed.

**Maintainability**: Database logic stays in repositories. HTTP logic stays in routes. Business logic stays in services. Changes are localized.

**Security**: Separation of concerns makes security review easier. Auth checks happen in one place. Input validation happens in one place.

## Adding A New Scanner

To add a new vulnerability scanner:

1. Create a new file in `scanners/`
2. Inherit from BaseScanner
3. Implement the scan() method
4. Add payloads to payloads.py if needed
5. Add the test type to core/enums.py
6. Add mapping in ScanService

```python
class XSSScanner(BaseScanner):
    def scan(self) -> TestResultCreate:
        # Detection logic here
        pass
```

The scanner pattern handles HTTP requests, retries, and evidence collection. You focus on the detection logic.
