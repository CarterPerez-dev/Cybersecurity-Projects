# Implementation Guide

This document walks through the actual code. We'll build key features step by step and explain the decisions along the way.

## File Structure Walkthrough
```
backend/
├── main.py              # Application entry point
├── factory.py           # FastAPI app factory with middleware
├── config.py            # Environment variables and constants
├── core/
│   ├── database.py      # SQLAlchemy engine and session factory
│   ├── security.py      # Password hashing, JWT creation/validation
│   ├── dependencies.py  # FastAPI dependencies (auth, database)
│   └── enums.py         # Type-safe enums for status, severity, test types
├── models/
│   ├── Base.py          # Base model with common fields (id, timestamps)
│   ├── User.py          # User authentication model
│   ├── Scan.py          # Scan metadata model
│   └── TestResult.py    # Individual test results model
├── repositories/
│   ├── user_repository.py         # User database operations
│   ├── scan_repository.py         # Scan database operations
│   └── test_result_repository.py  # Test result database operations
├── routes/
│   ├── auth.py          # Registration and login endpoints
│   └── scans.py         # Scan CRUD endpoints
├── schemas/
│   ├── user_schemas.py        # Pydantic models for user data
│   ├── scan_schemas.py        # Pydantic models for scan data
│   └── test_result_schemas.py # Pydantic models for test results
├── services/
│   ├── auth_service.py  # Authentication business logic
│   └── scan_service.py  # Scan orchestration business logic
└── scanners/
    ├── base_scanner.py      # Common HTTP logic, retry handling
    ├── rate_limit_scanner.py # Rate limiting detection
    ├── auth_scanner.py      # Authentication vulnerability detection
    ├── sqli_scanner.py      # SQL injection detection
    ├── idor_scanner.py      # IDOR/BOLA detection
    └── payloads.py          # Attack payloads organized by type
```

## Building Authentication

### Step 1: Password Hashing with Bcrypt

What we're building: Secure password storage that protects user credentials even if the database is compromised.

The code lives in `backend/core/security.py:11-28`:
```python
import bcrypt
from jose import JWTError, jwt

def hash_password(password: str) -> str:
    """
    Hash a plain text password using bcrypt
    """
    password_bytes = password.encode("utf-8")  # Convert string to bytes
    salt = bcrypt.gensalt()  # Generate random salt (default 12 rounds)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")  # Convert bytes back to string for storage
```

**Why this code works:**
- **Line 18-19**: Bcrypt requires byte input, not strings. The encoding/decoding dance converts between Python strings and byte arrays.
- **Line 19**: `bcrypt.gensalt()` generates a unique salt for each password. The salt is embedded in the output hash, so you don't store it separately.
- **Line 20**: `bcrypt.hashpw()` does the actual hashing. With default 12 rounds, this intentionally takes ~100ms. That's the point - makes brute forcing expensive.
- **Line 21**: Convert back to string because SQLAlchemy's `String` column type expects strings, not bytes.

The verification function (`security.py:21-31`):
```python
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a hashed password
    """
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)
```

**What's happening:**
1. Convert both inputs to bytes
2. `bcrypt.checkpw()` extracts the salt from `hashed_bytes` (it's embedded in the hash)
3. Hashes `password_bytes` with that same salt
4. Compares the result - if they match, password is correct

**Common mistakes here:**
```python
# Wrong - storing plaintext
user.password = password  # Database breach = everyone's password leaked

# Wrong - using weak hashing
import hashlib
user.password = hashlib.md5(password.encode()).hexdigest()  # Fast = easy to brute force

# Wrong - forgetting to salt
user.password = hashlib.sha256(password.encode()).hexdigest()  # Rainbow tables break this

# Right - bcrypt with automatic salting
user.hashed_password = hash_password(password)  # Secure
```

### Step 2: JWT Token Creation

Now we need to create authentication tokens after successful login.

In `core/security.py:34-56`:
```python
from datetime import datetime, timedelta
from config import settings

def create_access_token(
    data: dict[str, str],
    expires_delta: timedelta | None = None
) -> str:
    """
    Create a JWT access token
    """
    to_encode = data.copy()  # Don't modify the original dict
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES  # 1440 = 24 hours
        )
    
    to_encode.update({"exp": expire})  # Add expiration claim
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,  # MUST be random, 256+ bits
        algorithm=settings.ALGORITHM  # "HS256"
    )
    return encoded_jwt
```

**Key parts explained:**

**Line 43** - Copy the data dict because we're about to modify it. If we mutated the original, the caller would see `{"sub": "user@example.com", "exp": 1234567890}` instead of just the email.

**Line 45-50** - Calculate when the token expires. If no `expires_delta` is passed, default to 24 hours from `config.py`. The `exp` claim is part of the JWT standard - libraries automatically check it.

**Line 52** - This is where the magic happens. The `jwt.encode()` function:
1. Converts `to_encode` dict to JSON
2. Base64 encodes it as the payload
3. Creates a header: `{"alg": "HS256", "typ": "JWT"}`
4. Computes HMAC-SHA256 signature using `SECRET_KEY`
5. Joins header.payload.signature with periods

The result looks like:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoxNzM4MzY4MDAwfQ.signature_here
```

**Why we do it this way:**
JWTs are stateless. The server doesn't need to store session data. When a request comes in with a JWT, the server verifies the signature and trusts the payload. This means you can scale horizontally - any backend instance can validate any token without coordinating with other instances or a shared session store.

**Alternative approaches:**
- **Session-based auth**: Store session ID in cookie, look up user data on each request. Simpler but requires session storage (Redis, database). Doesn't scale as easily.
- **OAuth 2.0 with refresh tokens**: Short-lived access tokens (15 min) + long-lived refresh tokens. More secure (can revoke refresh tokens) but more complex to implement.

### Step 3: Token Validation

When a protected endpoint receives a request, we need to validate the JWT and load the user.

The dependency injection function in `core/dependencies.py:17-49`:
```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from .security import decode_token
from .database import get_db
from repositories.user_repository import UserRepository
from schemas.user_schemas import UserResponse

security = HTTPBearer()  # Extracts "Authorization: Bearer <token>" header

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    FastAPI dependency to extract and verify the current authenticated user
    """
    try:
        # Decode and verify the JWT
        payload = decode_token(credentials.credentials)
        email: str | None = payload.get("sub")
        
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Load user from database
        user = UserRepository.get_by_email(db, email)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return UserResponse.model_validate(user)
    
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
```

**What's happening:**

**Line 27** - `HTTPBearer()` is FastAPI's built-in extractor for `Authorization: Bearer <token>` headers. It parses the header and gives us the token string in `credentials.credentials`.

**Line 35** - Call `decode_token()` which lives in `security.py:48-62`:
```python
def decode_token(token: str) -> dict[str, str]:
    """
    Decode and verify a JWT token
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]  # Only accept HS256
        )
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {str(e)}") from e
```

This verifies:
- Signature is valid (token wasn't tampered with)
- Algorithm matches expected (prevents "none" algorithm attack)
- Token hasn't expired (checks `exp` claim automatically)

**Line 36** - Extract the `sub` (subject) claim. This is the user identifier we put in the token during login.

**Line 38-43** - If `sub` is missing, the token is malformed. Return 401 with `WWW-Authenticate` header per HTTP standards.

**Line 46** - Load the full user record from the database. We could skip this and just use the email from the token, but loading from DB ensures:
- User still exists (wasn't deleted after token was issued)
- User is still active (wasn't deactivated)
- We get the full user object with all fields

**Line 48-52** - If user doesn't exist in database, token is invalid. This catches deleted users with valid tokens.

**Line 54** - Convert SQLAlchemy model to Pydantic schema. This excludes `hashed_password` from the response (Pydantic schema doesn't include it).

**Line 56-61** - Catch `ValueError` from `decode_token()` and convert to HTTP 401. The `from None` suppresses the chained exception traceback - cleaner error messages for clients.

### Testing Authentication

How to verify this works:
```bash
# Register a user
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123"
  }'

# Response: {"id": 1, "email": "test@example.com", ...}

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123"
  }'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}

# Use token to access protected endpoint
curl http://localhost:8000/scans/ \
  -H "Authorization: Bearer eyJ..."

# Response: [list of scans]
```

Expected output: First request creates user, second returns JWT, third returns scans array (empty initially).

If you see `401 Unauthorized`, check:
- Token is being sent in header (not query param, not body)
- Format is exactly `Bearer <token>` with capital B
- Token hasn't expired (24 hours from login)
- User still exists in database

## Building SQL Injection Detection

### The Problem

We need to detect three types of SQL injection:
1. **Error-based** - Database errors leak information
2. **Boolean-based blind** - Responses differ for true/false conditions
3. **Time-based blind** - Database delays reveal injection

### The Solution

Use payload libraries and response analysis to detect each type. The scanner lives in `backend/scanners/sqli_scanner.py`.

### Implementation

Starting with error-based detection (`sqli_scanner.py:51-94`):
```python
def _test_error_based_sqli(self) -> dict[str, Any]:
    """
    Test for error based SQL injection
    
    Detects database errors in responses indicating SQLi vulnerability
    """
    error_signatures = SQLiPayloads.get_error_signatures()
    
    basic_payloads = SQLiPayloads.BASIC_AUTHENTICATION_BYPASS
    
    for payload in basic_payloads:
        try:
            response = self.make_request("GET", f"/?id={payload}")
            
            response_text_lower = response.text.lower()
            
            # Look for database error signatures
            for db_type, signatures in error_signatures.items():
                for signature in signatures:
                    if signature in response_text_lower:
                        return {
                            "vulnerable": True,
                            "database_type": db_type,
                            "payload": payload,
                            "status_code": response.status_code,
                            "error_signature": signature,
                            "response_excerpt": response.text[:500],
                        }
        
        except Exception:
            continue  # Network errors don't indicate SQLi
    
    return {
        "vulnerable": False,
        "payloads_tested": len(basic_payloads),
        "description": "No database errors detected",
    }
```

**Key parts explained:**

**Line 57** - Load error signatures from `scanners/payloads.py:9-30`. These are database-specific error messages:
```python
ERROR_SIGNATURES = {
    "mysql": [
        "sql syntax",
        "mysql_fetch",
        "mysql error",
    ],
    "postgres": [
        "postgresql",
        "pg_query",
        "syntax error",
    ],
    "mssql": [
        "sqlserver jdbc driver",
        "sqlexception",
    ],
}
```

**Line 59** - Basic payloads like `' OR '1'='1`, `' OR 1=1--`, `admin'--` from `payloads.py:33-48`.

**Line 63** - Make request with payload in query parameter. If the backend does:
```python
query = f"SELECT * FROM users WHERE id = {request.args['id']}"
```

And we send `id=' OR 1=1--`, it becomes:
```sql
SELECT * FROM users WHERE id = ' OR 1=1--'
```

That's invalid SQL. Database returns error: `"You have an error in your SQL syntax"`.

**Line 65** - Convert response to lowercase for case-insensitive matching. Error messages vary: "SQL syntax", "Sql Syntax", "sql syntax".

**Line 68-72** - Check each signature against response. If `"sql syntax"` appears in the HTML, we found SQLi.

**Line 73-79** - Return evidence: which payload worked, what database type was detected, the actual error message (first 500 chars).

**Line 81-82** - Network errors (timeout, connection refused) don't mean SQLi. Skip to next payload.

**Line 84-88** - No errors found across all payloads = not vulnerable (to error-based SQLi at least).

### Boolean-Based Blind Detection

When errors are suppressed, check if responses differ for true vs false conditions.

Code at `sqli_scanner.py:96-164`:
```python
def _test_boolean_based_sqli(self) -> dict[str, Any]:
    """
    Test for boolean based blind SQL injection
    
    Compares responses from true vs false conditions to detect SQLi
    """
    try:
        # Establish baseline
        baseline_response = self.make_request("GET", "/?id=1")
        baseline_length = len(baseline_response.text)
        baseline_status = baseline_response.status_code
        
        if baseline_status != 200:
            return {
                "vulnerable": False,
                "description": "Baseline request failed",
                "baseline_status": baseline_status,
            }
        
        boolean_payloads = SQLiPayloads.BOOLEAN_BASED_BLIND
        
        # Test true conditions: ' AND 1=1--
        true_payloads = [
            p for p in boolean_payloads
            if "AND '1'='1" in p or "AND 1=1" in p
        ]
        false_payloads = [
            p for p in boolean_payloads
            if "AND '1'='2" in p or "AND 1=2" in p or "AND 1=0" in p
        ]
        
        true_lengths = []
        for payload in true_payloads:
            response = self.make_request("GET", f"/?id={payload}")
            true_lengths.append(len(response.text))
        
        false_lengths = []
        for payload in false_payloads:
            response = self.make_request("GET", f"/?id={payload}")
            false_lengths.append(len(response.text))
        
        # Calculate averages
        avg_true = statistics.mean(true_lengths)
        avg_false = statistics.mean(false_lengths)
        
        length_diff = abs(avg_true - avg_false)
        
        # Significant difference indicates SQLi
        if length_diff > 100 and avg_true != avg_false:
            return {
                "vulnerable": True,
                "baseline_length": baseline_length,
                "true_condition_avg_length": avg_true,
                "false_condition_avg_length": avg_false,
                "length_difference": length_diff,
                "confidence": "HIGH" if length_diff > 500 else "MEDIUM",
            }
        
        return {
            "vulnerable": False,
            "description": "No boolean-based SQLi detected",
            "length_difference": length_diff,
        }
```

**What's happening:**

**Line 105-106** - Get baseline response with normal input (`id=1`). We need this to compare against.

**Line 121-128** - Split payloads into "always true" and "always false" conditions. 

True condition example: `1' AND 1=1--`
```sql
SELECT * FROM users WHERE id = 1' AND 1=1--'
```
The `1=1` is always true, so if vulnerable, this returns data.

False condition example: `1' AND 1=2--`
```sql
SELECT * FROM users WHERE id = 1' AND 1=2--'
```
The `1=2` is never true, so if vulnerable, this returns empty result.

**Line 130-141** - Send multiple true and false payloads, record response lengths.

**Line 144-147** - Calculate average length for true vs false. Statistical approach reduces false positives from network variance.

**Line 151** - If difference is significant (>100 bytes) and not zero, likely vulnerable. A difference of 500+ bytes is high confidence - probably seeing full records vs empty results.

**Why this works:**
If SQLi exists, true conditions return data (longer response), false conditions return nothing (shorter response). If no SQLi, both are treated as invalid input and return the same error page.

### Time-Based Blind Detection

Most sophisticated technique. Use database sleep functions to measure injection.

Code at `sqli_scanner.py:183-251`:
```python
def _test_time_based_sqli(self, delay_seconds: int = 5) -> dict[str, Any]:
    """
    Test for time based blind SQL injection
    
    Uses baseline timing comparison with statistical analysis
    for false positive reduction
    """
    try:
        # Establish baseline timing
        baseline_mean, baseline_stdev = self.get_baseline_timing("/")
        
        threshold = baseline_mean + (3 * baseline_stdev)
        expected_delay_time = baseline_mean + delay_seconds
        
        all_time_payloads = SQLiPayloads.TIME_BASED_BLIND
        
        # Group by database type
        delay_payloads = {
            "mysql": [p for p in all_time_payloads if "SLEEP" in p],
            "postgres": [p for p in all_time_payloads if "pg_sleep" in p],
            "mssql": [p for p in all_time_payloads if "WAITFOR" in p],
        }
        
        for db_type, payloads in delay_payloads.items():
            for payload in payloads:
                delay_times = []
                
                # Take multiple samples
                for _ in range(3):
                    try:
                        response = self.make_request(
                            "GET",
                            f"/?id={payload}",
                            timeout=delay_seconds + 10,
                        )
                        elapsed = getattr(response, "request_time", 0.0)
                        delay_times.append(elapsed)
                    
                    except Exception:
                        delay_times.append(delay_seconds + 10)  # Assume timeout = worked
                    
                    time.sleep(1)  # Space out requests
                
                avg_delay = statistics.mean(delay_times)
                
                # Check if delay matches expected
                if avg_delay >= expected_delay_time - 1:
                    confidence = "HIGH" if avg_delay >= expected_delay_time else "MEDIUM"
                    
                    return {
                        "vulnerable": True,
                        "database_type": db_type,
                        "payload": payload,
                        "baseline_time": f"{baseline_mean:.3f}s",
                        "response_time": f"{avg_delay:.3f}s",
                        "expected_delay": f"{expected_delay_time:.3f}s",
                        "confidence": confidence,
                        "individual_times": [f"{t:.3f}s" for t in delay_times],
                    }
```

**Important details:**

**Line 192** - Get baseline timing from `base_scanner.py:158-177`:
```python
def get_baseline_timing(
    self,
    endpoint: str,
    samples: int | None = None
) -> tuple[float, float]:
    """
    Establish baseline response time for an endpoint
    
    Takes multiple samples and calculates mean and standard deviation
    """
    if samples is None:
        samples = settings.DEFAULT_BASELINE_SAMPLES  # 10
    
    times = []
    
    for _ in range(samples):
        response = self.make_request("GET", endpoint)
        times.append(getattr(response, "request_time", 0.0))
        time.sleep(0.5)  # Space out samples
    
    return statistics.mean(times), statistics.stdev(times)
```

This makes 10 normal requests and calculates average and standard deviation. Example results:
- Mean: 0.15s
- Stdev: 0.02s

**Line 194** - Calculate threshold: `mean + 3*stdev`. With example above: `0.15 + 3*0.02 = 0.21s`. Any response over 0.21s is "unusually slow" (99.7% confidence if normally distributed).

**Line 195** - Expected delay: `baseline + 5s`. If baseline is 0.15s and we inject `SLEEP(5)`, we expect ~5.15s response.

**Line 200-204** - Group payloads by database. MySQL uses `SLEEP(5)`, Postgres uses `pg_sleep(5)`, MSSQL uses `WAITFOR DELAY '0:0:5'`.

**Line 211-225** - Take 3 samples of each payload. Network jitter can cause ±0.5s variance. Averaging 3 samples gives cleaner signal.

**Line 230** - If average delay is within 1 second of expected (5.15s ± 1s), that's SQLi. The 1 second tolerance accounts for network overhead.

**Why this works:**
Payloads like `1'; SELECT SLEEP(5)--` execute the sleep if SQLi exists. The response takes 5 extra seconds. Without SQLi, the payload is just treated as invalid input and returns immediately.

## Security Implementation

### JWT Signature Validation

Critical to prevent token forgery. The none algorithm attack test in `auth_scanner.py:168-213`:
```python
def _test_none_algorithm(self) -> dict[str, Any]:
    """
    Test if server accepts JWT with 'none' algorithm
    
    Critical vulnerability: allows unsigned tokens to be accepted
    """
    try:
        header, payload, signature = self.auth_token.split(".")
        
        none_variants = AuthPayloads.get_jwt_none_variants()
        # ["none", "None", "NONE", "nOnE", "NoNe", "NOne"]
        
        for variant in none_variants:
            # Create malicious header
            malicious_header = self._base64url_encode(
                json.dumps({"alg": variant, "typ": "JWT"})
            )
            
            # Remove signature (trailing period means "no signature")
            malicious_token = f"{malicious_header}.{payload}."
            
            response = self.make_request(
                "GET",
                "/",
                headers={"Authorization": f"Bearer {malicious_token}"}
            )
            
            if response.status_code == 200:
                return {
                    "vulnerable": True,
                    "vulnerability_type": "JWT None Algorithm",
                    "algorithm_variant": variant,
                    "status_code": response.status_code,
                    "recommendations": [
                        "Reject tokens with 'none' algorithm (all case variations)",
                        "Explicitly verify signature before accepting tokens",
                        "Use allowlist of accepted algorithms",
                    ],
                }
        
        return {
            "vulnerable": False,
            "description": "None algorithm properly rejected",
        }
```

**What this prevents:**

Normal JWT: `header.payload.signature`
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.signature
```

Malicious JWT: `header.payload.` (no signature)
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

Decoded malicious header:
```json
{"alg": "none", "typ": "JWT"}
```

Decoded malicious payload:
```json
{"sub": "admin"}
```

If the server accepts this, attacker can forge tokens with any user identity.

**How to defend:**

The project's JWT validation (`core/security.py:54-57`) explicitly specifies algorithms:
```python
payload = jwt.decode(
    token,
    settings.SECRET_KEY,
    algorithms=[settings.ALGORITHM]  # ["HS256"] - none not in this list
)
```

The `algorithms` parameter is an allowlist. The library will reject tokens with `alg: none` because it's not in `["HS256"]`.

**What NOT to do:**
```python
# BAD - accepts any algorithm
payload = jwt.decode(token, settings.SECRET_KEY)

# BAD - doesn't verify signature
payload = jwt.decode(token, options={"verify_signature": False})

# BAD - allows none
payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256", "none"])
```

### IDOR Prevention Pattern

Authorization checks in `services/scan_service.py:67-84`:
```python
@staticmethod
def get_scan_by_id(db: Session, scan_id: int, user_id: int) -> ScanResponse:
    """
    Get scan by ID with authorization check
    """
    scan = ScanRepository.get_by_id(db, scan_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # CRITICAL: Check if user owns this scan
    if scan.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this scan",
        )
    
    return ScanResponse.model_validate(scan)
```

**Why 404 before 403:**
Line 75-78 returns 404 if scan doesn't exist, BEFORE checking ownership. This prevents information disclosure.

If we checked ownership first:
- Request scan 999 (doesn't exist) → 404 "Scan not found"
- Request scan 123 (exists, belongs to someone else) → 403 "Not authorized"

Now attacker knows scan 123 exists. They can enumerate all scan IDs and find which ones are valid.

Better approach:
- Request scan 999 → 404
- Request scan 123 → 404

Can't tell difference between "doesn't exist" and "exists but you can't access it". Leak less information.

**The authorization check:**
Line 81-84 compares `scan.user_id` (owner) with `user_id` (requester). If they don't match, return 403.

This happens at the service layer, NOT the route layer. Every code path that retrieves scans goes through the service, so we can't forget the check.

## Data Flow Example

Let's trace a complete request through the system: User creates a scan that tests for SQLi.

### Request Comes In

Entry point: `routes/scans.py:23-37`
```python
@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.API_RATE_LIMIT_SCAN)  # "15/minute"
async def create_scan(
    request: Request,
    scan_request: ScanRequest,  # Pydantic validates this
    db: Session = Depends(get_db),  # Injects database session
    current_user: UserResponse = Depends(get_current_user),  # Validates JWT
) -> ScanResponse:
    """
    Create and execute a new security scan
    """
    return ScanService.run_scan(db, current_user.id, scan_request)
```

At this point:
- `scan_request` is validated by Pydantic (correct URL format, valid test types)
- `current_user` is authenticated (JWT was valid, user exists in database)
- `db` is a fresh SQLAlchemy session
- Rate limiting checked - if user exceeded 15 scans/minute, request was rejected before this function runs

What happens next: Call service layer to orchestrate the scan.

### Processing Layer

Service orchestrates scanners: `services/scan_service.py:23-65`
```python
@staticmethod
def run_scan(db: Session, user_id: int, scan_request: ScanRequest) -> ScanResponse:
    # Create scan record
    scan = ScanRepository.create_scan(
        db=db,
        user_id=user_id,
        target_url=str(scan_request.target_url),
    )
    
    # Map test types to scanner classes
    scanner_mapping: dict[TestType, type[BaseScanner]] = {
        TestType.RATE_LIMIT: RateLimitScanner,
        TestType.AUTH: AuthScanner,
        TestType.SQLI: SQLiScanner,
        TestType.IDOR: IDORScanner,
    }
    
    results: list[TestResultCreate] = []
    
    # Execute each requested test
    for test_type in scan_request.tests_to_run:
        scanner_class: type[BaseScanner] | None = scanner_mapping.get(test_type)
        
        if not scanner_class:
            continue  # Skip unknown test types
        
        try:
            scanner = scanner_class(
                target_url=str(scan_request.target_url),
                auth_token=scan_request.auth_token,
                max_requests=scan_request.max_requests,
            )
            
            result = scanner.scan()  # Execute the actual test
            results.append(result)
        
        except Exception as e:
            # Scanner crashed - return error result instead of failing entire scan
            results.append(
                TestResultCreate(
                    test_name=test_type,
                    status="error",
                    severity="info",
                    details=f"Scanner error: {str(e)}",
                    evidence_json={"error": str(e)},
                    recommendations_json=[
                        "Check target URL is accessible",
                        "Verify authentication token if provided",
                    ],
                )
            )
```

This code:
- Creates the scan record immediately (line 26-30) so it has an ID
- Maps test type enums to actual scanner classes (line 33-37)
- Loops through requested tests (line 42-60)
- Instantiates each scanner with target URL and auth token
- Calls `scanner.scan()` which returns `TestResultCreate` with findings
- Catches exceptions so one failing scanner doesn't kill the entire scan

### Storage/Output

Save results to database: `services/scan_service.py:62-65` continues:
```python
    # Save all results
    for result in results:
        TestResultRepository.create_test_result(
            db=db,
            scan_id=scan.id,
            test_name=result.test_name,
            status=result.status,
            severity=result.severity,
            details=result.details,
            evidence_json=result.evidence_json,
            recommendations_json=result.recommendations_json,
        )
    
    db.refresh(scan)  # Reload scan with test_results relationship populated
    
    return ScanResponse.model_validate(scan)
```

The result is a JSON response containing the scan with nested test results:
```json
{
  "id": 42,
  "user_id": 1,
  "target_url": "https://api.example.com/users",
  "scan_date": "2026-02-04T10:30:00Z",
  "created_at": "2026-02-04T10:30:00Z",
  "test_results": [
    {
      "id": 101,
      "scan_id": 42,
      "test_name": "sqli",
      "status": "vulnerable",
      "severity": "critical",
      "details": "Error-based SQL injection detected: mysql",
      "evidence_json": {
        "database_type": "mysql",
        "payload": "' OR 1=1--",
        "error_signature": "sql syntax"
      },
      "recommendations_json": [
        "Use parameterized queries (prepared statements)",
        "Never concatenate user input into SQL queries"
      ]
    }
  ]
}
```

## Error Handling Patterns

### Database Errors with Automatic Rollback

The `get_db()` dependency handles transaction management:
```python
# core/database.py:28-36
def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency for database sessions
    """
    db = SessionLocal()
    try:
        yield db  # Provide session to route handler
    finally:
        db.close()  # Always close, even if exception raised
```

If an exception occurs during request processing:
1. FastAPI catches it
2. Control returns to finally block
3. `db.close()` runs
4. SQLAlchemy automatically rolls back uncommitted transaction
5. Connection returned to pool

Example error scenario:
```python
@router.post("/scans/")
async def create_scan(db: Session = Depends(get_db), ...):
    scan = ScanRepository.create_scan(db, ...)  # INSERT INTO scans
    
    # Something goes wrong here
    raise ValueError("Oops")
    
    # This never runs
    TestResultRepository.create_test_result(db, ...)
```

Without explicit transaction handling:
- Scan record would be inserted
- Test result would not be inserted
- Database left in inconsistent state

With `get_db()` cleanup:
- ValueError propagates to FastAPI
- `db.close()` runs
- Scan INSERT is rolled back
- Database remains consistent

**What NOT to do:**
```python
# Bad - manual session management
db = SessionLocal()
try:
    scan = ScanRepository.create_scan(db, ...)
    db.commit()  # Committed before error could happen
    raise ValueError("Oops")
finally:
    db.close()

# Scan is committed, error occurs after - inconsistent state
```

### Scanner Timeout Recovery

Scanners use retry logic with exponential backoff (`base_scanner.py:92-156`):
```python
def make_request(
    self,
    method: str,
    endpoint: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Make HTTP request with retry logic and rate limit handling
    """
    self._wait_before_request()  # Implement request spacing
    
    url = urljoin(self.target_url, endpoint)
    retry_count = 0
    backoff_factor = 2.0
    
    kwargs.setdefault("timeout", settings.SCANNER_CONNECTION_TIMEOUT)
    
    while retry_count <= settings.DEFAULT_RETRY_COUNT:  # 3 retries
        try:
            start_time = time.time()
            response = self.session.request(method, url, **kwargs)
            
            # Track timing for time-based detection
            setattr(response, "request_time", time.time() - start_time)
            
            self.request_count += 1
            
            # Handle 429 Too Many Requests
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                wait_time = int(retry_after) if retry_after.isdigit() else 60
                time.sleep(wait_time)
                retry_count += 1
                continue  # Try again after waiting
            
            # Handle server errors with backoff
            if response.status_code >= 500 and retry_count < settings.DEFAULT_RETRY_COUNT:
                wait_time = backoff_factor ** retry_count  # 1s, 2s, 4s
                time.sleep(wait_time)
                retry_count += 1
                continue
            
            return response  # Success
        
        except (requests.Timeout, requests.ConnectionError):
            if retry_count < settings.DEFAULT_RETRY_COUNT:
                wait_time = backoff_factor ** retry_count
                time.sleep(wait_time)
                retry_count += 1
            else:
                raise  # Give up after 3 retries
    
    return response  # Return last response if loop completes
```

**Retry scenarios:**

1. **Timeout**: Wait 1s, retry. Still timeout? Wait 2s, retry. Still timeout? Wait 4s, retry. Still timeout? Raise exception.

2. **Connection refused**: Same exponential backoff strategy.

3. **429 Rate Limited**: Read `Retry-After` header, wait that long, retry. No exponential backoff needed - server told us exactly how long to wait.

4. **500 Server Error**: Exponential backoff, but only retry if `retry_count < 3`. After 3 attempts, return the 500 response (don't raise exception). Let caller decide how to handle.

## Performance Optimizations

### Before: Naive Database Queries (N+1 Problem)
```python
# Bad - triggers N+1 queries
@router.get("/scans/")
async def get_scans(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scans = db.query(Scan).filter(Scan.user_id == user.id).all()
    # SQL: SELECT * FROM scans WHERE user_id = 1
    
    for scan in scans:
        print(scan.test_results)  # Each access triggers new query!
        # SQL: SELECT * FROM test_results WHERE scan_id = 42
        # SQL: SELECT * FROM test_results WHERE scan_id = 43
        # ... repeated for each scan
    
    return scans
```

With 10 scans, 4 results each = 41 queries (1 + 10*4).

### After: Eager Loading with joinedload
```python
# Good - single query with JOIN
def get_by_user(db: Session, user_id: int) -> list[Scan]:
    return (
        db.query(Scan)
        .options(joinedload(Scan.test_results))  # Load relationship in same query
        .filter(Scan.user_id == user_id)
        .all()
    )
    # SQL: SELECT scans.*, test_results.* 
    #      FROM scans 
    #      LEFT JOIN test_results ON scans.id = test_results.scan_id
    #      WHERE scans.user_id = 1
```

Single query loads everything. Accessing `scan.test_results` uses already-loaded data, no additional query.

**Benchmarks:**
- Before: 41 queries, ~205ms (5ms per query)
- After: 1 query, ~15ms
- Improvement: **13x faster**

### Request Connection Pooling

Base scanner reuses HTTP session (`base_scanner.py:40-62`):
```python
def __init__(self, target_url: str, auth_token: str | None = None, ...):
    self.target_url = target_url.rstrip("/")
    self.auth_token = auth_token
    self.session = self._create_session()  # Created once
    
def _create_session(self) -> requests.Session:
    """
    Create persistent HTTP session with proper headers
    """
    session = requests.Session()
    
    session.headers.update({
        "User-Agent": f"{settings.APP_NAME}/{settings.VERSION}",
        "Accept": "application/json",
    })
    
    if self.auth_token:
        session.headers.update({"Authorization": f"Bearer {self.auth_token}"})
    
    return session
```

**Why this matters:**

Without session (making new request each time):
```python
# Each call creates new TCP connection
requests.get("https://api.example.com/endpoint1")  # Connect, TLS handshake, request, close
requests.get("https://api.example.com/endpoint2")  # Connect, TLS handshake, request, close
# 2 connections, 2 TLS handshakes
```

With session:
```python
session = requests.Session()
session.get("https://api.example.com/endpoint1")  # Connect, TLS handshake, request, keep-alive
session.get("https://api.example.com/endpoint2")  # Reuse connection, request
# 1 connection, 1 TLS handshake
```

TLS handshake takes 50-100ms. Over 100 requests, that's 5-10 seconds saved.

## Configuration Management

### Loading Config

All settings loaded from environment via Pydantic:
```python
# config.py:14-69
from functools import lru_cache
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="../.env",  # Load from .env file
        env_file_encoding="utf-8",
        case_sensitive=True  # DATABASE_URL != database_url
    )
    
    # Required fields (no default)
    DATABASE_URL: str
    SECRET_KEY: str
    
    # Optional fields (have defaults)
    APP_NAME: str = "API Security Tester"
    DEBUG: bool = False
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    @property
    def cors_origins_list(self) -> list[str]:
        """Convert comma-separated string to list"""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance
    
    @lru_cache ensures settings are loaded only once
    """
    return Settings()

settings = get_settings()
```

**Validation:**

Pydantic validates types at startup:
```python
# .env contains:
# DEBUG=not_a_boolean

# When Settings() instantiates:
# ValidationError: field required to be bool, got str 'not_a_boolean'
```

Application crashes immediately with clear error instead of mysterious runtime failures.

**Why cache with `@lru_cache`:**

Without cache:
```python
# Every import creates new Settings instance
from config import settings  # Loads .env
from config import settings  # Loads .env again
```

With cache:
```python
# First import loads .env
from config import settings  # Loads .env, caches result

# Subsequent imports reuse cached instance
from config import settings  # Returns cached Settings
```

Faster startup, consistent state across application.

## Database/Storage Operations

### Creating Records with Transactions

Repository method with explicit commit control:
```python
# repositories/scan_repository.py:13-32
@staticmethod
def create_scan(
    db: Session,
    user_id: int,
    target_url: str,
    commit: bool = True  # Allow caller to control commit
) -> Scan:
    """
    Create a new scan
    """
    scan = Scan(
        user_id=user_id,
        target_url=target_url,
        scan_date=datetime.now(UTC),
    )
    db.add(scan)
    
    if commit:
        db.commit()  # Flush to database
        db.refresh(scan)  # Reload to get auto-generated ID
    
    return scan
```

**Important details:**

- **Transaction management**: The `commit` parameter lets callers batch operations. Create scan + create results in single transaction.
- **Refresh after commit**: Line 30 reloads the object from database. This populates auto-generated fields like `id`, `created_at`, `updated_at`.
- **Foreign key constraints**: PostgreSQL enforces `test_results.scan_id` references `scans.id`. If we create test results before committing scan, foreign key check fails.

### Bulk Inserts for Performance

Creating test results in batch:
```python
# repositories/test_result_repository.py:52-67
@staticmethod
def bulk_create(
    db: Session,
    test_results: list[TestResult],
    commit: bool = True
) -> list[TestResult]:
    """
    Create multiple test results in bulk
    """
    db.add_all(test_results)  # Add all at once
    
    if commit:
        db.commit()
        for result in test_results:
            db.refresh(result)  # Refresh each to get IDs
    
    return test_results
```

**Why bulk insert:**

Individual inserts:
```python
for result in results:
    db.add(result)
    db.commit()  # Commit after each - 4 commits for 4 results
# 4 round trips to database
```

Bulk insert:
```python
db.add_all(results)
db.commit()  # Single commit for all 4 results
# 1 round trip to database
```

With 4 test results, bulk insert is 4x faster.

## Common Implementation Pitfalls

### Pitfall 1: Forgetting to Validate JWT Algorithm

**Symptom:**
Attacker sends token with `"alg": "none"` and gains admin access.

**Cause:**
```python
# Problematic code - accepts any algorithm
payload = jwt.decode(token, settings.SECRET_KEY)

# Attacker sends:
# eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
# (header: {"alg": "none"}, payload: {"sub": "admin"}, no signature)

# Library accepts it because no algorithm restriction
```

**Fix:**
```python
# Correct - explicitly allow only HS256
payload = jwt.decode(
    token,
    settings.SECRET_KEY,
    algorithms=["HS256"]  # Reject "none" and other algorithms
)
```

**Why this matters:**
Without algorithm validation, JWT security is completely bypassed. Attacker can forge tokens with any claims.

### Pitfall 2: SQL Injection in Raw Queries

**Symptom:**
Attacker sends `email=admin'--` and gets admin access.

**Cause:**
```python
# Vulnerable - concatenating user input
email = request.get("email")
query = f"SELECT * FROM users WHERE email = '{email}'"
db.execute(text(query))

# Becomes: SELECT * FROM users WHERE email = 'admin'--'
# Comment (--) removes password check
```

**Fix:**
```python
# Correct - parameterized query
email = request.get("email")
db.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email}
)

# SQLAlchemy escapes the email value safely
```

Or better, use ORM:
```python
# Best - ORM automatically parameterizes
db.query(User).filter(User.email == email).first()
```

**Why this matters:**
String concatenation treats user input as SQL code. Parameterization treats it as data.

### Pitfall 3: Missing Authorization Check

**Symptom:**
User can view other users' scans by changing scan ID in URL.

**Cause:**
```python
# Vulnerable - no ownership check
@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = ScanRepository.get_by_id(db, scan_id)
    if not scan:
        raise HTTPException(404)
    return scan  # Returns any scan, regardless of ownership
```

**Fix:**
```python
# Correct - verify ownership
@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = ScanRepository.get_by_id(db, scan_id)
    if not scan:
        raise HTTPException(404)
    
    if scan.user_id != current_user.id:
        raise HTTPException(403, detail="Not authorized")
    
    return scan
```

**Why this matters:**
Authentication proves who you are. Authorization proves what you can access. Both are required.

## Debugging Tips

### Issue Type 1: JWT Token Appears Invalid But Format Looks Correct

**Problem:** Getting 401 errors when using a token that decodes properly on jwt.io.

**How to debug:**

1. Check token expiration:
```python
import jwt
import datetime

token = "eyJ..."
decoded = jwt.decode(token, options={"verify_signature": False})  # Skip verification for debugging
print(decoded)
# {"sub": "user@example.com", "exp": 1704067200}

exp_time = datetime.datetime.fromtimestamp(decoded["exp"])
now = datetime.datetime.now()
print(f"Expires: {exp_time}, Now: {now}, Valid: {exp_time > now}")
```

2. Verify secret key matches:
```python
# In Python shell with access to settings
from config import settings
print(f"SECRET_KEY: {settings.SECRET_KEY}")
# Make sure this matches the key used to create the token
```

3. Check algorithm matches:
```python
# Decode header without verification
import base64
import json

token = "eyJ..."
header = token.split(".")[0]
# Add padding if needed
padding = 4 - (len(header) % 4)
if padding != 4:
    header += "=" * padding

decoded_header = json.loads(base64.urlsafe_b64decode(header))
print(decoded_header)
# {"alg": "HS256", "typ": "JWT"}

# Make sure "alg" matches settings.ALGORITHM
```

**Common causes:**
- Token expired (check `exp` claim)
- Wrong secret key (dev vs prod environments)
- Algorithm mismatch (created with HS256, verifying with RS256)

### Issue Type 2: Scanner Times Out on All Tests

**Problem:** All test results return `status="error"` with timeout messages.

**How to debug:**

1. Test target is accessible:
```bash
# From inside backend container
docker exec -it apisec_backend_dev bash
curl -v https://target-api.com/endpoint

# Check:
# - Does connection succeed?
# - What's the response time?
# - Are there redirects?
```

2. Check timeout settings:
```python
# config.py:51
SCANNER_CONNECTION_TIMEOUT: int = 180  # 3 minutes

# If target is slower, increase this
```

3. Look at actual error:
```python
# services/scan_service.py exception block shows error
except Exception as e:
    details=f"Scanner error: {str(e)}"
    
# Check what the exception says:
# - "Connection timeout" = target slow or unreachable
# - "Name resolution failed" = DNS issue
# - "SSL certificate verify failed" = TLS problem
```

4. Try with a known-good target:
```bash
# Test with httpbin (always responsive)
curl -X POST http://localhost:8000/scans/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://httpbin.org/get",
    "tests_to_run": ["rate_limit"],
    "max_requests": 10
  }'
```

**Common causes:**
- Target requires VPN or is behind firewall
- Target rate limiting scanner (ironically)
- DNS resolution failing in Docker network
- TLS certificate issues (self-signed, expired)

### Issue Type 3: Database Deadlock Errors

**Problem:** Intermittent `DeadlockDetected` errors under concurrent load.

**How to debug:**

1. Check transaction order:
```sql
-- PostgreSQL query to see locks
SELECT
  pid,
  state,
  query_start,
  state_change,
  query
FROM pg_stat_activity
WHERE state = 'active';
```

2. Look for transaction patterns:
```python
# Problematic pattern - different order
# Thread 1:
UPDATE scans SET ... WHERE id = 1;
UPDATE test_results SET ... WHERE scan_id = 1;

# Thread 2:
UPDATE test_results SET ... WHERE scan_id = 2;
UPDATE scans SET ... WHERE id = 2;

# Thread 1 locks scans.id=1, waits for test_results
# Thread 2 locks test_results.scan_id=2, waits for scans
# = Deadlock
```

3. Fix by consistent ordering:
```python
# Both threads update in same order = no deadlock
# Always update parent (scans) before child (test_results)
UPDATE scans SET ... WHERE id = ?;
UPDATE test_results SET ... WHERE scan_id = ?;
```

**Common causes:**
- Multiple transactions updating same rows in different orders
- Long-running transactions holding locks
- Missing indexes causing table scans that lock many rows

## Code Organization Principles

### Why Routes Stay Thin

Routes in `routes/scans.py` are intentionally simple:
```python
@router.post("/", response_model=ScanResponse)
async def create_scan(
    request: Request,
    scan_request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
) -> ScanResponse:
    return ScanService.run_scan(db, current_user.id, scan_request)
```

Just 3 lines:
1. Dependency injection provides db and current_user
2. Call service layer
3. Return result

**All business logic lives in services.** Routes handle HTTP concerns:
- Parsing request
- Validating with Pydantic
- Checking authentication
- Serializing response

This makes routes easy to test:
```python
# Test route with mocked service
def test_create_scan(mock_service):
    mock_service.run_scan.return_value = fake_scan
    
    response = client.post("/scans/", json={...})
    
    assert response.status_code == 201
    assert mock_service.run_scan.called
```

No need to mock database, scanners, or any complex logic. Service is mocked, route just handles HTTP.

### Naming Conventions

- `*Repository` = Data access classes (UserRepository, ScanRepository)
- `*Service` = Business logic classes (AuthService, ScanService)
- `*Scanner` = Security test implementations (SQLiScanner, AuthScanner)
- `*Schema` = Pydantic validation models (UserCreate, ScanResponse)
- `get_*` functions = FastAPI dependencies (get_db, get_current_user)
- `_private_method` = Internal helper (not part of public interface)

Following these patterns makes it easier to find code. Need to add a database query? Look in repositories. Need to change business logic? Look in services.

## Extending the Code

### Adding a New Security Test (XSS Example)

Want to add XSS (Cross-Site Scripting) detection? Here's the complete process:

**1. Create scanner** `backend/scanners/xss_scanner.py`:
```python
from .base_scanner import BaseScanner
from .payloads import XSSPayloads
from core.enums import TestType, ScanStatus, Severity
from schemas.test_result_schemas import TestResultCreate

class XSSScanner(BaseScanner):
    """
    Tests for Cross-Site Scripting vulnerabilities
    """
    
    def scan(self) -> TestResultCreate:
        reflected_test = self._test_reflected_xss()
        
        if reflected_test["vulnerable"]:
            return TestResultCreate(
                test_name=TestType.XSS,
                status=ScanStatus.VULNERABLE,
                severity=Severity.HIGH,
                details=f"Reflected XSS detected: {reflected_test['payload']}",
                evidence_json=reflected_test,
                recommendations_json=[
                    "Encode user input before rendering in HTML",
                    "Use Content-Security-Policy headers",
                    "Validate input on server side",
                ],
            )
        
        return TestResultCreate(
            test_name=TestType.XSS,
            status=ScanStatus.SAFE,
            severity=Severity.INFO,
            details="No XSS vulnerabilities detected",
            evidence_json=reflected_test,
            recommendations_json=[],
        )
    
    def _test_reflected_xss(self) -> dict[str, Any]:
        payloads = XSSPayloads.get_basic_payloads()
        
        for payload in payloads:
            response = self.make_request("GET", f"/?q={payload}")
            
            # Check if payload appears unencoded in response
            if payload in response.text:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "status_code": response.status_code,
                }
        
        return {"vulnerable": False}
```

**2. Add enum value** in `backend/core/enums.py:19-26`:
```python
class TestType(str, Enum):
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    SQLI = "sqli"
    IDOR = "idor"
    XSS = "xss"  # New test type
```

**3. Register scanner** in `backend/services/scan_service.py:32-38`:
```python
scanner_mapping: dict[TestType, type[BaseScanner]] = {
    TestType.RATE_LIMIT: RateLimitScanner,
    TestType.AUTH: AuthScanner,
    TestType.SQLI: SQLiScanner,
    TestType.IDOR: IDORScanner,
    TestType.XSS: XSSScanner,  # Register new scanner
}
```

**4. Add payloads** in `backend/scanners/payloads.py:250-280`:
```python
class XSSPayloads:
    BASIC_XSS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
    ]
    
    @classmethod
    def get_basic_payloads(cls) -> list[str]:
        return cls.BASIC_XSS
```

**5. Update frontend** in `frontend/src/config/constants.ts`:
```typescript
export const SCAN_TEST_TYPES = {
  // ... existing
  XSS: 'xss',
} as const;

export const TEST_TYPE_LABELS: Record<ScanTestType, string> = {
  // ... existing
  [SCAN_TEST_TYPES.XSS]: 'Cross-Site Scripting',
};
```

That's it. No database changes needed (TestType enum automatically updates). No route changes (they pass through test types). Just scanner implementation and registration.

## Next Steps

You've seen how the code works. Now:

1. **Try the challenges** - [04-CHALLENGES.md](./04-CHALLENGES.md) has extension ideas from adding stored XSS detection to implementing custom scanner plugins
2. **Modify scanners** - Change SQLi payload timing thresholds, add new auth bypass techniques, implement DOM-based XSS detection
3. **Read related projects** - The docker-security-audit project builds on container scanning concepts, network-traffic-analyzer goes deeper into packet analysis
