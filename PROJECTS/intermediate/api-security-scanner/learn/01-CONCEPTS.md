# 01-CONCEPTS.md

# Core Security Concepts

This document explains the security concepts you'll encounter while building this project. These are not just definitions. We'll dig into why they matter and how they actually work.

## Rate Limiting

### What It Is

Rate limiting controls how many requests a client can make to your API in a given time window. It's like a bouncer at a club counting how many times someone tries to get in. If they're hammering the door 100 times per minute, something's wrong.

The concept is simple: track requests by some identifier (IP address, user ID, API key) and reject requests that exceed a threshold. A basic implementation might be "100 requests per minute per IP address." When request 101 comes in within that minute, you return HTTP 429 Too Many Requests.

### Why It Matters

Without rate limiting, a single attacker can take down your entire service. In 2016, the Mirai botnet launched a DDoS attack against Dyn's DNS service by flooding it with requests. Major sites like Twitter, Netflix, and Reddit went down because Dyn had no effective rate limiting at the DNS level.

But it's not just about denial of service. Rate limiting also stops:
- **Credential stuffing** - attackers trying thousands of stolen passwords against your login endpoint
- **Data scraping** - competitors or bad actors pulling your entire product catalog through your API
- **Brute force attacks** - trying every possible value to crack passwords, API keys, or find valid user IDs
- **Cost attacks** - running up your AWS bill by triggering expensive operations repeatedly

The 2020 Venmo scraping incident exposed transaction data for millions of users. Attackers made unlimited requests to Venmo's public API and collected data on who was paying whom. Rate limiting would have detected and blocked this pattern immediately.

### How It Works

Look at how this project detects rate limiting in `backend/scanners/rate_limit_scanner.py`:

```python
# Lines 62-145
def _detect_rate_limiting(self, test_request_count: int = 20) -> dict[str, Any]:
    """
    Detect rate limiting by analyzing headers and response patterns
    """
    rate_limit_patterns = RateLimitBypassPayloads.get_header_patterns()
    
    results = {
        "rate_limit_detected": False,
        "rate_limit_headers": {},
        "enforcement_status": None,
    }
    
    for attempt in range(1, test_request_count + 1):
        response = self.make_request("GET", "/")
        
        # Check for standard rate limit headers
        for header_type, pattern in rate_limit_patterns.items():
            for header_name, header_value in headers_lower.items():
                if re.search(pattern, header_name, re.IGNORECASE):
                    results["rate_limit_headers"][header_type] = {
                        "header_name": header_name,
                        "value": header_value,
                    }
                    results["rate_limit_detected"] = True
        
        # Check if we hit the limit
        if response.status_code == 429:
            results["enforcement_status"] = "ACTIVE"
            results["attempts_until_limit"] = attempt
            break
```

This code makes requests until it either hits a 429 response or finds rate limit headers. The headers follow patterns like `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`. These are from the IETF draft standard that most APIs follow.

The scanner distinguishes between three states:
1. **No rate limiting** - sends 20 requests, never gets blocked or sees headers
2. **Headers only** - advertises limits in headers but never enforces them with 429
3. **Active enforcement** - actually blocks requests when limits are exceeded

### Common Attacks

1. **IP header spoofing** - Many rate limiters trust headers like `X-Forwarded-For` to identify clients. Attackers rotate fake IP addresses in this header to bypass limits. The scanner tests this in `rate_limit_scanner.py:218-255`.

2. **Distributed attacks** - Use botnets or cloud providers to attack from many real IPs simultaneously, staying under per-IP limits while overwhelming the service overall.

3. **Endpoint variation bypass** - Some rate limiters are case sensitive or miss URL variations. Try `/api/users`, `/API/users`, `/api/users/`, `/api/users?`, etc. Code at `rate_limit_scanner.py:257-286`.

4. **Resource exhaustion without limits** - Even with rate limiting, if limits are too high (1000 requests/minute), an attacker can still cause damage. The Cloudflare outage in 2022 was caused by a regex pattern that consumed CPU - even rate-limited requests added up.

### Defense Strategies

Implement rate limiting at multiple layers. This project shows how to detect it, but here's how to build it:

**Layer 1: Edge/CDN level**
Use Cloudflare, AWS WAF, or similar to block obvious abuse before it hits your infrastructure. This is cheap and fast because it happens at edge locations.

**Layer 2: API gateway**
Kong, AWS API Gateway, or nginx can enforce rate limits per IP, per API key, or per user. This catches most abuse.

**Layer 3: Application level**
The backend in this project uses SlowAPI (see `backend/factory.py:34-36`):
```python
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

And applies limits to specific endpoints (`backend/routes/auth.py:25-42`):
```python
@router.post("/register", ...)
@limiter.limit(settings.API_RATE_LIMIT_REGISTER)  # "15/minute" from config
async def register(request: Request, ...):
    return AuthService.register_user(db, user_data)
```

**Critical defenses:**
- Don't trust client-provided headers like `X-Forwarded-For` without validation
- Use multiple identifiers - IP, user ID, API key combined
- Implement exponential backoff - longer lockouts for repeated violations  
- Return `Retry-After` header telling clients when to try again
- Log rate limit violations for security monitoring

## Broken Authentication

### What It Is

Authentication proves who you are. When it's broken, attackers can bypass it, impersonate users, or access systems without valid credentials. This is OWASP API2:2023 - Broken Authentication.

Common authentication mechanisms for APIs:
- **Session tokens** - server generates a token, stores it, validates on each request
- **JWT tokens** - server signs a token, client sends it back, server verifies signature
- **API keys** - long-lived secrets that identify applications
- **OAuth 2.0** - delegated authorization with access tokens

This project focuses on JWT because it's widely used and frequently misconfigured.

### Why It Matters

The 2020 SolarWinds attack used stolen authentication tokens to access customer networks. Once inside, attackers moved laterally because authentication wasn't properly verified at each service boundary.

In 2018, a vulnerability in Facebook's "View As" feature let attackers steal access tokens for 50 million users. The tokens worked because Facebook didn't properly validate them when they were used.

Broken authentication is ranked #2 in OWASP's API Top 10 because it's both common and devastating. Bypass authentication and you often get full access to user data, admin functions, and internal systems.

### How It Works

JWT (JSON Web Token) has three parts separated by periods:
```
header.payload.signature
```

Example:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature_here
```

Decode the header (base64):
```json
{"alg": "HS256", "typ": "JWT"}
```

Decode the payload:
```json
{"sub": "user@example.com"}
```

The signature proves the token wasn't tampered with. It's created by:
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

Proper validation must:
1. Verify the signature using the server's secret key
2. Check the algorithm is what you expect (HS256, RS256, etc)
3. Validate expiration time if present
4. Reject tokens with the "none" algorithm

Look at how this project validates tokens in `backend/core/security.py:48-62`:
```python
def decode_token(token: str) -> dict[str, str]:
    """
    Decode and verify a JWT token
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]  # Explicitly specify allowed algorithms
        )
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {str(e)}") from e
```

### Common Attacks

1. **None algorithm attack** - JWT supports an algorithm called "none" which means "no signature required." Some libraries accept these tokens even though they're unsigned. The scanner tests this in `auth_scanner.py:168-213`:

```python
def _test_none_algorithm(self) -> dict[str, Any]:
    """
    Test if server accepts JWT with 'none' algorithm
    """
    header, payload, signature = self.auth_token.split(".")
    
    none_variants = ["none", "None", "NONE", "nOnE"]  # Case variations
    
    for variant in none_variants:
        malicious_header = self._base64url_encode(
            json.dumps({"alg": variant, "typ": "JWT"})
        )
        malicious_token = f"{malicious_header}.{payload}."  # No signature
        
        response = self.make_request(
            "GET", "/",
            headers={"Authorization": f"Bearer {malicious_token}"}
        )
        
        if response.status_code == 200:
            return {"vulnerable": True, "algorithm_variant": variant}
```

2. **Missing authentication** - Endpoints that should require auth don't check for it. Test in `auth_scanner.py:89-131`:
```python
def _test_missing_authentication(self) -> dict[str, Any]:
    """
    Test if endpoint requires authentication
    """
    session_without_auth = self.session.__class__()  # New session, no token
    
    response = session_without_auth.get(self.target_url, timeout=...)
    
    if response.status_code == 200:
        return {"vulnerable": True, "description": "Endpoint accessible without authentication"}
```

3. **Weak secret keys** - If the JWT secret is weak ("secret", "password", company name), attackers can brute force it and forge valid tokens. Tools like hashcat can try millions of secrets per second.

4. **Algorithm confusion** - Server expects RS256 (asymmetric) but accepts HS256 (symmetric). Attacker uses the public key as the HMAC secret to forge tokens.

### Defense Strategies

The project implements proper JWT validation. Here's what to do:

**Token creation** (`core/security.py:33-56`):
```python
def create_access_token(data: dict[str, str], expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=1440))
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,  # Must be cryptographically random, 256+ bits
        algorithm=settings.ALGORITHM  # "HS256"
    )
    return encoded_jwt
```

**Token validation** - Happens in `core/dependencies.py:17-49`:
```python
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> UserResponse:
    try:
        payload = decode_token(credentials.credentials)
        email: str | None = payload.get("sub")
        
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = UserRepository.get_by_email(db, email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return UserResponse.model_validate(user)
```

**Critical defenses:**
- Use a strong random secret (generate with `openssl rand -hex 32`)
- Explicitly specify allowed algorithms, reject "none"
- Verify signatures before trusting payload data
- Implement token expiration and check it
- Require authentication on all sensitive endpoints
- Use short-lived access tokens (15 minutes) with refresh tokens

### Common Pitfalls

**Mistake 1: Trusting unverified tokens**
```python
# Bad - decodes without verifying signature
import base64, json
header, payload, sig = token.split(".")
data = json.loads(base64.b64decode(payload))
user_id = data["user_id"]  # Attacker controlled!

# Good - verifies signature first
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
user_id = payload["user_id"]  # Safe to use
```

**Mistake 2: Not checking expiration**
```python
# Bad - no expiration check
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False})

# Good - validates expiration
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # verify_exp=True by default
```

## SQL Injection

### What It Is

SQL injection happens when you put untrusted data directly into SQL queries without proper escaping. The attacker sends malicious input that changes the query's logic.

Example vulnerable code:
```python
query = f"SELECT * FROM users WHERE email = '{email}'"
```

If the attacker sends `email = "admin'--"`, the query becomes:
```sql
SELECT * FROM users WHERE email = 'admin'--'
```

The `--` comments out the rest, changing a lookup into a bypass.

### Why It Matters

SQL injection has been in the OWASP Top 10 for two decades, yet it still causes breaches. The 2017 Equifax breach exposed 147 million records through a different vulnerability (Apache Struts), but once inside, attackers used SQL injection to extract data.

In 2019, a SQL injection in Canva exposed email addresses and passwords for 137 million users. The attackers manipulated input fields that were concatenated into queries.

Modern frameworks have made SQLi less common, but it still shows up when developers:
- Concatenate user input into queries
- Misuse ORM raw query features
- Build dynamic SQL from user-controlled data
- Trust input from internal sources (still needs validation)

### How It Works

There are three main types of SQL injection that this project detects:

**1. Error-based SQLi** - Trigger database errors that leak information

The scanner sends payloads like `' OR '1'='1` and checks if database error messages appear in the response (`sqli_scanner.py:51-94`):

```python
def _test_error_based_sqli(self) -> dict[str, Any]:
    """
    Test for error based SQL injection
    """
    error_signatures = SQLiPayloads.get_error_signatures()  # MySQL, Postgres, MSSQL, Oracle
    basic_payloads = SQLiPayloads.BASIC_AUTHENTICATION_BYPASS
    
    for payload in basic_payloads:
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
                        "error_signature": signature
                    }
```

Error signatures are defined in `scanners/payloads.py:9-30`:
```python
ERROR_SIGNATURES = {
    "mysql": ["sql syntax", "mysql_fetch", "mysql error"],
    "postgres": ["postgresql", "pg_query", "syntax error"],
    "mssql": ["sqlserver jdbc driver", "sqlexception"],
    "oracle": ["ora-", "oracle.jdbc", "pl/sql"],
}
```

**2. Boolean-based blind SQLi** - No errors shown, but responses differ for true vs false conditions

Send queries with conditions that are always true (`1=1`) vs always false (`1=2`) and compare response lengths:

```python
def _test_boolean_based_sqli(self) -> dict[str, Any]:
    """
    Test for boolean based blind SQL injection
    """
    baseline_response = self.make_request("GET", "/?id=1")
    baseline_length = len(baseline_response.text)
    
    # Try true conditions: ' AND 1=1--
    true_payloads = [p for p in boolean_payloads if "AND '1'='1" in p or "AND 1=1" in p]
    true_lengths = []
    for payload in true_payloads:
        response = self.make_request("GET", f"/?id={payload}")
        true_lengths.append(len(response.text))
    
    # Try false conditions: ' AND 1=2--
    false_payloads = [p for p in boolean_payloads if "AND '1'='2" in p]
    false_lengths = []
    for payload in false_payloads:
        response = self.make_request("GET", f"/?id={payload}")
        false_lengths.append(len(response.text))
    
    avg_true = statistics.mean(true_lengths)
    avg_false = statistics.mean(false_lengths)
    length_diff = abs(avg_true - avg_false)
    
    if length_diff > 100:  # Significant difference
        return {"vulnerable": True, "length_difference": length_diff}
```

**3. Time-based blind SQLi** - Force the database to delay, measure response time

Payloads like `'; SELECT SLEEP(5)--` make the database pause. If the response takes 5+ seconds, it's vulnerable:

```python
def _test_time_based_sqli(self, delay_seconds: int = 5) -> dict[str, Any]:
    """
    Test for time based blind SQL injection
    Uses baseline timing comparison with statistical analysis
    """
    # Establish normal response time
    baseline_mean, baseline_stdev = self.get_baseline_timing("/")
    expected_delay_time = baseline_mean + delay_seconds
    
    delay_payloads = {
        "mysql": [p for p in all_time_payloads if "SLEEP" in p],
        "postgres": [p for p in all_time_payloads if "pg_sleep" in p],
        "mssql": [p for p in all_time_payloads if "WAITFOR" in p],
    }
    
    for db_type, payloads in delay_payloads.items():
        for payload in payloads:
            delay_times = []
            for _ in range(3):  # Multiple samples
                response = self.make_request("GET", f"/?id={payload}", timeout=delay_seconds + 10)
                elapsed = getattr(response, "request_time", 0.0)
                delay_times.append(elapsed)
            
            avg_delay = statistics.mean(delay_times)
            
            if avg_delay >= expected_delay_time - 1:  # Within 1 second of expected
                return {"vulnerable": True, "database_type": db_type, "response_time": f"{avg_delay:.3f}s"}
```

### Common Attacks

The payloads are in `scanners/payloads.py`. Here are the techniques:

1. **Authentication bypass** (`payloads.py:33-48`):
```python
BASIC_AUTHENTICATION_BYPASS = [
    "' OR '1'='1",        # Makes WHERE clause always true
    "' OR 1=1--",         # Comments out rest of query
    "admin'--",           # Logs in as admin by ending query early
    ") or '1'='1--",      # Escapes parentheses in complex queries
]
```

2. **Union-based extraction** (`payloads.py:50-60`):
```python
UNION_BASED = [
    "' UNION SELECT NULL--",                    # Find column count
    "' UNION SELECT username,password FROM users--",  # Extract data
    "' UNION SELECT NULL,version()--",          # Get database version
]
```

3. **Stacked queries** (`payloads.py:92-99`):
```python
STACKED_QUERIES = [
    "'; DROP TABLE users--",                    # Delete data
    "'; INSERT INTO users VALUES('hacker','password')--",  # Add accounts
    "'; EXEC xp_cmdshell('whoami')--",         # Run OS commands (MSSQL)
]
```

### Defense Strategies

Never concatenate user input into SQL queries. Use parameterized queries (prepared statements) that treat data as data, not code.

**Vulnerable code:**
```python
# BAD - string concatenation
email = request.get("email")
query = f"SELECT * FROM users WHERE email = '{email}'"
result = db.execute(query)
```

**Safe code with SQLAlchemy:**
```python
# GOOD - parameterized query
email = request.get("email")
result = db.query(User).filter(User.email == email).first()

# SQLAlchemy generates safe SQL:
# SELECT * FROM users WHERE email = :email_1
# Parameters: {'email_1': 'user@example.com'}
```

This project uses the repository pattern to keep SQL safe. Look at `repositories/user_repository.py:25-35`:
```python
@staticmethod
def get_by_email(db: Session, email: str) -> User | None:
    """
    Get user by email address
    """
    return db.query(User).filter(User.email == email).first()
```

SQLAlchemy's `.filter(User.email == email)` creates a parameterized query automatically. The email value is passed separately from the SQL string, so it can't inject code.

**Critical defenses:**
- Use ORMs like SQLAlchemy, Django ORM, or Prisma
- When raw SQL is necessary, use parameterized queries
- Validate input types (if expecting int, convert to int and catch errors)
- Use least privilege database accounts (don't connect as admin)
- Disable error messages in production (don't leak database details)

### Common Pitfalls

**Mistake 1: Using ORM raw() incorrectly**
```python
# Bad - raw SQL with concatenation
email = request.get("email")
query = f"SELECT * FROM users WHERE email = '{email}'"
result = db.session.execute(text(query))  # Still vulnerable!

# Good - raw SQL with parameters
result = db.session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email}
)
```

**Mistake 2: Trusting "internal" data**
```python
# Bad - assumes data from another service is safe
external_api_result = fetch_from_partner()
user_id = external_api_result["user_id"]
query = f"SELECT * FROM orders WHERE user_id = {user_id}"  # Can still be exploited
```

## IDOR/BOLA (Broken Object Level Authorization)

### What It Is

IDOR (Insecure Direct Object Reference) and BOLA (Broken Object Level Authorization) are the same thing. OWASP's API Top 10 2023 calls it BOLA and ranks it #1.

The vulnerability: your API lets users access objects by ID, but doesn't check if that user should have access to that specific object.

Example:
```
GET /api/users/123/orders
```

The API checks if you're authenticated (you have a valid token), but doesn't check if user 123 is YOU. So you can change the ID to 124, 125, 126 and view other users' orders.

### Why It Matters

IDOR is ranked #1 in OWASP API Security Top 10 2023 because it's everywhere and easy to exploit. No special tools needed, just change a number in the URL.

Real breaches:
- **USPS Informed Delivery (2018)** - Change email addresses in requests to view anyone's mail scans
- **T-Mobile (2022)** - API endpoint leaked data on 37 million customers by allowing ID enumeration
- **Parler (2021)** - Sequential post IDs let researchers download the entire platform (70TB) by incrementing IDs

The damage isn't just data exposure. In 2019, researchers found IDOR in a car sharing app that let them unlock and start any car in the fleet by changing the vehicle ID.

### How It Works

The scanner tests two patterns:

**1. ID enumeration** - Sequential or predictable IDs make it easy to guess valid values

Extract IDs from API responses, then try variations (`idor_scanner.py:119-153`):

```python
def _extract_ids_from_response(self) -> list[Any]:
    """
    Extract potential IDs from API response
    """
    response = self.make_request("GET", "/")
    
    # Look for UUIDs: a1b2c3d4-1234-5678-9abc-def012345678
    uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    uuids = re.findall(uuid_pattern, response.text, re.IGNORECASE)
    
    # Look for numeric IDs: "id": 123
    numeric_id_pattern = r'"id"\s*:\s*(\d+)'
    numeric_ids = re.findall(numeric_id_pattern, response.text)
    
    ids = []
    ids.extend(uuids[:3])
    ids.extend([int(nid) for nid in numeric_ids[:3]])
    
    return ids
```

Then test if those IDs can be manipulated (`idor_scanner.py:155-204`):

```python
def _test_numeric_id_manipulation(self, extracted_ids: list[Any]) -> dict[str, Any]:
    """
    Test numeric ID manipulation for IDOR
    """
    numeric_ids = [id_val for id_val in extracted_ids if isinstance(id_val, int)]
    
    base_id = numeric_ids[0]
    test_ids = [0, -1, 1, 2, 9999, 99999, 999999]  # Common patterns
    
    accessible_unauthorized = []
    
    for test_id in test_ids:
        if test_id == base_id:
            continue
        
        response = self.make_request("GET", f"/{test_id}")
        
        if response.status_code == 200:  # Should be 403 or 404
            accessible_unauthorized.append({
                "id": test_id,
                "status_code": response.status_code,
                "response_length": len(response.text)
            })
    
    if accessible_unauthorized:
        return {"vulnerable": True, "unauthorized_access": accessible_unauthorized}
```

**2. Predictable patterns** - Sequential IDs reveal total count and enable scraping

If you get IDs `[100, 101, 102]` when making requests, you know there are at least 102 objects and you can enumerate all of them.

```python
def _test_predictable_id_patterns(self) -> dict[str, Any]:
    """
    Test if IDs follow predictable patterns
    """
    ids1 = self._extract_ids_from_response()
    ids2 = self._extract_ids_from_response()
    
    numeric_ids1 = [id for id in ids1 if isinstance(id, int)]
    numeric_ids2 = [id for id in ids2 if isinstance(id, int)]
    
    if len(numeric_ids1) >= 2:
        diff1 = abs(numeric_ids1[1] - numeric_ids1[0])
        
        if len(numeric_ids2) >= 2:
            diff2 = abs(numeric_ids2[1] - numeric_ids2[0])
            
            if diff1 == diff2 and diff1 == 1:  # Increments by 1 each time
                return {
                    "vulnerable": True,
                    "pattern_type": "Sequential IDs",
                    "id_difference": diff1
                }
```

### Common Attacks

Attack payloads in `scanners/payloads.py:179-216`:

1. **Numeric ID manipulation**:
```python
NUMERIC_ID_MANIPULATIONS = [
    0,        # First record
    -1,       # May wrap to last record  
    1,        # Common starting ID
    9999,     # Try common ranges
    999999,   # Higher ranges
]
```

2. **String ID manipulation**:
```python
STRING_ID_MANIPULATIONS = [
    "admin",               # Privileged accounts
    "root",
    "test",
    "../../../etc/passwd", # Path traversal attempts
]
```

3. **UUID guessing** - While UUIDs are random, poor implementations might:
- Use predictable seeds
- Accept all-zeros or all-ones UUIDs
- Not validate UUID format

### Defense Strategies

The fix is simple conceptually: check authorization before returning data. But you must do it on every single endpoint.

**Vulnerable code:**
```python
@router.get("/api/documents/{doc_id}")
async def get_document(doc_id: int, user: User = Depends(get_current_user)):
    document = db.query(Document).filter(Document.id == doc_id).first()
    return document  # IDOR vulnerability - didn't check ownership
```

**Fixed code:**
```python
@router.get("/api/documents/{doc_id}")
async def get_document(doc_id: int, user: User = Depends(get_current_user)):
    document = db.query(Document).filter(
        Document.id == doc_id,
        Document.owner_id == user.id  # Authorization check
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    return document
```

This project demonstrates proper authorization in `services/scan_service.py:67-84`:

```python
@staticmethod
def get_scan_by_id(db: Session, scan_id: int, user_id: int) -> ScanResponse:
    """
    Get scan by ID with authorization check
    """
    scan = ScanRepository.get_by_id(db, scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # CRITICAL: Check if user owns this scan
    if scan.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    return ScanResponse.model_validate(scan)
```

**Critical defenses:**
- Check object ownership on every access
- Use UUIDs instead of sequential integers (but still check authorization!)
- Implement row-level security in your database
- Return 404 for unauthorized access (don't leak existence with 403)
- Log suspicious access patterns (trying many IDs rapidly)

### Common Pitfalls

**Mistake 1: Checking auth only on writes**
```python
# Bad - checks auth for POST but not GET
@router.post("/api/orders/{order_id}/cancel")
async def cancel_order(order_id: int, user: User = Depends()):
    order = db.get(Order, order_id)
    if order.user_id != user.id:  # Auth check here
        raise HTTPException(403)
    order.status = "cancelled"

@router.get("/api/orders/{order_id}")
async def get_order(order_id: int):
    return db.get(Order, order_id)  # No auth check - vulnerable
```

**Mistake 2: Trusting UUIDs**
```python
# Bad - assumes UUID means authorization not needed
@router.get("/api/documents/{doc_uuid}")
async def get_document(doc_uuid: str):
    return db.query(Document).filter(Document.uuid == doc_uuid).first()
    # Still vulnerable! UUIDs are hard to guess but not impossible

# Good - check authorization even with UUIDs
@router.get("/api/documents/{doc_uuid}")
async def get_document(doc_uuid: str, user: User = Depends()):
    doc = db.query(Document).filter(
        Document.uuid == doc_uuid,
        Document.owner_id == user.id
    ).first()
    if not doc:
        raise HTTPException(404)
    return doc
```

## How These Concepts Relate

These vulnerabilities often appear together and compound each other:

```
No Rate Limiting
    ↓
  enables
    ↓
Rapid IDOR Enumeration
    ↓
 combined with
    ↓
Broken Authentication
    ↓
  allows
    ↓
SQL Injection Exploitation
    ↓
   results in
    ↓
Complete Data Breach
```

Real example: An API with weak rate limiting allows an attacker to:
1. Enumerate user IDs rapidly (IDOR)
2. Try stolen passwords against each ID (broken auth)
3. Once logged in, inject SQL to dump the entire database

Defense requires addressing all layers.

## Industry Standards and Frameworks

### OWASP Top 10

This project addresses:

- **API1:2023 Broken Object Level Authorization** - IDOR scanner (`idor_scanner.py`) detects missing authorization checks
- **API2:2023 Broken Authentication** - Auth scanner (`auth_scanner.py`) tests JWT vulnerabilities, missing auth, weak tokens
- **API4:2023 Unrestricted Resource Consumption** - Rate limit scanner (`rate_limit_scanner.py`) detects missing or bypassable rate limits
- **API8:2023 Security Misconfiguration** - Multiple scanners catch common misconfigurations

### MITRE ATT&CK

Relevant techniques:

- **T1190** - Exploit Public-Facing Application - All these vulnerabilities apply to public APIs
- **T1110** - Brute Force - Rate limiting prevents credential stuffing and brute force attacks
- **T1212** - Exploitation for Credential Access - SQL injection can extract credentials
- **T1078** - Valid Accounts - Authentication bypass provides attacker with valid access

### CWE

Common weakness enumerations covered:

- **CWE-89** - SQL Injection - Tested by `sqli_scanner.py` with error-based, boolean blind, and time-based techniques
- **CWE-287** - Improper Authentication - Auth scanner detects missing or broken authentication
- **CWE-639** - Authorization Bypass Through User-Controlled Key - IDOR scanner finds object-level authorization issues
- **CWE-770** - Allocation of Resources Without Limits - Rate limit scanner detects unrestricted resource consumption

## Real World Examples

### Case Study 1: The Parler Data Scrape (2021)

What happened: After Parler was removed from app stores, researchers downloaded the entire platform's content - 70TB including deleted posts, user data, and metadata with GPS coordinates.

How the attack worked:
1. Parler used sequential post IDs
2. No rate limiting on the API
3. No authentication required to view public posts
4. Researchers wrote a script that incremented post IDs from 1 to ~13 million
5. They downloaded everything, including "deleted" posts that weren't actually deleted

What defenses failed:
- IDOR: Sequential IDs made enumeration trivial
- Rate limiting: Could make millions of requests without throttling
- Data retention: Deleted posts remained accessible

How this could have been prevented:
- Use UUIDs for post IDs (makes enumeration harder but not impossible)
- Require authentication for API access
- Implement aggressive rate limiting (100 posts per hour per IP)
- Actually delete data when users delete it
- Log and alert on unusual access patterns

### Case Study 2: T-Mobile API Breach (2022)

What happened: Attackers exploited an API endpoint to access data on 37 million customers, including names, addresses, and phone numbers.

How the attack worked:
1. API endpoint accepted customer IDs as parameters
2. No authorization check verified the requester owned that customer ID
3. Attackers enumerated IDs to scrape customer records
4. Rate limiting was insufficient to stop the attack

What defenses failed:
- IDOR: No object-level authorization
- Rate limiting: Present but set too high
- Monitoring: Attack wasn't detected in real-time

How this could have been prevented:
- Check authorization: `if customer.id != current_user.id: return 403`
- Implement proper rate limiting (10 requests/minute per authenticated user)
- Monitor for sequential ID access patterns
- Require multi-factor authentication for sensitive data access
- Use database row-level security as defense in depth

## Testing Your Understanding

Before moving to the architecture, make sure you can answer:

1. Why doesn't using UUIDs instead of sequential IDs completely fix IDOR vulnerabilities?
2. What's the difference between detecting rate limiting headers and detecting active enforcement?
3. How can time-based blind SQL injection work even when you can't see database errors or response differences?
4. Why must JWT signature validation explicitly reject the "none" algorithm?

If these questions feel unclear, re-read the relevant sections. The implementation will make more sense once these fundamentals click.

## Further Reading

**Essential:**
- OWASP API Security Top 10 2023 - Full document with examples and remediation guidance
- PortSwigger Web Security Academy - Interactive labs for SQL injection, authentication, and authorization
- JWT.io - Decode tokens, understand structure, see libraries for different languages

**Deep dives:**
- "The Web Application Hacker's Handbook" - Chapter 9 (Attacking Data Stores) for SQL injection techniques
- OWASP Testing Guide v4 - Testing for SQL Injection (detailed methodology)
- Auth0 JWT Handbook - Comprehensive guide to JWT security

**Historical context:**
- "How I Hacked Facebook OAuth to Get Full Access" - Egor Homakov (2013)
- "Exploiting the Auth Token Length Oracle" - explains timing attacks on authentication
- Original JWT RFC 7519 - Understand the standard and its security considerations

