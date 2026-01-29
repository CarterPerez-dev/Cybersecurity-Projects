# API Vulnerabilities This Scanner Actually Detects

This scanner tests for four categories of vulnerabilities. Each one maps to real OWASP API Security Top 10 entries. Here is what they are, how attackers exploit them, and why they matter.

## Quick Reference

| Vulnerability | OWASP ID | Severity | What Happens |
|---------------|----------|----------|--------------|
| IDOR/BOLA | API1:2023 | High | Attacker accesses other users data |
| Broken Auth | API2:2023 | Critical | Attacker bypasses login entirely |
| SQL Injection | API8:2023 | Critical | Attacker reads/modifies your database |
| Missing Rate Limits | API4:2023 | High | Attacker brute forces or DoS attacks |

## IDOR/BOLA (Broken Object Level Authorization)

OWASP ranks this number one for a reason. It is the most common API vulnerability in the wild.

The problem: your API checks if a user is logged in, but not if they own the resource they are requesting.

```
GET /api/users/42/orders

User 42: sees their orders (correct)
User 99: also sees user 42's orders (vulnerable)
```

The scanner tests this by:
1. Extracting IDs from API responses (both numeric and UUIDs)
2. Trying to access resources with manipulated IDs
3. Checking if sequential IDs are predictable

Real world example: In 2019, First American Financial exposed 885 million records because their document URLs used sequential IDs with no authorization check. Change the number in the URL, see someone else's mortgage documents.

### Why UUIDs Do Not Fix This

Some developers think switching from numeric IDs to UUIDs solves IDOR. It does not.

UUIDs make enumeration harder, not impossible. If an attacker finds one UUID (from a shared link, email, logs, or browser history), they can still access that resource without authorization.

```
GET /api/documents/550e8400-e29b-41d4-a716-446655440000
```

The fix is always authorization checks. Verify the requesting user has permission to access the specific resource, regardless of ID format.

## Broken Authentication (API2:2023)

Authentication vulnerabilities let attackers log in as other users or bypass authentication entirely.

### Missing Authentication

The most obvious case: endpoints that should require login but do not.

```python
# Vulnerable: no auth required
@app.get("/api/admin/users")
def get_all_users():
    return db.query(User).all()
```

The scanner tests this by making requests without any authentication headers and checking if it gets a 200 response instead of 401.

### JWT Vulnerabilities

JWTs have specific implementation bugs that keep appearing.

**The None Algorithm Attack**

JWTs have three parts: header, payload, signature. The header specifies which algorithm verifies the signature. Some libraries accept "none" as a valid algorithm, meaning no signature required.

```
Original header: {"alg": "HS256", "typ": "JWT"}
Malicious header: {"alg": "none", "typ": "JWT"}
```

If the server accepts this, an attacker can forge any token they want. The scanner tests multiple case variations because some libraries only check for lowercase "none".

```python
# These all bypass poorly implemented JWT validation
"none", "None", "NONE", "nOnE"
```

**Signature Removal**

Related to the none algorithm: some implementations check if the algorithm is "none" but still accept tokens with empty signatures.

```
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.
                                              ^ empty signature
```

The scanner removes signatures from valid tokens and tests if the server still accepts them.

### Invalid Token Handling

Good APIs reject malformed tokens. Bad APIs might accept them or crash.

The scanner sends garbage tokens and checks for 200 responses:
- Empty strings
- Random characters
- SQL injection payloads in tokens
- Path traversal strings

If any of these return 200, something is wrong with your token validation.

## SQL Injection (API8:2023)

SQL injection has been around for 25 years and still makes the top 10 because developers keep building queries with string concatenation.

### Error Based Detection

The easiest SQLi to find. Send a malformed query, get a database error in the response.

```
GET /api/users?id=' OR '1'='1

Response: "You have an error in your SQL syntax near..."
```

The scanner looks for error signatures from MySQL, PostgreSQL, MSSQL, and Oracle. Each database has distinctive error messages.

| Database | Error Contains |
|----------|----------------|
| MySQL | "mysql_fetch", "sql syntax", "warning: mysql" |
| PostgreSQL | "pg_query", "pg_exec", "pgsql" |
| MSSQL | "odbc sql server", "sqlexception" |
| Oracle | "ora-", "pl/sql" |

Finding these errors means two things: the input reaches the database unsanitized, and error messages are exposed to users. Both are bad.

### Boolean Based Blind

When errors are hidden, you can still detect SQLi by comparing responses.

```
GET /api/users?id=1 AND 1=1    (true condition)
GET /api/users?id=1 AND 1=2    (false condition)
```

If the true condition returns normal results and the false condition returns empty or different results, the input is being evaluated as SQL.

The scanner measures response length differences. A significant difference (over 100 bytes typically) between true and false conditions indicates a vulnerability.

### Time Based Blind

The hardest to detect but most reliable for confirming SQLi.

```
GET /api/users?id=1; WAITFOR DELAY '0:0:5'--    (MSSQL)
GET /api/users?id=1'; SELECT SLEEP(5)--          (MySQL)
GET /api/users?id=1'; pg_sleep(5)--              (PostgreSQL)
```

If the response takes 5 seconds longer than normal, the database executed the delay. This works even when the application shows no visible difference in output.

The scanner:
1. Establishes baseline response times with multiple samples
2. Calculates standard deviation to account for network variance
3. Sends delay payloads and measures actual response time
4. Compares against expected delay time (baseline + injected delay)

False positives are rare with time based testing because network latency does not consistently add exactly 5 seconds.

## Rate Limiting (API4:2023)

APIs without rate limiting are vulnerable to brute force attacks, credential stuffing, and denial of service.

### Detection

The scanner makes multiple requests and looks for:
1. Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, etc.)
2. 429 Too Many Requests responses
3. Retry-After headers

Finding rate limit headers but never hitting 429 means the limits exist in name only. The scanner flags this as "headers only" which is a medium severity issue.

### Bypass Testing

Rate limiters often have implementation bugs.

**IP Header Spoofing**

Many rate limiters use client IP for tracking. If they trust X-Forwarded-For or similar headers, attackers can bypass limits by rotating fake IPs.

```
X-Forwarded-For: 10.0.0.1
X-Forwarded-For: 10.0.0.2
X-Forwarded-For: 10.0.0.3
```

The scanner tests X-Forwarded-For, X-Real-IP, X-Client-IP, X-Originating-IP, CF-Connecting-IP, and True-Client-IP. If any of these bypass rate limits, attackers can make unlimited requests.

**Endpoint Variations**

Some rate limiters are case sensitive or miss URL variations.

```
/api/login     (rate limited)
/API/LOGIN     (not rate limited?)
/api/login/    (not rate limited?)
/api/./login   (not rate limited?)
```

The scanner tests path variations including case changes, trailing slashes, and encoded characters.

## What The Severity Ratings Mean

The scanner uses five severity levels.

**Critical**: Immediate risk of data breach or system compromise. SQL injection and JWT bypass fall here. Fix before anything else.

**High**: Serious risk that needs prompt attention. IDOR and missing rate limits on auth endpoints. Attackers will find and exploit these.

**Medium**: Moderate risk. Rate limit headers without enforcement, or predictable ID patterns. Still needs fixing, but less urgent.

**Low**: Minor issues. Might indicate poor practices but no immediate exploit path.

**Info**: Informational findings. The test passed or found something worth noting.

## Further Reading

- OWASP API Security Top 10 2023: https://owasp.org/API-Security/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTricks API Pentesting: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/api-pentesting.html
