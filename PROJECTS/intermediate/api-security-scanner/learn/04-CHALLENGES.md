# 04-CHALLENGES.md

# Extension Challenges

You've built the base project. Now make it yours by extending it with new features.

These challenges are ordered by difficulty. Start with the easier ones to build confidence, then tackle the harder ones when you want to dive deeper.

## Easy Challenges

### Challenge 1: Add CORS Misconfiguration Detection

**What to build:**
A scanner that tests for overly permissive CORS (Cross-Origin Resource Sharing) policies. Check if the API accepts requests from any origin, reflects the Origin header, or allows credentials with wildcard origins.

**Why it's useful:**
CORS misconfigurations let attackers steal data from authenticated users. If an API accepts `Origin: https://evil.com` and responds with `Access-Control-Allow-Origin: https://evil.com`, the attacker can make requests from their site and read the responses. This was how the PayPal information disclosure vulnerability (2020) worked.

**What you'll learn:**
- HTTP header analysis and pattern matching
- Origin header manipulation techniques
- Understanding CORS security model
- How browsers enforce same-origin policy

**Hints:**
- Look at `backend/scanners/auth_scanner.py` for header manipulation examples
- The scanner needs to make requests with different `Origin` headers
- Check response for `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`
- Test cases: wildcard (`*`), reflected origin, `null` origin

**Test it works:**
```python
# In scanners/cors_scanner.py
origins_to_test = [
    "https://evil.com",
    "null",
    "https://attacker.com",
]

for origin in origins_to_test:
    response = self.make_request("GET", "/", headers={"Origin": origin})
    
    allow_origin = response.headers.get("Access-Control-Allow-Origin")
    allow_creds = response.headers.get("Access-Control-Allow-Credentials")
    
    if allow_origin == origin or allow_origin == "*":
        # Found CORS misconfiguration
```

Verify by scanning an endpoint with permissive CORS. Should detect `Access-Control-Allow-Origin: *` as vulnerable.

### Challenge 2: Add Password Strength Reporting

**What to build:**
Enhance registration to check password strength and provide feedback. Test against common password lists (rockyou.txt top 10000), check for patterns (keyboard walks like "qwerty"), and calculate entropy.

**Why it's useful:**
Weak passwords are the #1 cause of account takeovers. The LinkedIn breach (2012) exposed 117 million passwords, many were "123456" and "password". Real-time feedback helps users create stronger passwords.

**What you'll learn:**
- Password entropy calculation (bits of randomness)
- Pattern detection in strings
- Working with wordlists and datasets
- Balancing security with usability

**Hints:**
- Modify `backend/schemas/user_schemas.py:26-38` (the password validator)
- Download common password lists from SecLists on GitHub
- Calculate entropy: `log2(character_space ^ length)`
- Check for sequential characters, repeated characters, dictionary words

**Implementation approach:**

1. **Add password checker utility** in `backend/core/security.py`:
```python
def check_password_strength(password: str) -> dict[str, Any]:
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 12 characters")
    
    # Character variety
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    
    # Check against common passwords
    common_passwords = load_common_passwords()  # Load from file
    if password.lower() in common_passwords:
        score = 0
        feedback.append("This is a commonly used password")
    
    # Patterns
    if re.search(r"(.)\1{2,}", password):  # Repeated chars
        score -= 1
        feedback.append("Avoid repeated characters")
    
    strength = "weak" if score < 3 else "medium" if score < 5 else "strong"
    
    return {
        "strength": strength,
        "score": score,
        "feedback": feedback,
    }
```

2. **Update registration endpoint** to return strength info (optional, informational only).

**Test edge cases:**
- `password123` - Common pattern
- `P@ssw0rd` - Meets requirements but still weak
- `correct-horse-battery-staple` - Long passphrase (good)
- `aaaaAAAA1111!!!!` - Meets requirements but has patterns

### Challenge 3: Add Response Time Monitoring Dashboard

**What to build:**
Track and visualize scanner performance metrics. Store response times for each test, calculate percentiles (p50, p95, p99), and detect when targets are slowing down.

**Why it's useful:**
Performance data helps tune scanner timeouts and detect issues. If the SQLi scanner's time-based detection shows high variance, you know the baseline isn't reliable. If all tests against a target suddenly take 10x longer, the target might be rate limiting you.

**What you'll learn:**
- Metrics collection and aggregation
- Percentile calculation (not just averages)
- Time-series data visualization
- Performance baseline establishment

**Hints:**
- `BaseScanner.make_request()` already tracks `request_time` at line 117
- Store timing data in new `ScanMetrics` model
- Calculate percentiles with `numpy.percentile()`
- Frontend can use Chart.js or Recharts to visualize

**Extra credit:**
Add alerting when p95 response time exceeds threshold. If average scan takes 30s but p95 is 120s, some scans are timing out frequently.

## Intermediate Challenges

### Challenge 4: Implement Stored XSS Detection

**What to build:**
Extend XSS testing beyond reflected XSS. Submit payloads via POST, then retrieve the resource via GET to check if the payload persists. Test comment fields, user profiles, any data that gets stored and displayed.

**Why it's useful:**
Stored XSS is more dangerous than reflected because it affects all users, not just the victim who clicks a malicious link. The MySpace Samy worm (2005) used stored XSS to infect over 1 million profiles in 20 hours.

**Real world application:**
Any API with user-generated content needs stored XSS testing. Forums, comment systems, profile pages, file uploads with previews.

**What you'll learn:**
- Multi-step testing workflows (submit then retrieve)
- Payload encoding variations (URL encoding, HTML entities, Unicode)
- Context-aware XSS detection (JavaScript context vs HTML context)
- False positive reduction in fuzzy matching

**Implementation approach:**

1. **Create stored XSS scanner** in `backend/scanners/stored_xss_scanner.py`:
```python
class StoredXSSScanner(BaseScanner):
    def scan(self) -> TestResultCreate:
        # Generate unique marker
        marker = f"XSS_{uuid.uuid4().hex[:8]}"
        payload = f"<script>alert('{marker}')</script>"
        
        # Step 1: Submit payload
        submit_result = self._submit_payload(payload, marker)
        if not submit_result["submitted"]:
            return self._safe_result("Could not submit payload")
        
        # Step 2: Retrieve and check
        retrieve_result = self._retrieve_and_check(marker)
        if retrieve_result["vulnerable"]:
            return self._vulnerable_result(payload, marker, retrieve_result)
        
        return self._safe_result("No stored XSS detected")
    
    def _submit_payload(self, payload: str, marker: str) -> dict[str, Any]:
        # Try common endpoints
        endpoints = ["/comments", "/api/posts", "/api/profile"]
        
        for endpoint in endpoints:
            try:
                response = self.make_request(
                    "POST",
                    endpoint,
                    json={"content": payload, "text": payload, "bio": payload}
                )
                
                if response.status_code in (200, 201):
                    return {"submitted": True, "endpoint": endpoint}
            except Exception:
                continue
        
        return {"submitted": False}
    
    def _retrieve_and_check(self, marker: str) -> dict[str, Any]:
        # Retrieve content to see if payload persists
        response = self.make_request("GET", "/")
        
        if marker in response.text:
            # Check if it's encoded
            if f"&lt;script&gt;" in response.text:
                return {"vulnerable": False, "encoded": True}
            
            # Check if CSP would block it
            csp = response.headers.get("Content-Security-Policy", "")
            if "script-src 'none'" in csp or "script-src 'self'" in csp:
                return {"vulnerable": False, "csp_protected": True}
            
            return {"vulnerable": True, "marker": marker}
        
        return {"vulnerable": False}
```

2. **Add cleanup** to remove test payloads after scanning (good citizenship).

3. **Test edge cases:**
- Payload gets HTML encoded (safe)
- Payload stored but CSP prevents execution (still report as stored XSS)
- Payload appears in JSON response (context matters)

**Gotchas:**
- Don't leave test payloads in production systems (always clean up)
- Some systems delay rendering (cache, async processing) so marker might not appear immediately
- Be careful with user attribution - don't associate test payloads with real users

### Challenge 5: Add API Rate Limit Bypass Testing with Header Rotation

**What to build:**
Extend rate limit bypass testing with more sophisticated techniques. Test User-Agent rotation, session ID manipulation, timestamp fuzzing, and Origin header variations.

**Why this is challenging:**
Modern rate limiters use multiple signals (IP, user agent, session, fingerprint). You need to test combinations systematically.

**What you'll learn:**
- Advanced rate limiting evasion techniques
- HTTP header manipulation at scale
- Statistical analysis of rate limit effectiveness
- Designing test matrices (combinatorial testing)

**Implementation approach:**

1. **Extend rate limit scanner** in `backend/scanners/rate_limit_scanner.py`:
```python
def _test_header_rotation_bypass(self) -> dict[str, Any]:
    """
    Test if rotating headers bypasses rate limits
    """
    user_agents = RateLimitBypassPayloads.USER_AGENT_ROTATION
    
    # Establish that rate limit exists
    for _ in range(20):
        response = self.make_request("GET", "/")
        if response.status_code == 429:
            break
    else:
        return {"bypass_successful": False, "reason": "No rate limit found"}
    
    # Try bypassing with User-Agent rotation
    success_count = 0
    for i in range(20):
        ua = user_agents[i % len(user_agents)]
        
        response = self.make_request(
            "GET", "/",
            headers={"User-Agent": ua}
        )
        
        if response.status_code != 429:
            success_count += 1
        else:
            break
    
    if success_count == 20:
        return {
            "bypass_successful": True,
            "bypass_method": "User-Agent Rotation",
            "requests_completed": success_count,
        }
    
    return {"bypass_successful": False}
```

2. **Test combinations**:
```python
combinations = [
    {"User-Agent": ua, "X-Forwarded-For": ip},
    {"User-Agent": ua, "Origin": origin},
    # etc
]
```

3. **Add timing analysis** to detect soft limits (degraded but not blocked).

**Resources:**
- Read "Bypassing Rate Limits" on PortSwigger Research blog
- Study Cloudflare's rate limiting documentation to understand what you're up against

### Challenge 6: Implement XML External Entity (XXE) Detection

**What to build:**
Test for XXE vulnerabilities in APIs that accept XML. Submit payloads with external entity references and check for file disclosure, SSRF, or denial of service.

**Why this is hard:**
XXE requires understanding XML parsers, DTD syntax, and different attack vectors (file disclosure vs SSRF vs billion laughs).

**What you'll learn:**
- XML parsing vulnerabilities
- Out-of-band data exfiltration techniques
- SSRF exploitation through XML
- Parser configuration security

**Implementation:**

Create `backend/scanners/xxe_scanner.py`:

```python
class XXEScanner(BaseScanner):
    def scan(self) -> TestResultCreate:
        # Test file disclosure
        file_disclosure = self._test_file_disclosure()
        if file_disclosure["vulnerable"]:
            return self._vulnerable_result(
                "XXE file disclosure detected",
                file_disclosure,
                Severity.CRITICAL
            )
        
        # Test SSRF
        ssrf_test = self._test_ssrf_xxe()
        if ssrf_test["vulnerable"]:
            return self._vulnerable_result(
                "XXE SSRF detected",
                ssrf_test,
                Severity.HIGH
            )
        
        return self._safe_result()
    
    def _test_file_disclosure(self) -> dict[str, Any]:
        # Payload to read /etc/passwd
        payload = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <data>&xxe;</data>"""
        
        response = self.make_request(
            "POST",
            "/",
            data=payload,
            headers={"Content-Type": "application/xml"}
        )
        
        # Check if file contents leaked
        if "root:" in response.text or "bin/bash" in response.text:
            return {
                "vulnerable": True,
                "payload": payload,
                "leaked_data": response.text[:200]
            }
        
        return {"vulnerable": False}
    
    def _test_ssrf_xxe(self) -> dict[str, Any]:
        # Test if parser makes external requests
        # Use Burp Collaborator or similar out-of-band detection
        
        collaborator_url = "http://burpcollaborator.net/unique-id"
        
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [
          <!ENTITY xxe SYSTEM "{collaborator_url}">
        ]>
        <data>&xxe;</data>"""
        
        response = self.make_request(
            "POST",
            "/",
            data=payload,
            headers={"Content-Type": "application/xml"}
        )
        
        # Check if request was made (need out-of-band detection)
        # This is simplified - real implementation needs callback server
        
        return {"vulnerable": False, "note": "Manual verification required"}
```

**Success criteria:**
- Detects XXE in XML endpoints
- Tests multiple entity types (file, http, parameter entities)
- Handles different parser responses (error messages, timeout, data)
- Reports severity based on impact (file disclosure = CRITICAL, SSRF = HIGH)

## Advanced Challenges

### Challenge 7: Build a Scanner Plugin System

**What to build:**
Create a plugin architecture that lets users write custom scanners without modifying core code. Scanners should be loadable from a `plugins/` directory, with automatic discovery and registration.

**Why this is hard:**
Requires dynamic module loading, interface contracts, error isolation (broken plugin shouldn't crash scanner), and documentation for plugin developers.

**What you'll learn:**
- Python module introspection and dynamic imports
- Abstract base classes and interface design
- Plugin architecture patterns
- Sandboxing and error isolation

**Architecture changes needed:**

```
Current:
scanner_mapping = {
    TestType.SQLI: SQLiScanner,  # Hardcoded
    ...
}

New:
scanner_registry = ScannerRegistry()
scanner_registry.load_builtin_scanners()
scanner_registry.discover_plugins("plugins/")

scanner_mapping = scanner_registry.get_all_scanners()
```

**Implementation steps:**

1. **Define plugin interface** in `backend/scanners/plugin_interface.py`:
```python
from abc import ABC, abstractmethod
from typing import Any

class ScannerPlugin(ABC):
    """
    Base class for scanner plugins
    
    All plugins must inherit from this and implement required methods
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner name (e.g., 'custom_xxe')"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version (semver: '1.0.0')"""
        pass
    
    @property
    @abstractmethod
    def test_type(self) -> str:
        """Test type identifier (must be unique)"""
        pass
    
    @abstractmethod
    def scan(self, target_url: str, **kwargs: Any) -> dict[str, Any]:
        """
        Execute scan and return results
        
        Returns:
            dict with keys: vulnerable, details, evidence, recommendations
        """
        pass
    
    def validate(self) -> bool:
        """
        Validate plugin configuration
        Override this to add custom validation
        """
        return True
```

2. **Create plugin loader** in `backend/scanners/plugin_loader.py`:
```python
import os
import importlib.util
from pathlib import Path
from typing import Type

class PluginLoader:
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)
        self.loaded_plugins: dict[str, Type[ScannerPlugin]] = {}
    
    def discover_plugins(self) -> list[Type[ScannerPlugin]]:
        """
        Discover and load all plugins from plugin directory
        """
        if not self.plugin_dir.exists():
            return []
        
        plugins = []
        
        for file in self.plugin_dir.glob("*.py"):
            if file.stem.startswith("_"):
                continue  # Skip __init__.py, _template.py
            
            try:
                plugin_class = self._load_plugin_from_file(file)
                if plugin_class:
                    plugins.append(plugin_class)
            except Exception as e:
                print(f"Failed to load plugin {file}: {e}")
                continue  # Don't let broken plugins crash the scanner
        
        return plugins
    
    def _load_plugin_from_file(self, filepath: Path) -> Type[ScannerPlugin] | None:
        """
        Dynamically load plugin class from Python file
        """
        spec = importlib.util.spec_from_file_location(
            f"plugins.{filepath.stem}",
            filepath
        )
        
        if spec is None or spec.loader is None:
            return None
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find ScannerPlugin subclass
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            
            if (isinstance(attr, type) and 
                issubclass(attr, ScannerPlugin) and 
                attr is not ScannerPlugin):
                
                # Instantiate to validate
                instance = attr()
                if instance.validate():
                    return attr
        
        return None
```

3. **Create example plugin** in `plugins/example_scanner.py`:
```python
from scanners.plugin_interface import ScannerPlugin
from scanners.base_scanner import BaseScanner

class ExampleScanner(ScannerPlugin, BaseScanner):
    """
    Example scanner plugin
    
    Copy this to create your own scanners
    """
    
    @property
    def name(self) -> str:
        return "example_scanner"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def test_type(self) -> str:
        return "example"
    
    def scan(self, target_url: str, **kwargs) -> dict[str, Any]:
        """
        Your scanner logic here
        """
        self.target_url = target_url
        
        response = self.make_request("GET", "/")
        
        # Implement your detection logic
        vulnerable = self._check_for_vulnerability(response)
        
        return {
            "vulnerable": vulnerable,
            "details": "Example vulnerability found" if vulnerable else "Safe",
            "evidence": {"status_code": response.status_code},
            "recommendations": ["Fix the issue"] if vulnerable else [],
        }
    
    def _check_for_vulnerability(self, response) -> bool:
        # Your detection logic
        return False
```

**Testing strategy:**
- Unit test plugin discovery (create test plugins in temp directory)
- Test error isolation (broken plugin doesn't crash scanner)
- Test plugin versioning (handle multiple versions of same plugin)

**Known challenges:**

1. **Plugin naming conflicts**
   - Problem: Two plugins register same `test_type`
   - Hint: Use namespacing or first-come-first-served with warnings

2. **Plugin security**
   - Problem: Malicious plugins could access database, file system
   - Hint: Run plugins in restricted mode, limit imports, use subprocess isolation

**Resources:**
- Read about Python's `importlib` module
- Study Flask's extension system for inspiration
- Look at pytest's plugin architecture

### Challenge 8: Implement Blind SSRF Detection with Out-of-Band Channels

**What to build:**
Detect Server-Side Request Forgery vulnerabilities even when responses don't leak data. Use DNS callbacks, HTTP callbacks, or timing attacks to confirm SSRF.

**Why this is challenging:**
Blind SSRF doesn't show response data. You need infrastructure (callback server) to detect when target makes requests.

**Estimated time:**
8-12 hours for basic implementation, 20+ hours for robust production version.

**Prerequisites:**
You should have completed the SQLi and Auth challenges first because this builds on request timing analysis and header manipulation.

**What you'll learn:**
- Out-of-band vulnerability detection techniques
- DNS exfiltration and callback mechanisms
- Time-based blind detection with statistical significance
- Building supporting infrastructure (callback servers)

**Planning this feature:**

Before you code, think through:
- How does the callback server work? (DNS? HTTP?)
- What if target has egress filtering? (Can't make outbound requests)
- How do you match callbacks to scans? (Unique identifiers)
- What's your false positive rate? (Network noise, CDN prefetching)

**High level architecture:**

```
Scanner                    Callback Server               Target API
   |                              |                            |
   |--SSRF Payload-------------->|                            |
   |  (http://callback.io/abc)   |                            |
   |                              |                            |
   |                              |<---HTTP Request------------|
   |                              |   (GET /abc)               |
   |                              |                            |
   |<--Confirmation---------------|                            |
   |   (Received request abc)     |                            |
```

**Implementation phases:**

**Phase 1: Build Callback Server** (3-4 hours)

Create `backend/ssrf_callback_server.py`:

```python
from fastapi import FastAPI, Request
from datetime import datetime, timedelta
import asyncio

app = FastAPI()

# Store received callbacks
callbacks_received: dict[str, dict] = {}

@app.get("/callback/{identifier}")
async def handle_callback(identifier: str, request: Request):
    """
    Receive SSRF callback
    """
    callbacks_received[identifier] = {
        "timestamp": datetime.utcnow(),
        "headers": dict(request.headers),
        "client_ip": request.client.host,
    }
    
    return {"status": "received"}

@app.get("/check/{identifier}")
async def check_callback(identifier: str):
    """
    Check if callback was received
    """
    callback = callbacks_received.get(identifier)
    
    if callback:
        # Clean up old callback
        del callbacks_received[identifier]
        return {"received": True, "data": callback}
    
    return {"received": False}
```

Run this on a public server (DigitalOcean, AWS) with a domain pointing to it.

**Phase 2: Implement SSRF Scanner** (3-4 hours)

Create `backend/scanners/ssrf_scanner.py`:

```python
import uuid
import time

class SSRFScanner(BaseScanner):
    def __init__(self, target_url: str, callback_server: str, **kwargs):
        super().__init__(target_url, **kwargs)
        self.callback_server = callback_server  # http://callback.io
    
    def scan(self) -> TestResultCreate:
        # Test URL parameters
        url_param_test = self._test_url_parameters()
        if url_param_test["vulnerable"]:
            return self._vulnerable_result(url_param_test)
        
        # Test headers
        header_test = self._test_headers()
        if header_test["vulnerable"]:
            return self._vulnerable_result(header_test)
        
        return self._safe_result()
    
    def _test_url_parameters(self) -> dict[str, Any]:
        # Generate unique identifier
        identifier = str(uuid.uuid4())
        
        # Payloads to test
        params = ["url", "callback", "webhook", "redirect", "link"]
        
        for param in params:
            callback_url = f"{self.callback_server}/callback/{identifier}"
            
            # Submit SSRF payload
            response = self.make_request(
                "GET",
                f"/?{param}={callback_url}"
            )
            
            # Wait for callback
            time.sleep(5)
            
            # Check if callback was received
            check_response = requests.get(
                f"{self.callback_server}/check/{identifier}"
            )
            
            if check_response.json()["received"]:
                return {
                    "vulnerable": True,
                    "parameter": param,
                    "callback_data": check_response.json()["data"],
                }
        
        return {"vulnerable": False}
    
    def _test_headers(self) -> dict[str, Any]:
        """
        Test headers like Referer, X-Forwarded-Host for SSRF
        """
        identifier = str(uuid.uuid4())
        callback_url = f"{self.callback_server}/callback/{identifier}"
        
        headers_to_test = [
            "Referer",
            "X-Forwarded-Host",
            "X-Original-URL",
            "Host",
        ]
        
        for header in headers_to_test:
            response = self.make_request(
                "GET",
                "/",
                headers={header: callback_url}
            )
            
            time.sleep(5)
            
            check_response = requests.get(
                f"{self.callback_server}/check/{identifier}"
            )
            
            if check_response.json()["received"]:
                return {
                    "vulnerable": True,
                    "header": header,
                    "callback_data": check_response.json()["data"],
                }
        
        return {"vulnerable": False}
```

**Phase 3: Add DNS Callback Alternative** (2-3 hours)

Some environments block HTTP but allow DNS. Use DNS callbacks:

```python
def _test_dns_callback(self) -> dict[str, Any]:
    """
    Use DNS exfiltration for SSRF detection
    """
    identifier = uuid.uuid4().hex[:8]
    dns_domain = f"{identifier}.callback.io"  # Your DNS server
    
    # Submit payload that triggers DNS lookup
    payloads = [
        f"http://{dns_domain}/",
        f"https://{dns_domain}/",
        f"//{dns_domain}/",
    ]
    
    for payload in payloads:
        self.make_request("GET", f"/?url={payload}")
    
    time.sleep(5)
    
    # Check DNS logs for lookup
    # (Requires DNS server that logs queries)
    
    return {"vulnerable": False}  # Implement DNS checking
```

**Phase 4: Add Time-Based Detection** (3-4 hours)

For fully blind SSRF (no callbacks possible), use timing:

```python
def _test_timing_based_ssrf(self) -> dict[str, Any]:
    """
    Detect SSRF via timing differences
    
    Internal IPs respond fast, external IPs are slower
    """
    # Baseline with external IP (slow)
    baseline_times = []
    for _ in range(5):
        start = time.time()
        self.make_request("GET", "/?url=http://example.com/")
        baseline_times.append(time.time() - start)
    
    baseline_avg = statistics.mean(baseline_times)
    
    # Test with internal IPs (should be faster if SSRF exists)
    internal_ips = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://192.168.1.1/",
    ]
    
    for ip in internal_ips:
        test_times = []
        for _ in range(5):
            start = time.time()
            self.make_request("GET", f"/?url={ip}")
            test_times.append(time.time() - start)
        
        test_avg = statistics.mean(test_times)
        
        # If internal IP is significantly faster, SSRF likely exists
        if test_avg < (baseline_avg * 0.5):
            return {
                "vulnerable": True,
                "technique": "timing-based",
                "baseline_time": baseline_avg,
                "internal_ip_time": test_avg,
            }
    
    return {"vulnerable": False}
```

**Testing the scanner:**

Set up a vulnerable test API:
```python
# test_api.py
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/")
def ssrf_vulnerable():
    url = request.args.get("url")
    if url:
        # Vulnerable - makes request to user-supplied URL
        requests.get(url)
    return "OK"

if __name__ == "__main__":
    app.run(port=5000)
```

Run scanner against it:
```bash
# Should detect SSRF and receive callback
python -m backend.scanners.ssrf_scanner http://localhost:5000
```

**Success criteria:**
- [ ] Detects SSRF in URL parameters
- [ ] Detects SSRF in headers
- [ ] Uses DNS callbacks when HTTP blocked
- [ ] Falls back to timing-based detection
- [ ] Handles network delays gracefully
- [ ] Cleans up test callbacks

### Challenge 9: Build a Full Vulnerability Report Generator

**What to build:**
Generate professional PDF reports of scan results with executive summary, technical details, remediation steps, and CVSS scoring.

**Estimated time:**
10-15 hours for complete implementation with styling and charts.

**What you'll learn:**
- PDF generation with ReportLab or WeasyPrint
- CVSS scoring calculation
- Data visualization (matplotlib, plotly)
- Report templating and styling
- Professional documentation standards

**Implementation phases:**

**Phase 1: Report Data Structure** (2-3 hours)

Create `backend/services/report_service.py`:

```python
from dataclasses import dataclass
from typing import List
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

@dataclass
class VulnerabilitySummary:
    critical: int
    high: int
    medium: int
    low: int
    info: int
    
    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

class ReportGenerator:
    def __init__(self, scan_id: int, db: Session):
        self.scan = ScanRepository.get_by_id(db, scan_id)
        self.db = db
    
    def generate_pdf(self, output_path: str) -> str:
        """
        Generate comprehensive PDF report
        """
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        
        # Cover page
        self._add_cover_page(c, width, height)
        c.showPage()
        
        # Executive summary
        self._add_executive_summary(c, width, height)
        c.showPage()
        
        # Vulnerability details
        self._add_vulnerability_details(c, width, height)
        
        c.save()
        return output_path
    
    def _add_cover_page(self, c, width, height):
        c.setFont("Helvetica-Bold", 24)
        c.drawString(100, height - 100, "Security Scan Report")
        
        c.setFont("Helvetica", 14)
        c.drawString(100, height - 150, f"Target: {self.scan.target_url}")
        c.drawString(100, height - 180, f"Date: {self.scan.scan_date}")
        
        # Add severity chart
        self._add_severity_chart(c, width, height - 400)
    
    def _add_severity_chart(self, c, x, y):
        """
        Create pie chart of vulnerabilities by severity
        """
        summary = self._calculate_summary()
        
        # Create matplotlib chart
        fig, ax = plt.subplots(figsize=(4, 4))
        
        labels = ["Critical", "High", "Medium", "Low", "Info"]
        sizes = [summary.critical, summary.high, summary.medium, summary.low, summary.info]
        colors = ["#dc2626", "#ea580c", "#f59e0b", "#3b82f6", "#6b7280"]
        
        ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%")
        
        # Save to temp file and embed in PDF
        chart_path = "/tmp/severity_chart.png"
        plt.savefig(chart_path)
        plt.close()
        
        c.drawImage(chart_path, x, y, width=300, height=300)
```

**Phase 2: CVSS Scoring** (2-3 hours)

Add CVSS score calculation:

```python
class CVSSCalculator:
    """
    Calculate CVSS v3.1 scores for vulnerabilities
    """
    
    def calculate_score(
        self,
        test_result: TestResult
    ) -> dict[str, Any]:
        """
        Calculate CVSS score based on test result
        """
        # Base metrics
        av = self._attack_vector(test_result.test_name)  # Network
        ac = self._attack_complexity(test_result)  # Low/High
        pr = self._privileges_required(test_result)  # None/Low/High
        ui = self._user_interaction(test_result)  # None/Required
        s = "U"  # Scope: Unchanged
        c = self._confidentiality_impact(test_result)  # High/Low/None
        i = self._integrity_impact(test_result)
        a = self._availability_impact(test_result)
        
        # Calculate base score using CVSS formula
        # (Simplified - full implementation in CVSS spec)
        
        impact = 1 - ((1 - c) * (1 - i) * (1 - a))
        exploitability = 8.22 * av * ac * pr * ui
        
        if impact <= 0:
            base_score = 0
        else:
            base_score = min(
                (impact + exploitability) * 1.08,
                10.0
            )
        
        return {
            "score": round(base_score, 1),
            "severity": self._score_to_severity(base_score),
            "vector": f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}",
        }
```

**Phase 3: Remediation Guide** (2-3 hours)

Add detailed remediation for each vulnerability type:

```python
REMEDIATION_GUIDES = {
    TestType.SQLI: {
        "title": "SQL Injection Remediation",
        "steps": [
            "1. Use parameterized queries (prepared statements) for all database operations",
            "2. Never concatenate user input into SQL strings",
            "3. Use ORMs like SQLAlchemy that handle escaping automatically",
            "4. Implement input validation to reject suspicious patterns",
            "5. Use least privilege database accounts",
        ],
        "code_example": """
# Before (Vulnerable)
query = f"SELECT * FROM users WHERE email = '{email}'"

# After (Safe)
query = db.query(User).filter(User.email == email).first()
        """,
        "references": [
            "OWASP SQL Injection Prevention Cheat Sheet",
            "CWE-89: Improper Neutralization of Special Elements",
        ],
    },
    # ... other test types
}
```

**Success criteria:**
- [ ] Generates professional-looking PDFs
- [ ] Includes executive summary (high-level findings)
- [ ] Shows vulnerability breakdown by severity
- [ ] Calculates CVSS scores
- [ ] Provides specific remediation steps
- [ ] Includes code examples
- [ ] Charts and visualizations

## Mix and Match

Combine features for bigger projects:

**Project Idea 1: Complete API Security Platform**
- Combine Challenge 7 (plugin system) + Challenge 9 (report generation) + Challenge 8 (SSRF detection)
- Add web UI for scheduling scans
- Add email notifications when vulnerabilities found
- Result: Production-ready continuous API security testing

**Project Idea 2: CI/CD Security Integration**
- Combine Challenge 4 (stored XSS) + Challenge 6 (XXE) + Challenge 2 (password strength)
- Build GitHub Action that runs scans on every commit
- Fail builds if critical vulnerabilities found
- Result: Security testing in development pipeline

## Real World Integration Challenges

### Integrate with Slack for Notifications

**The goal:**
Send Slack messages when scans complete or vulnerabilities are found.

**What you'll need:**
- Slack workspace with admin access
- Slack App with incoming webhook
- Understanding of Slack's Block Kit for rich messages

**Implementation plan:**

1. **Create Slack App** at https://api.slack.com/apps
2. **Enable Incoming Webhooks** and get webhook URL
3. **Add to config** in `.env`:
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

4. **Create notification service** in `backend/services/notification_service.py`:
```python
import requests
from typing import List

class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
    
    def send_scan_complete(self, scan: Scan):
        """
        Send notification when scan completes
        """
        summary = self._calculate_summary(scan)
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔒 Security Scan Complete"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{scan.target_url}"},
                    {"type": "mrkdwn", "text": f"*Date:*\n{scan.scan_date}"},
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Critical:* {summary.critical}"},
                    {"type": "mrkdwn", "text": f"*High:* {summary.high}"},
                    {"type": "mrkdwn", "text": f"*Medium:* {summary.medium}"},
                ]
            }
        ]
        
        if summary.critical > 0 or summary.high > 0:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "⚠️ *Critical vulnerabilities found!* Review immediately."
                }
            })
        
        requests.post(self.webhook_url, json={"blocks": blocks})
```

5. **Hook into scan service** at end of `ScanService.run_scan()`:
```python
# After saving results
if settings.SLACK_WEBHOOK_URL:
    notifier = SlackNotifier(settings.SLACK_WEBHOOK_URL)
    notifier.send_scan_complete(scan)
```

**Watch out for:**
- Rate limits on Slack webhooks (1 message per second)
- Message size limits (3000 characters for text blocks)
- Error handling (webhook URL might be invalid)

### Deploy to Production (AWS/DigitalOcean)

**The goal:**
Get this running in production on real infrastructure.

**What you'll learn:**
- Docker deployment to cloud
- Environment variable management in production
- SSL/TLS certificate setup
- Database backups and maintenance

**Steps:**

1. **Provision server** (DigitalOcean Droplet, AWS EC2)
   - Ubuntu 24.04 LTS
   - 2GB RAM minimum (4GB recommended)
   - Open ports: 80 (HTTP), 443 (HTTPS), 22 (SSH)

2. **Install Docker** on server:
```bash
ssh root@your-server-ip

curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

apt install docker-compose-plugin
```

3. **Clone project** and configure:
```bash
git clone https://github.com/yourusername/api-security-scanner.git
cd api-security-scanner

cp .env.example .env
nano .env  # Edit production settings
```

4. **Set production environment variables**:
```bash
# .env for production
SECRET_KEY=$(openssl rand -hex 32)
DEBUG=false
DATABASE_URL=postgresql://...
CORS_ORIGINS=https://yourdomain.com
```

5. **Set up SSL with Let's Encrypt**:
```bash
# Install certbot
apt install certbot python3-certbot-nginx

# Get certificate
certbot --nginx -d yourdomain.com
```

6. **Update nginx config** in `conf/nginx/prod.nginx` to use SSL:
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;
    
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # ... rest of config
}
```

7. **Deploy**:
```bash
docker compose -f compose.yml up -d --build
```

**Production checklist:**
- [ ] Changed `SECRET_KEY` to random value
- [ ] Set `DEBUG=false`
- [ ] Configured real database (not localhost)
- [ ] Set up SSL certificates
- [ ] Configured firewall (ufw allow 80,443,22)
- [ ] Set up backups (database dumps to S3/Spaces)
- [ ] Configure monitoring (Prometheus, Grafana, or cloud provider)
- [ ] Set up logging (centralized logs, log rotation)

## Performance Challenges

### Challenge: Handle 1000 concurrent scans

**The goal:**
Scale the system to handle 1000 scans running simultaneously without crashing or slowing down.

**Current bottleneck:**
Scans run synchronously in request handler. Database connections limited to 5 by default. Memory usage grows linearly with concurrent scans.

**Optimization approaches:**

**Approach 1: Task Queue with Celery**
- How: Move scans to background workers with Celery + Redis
- Gain: Non-blocking API, horizontal scaling, retry logic
- Tradeoff: Added complexity, need Redis infrastructure

Implementation:
```bash
# Install Celery
pip install celery redis

# backend/celery_app.py
from celery import Celery

celery = Celery(
    "scanner",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

@celery.task
def run_scan_async(scan_id: int):
    """Run scan in background"""
    db = SessionLocal()
    scan = ScanRepository.get_by_id(db, scan_id)
    # ... execute scan
```

**Approach 2: Increase Database Connections**
- How: Configure connection pooling in SQLAlchemy
- Gain: More concurrent database operations
- Tradeoff: Higher memory usage, Postgres connection limits

```python
# core/database.py
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=20,  # Increased from 5
    max_overflow=40,  # Up to 60 total connections
    pool_pre_ping=True,
)
```

**Benchmark it:**
```bash
# Load testing with Apache Bench
ab -n 1000 -c 100 http://localhost:8000/scans/ \
   -H "Authorization: Bearer TOKEN" \
   -p scan_request.json
```

Target metrics:
- Throughput: 50+ requests/second
- Latency p95: <2 seconds (for scan creation, not execution)
- Error rate: <1%

### Challenge: Reduce Scanner Memory Usage

**The goal:**
Cut memory usage by 50% when running 100 concurrent scans.

**Profile first:**
```python
# Add memory profiling
import tracemalloc

tracemalloc.start()

# Run scan
scanner.scan()

current, peak = tracemalloc.get_traced_memory()
print(f"Current: {current / 1024 / 1024:.2f} MB")
print(f"Peak: {peak / 1024 / 1024:.2f} MB")

tracemalloc.stop()
```

**Common optimization areas:**
- Store response bodies in memory (large responses eat RAM)
- Session objects not being cleaned up
- Evidence JSON storing entire responses

Fix:
```python
# Instead of storing full response
evidence = {"response": response.text}  # 100KB+

# Store summary
evidence = {
    "status_code": response.status_code,
    "length": len(response.text),
    "excerpt": response.text[:500],  # Just first 500 chars
}
```

## Security Challenges

### Challenge: Add Webhook Signature Verification

**What to implement:**
When sending scan results to webhooks, sign the payload so receivers can verify it's from your scanner.

**Threat model:**
This protects against:
- Attacker sending fake scan results to webhook
- Man-in-the-middle tampering with webhook data

**Implementation:**

```python
import hmac
import hashlib

class WebhookSigner:
    def __init__(self, secret: str):
        self.secret = secret.encode()
    
    def sign(self, payload: str) -> str:
        """
        Create HMAC-SHA256 signature of payload
        """
        signature = hmac.new(
            self.secret,
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify(self, payload: str, signature: str) -> bool:
        """
        Verify signature is valid
        """
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)
```

Usage:
```python
# When sending webhook
signer = WebhookSigner(settings.WEBHOOK_SECRET)
payload_json = json.dumps(scan_data)
signature = signer.sign(payload_json)

requests.post(
    webhook_url,
    json=scan_data,
    headers={"X-Signature": signature}
)

# Receiver verifies
received_signature = request.headers["X-Signature"]
if not signer.verify(payload_json, received_signature):
    raise HTTPException(401, "Invalid signature")
```

### Challenge: Pass OWASP Top 10 Compliance

**The goal:**
Make this project compliant with OWASP Top 10 2021.

**Current gaps:**
- A01:2021-Broken Access Control: IDOR checks implemented ✓
- A02:2021-Cryptographic Failures: Bcrypt for passwords ✓, but no HTTPS enforcement
- A03:2021-Injection: SQL injection detection ✓, but could add command injection
- A07:2021-Identification and Authentication Failures: JWT validation ✓
- A09:2021-Security Logging and Monitoring Failures: No audit logging ❌

**Remediation:**

Add audit logging:
```python
# models/AuditLog.py
class AuditLog(BaseModel):
    __tablename__ = "audit_logs"
    
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(100))  # "scan_created", "login_success"
    ip_address = Column(String(45))  # Support IPv6
    user_agent = Column(String(255))
    details = Column(JSON)

# Log every important action
def log_action(user_id: int, action: str, request: Request, **details):
    log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=request.client.host,
        user_agent=request.headers.get("User-Agent"),
        details=details,
    )
    db.add(log)
    db.commit()
```

## Contribution Ideas

Finished a challenge? Share it back:

1. **Fork the repo** at github.com/yourusername/api-security-scanner
2. **Implement your extension** in a feature branch (`git checkout -b feature/xxe-scanner`)
3. **Document it** - Add to learn folder, update README
4. **Submit a PR** with:
   - Implementation code
   - Unit tests (minimum 80% coverage)
   - Integration tests
   - Documentation (docstrings, README updates)
   - Example usage

Good extensions might get merged into the main project.

## Challenge Yourself Further

### Build Something New

Use the concepts you learned here to build:

- **GraphQL security scanner** - Test for introspection leaks, query depth limits, batching attacks
- **WebSocket security tester** - Test for injection, authentication, rate limiting in WebSocket connections
- **Cloud API scanner** - Test AWS, Azure, GCP APIs for misconfiguration (public S3 buckets, open databases)

### Study Real Implementations

Compare your implementation to production tools:

- **Burp Suite** - Study how their active scanner detects SQLi (multiple techniques, adaptive testing)
- **OWASP ZAP** - Look at their scanner plugin architecture
- **Nuclei** - Check out their YAML-based template system for custom checks

Read their code (many are open source), understand their tradeoffs, steal their good ideas.

### Write About It

Document your extension:

- Blog post explaining what you built and why ("Adding XXE Detection to an API Scanner")
- Tutorial for others to follow ("How to Build a CORS Misconfiguration Scanner")
- Comparison with alternative approaches ("Callback-based SSRF Detection vs Timing-based")

Teaching others is the best way to verify you understand it.

## Getting Help

Stuck on a challenge?

1. **Debug systematically**
   - What did you expect to happen?
   - What actually happened?
   - What's the smallest test case that reproduces it?
   - What have you already tried?

2. **Read the existing code**
   - SQLi scanner does time-based detection (similar to SSRF timing)
   - Auth scanner does multi-step testing (similar to stored XSS)
   - Base scanner has retry logic you can reuse

3. **Search for similar problems**
   - Stack Overflow with tags: python, fastapi, security-testing
   - GitHub issues in similar projects (ZAP, Nuclei, SQLMap)
   - InfoSec forums like /r/netsec, /r/AskNetsec

4. **Ask for help with context**
   - Post in project discussions or issues
   - Include: what you're trying to build, what you tried, what happened, what you expected
   - Provide code snippets and error messages
   - Don't just paste error messages without explanation

## Challenge Completion Tracker

Track your progress:

- [ ] Easy Challenge 1: CORS Detection
- [ ] Easy Challenge 2: Password Strength
- [ ] Easy Challenge 3: Response Time Monitoring
- [ ] Intermediate Challenge 4: Stored XSS
- [ ] Intermediate Challenge 5: Advanced Rate Limit Bypass
- [ ] Intermediate Challenge 6: XXE Detection
- [ ] Advanced Challenge 7: Plugin System
- [ ] Advanced Challenge 8: Blind SSRF
- [ ] Expert Challenge 9: Report Generation

**Bonus challenges:**
- [ ] Slack Integration
- [ ] Production Deployment
- [ ] Performance: 1000 Concurrent Scans
- [ ] Security: Webhook Signatures
- [ ] Compliance: OWASP Top 10

Completed all of them? You've mastered API security testing. Time to build something new, contribute to open source security tools, or apply these skills professionally in penetration testing or security engineering roles.
