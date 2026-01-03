### docs/research/waf-design.md

# Web Application Firewall (WAF) Rule Engine Design Research

### 1. Executive Summary

A Web Application Firewall (WAF) is a critical component of modern web application security, acting as a shield that inspects and filters HTTP traffic between a web application and the Internet. This document provides an in-depth analysis of the design and implementation of a robust WAF rule engine. It explores the core components of a WAF, strategies for detecting the OWASP Top 10 vulnerabilities, and the intricacies of rule creation and management. By examining detection techniques ranging from traditional signature-based methods to advanced machine learning models, this research outlines a blueprint for a high-performance, low-latency WAF that effectively mitigates threats while minimizing false positives. The document also delves into the ModSecurity rule format as a source of inspiration for a powerful and flexible custom Domain Specific Language (DSL) for defining security rules. Finally, it addresses the ever-evolving landscape of attacker evasion techniques, providing insights into building a resilient WAF architecture.

### 2. OWASP Top 10 Detection Strategies

The Open Web Application Security Project (OWASP) Top 10 represents a consensus among security experts about the most critical web application security risks. A modern WAF must have effective strategies to detect and mitigate these vulnerabilities.

#### **A01:2021 - Broken Access Control**

Broken Access Control remains a prevalent and severe vulnerability. A WAF can help enforce access control policies by:

*   **URL and Parameter-Based Access Control:** Defining rules that restrict access to specific URLs, directories, and API endpoints based on user roles or IP addresses.
*   **Session and Token Analysis:** Inspecting session cookies and tokens to ensure they are valid and correspond to the appropriate user privileges for the requested resource.
*   **Business Logic Anomaly Detection:** Utilizing anomaly detection to identify unusual patterns in user behavior that might indicate an attempt to bypass access controls, such as a standard user attempting to access administrative functions.

#### **A02:2021 - Cryptographic Failures**

While primarily an application-level concern, a WAF can contribute to mitigating cryptographic failures by:

*   **Enforcing HTTPS:** Redirecting all HTTP traffic to HTTPS to ensure data is encrypted in transit.
*   **Inspecting SSL/TLS Handshakes:** Identifying and blocking connections that use weak or deprecated cipher suites.
*   **Detecting Sensitive Data Exposure:** Using regular expressions to identify and potentially mask sensitive data, such as credit card numbers or social security numbers, in server responses to prevent accidental leakage.

#### **A03:2021 - Injection**

Injection flaws, such as SQL, NoSQL, and Command Injection, are a broad category of attacks. A WAF can detect these by:

*   **Signature-Based Detection:** Employing a database of known attack patterns and signatures to identify malicious payloads. This includes looking for common SQL keywords (`SELECT`, `UNION`, `INSERT`), command injection payloads (`/bin/sh`, `powershell`), and other malicious strings.
*   **Behavioral Analysis:** Understanding the normal structure of SQL queries and application traffic to identify anomalous requests that may indicate an injection attempt.
*   **Input Validation and Sanitization:** Defining rules that enforce strict input validation, rejecting requests that contain unexpected or malicious characters. In some cases, the WAF can sanitize input by removing or encoding dangerous characters.

#### **A04:2021 - Insecure Design**

Insecure design is a broad category that is challenging to address solely with a WAF, as it often stems from fundamental architectural flaws. However, a WAF can provide a layer of defense by:

*   **Virtual Patching:** Applying rules that block known exploits against insecure design patterns until the underlying application code can be fixed.
*   **Enforcing Security Best Practices:** Implementing rules that check for common insecure design flaws, such as predictable resource locations or the exposure of sensitive files through directory traversal.

#### **A05:2021 - Security Misconfiguration**

A WAF can help detect and prevent attacks that exploit security misconfigurations by:

*   **Header Inspection:** Checking for misconfigured security headers (e.g., `Content-Security-Policy`, `Strict-Transport-Security`) and enforcing secure configurations.
*   **Blocking Verbose Error Messages:** Preventing the leakage of sensitive information by intercepting and sanitizing detailed error messages that could reveal underlying system details.
*   **Enforcing Whitelists:** Defining strict rules that only allow access to specific, known-safe resources and blocking everything else.

#### **A06:2021 - Vulnerable and Outdated Components**

A WAF can mitigate the risks associated with vulnerable components through:

*   **Virtual Patching:** Creating rules to block requests that attempt to exploit known vulnerabilities in third-party libraries and frameworks. This provides a temporary shield while developers work on updating the components.
*   **Signature-Based Detection:** Using signatures of known exploits for vulnerable components to identify and block attacks.
*   **Information Leakage Prevention:** Preventing the disclosure of component versions in HTTP headers and error messages, making it harder for attackers to identify vulnerable systems.

#### **A07:2021 - Identification and Authentication Failures**

A WAF can help protect against authentication-related attacks by:

*   **Brute-Force Protection:** Implementing rate-limiting rules to block or slow down repeated login attempts from a single IP address.
*   **Credential Stuffing Detection:** Using reputation-based blocking of IPs known for malicious activity and identifying automated login attempts.
*   **Session Hijacking Prevention:** Enforcing the use of secure and HttpOnly cookies and monitoring for suspicious session ID manipulation.

#### **A08:2021 - Software and Data Integrity Failures**

This category, which includes issues like insecure deserialization, can be addressed by a WAF through:

*   **Signature-Based Detection:** Using rules that look for the signatures of known insecure deserialization payloads.
*   **Content-Type Validation:** Enforcing strict content-type validation to prevent unexpected data formats from being processed by the application.

#### **A09:2021 - Security Logging and Monitoring Failures**

While a WAF is not a replacement for a comprehensive logging and monitoring solution, it plays a crucial role by:

*   **Generating Detailed Logs:** Providing rich logs of all inspected traffic, including blocked requests, matched rules, and request metadata, which can be fed into a SIEM for analysis.
*   **Alerting on Malicious Activity:** Generating real-time alerts when high-severity rules are triggered, enabling a rapid response to potential attacks.

#### **A10:2021 - Server-Side Request Forgery (SSRF)**

A WAF can help prevent SSRF attacks by:

*   **Enforcing Whitelists of Allowed Domains:** Creating rules that restrict outgoing requests from the server to a predefined list of trusted domains.
*   **Blocking Internal IP Addresses:** Preventing requests to internal or loopback IP addresses.
*   **URL Schema Validation:** Ensuring that user-supplied URLs conform to expected formats and protocols.

### 3. Detection Techniques

A multi-layered approach to detection is essential for an effective WAF.

#### **Regex Patterns (Signature-Based Detection)**

Regular expressions are a cornerstone of traditional WAFs, used to identify known attack patterns. For example, a simple regex to detect a basic SQL injection attempt might be `/(union|select|insert|update|delete|from|where)/i`. While effective against common attacks, regex-based detection can be bypassed by sophisticated attackers and can lead to a high number of false positives if not carefully crafted.

#### **Machine Learning (ML) and Anomaly Detection**

Modern WAFs are increasingly incorporating machine learning to move beyond static signatures and detect novel attacks. ML models can be trained on vast datasets of both legitimate and malicious traffic to learn the normal behavior of a web application.

*   **Supervised Learning:** Models are trained on labeled data to classify requests as malicious or benign. This is effective for identifying known attack types with high accuracy.
*   **Unsupervised Learning (Anomaly Detection):** Models are trained on a baseline of normal traffic to identify deviations that could indicate an attack. This approach is particularly useful for detecting zero-day exploits and other unknown threats. Techniques like clustering and statistical modeling can be used to flag requests that fall outside the established norm.

#### **Behavioral Analysis**

Behavioral analysis focuses on the sequence and context of user actions. By creating a profile of normal user behavior, a WAF can detect anomalies such as:

*   **Anomalous Sequences of Requests:** A user suddenly accessing pages in an illogical order or performing actions at an unusually high speed.
*   **Atypical Parameter Values:** Submitting data in a format or range that is not typical for a given user or the application.
*   **Session Hijacking Indicators:** Sudden changes in the user agent, IP address, or other session-related parameters.

### 4. False Positive Reduction Strategies

False positives, where legitimate traffic is incorrectly blocked, are a significant challenge for WAF administrators. Effective strategies for reduction include:

*   **Rule Tuning and Customization:** Regularly reviewing and refining WAF rules based on the specific application's traffic patterns is crucial. This includes creating exceptions for known safe IP addresses or specific URLs.
*   **Risk-Based Scoring:** Instead of a simple block/allow decision, a WAF can assign a risk score to each request based on a variety of factors. Requests with a low score are allowed, those with a high score are blocked, and those in the middle may be subjected to further scrutiny, such as a CAPTCHA challenge.
*   **Learning Mode:** Running the WAF in a non-blocking "learning mode" to gather data on normal traffic patterns before enforcing blocking rules.
*   **Integration with Dynamic Application Security Testing (DAST):** Combining a WAF with a DAST scanner can help to identify which vulnerabilities are actually exploitable and tune WAF rules accordingly.
*   **Feedback Loops:** Providing a mechanism for users or administrators to report false positives, which can then be used to refine the rule set.

### 5. ModSecurity Rule Format (for inspiration)

ModSecurity is a widely-used open-source WAF, and its rule language provides a powerful and flexible model for a custom DSL. The basic syntax of a ModSecurity rule is:

`SecRule VARIABLES OPERATOR [ACTIONS]`

*   **VARIABLES:** Specifies where to look in the HTTP request or response (e.g., `ARGS`, `REQUEST_HEADERS`, `RESPONSE_BODY`).
*   **OPERATOR:** Defines how to inspect the variable (e.g., `@rx` for regular expression matching, `@streq` for string equality).
*   **ACTIONS:** Specifies what to do if the rule matches (e.g., `deny`, `log`, `pass`, `t:lowercase` for transformation).

ModSecurity's phased processing model (request headers, request body, response headers, response body, logging) is also a valuable concept for ensuring that rules are executed at the appropriate stage of the transaction.

### 6. Custom Rule DSL Design

Designing a custom Domain Specific Language (DSL) for WAF rules should prioritize clarity, expressiveness, and ease of use. Key considerations include:

*   **Human-Readability:** The syntax should be intuitive and easy for security analysts to understand and write.
*   **Structured Format:** Using a structured format like YAML or JSON can make rules easier to parse and manage programmatically.
*   **Modularity and Reusability:** The DSL should allow for the creation of reusable rule sets and policies that can be applied to different applications.
*   **Extensibility:** The language should be designed to easily accommodate new detection techniques and actions as threats evolve.
*   **Clear Semantics for Conditions and Actions:** The DSL should have a well-defined set of conditions (e.g., `matches_regex`, `is_in_ip_list`) and corresponding actions (`block`, `log`, `redirect`, `add_header`).

### 7. Performance Optimization

A WAF must inspect traffic with minimal impact on latency to avoid degrading the user experience. Performance optimization strategies include:

*   **Efficient Rule Processing:** The rule engine should be designed for high-speed matching. This can involve using efficient regular expression engines and compiling rules into a faster format.
*   **Caching of Rules and Results:** Caching frequently used rules and the results of certain checks can reduce redundant processing.
*   **Asynchronous Logging:** Decoupling the logging of events from the request processing path can prevent logging operations from becoming a bottleneck.
*   **Hardware Acceleration:** Utilizing specialized hardware for tasks like SSL/TLS decryption and pattern matching can significantly improve performance.
*   **Selective Inspection:** Applying more resource-intensive rules only to specific parts of the application or to traffic that has already been flagged as suspicious.

### 8. Evasion Techniques Attackers Use

Attackers constantly devise new ways to bypass WAFs. A robust WAF design must anticipate and counter these techniques:

*   **Encoding and Obfuscation:** Attackers use various encoding schemes (URL encoding, Base64, etc.) to disguise malicious payloads. A WAF must normalize and decode all input before inspection.
*   **Polyglot Payloads:** Crafting payloads that are valid in multiple contexts (e.g., a string that is both valid HTML and JavaScript) to confuse WAF parsers.
*   **HTTP Parameter Pollution (HPP):** Sending multiple parameters with the same name to see how the WAF and the backend application handle the duplicate parameters.
*   **Request Smuggling:** Exploiting discrepancies in how a WAF and the backend server parse `Content-Length` and `Transfer-Encoding` headers to smuggle malicious requests.
*   **Case Variation:** Using different cases for characters in attack payloads (e.g., `SeLeCt` instead of `select`) to bypass case-sensitive regex patterns.
*   **Whitespace and Comment Obfuscation:** Inserting whitespace characters or comments within attack payloads to break up known signatures.

### 9. Example Rule Library

A baseline rule library should provide broad protection against common attacks.

#### **SQL Injection**

```
rule "SQL Injection - Common Keywords" {
  match {
    request_body contains_any_case [
      "select ", " from ", " where ",
      "union all select", "insert into", "update set", "delete from"
    ]
  }
  action {
    block
    log "High-risk SQL keywords detected in request body"
  }
}
```

#### **Cross-Site Scripting (XSS)**

```
rule "XSS - Script Tags" {
  match {
    any_parameter contains_regex "<script.*>"
  }
  action {
    block
    log "Script tags detected in a parameter"
  }
}
```

#### **Cross-Site Request Forgery (CSRF)**

```
rule "CSRF - Missing Anti-CSRF Token" {
  match {
    request_method == "POST"
    and not header_exists "X-CSRF-Token"
  }
  action {
    block
    log "POST request missing X-CSRF-Token header"
  }
}```

**Key Architectural Trends:**

*   **Cloud-Native and Containerized Deployment:** Traditional appliance-based WAFs are ill-suited for ephemeral, containerized environments. Modern WAFs are designed as lightweight, containerized services that can be deployed directly within a Kubernetes cluster, often as an ingress controller or a sidecar proxy. This "close-to-the-application" deployment model allows for granular, microservice-specific security policies and scales automatically with the application. Azure's Application Gateway for Containers, for instance, introduces a Kubernetes-native `WebApplicationFirewallPolicy` custom resource, allowing WAF policies to be defined and scoped directly within the cluster.
*   **Decoupled Control and Data Planes:** To enhance agility and performance, leading WAFs now separate the control plane (policy management) from the data plane (traffic inspection). This allows security teams to update policies without impacting the data path, preventing latency and enabling faster deployment cycles, a core tenet of DevOps and CI/CD pipelines.
*   **AI and Machine Learning at the Core:** The most significant evolution is the integration of Artificial Intelligence (AI) and Machine Learning (ML) to move beyond reactive signature-based detection. These systems establish a baseline of normal application behavior to detect anomalies and identify zero-day attacks that have no known signature.

### 2. OWASP Top 10 Detection Strategies (2025 Release Candidate Perspective)

The upcoming OWASP Top 10 for 2025, currently in its release candidate stage, reflects the changing threat landscape. A modern WAF must address these evolving risks with sophisticated detection strategies.

#### **A01:2025 - Broken Access Control (Unchanged at #1)**

Still the most prevalent risk, modern WAFs address this not just with URL-based rules, but through stateful analysis.

*   **Stateful Policy Enforcement:** By tracking user sessions and understanding application logic, a WAF can detect when a user attempts to access resources outside their prescribed role, even if the URL pattern seems benign. This is a significant advancement over stateless pattern matching.
*   **API Endpoint Authorization:** Modern WAFs can parse and enforce access control policies on a per-endpoint basis for REST and GraphQL APIs, ensuring that only authorized users can perform specific mutations or queries.

#### **A02:2025 - Security Misconfiguration (Moved up from #5)**

This has risen in prominence with the complexity of cloud environments.

*   **Cloud Security Posture Management (CSPM) Integration:** A WAF can integrate with CSPM tools to receive real-time updates about misconfigurations in the underlying cloud infrastructure (e.g., publicly exposed S3 buckets) and apply virtual patching rules to block attempts to exploit them.
*   **Automated Header Enforcement:** WAFs can be configured to automatically enforce secure HTTP headers (like Content-Security-Policy, Strict-Transport-Security) and block responses that lack them, ensuring a consistent security posture.

#### **A03:2025 - Software Supply Chain Failures (New Category)**

This is a new and critical area of focus.

*   **Virtual Patching for Known Vulnerabilities:** When a vulnerability is discovered in a third-party library, a WAF can immediately deploy a virtual patch to block exploit attempts, giving developers time to update the component without exposing the application to risk.
*   **Threat Intelligence Integration:** Modern WAFs integrate with threat intelligence feeds to be aware of newly discovered vulnerabilities in open-source components and automatically apply relevant blocking rules.

#### **A05:2025 - Injection (Moved down from #3)**

While its ranking has slightly decreased, injection remains a severe threat that requires more than just basic regex.

*   **Semantic Analysis:** Instead of just looking for keywords like `' OR '1'='1`, AI-powered WAFs can parse and understand the structure of a SQL query or a command. This allows them to detect syntactically correct but malicious queries that would bypass simple pattern matching.
*   **NoSQL and GraphQL Injection:** Modern WAFs have specific parsers for NoSQL databases and GraphQL, allowing them to detect injection attacks that are unique to these technologies.

### 3. Advanced Detection Techniques: Beyond Regex

*   **Behavioral Analysis and Anomaly Detection:** This is the cornerstone of modern WAFs. By building a high-dimensional model of normal user behavior (including session duration, request frequency, and typical data patterns), the WAF can identify outliers that indicate an attack. This is highly effective against automated threats and zero-day exploits.
*   **Machine Learning Models:**
    *   **Supervised Learning:** Trained on vast datasets of labeled malicious and benign traffic, models like Support Vector Machines (SVMs) and Random Forests can accurately classify known attack types.
    *   **Unsupervised Learning:** Techniques like Isolation Forests and K-Means clustering are used to find anomalies without pre-labeled data, which is crucial for detecting novel attacks.
    *   **Deep Learning:** For complex sequence-based attacks, models like Long Short-Term Memory (LSTM) networks are being used to analyze the sequence of characters in a payload, providing a deeper understanding of its intent.
*   **Threat Intelligence Integration:** Modern WAFs consume real-time threat intelligence feeds to block traffic from known malicious IPs, botnets, and anonymizing proxies, proactively reducing the attack surface.

### 4. False Positive Reduction: The Modern Approach

Minimizing the blocking of legitimate traffic is paramount.

*   **Adaptive Learning and Automated Tuning:** The WAF continuously learns from traffic patterns to refine its rules and reduce false positives over time. This moves away from manual rule tuning, which is often slow and error-prone.
*   **Risk-Based Scoring:** Instead of a binary block/allow decision, each request is assigned a risk score. Low-score requests pass, high-score requests are blocked, and medium-score requests can be challenged with a CAPTCHA or subjected to more intense scrutiny.
*   **Context-Aware Policies:** Security rules can be fine-tuned based on the application's specific behavior. For example, a rule that blocks special characters might be relaxed for a specific form field where such characters are expected.

### 5. Custom Rule DSL Design: Moving Past ModSecurity

With ModSecurity reaching its end-of-life, the focus has shifted to more developer-friendly and expressive rule languages.

*   **YAML/JSON-Based Syntax:** Modern rule formats are often based on human-readable formats like YAML or JSON, which are easy to parse and integrate into CI/CD pipelines.
*   **Expressive and Composable Rules:** The DSL should allow for complex logic, combining multiple conditions with `AND/OR` operators and referencing dynamic data like threat intelligence feeds.
*   **GitOps-Friendly:** Storing WAF policies as code in a Git repository allows for version control, peer review, and automated deployment, fully integrating security into the DevOps workflow.

### 6. Performance Optimization in the Modern Era

*   **High-Performance Rule Engines:** Modern WAF engines are designed for speed, often using compiled rule sets and efficient algorithms to minimize latency.
*   **Hardware Offloading:** For high-traffic environments, WAFs can leverage hardware acceleration for computationally expensive tasks like SSL/TLS decryption.
*   **Edge Deployment:** Deploying the WAF at the edge, as part of a CDN, allows for malicious traffic to be blocked before it ever reaches the origin server, improving both security and performance.

### 7. The Latest in WAF Evasion Techniques

Attackers are constantly innovating to bypass WAFs.

*   **HTTP/2 and HTTP/3 Based Attacks:** The newer HTTP protocols introduce complexities that can be exploited to smuggle requests or desynchronize how a WAF and a backend server interpret a request.
*   **Payload Obfuscation and Encoding:** Attackers use a variety of encoding techniques, including double encoding and mixing cases, to bypass WAFs that don't properly normalize input.
*   **Logical Flaws:** Exploiting business logic flaws, such as race conditions or Insecure Direct Object References (IDOR), can completely bypass WAFs that are focused on syntax rather than logic.
*   **Payload Fragmentation:** Splitting malicious payloads across multiple HTTP requests or IP fragments can make it difficult for a WAF to detect the attack.

### **OWASP Top 10 Detection Strategies (Detailed)**

This section provides a more detailed look at modern detection strategies for the OWASP Top 10.

*   **A01: Broken Access Control:**
    *   **Detection:** Monitor for users attempting to access API endpoints or data objects that are not associated with their session or role. Use anomaly detection to flag when a user's behavior deviates significantly from their typical access patterns.
    *   **Example:** A user with a `customer` role suddenly attempting to access an `/admin` endpoint would be flagged, even if they have a valid session token.
*   **A02: Cryptographic Failures:**
    *   **Detection:** Scan HTTP headers for weak TLS/SSL ciphers and protocols. Inspect responses for sensitive data (e.g., credit card numbers, API keys) that is not properly masked or encrypted. Enforce HSTS to prevent protocol downgrade attacks.
*   **A03: Injection:**
    *   **Detection:** Use a combination of signature-based detection for common injection patterns and ML-based analysis to understand the grammatical structure of queries. A query that is syntactically valid but semantically anomalous (e.g., a query in a username field) would be flagged.
*   **A04: Insecure Design:**
    *   **Detection:** While hard to detect directly, a WAF can be configured to enforce secure design principles. For example, it can block requests that attempt to enumerate resource IDs sequentially, a common tactic for exploiting IDOR vulnerabilities.
*   **A05: Security Misconfiguration:**
    *   **Detection:** Continuously check for the presence and correctness of security headers. Block requests that attempt to access sensitive files (e.g., `.git`, `.env`) that may have been accidentally exposed.
*   **A06: Vulnerable and Outdated Components:**
    *   **Detection:** Integrate with a Software Composition Analysis (SCA) tool to be aware of the components used by the application. The WAF can then apply virtual patches for any known vulnerabilities in those components.
*   **A07: Identification and Authentication Failures:**
    *   **Detection:** Implement rate-limiting on login endpoints to prevent brute-force attacks. Use device fingerprinting and behavioral analysis to detect credential stuffing attempts, where an attacker uses stolen credentials from other breaches.
*   **A08: Software and Data Integrity Failures:**
    *   **Detection:** For applications that use serialized data, the WAF can inspect the serialized objects for known malicious gadgets or patterns that could lead to insecure deserialization.
*   **A09: Security Logging and Monitoring Failures:**
    *   **Detection:** While primarily a backend concern, a WAF is a critical source of logs. A modern WAF will provide detailed, structured logs (e.g., in JSON format) that can be easily ingested by a SIEM for analysis and alerting.
*   **A10: Server-Side Request Forgery (SSRF):**
    *   **Detection:** Maintain a strict allowlist of domains and IP addresses that the application is allowed to make requests to. Block any requests that attempt to access internal IP ranges or metadata services (e.g., `169.254.169.254`).

### **Rule Format Specification (Modern, YAML-based)**

This proposed format is designed to be human-readable, expressive, and CI/CD-friendly.

```yaml
---
name: "SQL Injection Prevention Rule"
description: "Blocks common SQL injection patterns with a high confidence score."
id: "sql-001"
severity: "critical"
enabled: true

# Conditions under which the rule is evaluated.
match:
  - # This rule will only run on paths that accept user input.
    path:
      - "/api/v1/search"
      - "/api/v1/products"
    methods:
      - "POST"
      - "GET"

  - # A list of conditions that are ANDed together.
    conditions:
      - # Check for SQL keywords in any part of the request body.
        target: "request.body"
        operator: "contains_any_case"
        values:
          - "select "
          - " from "
          - " where "
          - "union all select"
          - "insert into"
          - "update set"
          - "delete from"
      - # Also check for suspicious special characters.
        target: "request.body"
        operator: "contains_any"
        values:
          - "--"
          - ";"
          - "'"

# The action to take if the conditions are met.
action:
  type: "block"
  response_code: 403
  log: true
  message: "SQL Injection attempt detected and blocked."
```

### **Example Rule Library**

#### **Cross-Site Scripting (XSS) Protection**

```yaml
---
name: "XSS Protection - Script Tags"
description: "Blocks requests containing script tags in parameters."
id: "xss-001"
severity: "high"
enabled: true

match:
  - conditions:
      - target: "request.all_params"
        operator: "matches_regex"
        value: "<script.*>"

action:
  type: "block"
  response_code: 403
  log: true
  message: "XSS attempt with script tags detected."
```

#### **API - Broken Object Level Authorization (BOLA/IDOR)**

```yaml
---
name: "API - BOLA/IDOR Prevention"
description: "Prevents users from accessing resources that do not belong to them."
id: "api-bola-001"
severity: "critical"
enabled: true

match:
  - path:
      - "/api/v1/users/{userId}/profile"
    methods:
      - "GET"
      - "PUT"

  - conditions:
      - # This assumes the user's ID is stored in a JWT claim named 'sub'.
        target: "request.path.userId"
        operator: "not_equals"
        value: "jwt.claims.sub"

action:
  type: "block"
  response_code: 403
  log: true
  message: "Attempted to access another user's profile."
```

#### **Rate Limiting for Brute-Force Prevention**

```yaml
---
name: "Login Brute-Force Prevention"
description: "Rate limits login attempts from a single IP address."
id: "rate-limit-001"
severity: "medium"
enabled: true

match:
  - path:
      - "/login"
    methods:
      - "POST"

action:
  type: "rate_limit"
  # Allow 5 requests per IP every 1 minute.
  limit: 5
  period: 60 # in seconds
  key_by: "ip"
  log: true
  message: "Rate limit exceeded on login endpoint."
```
