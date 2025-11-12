# OAuth Token Analyzer

## Overview
Create a tool that decodes JWT (JSON Web Tokens) used in OAuth implementations, validates cryptographic signatures, checks for common vulnerabilities like algorithm confusion and expired tokens, and displays token claims. This project teaches authentication security, JWT mechanics, and demonstrates analysis techniques for OAuth/OpenID Connect implementations.

## Step-by-Step Instructions

1. **Understand JWT structure and components** by learning that JWTs consist of three Base64-encoded parts separated by periods: header (specifies algorithm), payload (contains claims about the subject), and signature (cryptographic proof of authenticity). Study common JWT algorithms (HS256 for HMAC-SHA256 using symmetric keys, RS256 for RSA signatures using public/private keys) and understand how each works. Learn what claims typically appear in tokens (sub for subject/user ID, exp for expiration, iat for issued-at time, aud for audience, etc.).

2. **Implement JWT decoding functionality** using the `PyJWT` library to parse JWT tokens, extract header and payload components, and decode them from Base64 to readable JSON. Display the structured token information including algorithm used, all claims present, and token metadata like expiration time. Handle edge cases like malformed tokens and provide clear error messages when decoding fails.

3. **Build signature validation capabilities** that verify JWT signatures using various algorithms: for HS256 tokens, validate HMAC signatures by computing expected signature with provided key; for RS256/ES256 tokens, validate signatures using public key certificates. Allow users to provide keys/certificates or test common weak secrets (common patterns like "secret", "password", application names). Report whether signatures are valid or indicate tampering/forgery.

4. **Implement algorithm confusion detection** identifying the dangerous vulnerability where attackers can bypass signature verification by changing the algorithm field: detect when HS256 (symmetric) tokens could be confused with RS256 (asymmetric) algorithms, flag tokens using "none" algorithm (no signature required, highly dangerous), and identify algorithm downgrades. Explain the security implications of each detected vulnerability.

5. **Create expiration and timing analysis** checking whether tokens are currently valid or have expired, calculating remaining validity period, and flagging tokens with unusual timing (expiration far in future suggesting weak security, very short expiration suggesting session tokens). Display issued-at time, expiration time, and calculated age of tokens for temporal analysis.

6. **Build claims analysis and inspection** that displays all claims contained in token payload, identifies common claims (user ID, roles, permissions, email address), and flags suspicious claims. Detect privilege escalation attempts (roles or permissions beyond what user should have), check for sensitive information stored in token (passwords, API keys—never store these in tokens), and validate claim values are reasonable.

7. **Implement batch analysis and logging** accepting multiple tokens for analysis, supporting token import from files, and generating reports showing vulnerabilities across analyzed tokens. Create a database tracking analyzed tokens with their vulnerabilities, allowing tracking of token patterns and identifying systematic security issues. Export findings in formats suitable for security teams and developers.

8. **Build comprehensive documentation** explaining JWT concepts, discussing common OAuth/OIDC vulnerabilities, and providing examples of vulnerable vs. secure token implementations. Include guidance on detecting compromised tokens, handling token leakage, and implementing proper key management. Compare your tool to online JWT debuggers (jwt.io), discuss limitations (cannot validate without key material), and explain where JWT analysis fits into OAuth security assessment workflows during penetration testing and security audits.

## Key Concepts to Learn
- JWT structure and components
- Cryptographic signature validation
- Algorithm confusion and security vulnerabilities
- HMAC and RSA signature algorithms
- Claim analysis and token inspection
- Expiration and timing validation
- OAuth/OIDC security concepts

## Deliverables
- JWT decoding and parsing
- Multiple algorithm signature validation
- Algorithm confusion detection
- Expiration and timing analysis
- Claims inspection and anomaly detection
- Batch analysis and reporting
- Vulnerable token identification
