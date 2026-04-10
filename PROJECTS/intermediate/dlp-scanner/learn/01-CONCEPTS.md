# 01-CONCEPTS.md

# DLP Concepts

## What is Data Loss Prevention?

DLP is the practice of detecting and preventing sensitive data from being stored, transmitted, or accessed in unauthorized ways. The three modes of DLP correspond to the three scan surfaces in this project:

- **Data at rest**: files on disk, records in databases, documents in cloud storage. Our file scanner and database scanner cover this surface.
- **Data in motion**: network traffic, API calls, email transmissions. Our network scanner covers this surface.
- **Data in use**: clipboard contents, screen captures, application memory. Not covered here (requires endpoint agents).

The fundamental question DLP answers: "Where is our sensitive data, and is it protected?"

## Detection Techniques

### Pattern Matching with Validation

The simplest approach: regex patterns that match structural formats like SSNs (XXX-XX-XXXX), credit card numbers (16 digits with known prefixes), and API keys (known prefix patterns like `AKIA` for AWS).

The problem with regex alone is false positive rates. The string `123-45-6789` matches an SSN pattern but appears in test data, serial numbers, and phone extensions. The string `4532015112830366` matches a Visa card pattern but could be a random 16-digit identifier.

This is why production DLP systems never rely on regex alone. They add validation layers:

**Checksum validation** eliminates structurally invalid matches. Credit card numbers use the Luhn algorithm: double every second digit from right, subtract 9 if the result exceeds 9, and verify the total is divisible by 10. A random 16-digit number has a ~10% chance of passing Luhn, which is still useful signal. IBANs use Mod-97 (ISO 7064): rearrange the country code and check digits, convert letters to numbers, and verify the result mod 97 equals 1. NHS numbers use Mod-11 with weighted digit multiplication.

**SSN area validation** checks that the first three digits are not 000, 666, or 900-999 (never assigned by the SSA). Group and serial numbers must also be non-zero. This eliminates ranges that the Social Security Administration has never used.

### Context Keyword Scoring

A 9-digit number matching SSN format near the word "social security" is more likely to be an actual SSN than the same number in a column labeled "serial_number". Context scoring scans a bidirectional window around each match for relevant keywords:

```
For SSN patterns: "ssn", "social security", "social_security_number", "tax id"
For credit cards: "credit card", "card number", "payment", "billing"
For API keys: "api_key", "secret", "token", "authorization"
```

Keywords found within the window (default: 10 tokens in each direction) add a boost of +0.05 to +0.35 depending on proximity. Closer keywords contribute more confidence.

### Shannon Entropy

Random-looking strings often indicate secrets: API keys, encrypted values, base64-encoded credentials. Shannon entropy measures the randomness of a string:

```
H = -sum(p(x) * log2(p(x))) for each unique character x
```

English text has entropy around 3.5-4.5 bits per character. Base64-encoded data is around 5.5-6.0. Hex-encoded data is around 3.5-4.0. Truly random data approaches log2(alphabet_size). A 40-character string with entropy above 4.5 is flagged as a potential secret.

### Confidence Scoring Pipeline

Each detection produces a confidence score between 0.0 and 1.0:

```
1. Regex match            -> base_score (0.10 to 0.85, configured per rule)
2. Checksum validation    -> +0.30 if the checksum passes
3. Context keyword search -> +0.05 to +0.35 based on keyword proximity
4. Entity co-occurrence   -> +0.10 to +0.20 if multiple PII types appear nearby
5. Final score capped at 1.0
```

The score maps to severity:
- 0.85+ = critical
- 0.65+ = high
- 0.40+ = medium
- 0.20+ = low
- below 0.20 = discarded

An SSN match (base 0.45) with valid area/group/serial and the word "ssn" nearby scores 0.45 + 0.30 (area validation acts as implicit checksum) + 0.15 (context) = 0.90, classified as critical. The same pattern without context scores 0.45, classified as medium, which is appropriate because it might be a phone number fragment.

## Compliance Frameworks

Regulatory frameworks define what data types require protection and what happens when they are exposed:

**HIPAA (Health Insurance Portability and Accountability Act)**: Defines 18 types of Protected Health Information (PHI) including SSNs, medical record numbers, health plan beneficiary numbers, and biometric identifiers. A covered entity that fails to protect PHI faces fines from $100 to $50,000 per violation (up to $1.5 million per year per category). The 2015 Anthem breach exposed 78.8 million records and resulted in a $16 million settlement with HHS.

**PCI-DSS (Payment Card Industry Data Security Standard)**: Requires protection of cardholder data: primary account numbers (PAN), cardholder names, expiration dates, and service codes. PAN must be rendered unreadable (encrypted, hashed, truncated, or tokenized). The Heartland Payment Systems breach (2008) compromised 130 million credit card numbers and cost the company $140 million in compensation.

**GDPR (General Data Protection Regulation)**: Applies to personal data of EU residents including names, email addresses, phone numbers, IP addresses, and location data. Fines reach 4% of annual global revenue or 20 million euros, whichever is higher. Meta was fined 1.2 billion euros in 2023 for transferring EU user data to the US without adequate safeguards.

**CCPA (California Consumer Privacy Act)**: Covers personal information of California residents. Similar categories to GDPR but with different enforcement mechanisms. Consumers can sue directly for data breaches involving unencrypted personal information ($100-$750 per consumer per incident).

## Network DLP Concepts

### DNS Exfiltration

Attackers encode stolen data in DNS queries to bypass firewalls that do not inspect DNS traffic. The data is encoded in subdomain labels:

```
aGVsbG8gd29ybGQ.evil.com    (base64 "hello world" in subdomain)
```

Detection signals:
- **Label entropy**: legitimate subdomains (www, mail, api) have low entropy. Base64-encoded data has entropy above 4.0
- **QNAME length**: normal queries are under 50 characters. Exfiltration queries exceed 100+
- **TXT query volume**: TXT records are used to receive exfiltrated data. A spike in TXT queries to a single domain is suspicious
- **Subdomain label length**: DNS labels above 50 characters are almost never legitimate

The OilRig APT group (attributed to Iran) used DNS tunneling extensively in campaigns against Middle Eastern governments, encoding stolen documents in subdomain queries to command-and-control infrastructure. DNSCat2 and Iodine are open-source tools that implement this technique.

### Protocol Identification

Deep Packet Inspection (DPI) identifies application protocols from payload byte prefixes without relying on port numbers:

- HTTP requests start with methods: `GET `, `POST `, `PUT `, `DELETE `
- HTTP responses start with `HTTP/`
- TLS records start with `\x16\x03` (handshake + TLS version)
- SSH connections start with `SSH-`
- SMTP starts with `220 ` (server greeting)

This matters because sensitive data in HTTP traffic (API keys in headers, SSNs in POST bodies) requires different handling than the same data in an encrypted TLS stream (where you can only flag that sensitive data was transmitted, not read the content).

### TCP Stream Reassembly

Application-layer data spans multiple TCP packets. Reassembly reconstructs the original byte stream:

1. Track flows by 4-tuple: (src_ip, dst_ip, src_port, dst_port)
2. Use bidirectional flow keys so both directions of a conversation map to the same flow
3. Store segments indexed by TCP sequence number
4. Sort by sequence number and concatenate payloads, deduplicating retransmissions

Without reassembly, a credit card number split across two packets would be missed by pattern matching on individual payloads.

## Redaction

DLP reports must never contain the raw sensitive data they detect. Redaction strategies:

- **Partial**: preserve structure but mask content: `***-**-6789`, `4532****0366`
- **Full**: replace entirely: `[REDACTED]`
- **None**: no redaction (for debugging only, never in production reports)

Partial redaction is preferred for triage because analysts can identify the data type and approximate value without exposing the full sensitive content. The last 4 digits of an SSN or credit card are commonly used as verification tokens and are considered non-sensitive by PCI-DSS.
