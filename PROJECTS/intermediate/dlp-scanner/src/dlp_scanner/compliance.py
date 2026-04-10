"""
©AngelaMos | 2026
compliance.py
"""


from dlp_scanner.constants import (
    SEVERITY_SCORE_THRESHOLDS,
    Severity,
)


RULE_FRAMEWORK_MAP: dict[str,
                         list[str]] = {
                             "PII_SSN": ["HIPAA",
                                         "CCPA",
                                         "GLBA",
                                         "GDPR"],
                             "PII_EMAIL": ["GDPR",
                                           "CCPA"],
                             "PII_PHONE": ["GDPR",
                                           "CCPA",
                                           "HIPAA"],
                             "PII_PHONE_INTL": ["GDPR",
                                                "CCPA"],
                             "PII_PASSPORT_US": ["GDPR",
                                                 "CCPA"],
                             "PII_PASSPORT_UK": ["GDPR"],
                             "PII_DRIVERS_LICENSE": ["CCPA",
                                                     "HIPAA"],
                             "PII_DRIVERS_LICENSE_FL": ["CCPA",
                                                        "HIPAA"],
                             "PII_DRIVERS_LICENSE_IL": ["CCPA",
                                                        "HIPAA"],
                             "PII_IPV4": ["GDPR"],
                             "FIN_CREDIT_CARD_VISA": ["PCI_DSS",
                                                       "GLBA"],
                             "FIN_CREDIT_CARD_MC": ["PCI_DSS",
                                                     "GLBA"],
                             "FIN_CREDIT_CARD_AMEX": ["PCI_DSS",
                                                       "GLBA"],
                             "FIN_CREDIT_CARD_DISC": ["PCI_DSS",
                                                       "GLBA"],
                             "FIN_IBAN": ["GDPR",
                                          "GLBA"],
                             "FIN_NHS_NUMBER": ["GDPR"],
                             "CRED_AWS_ACCESS_KEY": [],
                             "CRED_GITHUB_TOKEN": [],
                             "CRED_GITHUB_FINE_GRAINED": [],
                             "CRED_GITHUB_OAUTH": [],
                             "CRED_GITHUB_APP": [],
                             "CRED_JWT": [],
                             "CRED_STRIPE_KEY": [],
                             "CRED_SLACK_TOKEN": [],
                             "CRED_GENERIC_API_KEY": [],
                             "CRED_PRIVATE_KEY": [],
                             "HEALTH_MEDICAL_RECORD": ["HIPAA"],
                             "HEALTH_DEA_NUMBER": ["HIPAA"],
                             "HEALTH_NPI": ["HIPAA"],
                             "NET_HIGH_ENTROPY": [],
                             "NET_DNS_EXFIL_LONG_LABEL": [],
                             "NET_DNS_EXFIL_HIGH_ENTROPY": [],
                             "NET_DNS_EXFIL_LONG_QNAME": [],
                             "NET_DNS_EXFIL_TXT_VOLUME": [],
                             "NET_ENCODED_BASE64": [],
                             "NET_ENCODED_HEX": [],
                         }

RULE_REMEDIATION_MAP: dict[
    str,
    str] = {
        "PII_SSN": (
            "Remove or encrypt SSNs. Use tokenization "
            "for storage. Never store in plaintext."
        ),
        "PII_EMAIL": (
            "Evaluate if email storage is necessary. "
            "Hash or pseudonymize where possible."
        ),
        "PII_PHONE": (
            "Restrict access to phone number fields. "
            "Consider masking in non-production environments."
        ),
        "PII_PHONE_INTL": (
            "Restrict access to phone number fields. "
            "Consider masking in non-production environments."
        ),
        "PII_PASSPORT_US": (
            "Passport numbers must be encrypted at rest. "
            "Limit access to identity verification systems."
        ),
        "PII_PASSPORT_UK": (
            "Passport numbers must be encrypted at rest. "
            "Limit access to identity verification systems."
        ),
        "PII_IPV4": (
            "Evaluate whether IP address storage is necessary. "
            "Anonymize or pseudonymize where possible."
        ),
        "PII_DRIVERS_LICENSE": (
            "Encrypt driver's license numbers at rest. "
            "Restrict access per CCPA/HIPAA requirements."
        ),
        "PII_DRIVERS_LICENSE_FL": (
            "Encrypt driver's license numbers at rest. "
            "Restrict access per CCPA/HIPAA requirements."
        ),
        "PII_DRIVERS_LICENSE_IL": (
            "Encrypt driver's license numbers at rest. "
            "Restrict access per CCPA/HIPAA requirements."
        ),
        "FIN_CREDIT_CARD_VISA": (
            "PCI-DSS requires PANs to be encrypted, hashed, "
            "or truncated. Never store in plaintext."
        ),
        "FIN_CREDIT_CARD_MC": (
            "PCI-DSS requires PANs to be encrypted, hashed, "
            "or truncated. Never store in plaintext."
        ),
        "FIN_CREDIT_CARD_AMEX": (
            "PCI-DSS requires PANs to be encrypted, hashed, "
            "or truncated. Never store in plaintext."
        ),
        "FIN_CREDIT_CARD_DISC": (
            "PCI-DSS requires PANs to be encrypted, hashed, "
            "or truncated. Never store in plaintext."
        ),
        "FIN_IBAN": (
            "Encrypt IBAN numbers at rest. "
            "Restrict access to financial systems."
        ),
        "FIN_NHS_NUMBER": (
            "NHS numbers are personal data under UK GDPR. "
            "Encrypt at rest and restrict access."
        ),
        "CRED_AWS_ACCESS_KEY": (
            "Rotate exposed AWS credentials immediately. "
            "Use IAM roles or Vault dynamic secrets."
        ),
        "CRED_GITHUB_TOKEN": (
            "Revoke the token at github.com/settings/tokens. "
            "Use environment variables, not hardcoded values."
        ),
        "CRED_GITHUB_FINE_GRAINED": (
            "Revoke the token at github.com/settings/tokens. "
            "Use environment variables, not hardcoded values."
        ),
        "CRED_GITHUB_OAUTH": (
            "Revoke the OAuth token in GitHub settings. "
            "Store tokens in a secrets manager."
        ),
        "CRED_GITHUB_APP": (
            "Revoke the app installation token. "
            "Rotate app private keys if compromised."
        ),
        "CRED_JWT": (
            "Rotate the signing key if the JWT secret is "
            "exposed. Never hardcode tokens in source."
        ),
        "CRED_STRIPE_KEY": (
            "Rotate the Stripe key at dashboard.stripe.com. "
            "Use restricted keys with minimal permissions."
        ),
        "CRED_SLACK_TOKEN": (
            "Revoke the Slack token in workspace settings. "
            "Use environment variables for bot tokens."
        ),
        "CRED_GENERIC_API_KEY": (
            "Rotate the exposed API key immediately. "
            "Store secrets in a vault, not in source code."
        ),
        "CRED_PRIVATE_KEY": (
            "Rotate the compromised key pair. Store private "
            "keys in a secrets manager, never in source code."
        ),
        "HEALTH_MEDICAL_RECORD": (
            "MRNs are PHI under HIPAA. Encrypt at rest and "
            "apply minimum necessary access controls."
        ),
        "HEALTH_DEA_NUMBER": (
            "DEA numbers identify prescribers of controlled "
            "substances. Encrypt and restrict access per HIPAA."
        ),
        "HEALTH_NPI": (
            "NPIs are provider identifiers under HIPAA. "
            "Restrict access to authorized systems only."
        ),
        "NET_HIGH_ENTROPY": (
            "High entropy data may indicate encrypted or "
            "compressed secrets in transit. Investigate the flow."
        ),
        "NET_DNS_EXFIL_LONG_LABEL": (
            "Unusually long DNS labels may indicate DNS "
            "tunneling. Investigate the queried domain."
        ),
        "NET_DNS_EXFIL_HIGH_ENTROPY": (
            "High-entropy DNS subdomains suggest data "
            "exfiltration via DNS tunneling. Block the domain."
        ),
        "NET_DNS_EXFIL_LONG_QNAME": (
            "Excessively long DNS QNAMEs may carry encoded "
            "data. Investigate and block suspicious domains."
        ),
        "NET_DNS_EXFIL_TXT_VOLUME": (
            "High ratio of TXT queries to a domain suggests "
            "DNS-based command and control. Investigate traffic."
        ),
        "NET_ENCODED_BASE64": (
            "Base64-encoded payloads in network traffic may "
            "carry exfiltrated data. Inspect the content."
        ),
        "NET_ENCODED_HEX": (
            "Hex-encoded payloads in network traffic may "
            "indicate data exfiltration. Inspect the content."
        ),
    }

DEFAULT_REMEDIATION: str = (
    "Review and restrict access to this data. "
    "Apply encryption at rest if required by policy."
)


def get_frameworks_for_rule(rule_id: str) -> list[str]:
    """
    Return applicable compliance frameworks for a rule
    """
    return RULE_FRAMEWORK_MAP.get(rule_id, [])


def get_remediation_for_rule(rule_id: str) -> str:
    """
    Return remediation guidance for a rule
    """
    return RULE_REMEDIATION_MAP.get(rule_id, DEFAULT_REMEDIATION)


def score_to_severity(score: float) -> Severity:
    """
    Convert a confidence score to a severity level
    """
    for threshold, severity in SEVERITY_SCORE_THRESHOLDS:
        if score >= threshold:
            return severity
    return "low"
