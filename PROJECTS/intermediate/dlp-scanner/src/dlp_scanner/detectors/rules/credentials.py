"""
©AngelaMos | 2026
credentials.py
"""


import re

from dlp_scanner.detectors.base import DetectionRule


AWS_ACCESS_KEY_PATTERN = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")

GITHUB_CLASSIC_PAT_PATTERN = re.compile(r"\bghp_[a-zA-Z0-9]{36}\b")

GITHUB_FINE_GRAINED_PATTERN = re.compile(
    r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b"
)

GITHUB_OAUTH_PATTERN = re.compile(r"\bgho_[a-zA-Z0-9]{36}\b")

GITHUB_APP_PATTERN = re.compile(r"\bghs_[a-zA-Z0-9]{36}\b")

JWT_PATTERN = re.compile(
    r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"
)

STRIPE_KEY_PATTERN = re.compile(
    r"\b(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,}\b"
)

SLACK_TOKEN_PATTERN = re.compile(r"\bxox[baprs]-[a-zA-Z0-9\-]{10,48}\b")

GENERIC_API_KEY_PATTERN = re.compile(
    r"(?i)(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?key|secret[_\-]?key)"
    r"\s*[:=]\s*['\"]?"
    r"([a-zA-Z0-9\-_.]{20,64})"
    r"['\"]?"
)

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)

API_KEY_CONTEXT = [
    "api_key",
    "apikey",
    "api key",
    "secret",
    "token",
    "authorization",
    "bearer",
    "credential",
    "password",
    "access_key",
]

CREDENTIAL_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id = "CRED_AWS_ACCESS_KEY",
        rule_name = "AWS Access Key ID",
        pattern = AWS_ACCESS_KEY_PATTERN,
        base_score = 0.85,
        context_keywords = [
            "aws",
            "amazon",
            "access_key",
            "aws_access_key_id",
        ],
    ),
    DetectionRule(
        rule_id = "CRED_GITHUB_TOKEN",
        rule_name = "GitHub Personal Access Token",
        pattern = GITHUB_CLASSIC_PAT_PATTERN,
        base_score = 0.90,
        context_keywords = ["github",
                            "token",
                            "pat"],
    ),
    DetectionRule(
        rule_id = "CRED_GITHUB_FINE_GRAINED",
        rule_name = "GitHub Fine-Grained PAT",
        pattern = GITHUB_FINE_GRAINED_PATTERN,
        base_score = 0.90,
        context_keywords = ["github",
                            "token"],
    ),
    DetectionRule(
        rule_id = "CRED_GITHUB_OAUTH",
        rule_name = "GitHub OAuth Token",
        pattern = GITHUB_OAUTH_PATTERN,
        base_score = 0.90,
        context_keywords = ["github",
                            "oauth"],
    ),
    DetectionRule(
        rule_id = "CRED_GITHUB_APP",
        rule_name = "GitHub App Token",
        pattern = GITHUB_APP_PATTERN,
        base_score = 0.90,
        context_keywords = ["github",
                            "app"],
    ),
    DetectionRule(
        rule_id = "CRED_JWT",
        rule_name = "JSON Web Token",
        pattern = JWT_PATTERN,
        base_score = 0.70,
        context_keywords = [
            "jwt",
            "token",
            "bearer",
            "authorization",
        ],
    ),
    DetectionRule(
        rule_id = "CRED_STRIPE_KEY",
        rule_name = "Stripe API Key",
        pattern = STRIPE_KEY_PATTERN,
        base_score = 0.90,
        context_keywords = [
            "stripe",
            "payment",
            "api_key",
        ],
    ),
    DetectionRule(
        rule_id = "CRED_SLACK_TOKEN",
        rule_name = "Slack Token",
        pattern = SLACK_TOKEN_PATTERN,
        base_score = 0.85,
        context_keywords = [
            "slack",
            "token",
            "webhook",
        ],
    ),
    DetectionRule(
        rule_id = "CRED_GENERIC_API_KEY",
        rule_name = "Generic API Key",
        pattern = GENERIC_API_KEY_PATTERN,
        base_score = 0.50,
        context_keywords = API_KEY_CONTEXT,
    ),
    DetectionRule(
        rule_id = "CRED_PRIVATE_KEY",
        rule_name = "Private Key",
        pattern = PRIVATE_KEY_PATTERN,
        base_score = 0.95,
        context_keywords = [
            "private key",
            "rsa",
            "ssh",
            "certificate",
        ],
    ),
]
