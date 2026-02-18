"""
©AngelaMos | 2026
patterns.py
"""

import re

ENCODED_CHARS = re.compile(r"%[0-9a-fA-F]{2}")
DOUBLE_ENCODED = re.compile(r"%25[0-9a-fA-F]{2}")

_SQLI = (
    r"(?:union\s+(?:all\s+)?select|"
    r"'\s*or\s+.+=|"
    r"'\s*and\s+.+=|"
    r"1\s*=\s*1|"
    r"sleep\s*\(|"
    r"benchmark\s*\(|"
    r"waitfor\s+delay|"
    r"extractvalue\s*\(|"
    r"updatexml\s*\(|"
    r"load_file\s*\(|"
    r"into\s+(?:out|dump)file|"
    r"group\s+by\s+.+having|"
    r"order\s+by\s+\d+|"
    r"(?:drop|alter|create)\s+table|"
    r"information_schema|"
    r"(?:char|concat|hex|unhex)\s*\(|"
    r"0x[0-9a-f]{6,}|"
    r"--\s*$|"
    r"/\*.*?\*/)"
)

_XSS = (
    r"(?:<\s*script|"
    r"javascript\s*:|"
    r"vbscript\s*:|"
    r"on(?:error|load|click|mouse\w+|focus|blur|submit|change)\s*=|"
    r"<\s*(?:img|svg|iframe|object|embed|link|style|body|input|form)\b[^>]*\bon\w+\s*=|"
    r"<\s*iframe|"
    r"<\s*svg\b.*?on\w+\s*=|"
    r"document\s*\.\s*(?:cookie|write|location)|"
    r"window\s*\.\s*(?:location|open)|"
    r"eval\s*\(|"
    r"alert\s*\(|"
    r"prompt\s*\(|"
    r"confirm\s*\(|"
    r"expression\s*\(|"
    r"String\s*\.\s*fromCharCode)"
)

_PATH_TRAVERSAL = (
    r"(?:\.\./|"
    r"\.\.\\|"
    r"%2e%2e[%/\\]|"
    r"%252e%252e|"
    r"(?:etc/(?:passwd|shadow|hosts)|"
    r"proc/self/|"
    r"windows/system32|"
    r"boot\.ini|"
    r"web\.config|"
    r"\.env|"
    r"\.git/config|"
    r"wp-config\.php))"
)

_COMMAND_INJECTION = (
    r"(?:;\s*(?:ls|cat|rm|wget|curl|chmod|chown|nc|bash|sh|python|perl|ruby|php)\b|"
    r"\|\s*(?:cat|ls|id|whoami|uname|pwd|env|set|netstat|ifconfig|ip)\b|"
    r"\$\(|"
    r"`[^`]+`|"
    r"\$\{|"
    r">\s*/(?:etc|tmp|var)|"
    r"&&\s*(?:cat|ls|id|whoami|wget|curl)\b)"
)

_FILE_INCLUSION = (
    r"(?:php://|"
    r"file://|"
    r"data://|"
    r"expect://|"
    r"input://|"
    r"zip://|"
    r"phar://|"
    r"glob://)"
)

SQLI = re.compile(_SQLI, re.IGNORECASE)
XSS = re.compile(_XSS, re.IGNORECASE)
PATH_TRAVERSAL = re.compile(_PATH_TRAVERSAL, re.IGNORECASE)
COMMAND_INJECTION = re.compile(_COMMAND_INJECTION, re.IGNORECASE)
FILE_INCLUSION = re.compile(_FILE_INCLUSION, re.IGNORECASE)

ATTACK_COMBINED = re.compile(
    r"|".join((_SQLI, _XSS, _PATH_TRAVERSAL, _COMMAND_INJECTION, _FILE_INCLUSION)),
    re.IGNORECASE,
)
