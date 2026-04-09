"""
©AngelaMos | 2026
signatures.py

User-agent signature sets for bot and security scanner
detection

BOT_USER_AGENTS contains 34 lowercase search engine and
crawler identifiers (googlebot, bingbot, gptbot, claudebot,
etc.) for benign bot classification. SCANNER_USER_AGENTS
contains 41 lowercase security tool signatures (nikto,
sqlmap, nmap, burp, nuclei, metasploit, hydra, etc.) for
hostile scanner detection. Both are frozensets matched via
substring search against lowercased user-agent strings

Connects to:
  core/features/
    extractor    - is_known_bot, is_known_scanner features
  core/detection/
    rules        - SCANNER_USER_AGENTS for UA rule scoring
"""

BOT_USER_AGENTS: frozenset[str] = frozenset({
    "googlebot",
    "bingbot",
    "slurp",
    "duckduckbot",
    "baiduspider",
    "yandexbot",
    "sogou",
    "facebot",
    "ia_archiver",
    "applebot",
    "petalbot",
    "semrushbot",
    "ahrefsbot",
    "mj12bot",
    "dotbot",
    "rogerbot",
    "linkedinbot",
    "twitterbot",
    "gptbot",
    "claudebot",
    "amazonbot",
    "bytespider",
    "ccbot",
    "dataforseo",
    "seznambot",
    "megaindex",
    "blexbot",
    "exabot",
    "archive.org_bot",
    "mojeekbot",
    "uptimerobot",
    "deadlinkchecker",
    "sitebulb",
    "screaming frog",
})

SCANNER_USER_AGENTS: frozenset[str] = frozenset({
    "nikto",
    "sqlmap",
    "nessus",
    "openvas",
    "acunetix",
    "w3af",
    "nmap",
    "masscan",
    "zgrab",
    "gobuster",
    "dirbuster",
    "dirb",
    "wfuzz",
    "ffuf",
    "nuclei",
    "burp",
    "zap",
    "arachni",
    "skipfish",
    "wpscan",
    "joomscan",
    "whatweb",
    "httprint",
    "fierce",
    "subfinder",
    "amass",
    "httpx",
    "jaeles",
    "xray",
    "gau",
    "hakrawler",
    "katana",
    "cariddi",
    "gospider",
    "feroxbuster",
    "rustbuster",
    "patator",
    "hydra",
    "medusa",
    "metasploit",
    "cobalt",
})
