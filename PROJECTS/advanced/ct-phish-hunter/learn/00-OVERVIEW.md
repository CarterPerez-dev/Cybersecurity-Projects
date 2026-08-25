# 00 - Overview

## What this project does

glasswatch watches Certificate Transparency (CT) logs, the public, append-only record every trusted TLS certificate gets written to before a browser accepts it, and flags newly issued certificates that look like they are impersonating a domain you care about. It talks to the logs directly over their real wire protocol (RFC 6962), decodes each certificate, and scores every domain name it finds against a watchlist using homoglyph, typosquat, and combosquat detection.

Point it at a brand's real domain, and it tells you the moment someone gets a valid certificate for `pаypal.com` (with a Cyrillic а) or `acmepay-login-secure.net`, usually within minutes of the certificate authority issuing it.

## Who this is for

This is the advanced tier, so it assumes you are comfortable with:

- Python (dataclasses, type hints, working with bytes and encodings)
- Reading an RFC and translating byte-layout diagrams into parsing code
- Basic X.509 / TLS certificate concepts (what a SAN is, what a CA does)
- SQLite well enough to read a schema

If any of that is new, `01-CONCEPTS.md` covers the security theory in more depth, but this project does not re-teach Python or general networking from scratch the way the Foundations tier projects do.

## Prerequisites

- Python 3.10 or newer
- Outbound HTTPS access (the CT logs and Google's log-list host are all public, no auth needed)
- `pip` (or `uv`, see the repo's `CONTRIBUTING.md`)

## Quick start

```bash
cd PROJECTS/advanced/ct-phish-hunter
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest   # 39 tests, should all pass with no network required
```

Try the offline detection engine first, since it needs no network and shows the core idea in one command:

```bash
printf 'paypal.com\npaypal-login-secure.net\n' > domains.txt
cat <<'EOF' > watchlist.yml
brands:
  - paypal.com
EOF
glasswatch scan-file domains.txt --watchlist watchlist.yml --all
```

Expected output:

```
[  MEDIUM] score=25  paypal-login-secure.net  (brand: paypal.com)
    - combosquat:paypal-login-secure:login+secure

scanned 2 domains, 1 findings
```

`paypal.com` itself produces no output. That is correct: it is the real brand domain, and a working detector needs to stay quiet about its own target.

Once that works, try it against live traffic:

```bash
glasswatch logs                                                    # see what CT logs exist right now
glasswatch stream --watchlist watchlist.yml --db findings.db --seconds 60
glasswatch serve --db findings.db                                  # http://127.0.0.1:8787
```

## What you'll learn

- How Certificate Transparency actually works on the wire, not just "certificates get logged somewhere"
- How to parse a binary protocol from an RFC spec by hand (TLS presentation language, length-prefixed fields, nested structures)
- Why homoglyph attacks work and how Unicode's own confusables data is used to catch them
- The difference between a certificate's leaf entry and its precertificate, and why CT logs have both
- How to build a small, dependency-light local tool (stdlib `sqlite3` and `http.server` instead of reaching for Postgres and FastAPI by default)

## Where to go next

- **`01-CONCEPTS.md`** — Certificate Transparency, Merkle trees, and the three families of domain-impersonation attacks this project detects
- **`02-ARCHITECTURE.md`** — how the pieces fit together and why
- **`03-IMPLEMENTATION.md`** — a guided walk through the actual parsing and scoring code
- **`04-CHALLENGES.md`** — extension exercises, from easy to genuinely hard
