# jwt-auditor

## What This Is

A command line tool that takes a JSON Web Token and reports the security
problems in it: unsigned `alg: none` tokens, weak HMAC secrets you can guess,
the RS256 to HS256 confusion attack, tokens with no expiration, and secrets
carried in the payload. It decodes and audits offline, with no network calls
and no third party JWT library.

## Why This Matters

JWTs are the default bearer credential for modern web apps. They sit in
`Authorization` headers, in cookies, and in service to service calls. When one
is built wrong, the failure is silent. A token signed with the secret `secret`
verifies exactly like one signed with a 256 bit random key, right up until an
attacker runs a wordlist against it and starts minting admin tokens.

The mistakes this tool looks for are not theoretical. They have real CVEs and
real breaches behind them.

**Real world scenarios where this applies:**

- You are reviewing an API before launch and want to confirm its tokens expire,
  are signed with a strong key, and do not leak PII in the claims.
- You are on a bug bounty program, you captured a JWT, and you want to know in
  one command whether the secret is guessable or the header accepts `none`.
- You run a CI pipeline and want a gate that fails the build if someone commits
  code that issues a token with no `exp` or a hardcoded weak secret.

## What You'll Learn

This project teaches you how a JWT works under the hood and why the common
attacks against it succeed. By building it yourself, you will understand:

**Security Concepts:**

- Signature stripping and the `alg: none` downgrade, where a token declares it
  is unsigned and a naive verifier believes it.
- Algorithm confusion, where a server that trusts the token's declared
  algorithm can be tricked into verifying an RSA token with HMAC, using the
  public key as the secret.
- Why HMAC secrets have to be high entropy, and how offline guessing works when
  the attacker holds the token.

**Technical Skills:**

- Decoding base64url without padding, the encoding JWT actually uses.
- Computing and verifying an HMAC signature with the standard library, and why
  the comparison has to be constant time.
- Turning a set of independent checks into a scored report with a clean data
  model.

**Tools and Techniques:**

- `hmac` and `hashlib` for signatures, used the way a JWT library uses them.
- Typer and Rich for a CLI that prints readable tables and clean JSON.

## Prerequisites

**Required knowledge:**

- Basic Python: functions, dataclasses, dictionaries, exceptions.
- What base64 is, roughly. You do not need to know the alphabet by heart.
- The idea of a bearer token: whoever holds it is treated as the user.

**Tools you'll need:**

- Python 3.12 or newer, for the modern type syntax the code uses.
- [uv](https://github.com/astral-sh/uv), the package manager this repository
  standardizes on.

**Helpful but not required:**

- Familiarity with HMAC and public key crypto.
- Having seen a JWT on [jwt.io](https://jwt.io) before.

## Quick Start

```bash
cd PROJECTS/beginner/jwt-auditor

# install the tool and its dev dependencies
uv sync --all-extras

# build a throwaway HS256 token signed with the weak secret "secret",
# then audit it (generated at runtime so no token is hardcoded here)
python3 - <<'PY' | uv run jwt-auditor audit -
import base64, hmac, hashlib, json
b = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
head = b(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
body = b(json.dumps({"sub": "admin"}).encode())
sig = b(hmac.new(b"secret", f"{head}.{body}".encode(), hashlib.sha256).digest())
print(f"{head}.{body}.{sig}")
PY
```

Expected output: a summary panel with a risk score of 10.0 and a findings
table calling out the recovered secret. If you see that, the tool works.

## Project Structure

```
jwt-auditor/
├── src/jwt_auditor/
│   ├── decoder.py      # split and decode a token, no verification
│   ├── signatures.py   # HMAC sign, verify, crack, confusion test
│   ├── checks.py       # the individual checks and the audit() runner
│   ├── models.py       # Severity, Finding, AuditReport, risk score
│   ├── output.py       # Rich tables and JSON rendering
│   ├── wordlist.py     # built in weak secrets and sensitive claim names
│   └── main.py         # Typer CLI: decode, audit, crack
├── tests/              # 59 tests covering every check and command
└── learn/              # this documentation
```

## Next Steps

1. **Understand the concepts** - Read [01-CONCEPTS.md](./01-CONCEPTS.md) for the
   security fundamentals behind each check.
2. **Study the architecture** - Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md)
   to see how the pieces fit together.
3. **Walk through the code** - Read
   [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for a line by line tour.
4. **Extend the project** - Read [04-CHALLENGES.md](./04-CHALLENGES.md) for
   ideas to build on.

## Common Issues

**`uv: command not found`**
```
uv: command not found
```
Solution: install uv with `curl -LsSf https://astral.sh/uv/install.sh | sh`,
then restart your shell.

**Pasting a token that got line wrapped**
```
Not a valid JWT: a JWT has 3 dot separated segments, this has 1
```
Solution: your terminal split the token across lines. Put it in a file and use
`--input-file token.txt`, or pipe it in with `echo "$TOKEN" | jwt-auditor audit`.

## Related Projects

If you found this interesting, check out:

- **caesar-cipher** - another from scratch crypto tool in this repo, good for
  seeing how a small cipher is built and attacked.
- **secrets-scanner** - uses the same HIBP style thinking about weak secrets,
  applied to source code instead of tokens.
