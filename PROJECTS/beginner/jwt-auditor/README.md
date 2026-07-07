# jwt-auditor

A command line tool that decodes JSON Web Tokens and audits them for the
mistakes that keep showing up in real systems: the `alg: none` downgrade,
weak HMAC secrets, the RS256 to HS256 confusion attack, tokens that never
expire, and secrets stuffed into the payload.

Everything runs offline against a token string. No network calls, and no
PyJWT. The signature code is plain `hmac` from the standard library, because
seeing that "verify" is just "recompute the HMAC and compare" is the fastest
way to understand why half of these attacks work.

```
$ jwt-auditor audit eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.abc...

╭─── JWT Audit Summary ────╮
│ algorithm    : HS256     │
│ risk score   : 10.0 / 10 │
│ worst finding: critical  │
╰──────────────────────────╯
CRITICAL  HMAC secret recovered from wordlist   secret = 'secret'
HIGH      Payload may contain sensitive data    ['user_password']
MEDIUM    No expiration claim                   payload has no 'exp'
```

## Why this is useful

JWTs are everywhere: session tokens, API keys, OAuth access tokens, service
to service auth. They are also easy to get wrong, and the failures are quiet.
A token signed with the secret `secret` looks identical to one signed with a
256 bit random key until someone runs a wordlist against it.

This tool checks a token the way an attacker would look at it, then tells you
what a defender should fix. Point it at a token from your app, your staging
environment, or a bug bounty target you are authorized to test, and it flags
the problems in one pass.

## Features

- **Decode** any JWT into its header, payload, and signature without trusting it
- **`alg: none` detection**, the classic signature stripping downgrade
- **Weak secret cracking** against a built in list or your own wordlist
- **RS256 to HS256 confusion test**, and it proves the finding when you supply
  the server's public key
- **Expiration checks**: missing `exp`, already expired, or a suspiciously long
  lifetime
- **Clock sanity checks** on `iat` and `nbf`
- **Sensitive data detection**, catching passwords and PII carried in claims
- **Missing claim hints** for `iss`, `aud`, and `sub`
- **JSON output** and a `--fail-level` exit code so it drops into CI as a gate

## Educational value

Building and reading this project teaches you:

- How a JWT is actually structured, down to base64url without padding
- Why `alg: none` was a real vulnerability in many libraries around 2015, and
  why you never let a token pick its own verification algorithm
- How the RS256 to HS256 confusion attack turns a public key into a signing key
- Why HMAC verification must use a constant time compare
- What belongs in a token and what never should, since the payload is encoded,
  not encrypted

The `learn/` folder walks through all of this, from the concepts to a line by
line tour of the code.

## Prerequisites

- **Python 3.12 or newer**
- **[uv](https://github.com/astral-sh/uv)** for dependency management. It is
  what this repository standardizes on.
- Basic comfort with the terminal. You paste a token, you read a table.

Helpful but not required: familiarity with base64, HMAC, and the idea of a
bearer token.

## Installation

```bash
# from the project directory
cd PROJECTS/beginner/jwt-auditor

# create the environment and install the tool plus dev dependencies
uv sync --all-extras

# confirm it runs
uv run jwt-auditor --help
```

## Usage

The tool has three commands: `decode`, `audit`, and `crack`. Each one reads
the token from an argument, from `--input-file`, or from stdin, so it fits
into a pipeline.

### Decode a token

```bash
uv run jwt-auditor decode eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig
```

Add `--json` for machine readable output. Decode never checks the signature.
It only shows you what the token claims.

### Audit a token

```bash
# run every check with the built in wordlist
uv run jwt-auditor audit <token>

# use your own wordlist for the secret check
uv run jwt-auditor audit <token> --wordlist rockyou.txt

# prove the RS to HS confusion attack with the server public key
uv run jwt-auditor audit <token> --public-key server_pub.pem

# fail the process on medium or worse, for CI
uv run jwt-auditor audit <token> --fail-level medium
```

Pipe a token in without it landing in your shell history:

```bash
echo "$TOKEN" | uv run jwt-auditor audit
```

### Crack an HMAC secret

```bash
uv run jwt-auditor crack <token> --wordlist rockyou.txt
```

Exits 0 and prints the secret on a hit, exits 1 if nothing matched.

## Configuration

There are no config files or environment variables. Behavior is controlled by
flags:

| Flag | Command | Meaning |
|------|---------|---------|
| `--input-file`, `-i` | all | read the token from a file |
| `--json` | decode, audit | emit JSON instead of a table |
| `--wordlist`, `-w` | audit, crack | secrets to try against HS tokens |
| `--public-key`, `-p` | audit | public key PEM to test alg confusion |
| `--max-lifetime` | audit | hours before a token counts as long lived (default 24) |
| `--fail-level` | audit | exit non-zero at this severity or worse (default `high`) |

## Architecture

The pipeline is small and one directional:

```
token string
   │
   ▼
decoder.py     split into 3 parts, decode header and payload
   │
   ▼
checks.py      run each check, collect Finding objects
   │           (calls signatures.py for the secret and confusion checks)
   ▼
models.py      AuditReport scores the findings
   │
   ▼
output.py      render a Rich table or JSON
```

The checks never print and never import Rich, so they are easy to test in
isolation. See `learn/02-ARCHITECTURE.md` for the full breakdown.

## Security considerations

- **Only test tokens you are authorized to test.** Cracking a secret for a
  system you do not own is not authorized security testing.
- **Tokens are credentials.** Prefer stdin or a file over pasting a live token
  as a shell argument, where it lands in your history and process list.
- This tool does not verify RSA or ECDSA signatures. It decodes them and warns
  about algorithm handling. The point is auditing configuration, not acting as
  a full JOSE verifier for production traffic.

## Running the tests

```bash
uv run pytest tests/ -v          # 59 tests
uv run pytest --cov=jwt_auditor  # coverage
uv run ruff check src/ tests/    # lint
uv run mypy src/                 # types
```

## License

Released under the GNU Affero General Public License v3.0. See
[LICENSE](./LICENSE).
