# Implementation Guide

This document walks through the real code, file by file, in the order the data
flows. Every snippet is copied from the project, with the file and line noted so
you can open it alongside.

## File Structure Walkthrough

```
src/jwt_auditor/
├── decoder.py      # parse a token string into DecodedToken
├── signatures.py   # HMAC sign, verify, crack, confusion test
├── checks.py       # the checks and the audit() runner
├── models.py       # Severity, Finding, AuditReport
├── output.py       # Rich and JSON rendering
├── wordlist.py     # built in secrets and sensitive claim names
└── main.py         # the Typer CLI
```

## Building the Decoder

### Step 1: base64url with the padding put back

JWT uses base64url and strips the `=` padding to keep tokens short. The standard
decoder wants that padding, so we add it back before decoding.

`src/jwt_auditor/decoder.py:33`

```python
def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise InvalidTokenError(f"segment is not valid base64url: {exc}") from None
```

**Why this code works:**
- `-len(segment) % 4` computes how many pad characters are missing. For a length
  that is already a multiple of 4 it is 0, otherwise 1, 2, or 3.
- We convert every decoding error into `InvalidTokenError`, so callers deal with
  one exception type instead of `binascii` internals.

**Common mistake here:**
```python
# Wrong: no padding, base64 rejects most real segments
base64.urlsafe_b64decode(segment)

# Why this fails: JWT segments are almost never a multiple of 4 in length,
# so the decoder raises "Invalid base64-encoded string".
```

### Step 2: parse into a DecodedToken

`decode` splits the token, decodes both JSON parts, and keeps the signing input.

`src/jwt_auditor/decoder.py:90`

```python
def decode(token: str) -> DecodedToken:
    token = token.strip()
    if not token:
        raise InvalidTokenError("token is empty")

    segments = token.split(".")
    if len(segments) != 3:
        raise InvalidTokenError(
            f"a JWT has 3 dot separated segments, this has {len(segments)}"
        )

    header_b64, payload_b64, signature_b64 = segments
    header = _decode_json_segment(header_b64, "header")
    payload = _decode_json_segment(payload_b64, "payload")
    signature = _b64url_decode(signature_b64) if signature_b64 else b""

    return DecodedToken(
        raw=token,
        header=header,
        payload=payload,
        signature=signature,
        signing_input=f"{header_b64}.{payload_b64}".encode("ascii"),
        header_b64=header_b64,
        payload_b64=payload_b64,
        signature_b64=signature_b64,
    )
```

**What is happening:**
1. An empty signature segment (the `alg: none` case) is allowed. We store `b""`
   rather than raising, because a check further down needs to see it.
2. `signing_input` is computed once, from the original base64 text, not by
   re-encoding the parsed JSON. That matters: re-encoding could reorder keys or
   change spacing and produce different bytes than what was signed.

**Why we do it this way:** the decoder is deliberately trusting. It reports what
the token says. Deciding whether the token is dangerous is the job of `checks.py`,
not the parser.

## Building the Signature Layer

### Verifying in constant time

`src/jwt_auditor/signatures.py:58`

```python
def verify_hmac(token: DecodedToken, secret: bytes, alg: str | None = None) -> bool:
    chosen = alg or token.algorithm
    if chosen not in _HASH_BY_ALG:
        return False
    if not token.signature:
        return False
    expected = hmac_sign(token.signing_input, secret, chosen)
    return hmac.compare_digest(expected, token.signature)
```

**Key parts explained:**

`hmac.compare_digest` (`src/jwt_auditor/signatures.py:78`) is the important line.
A normal `==` on bytes short circuits at the first differing byte, so a wrong
guess that shares a longer prefix takes measurably longer. Over many requests an
attacker can use that timing to recover the signature one byte at a time.
`compare_digest` always takes the same time for equal length inputs.

The `alg` parameter defaults to the token's declared algorithm but can be forced.
That is what lets the confusion test say "verify this as HS256 even though it
claims RS256".

### Cracking a secret

`src/jwt_auditor/signatures.py:81`

```python
def crack_hmac_secret(token, candidates):
    if token.algorithm not in _HASH_BY_ALG:
        return None
    for candidate in candidates:
        if verify_hmac(token, candidate.encode("utf-8")):
            return candidate
    return None
```

This is the whole attack. For a non HMAC token there is no shared secret, so it
returns immediately instead of pointlessly hashing the wordlist. On the first
match it returns the secret.

### The key confusion test

`src/jwt_auditor/signatures.py:100`

```python
def key_confusion_secret(token, public_key_pem):
    variants = {
        "public key PEM as stored": public_key_pem,
        "public key PEM without trailing newline": public_key_pem.rstrip(b"\n"),
        "public key PEM with trailing newline": public_key_pem.rstrip(b"\n") + b"\n",
    }
    for alg in _HASH_BY_ALG:
        for label, material in variants.items():
            if verify_hmac(token, material, alg=alg):
                return f"{label} (verified as {alg})"
    return None
```

**Why the variants:** HMAC is over exact bytes. Whether the server stored the PEM
with a trailing newline changes every byte of the output. Servers differ, so we
try the common forms rather than guess one.

## Building the Checks

Each check is small and returns findings. Here is the `alg: none` one in full.

`src/jwt_auditor/checks.py:76`

```python
def check_alg_none(token: DecodedToken) -> list[Finding]:
    if token.algorithm.lower() != "none":
        return []
    return [
        Finding(
            check_id="alg-none",
            title="Algorithm is 'none' (unsigned token)",
            severity=Severity.CRITICAL,
            detail=(
                "The header declares alg 'none', meaning the token is not "
                "signed at all. A server that honors this accepts any payload "
                "an attacker types, including admin claims."
            ),
            evidence=f"header.alg = {token.header.get('alg')!r}",
            recommendation=(
                "Reject 'none' outright. Verify against an explicit allowlist "
                "of algorithms and never let the token pick its own."
            ),
        )
    ]
```

Note `token.algorithm.lower()`. The attack has been carried out with `none`,
`None`, and `NONE` to slip past a case sensitive string compare, so we normalize.

### A subtle bug this design avoids: bool is an int

`src/jwt_auditor/checks.py:66`

```python
def _as_timestamp(payload, claim):
    value = payload.get(claim)
    if isinstance(value, bool):  # bool is an int subclass, reject it explicitly
        return None
    if isinstance(value, int | float):
        return float(value)
    return None
```

In Python, `True` is an instance of `int` and equals `1`. Without the explicit
`bool` check, a token with `"exp": true` would be read as expiring at Unix time
1, which is nonsense. `test_bool_claim_is_not_treated_as_timestamp` in
`tests/test_checks.py` locks this behavior in.

## The audit runner

`src/jwt_auditor/checks.py:391`

```python
def audit(token, *, now=None, wordlist=None, public_key_pem=None,
          max_lifetime_hours=_DEFAULT_MAX_LIFETIME_HOURS):
    current = time.time() if now is None else now
    secrets = COMMON_SECRETS if wordlist is None else wordlist

    findings: list[Finding] = []
    findings += check_alg_none(token)
    findings += check_unknown_algorithm(token)
    findings += check_unsigned(token)
    findings += check_weak_hmac_secret(token, secrets)
    findings += check_key_confusion(token, public_key_pem)
    findings += check_expiration(token, current, max_lifetime_hours)
    findings += check_time_sanity(token, current)
    findings += check_missing_claims(token)
    findings += check_sensitive_data(token)

    return AuditReport(token=token, findings=findings)
```

`now` is injectable. In production it is `time.time()`. In tests it is a fixed
value (`FIXED_NOW` in `tests/conftest.py`) so the expiration checks are
deterministic. That single design choice is why the time based tests are not
flaky.

## The risk score

`src/jwt_auditor/models.py`

```python
@property
def risk_score(self) -> float:
    if not self.findings:
        return 0.0
    base = max(f.severity.weight for f in self.findings)
    extra = 0.4 * (len(self.findings) - 1)
    return round(min(10.0, base + extra), 1)
```

The worst finding sets the floor. Extra findings nudge it up, because five medium
issues are worse than one. It is capped at 10. A clean token is exactly 0.0.
`tests/test_models.py` covers the empty, single, and capped cases.

## Error Handling in the CLI

`src/jwt_auditor/main.py`

```python
def _decode_or_exit(raw: str) -> DecodedToken:
    try:
        return decode(raw)
    except InvalidTokenError as exc:
        err_console.print(f"[red]Not a valid JWT:[/red] {exc}")
        raise typer.Exit(code=2) from None
```

**What NOT to do:**
```python
# Bad: swallow everything
try:
    return decode(raw)
except Exception:
    return None   # now every caller has to wonder what None means
```

We catch the one exception the decoder raises and turn it into a clean exit code
2 with a message. Everything else is a real bug and should crash loudly.

## Testing Strategy

### Unit test for a single check

`tests/test_checks.py`

```python
def test_weak_secret_recovered():
    token = decode(build_hs_token({"sub": "x"}, secret="secret"))
    findings = checks.check_weak_hmac_secret(token, ["secret", "other"])
    assert findings[0].severity is Severity.CRITICAL
    assert "secret" in findings[0].evidence
```

The fixture `build_hs_token` in `tests/conftest.py` signs a token with the
project's own `hmac_sign`, so the test exercises the real signing and cracking
path with no external library.

### End to end test through the CLI

`tests/test_cli.py`

```python
def test_audit_none_token_fails_and_reports_critical():
    token = build_none_token({"sub": "x"})
    result = runner.invoke(app, ["audit", token])
    assert result.exit_code == 1
    assert "CRITICAL" in result.stdout
```

Typer's `CliRunner` runs the command in process and captures output and the exit
code, so this checks the real argument parsing and the fail level logic together.

### Running the tests

```bash
uv run pytest tests/ -v
```

All 59 pass. If one fails with an import error, you probably skipped `uv sync`.

## Dependencies

- **typer** - the CLI framework. Gives us subcommands, help text, and exit codes
  with almost no boilerplate.
- **rich** - tables and panels for readable output, JSON pretty printing.

That is the entire runtime dependency list. Signatures, base64, and JSON all come
from the standard library, which keeps the security relevant code auditable in
one sitting.

## Next Steps

Read [04-CHALLENGES.md](./04-CHALLENGES.md) to extend the tool. Good first steps:
a new check, or real RSA verification with the `cryptography` library.
