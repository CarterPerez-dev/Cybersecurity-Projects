# System Architecture

This document explains how the tool is put together and why it is split the way
it is.

## High Level Architecture

```
             ┌──────────────┐
   token ───▶│   main.py    │  Typer CLI: decode, audit, crack
             └──────┬───────┘
                    │
                    ▼
             ┌──────────────┐
             │  decoder.py  │  split into 3 parts, decode header/payload
             └──────┬───────┘
                    │ DecodedToken
                    ▼
             ┌──────────────┐      ┌──────────────┐
             │   checks.py  │─────▶│ signatures.py│  HMAC sign/verify/crack
             └──────┬───────┘      └──────────────┘
                    │ list[Finding]        ▲
                    ▼                       │ COMMON_SECRETS
             ┌──────────────┐      ┌──────────────┐
             │   models.py  │      │  wordlist.py │
             │  AuditReport │      └──────────────┘
             └──────┬───────┘
                    │
                    ▼
             ┌──────────────┐
             │  output.py   │  Rich table or JSON
             └──────────────┘
```

### Component Breakdown

**decoder.py**
- Purpose: turn a token string into structured data.
- Responsibilities: split on dots, base64url decode, JSON parse, expose the
  signing input.
- Interfaces: `decode(str) -> DecodedToken`. Raises `InvalidTokenError`.

**signatures.py**
- Purpose: everything involving the HMAC primitive.
- Responsibilities: sign, verify in constant time, crack a wordlist, run the
  key confusion test.
- Interfaces: pure functions that take a `DecodedToken` and bytes.

**checks.py**
- Purpose: the security policy. Each check is one rule.
- Responsibilities: inspect a `DecodedToken`, return `Finding` objects, and
  orchestrate all checks in `audit()`.
- Interfaces: `audit(token, ...) -> AuditReport`, plus each `check_*` function.

**models.py**
- Purpose: the shared vocabulary.
- Responsibilities: define `Severity`, `Finding`, `AuditReport`, and compute the
  risk score.
- Interfaces: dataclasses and one enum. No behavior beyond scoring.

**output.py**
- Purpose: presentation.
- Responsibilities: render a report as a Rich table or as a JSON dict.
- Interfaces: `render_report`, `render_decoded`, `report_to_dict`.

**main.py**
- Purpose: wire it together for a human.
- Responsibilities: parse arguments, read the token, call the right functions,
  set the exit code.

## Data Flow

### Auditing a token

Step by step of what happens on `jwt-auditor audit <token>`:

```
1. main.audit_command reads the token       (src/jwt_auditor/main.py)
   resolves it from arg, --input-file, or stdin

2. decoder.decode parses it                  (src/jwt_auditor/decoder.py:90)
   returns a DecodedToken, or exits 2 on a bad token

3. checks.audit runs every check             (src/jwt_auditor/checks.py:391)
   each check appends zero or more Finding objects

4. models.AuditReport scores the findings    (src/jwt_auditor/models.py)
   risk_score and highest_severity are computed properties

5. output renders the report                 (src/jwt_auditor/output.py)
   table by default, JSON with --json

6. main sets the exit code                   (src/jwt_auditor/main.py)
   non-zero if a finding reaches --fail-level
```

## Design Patterns

### Checks as small pure functions

**What it is:** every check is a standalone function of shape
`check_x(token, ...) -> list[Finding]`.

**Where we use it:** all of `checks.py`, for example `check_alg_none`
(`src/jwt_auditor/checks.py:76`) and `check_expiration`
(`src/jwt_auditor/checks.py:238`).

**Why we chose it:** a check that returns data instead of printing is trivial to
test. `test_checks.py` calls each one directly with a crafted token and asserts
on the returned findings. There is no need to capture stdout or mock a console.

**Trade-offs:**
- Pros: isolated, testable, easy to add a new check.
- Cons: `audit()` has to know the list of checks and call each one. That list
  lives in one place (`src/jwt_auditor/checks.py:409`) so it is easy to find.

### Separating policy from presentation

The checks decide *what* is wrong. `output.py` decides *how* it looks. They
never mix. That is why the same `AuditReport` renders as a table for a human and
as JSON for a script with no duplicated logic.

## Layer Separation

```
┌───────────────────────────────────────┐
│  CLI layer: main.py                    │
│  - argument parsing, exit codes        │
│  - does not implement any check        │
└───────────────────────────────────────┘
              ↓
┌───────────────────────────────────────┐
│  Logic layer: checks.py, signatures.py │
│  - the actual security rules           │
│  - no printing, no Typer, no Rich       │
└───────────────────────────────────────┘
              ↓
┌───────────────────────────────────────┐
│  Data layer: decoder.py, models.py     │
│  - parse the token, hold the results   │
│  - no policy decisions                 │
└───────────────────────────────────────┘
```

### Why Layers?

- You can import `jwt_auditor.audit` in your own script and never touch the CLI.
- A test can build a `DecodedToken` and call one check with no I/O.
- Swapping the output format touches one file.

### What Lives Where

**Logic layer:**
- Files: `checks.py`, `signatures.py`.
- Imports: `decoder`, `models`, `wordlist`.
- Forbidden: importing `rich` or `typer`. If a check needs to print, the design
  is wrong.

**Data layer:**
- Files: `decoder.py`, `models.py`.
- Forbidden: making security decisions. `decoder.decode` never rejects a token
  for being insecure, only for being malformed. The `alg: none` token decodes
  fine so a check can flag it.

## Data Models

### DecodedToken

```python
@dataclass
class DecodedToken:
    raw: str
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: bytes
    signing_input: bytes   # header_b64 + "." + payload_b64, ASCII bytes
    header_b64: str
    payload_b64: str
    signature_b64: str
```

**Fields explained:**
- `signing_input`: the exact bytes any signature is computed over. Storing it
  here means `signatures.py` never re-derives it and cannot get it subtly wrong.
- `signature`: the raw decoded bytes, empty for an `alg: none` token.

### Finding and Severity

```python
class Severity(Enum):
    CRITICAL = ("critical", 10.0)
    HIGH     = ("high", 7.0)
    MEDIUM   = ("medium", 4.0)
    LOW      = ("low", 2.0)
    INFO     = ("info", 0.5)
```

The weight drives the risk score. The rank (declaration order) drives sorting.
Keeping both on the enum means there is one source of truth.

## Security Architecture

### Threat Model

What the tool assumes about the person running it: they hold a token and want to
know if it is safe. What it protects the *user* from is shipping a bad token.

What we are analyzing for:
1. Forgeable tokens (`none`, weak secret, confusion).
2. Tokens that leak data (sensitive claims).
3. Tokens that live too long (missing or long `exp`).

Out of scope:
- Verifying real RSA or ECDSA signatures. That needs a crypto library and is a
  different job. We audit configuration, not production traffic.
- Fetching keys or tokens over the network. Everything is offline by design.

## Configuration

There are no config files. All behavior comes from flags, parsed in `main.py`.
The two that change results rather than formatting are `--wordlist` (which
secrets to try) and `--public-key` (enables the proven confusion test).

## Performance Considerations

### Bottlenecks

The only loop that can get slow is the secret crack in `crack_hmac_secret`. It
is linear in the wordlist size, one HMAC per candidate. With `rockyou.txt` at
about 14 million lines that is 14 million HMACs, which still runs in seconds
because HMAC-SHA256 is fast and there is no I/O per candidate.

### Optimizations

The crack returns on the first match rather than scanning the whole list. For a
weak secret near the top of a list, it finishes almost immediately.

## Error Handling Strategy

### Error Types

1. **Malformed token** - `decoder.decode` raises `InvalidTokenError`. The CLI
   catches it in `_decode_or_exit` and exits 2 with a clear message.
2. **Bad flag value** - for example an unknown `--fail-level`. Raised as
   `typer.BadParameter`, which Typer renders as a usage error.

We never catch a broad `Exception` and continue. A malformed token is a real
answer ("this is not a JWT"), not something to paper over.

## Extensibility

### Where to Add a Check

1. Write `check_yourthing(token, ...) -> list[Finding]` in `checks.py`.
2. Add one line to `audit()` to call it
   (`src/jwt_auditor/checks.py:409`).
3. Add a test in `tests/test_checks.py`.

That is the whole process. Because output and scoring are generic over
`Finding`, a new check shows up in the table, the JSON, and the risk score with
no other changes.

## Limitations

1. **No asymmetric verification.** We cannot tell you an RS256 signature is
   valid, only reason about the algorithm handling. Fixing this means adding the
   `cryptography` dependency, a conscious trade-off against staying standard
   library only.
2. **Heuristic sensitive data check.** It matches claim names, not values. A
   secret in a claim called `data` slips past. That is the cost of not guessing
   at every string.

These are trade-offs, not bugs. `04-CHALLENGES.md` turns several of them into
exercises.

## Key Files Reference

- `src/jwt_auditor/decoder.py` - parsing.
- `src/jwt_auditor/signatures.py` - the HMAC primitive and attacks.
- `src/jwt_auditor/checks.py` - the security rules and `audit()`.
- `src/jwt_auditor/models.py` - types and risk scoring.

## Next Steps

Now that you understand the shape, read
[03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for the code itself.
