# Extension Challenges

You have a working auditor. Now make it yours. These are ordered from quick wins
to real projects. Each one names the files you will touch and how to know it
works.

## Easy Challenges

### Challenge 1: Add a check for the `kid` header injection risk

**What to build:** a check that flags a `kid` (key ID) header containing shell or
SQL metacharacters. Some servers use `kid` to look up a key by filename or in a
database, and an unsanitized `kid` has led to path traversal and SQL injection.

**Why it's useful:** `kid` injection is a real JWT attack class that the current
tool does not cover.

**What you'll learn:**
- How header parameters beyond `alg` become attack surface.
- Writing a check that inspects the header rather than the payload.

**Hints:**
- Add `check_kid_injection(token)` in `src/jwt_auditor/checks.py` and wire it into
  `audit()` next to the other calls.
- Look at `token.header.get("kid")`. Flag characters like `../`, `;`, `'`, `|`.
- Follow the shape of `check_alg_none` for the Finding fields.

**Test it works:** build a token with `header={"alg":"HS256","kid":"../../etc/passwd"}`
using the pattern in `tests/conftest.py`, and assert your check returns a finding.

### Challenge 2: Warn on HS256 keys that are too short

**What to build:** when a weak secret is recovered, also report if the recovered
secret is shorter than 32 bytes, since RFC 7518 requires an HMAC key at least as
long as the hash output.

**Why it's useful:** it turns "your secret is guessable" into a concrete "and it
is only 6 bytes, well under the 32 byte minimum".

**What you'll learn:** reading a spec requirement and encoding it as a check.

**Hints:** extend `check_weak_hmac_secret` in `checks.py`. You already have the
secret string once it is cracked.

**Test it works:** crack a short secret and assert the evidence mentions the
length.

### Challenge 3: Add a `--quiet` flag to audit

**What to build:** a flag that prints only the risk score and worst severity, no
table. Handy in scripts.

**What you'll learn:** adding a Typer option and branching the output.

**Hints:** add the option in `audit_command` in `main.py`, and guard the call to
`render_report`.

**Test it works:** add a `tests/test_cli.py` case asserting the table header is
absent in quiet mode.

## Intermediate Challenges

### Challenge 4: Real RS256 and ES256 verification

**What to build:** given a public key, actually verify an RSA or ECDSA signature,
not just warn about it.

**Real world application:** this makes the tool useful for confirming a token is
genuinely valid, not only that its configuration is sound.

**What you'll learn:**
- Using the `cryptography` library for signature verification.
- The difference between HMAC (symmetric) and RSA/ECDSA (asymmetric) verification.

**Implementation approach:**
1. Add `cryptography` to `[project.optional-dependencies]` or the main
   dependencies in `pyproject.toml`.
2. Create `verify_asymmetric(token, public_key_pem)` in `signatures.py`.
3. Add `check_asymmetric_signature` that reports whether a supplied public key
   validates the token.

**Hints:**
- `cryptography.hazmat.primitives.asymmetric` has the verify functions.
- RS256 is RSA with PKCS1v15 padding and SHA256. PS256 is RSA-PSS.
- Catch `InvalidSignature` and turn it into a finding, do not let it crash.

**Extra credit:** if verification fails, say whether the key format was wrong
versus the signature was invalid. Those are different problems for the user.

### Challenge 5: Detect nested and encrypted tokens (JWE)

**What to build:** recognize a five segment token (JWE, encrypted) versus a three
segment JWS, and report clearly instead of failing with "expected 3 segments".

**What you'll learn:** the difference between a signed token and an encrypted one,
and how the JOSE family is structured.

**Implementation approach:**
1. In `decoder.decode`, detect a five segment token and raise a specific error,
   or return a marker the CLI explains.
2. Update `main.py` to print a helpful message for JWE input.

**Hints:** a JWE is `header.encrypted_key.iv.ciphertext.tag`. You cannot audit
the claims without the decryption key, and that is the honest thing to report.

## Advanced Challenges

### Challenge 6: A batch mode for scanning many tokens

**What to build:** accept a file with one token per line and produce a summary
report: how many tokens, how many with each finding, the worst offenders.

**Why this is hard:** you have to aggregate `AuditReport` objects and design a
summary that is useful at scale without drowning the reader.

**What you'll learn:**
- Aggregating structured results.
- Designing output that scales from 1 to 10,000 items.

**Architecture changes needed:**

```
tokens.txt ──▶ decode+audit each ──▶ list[AuditReport] ──▶ aggregate ──▶ summary
```

**Implementation steps:**
1. Add a `scan` command in `main.py` that reads a file line by line.
2. Reuse `checks.audit` per line. Skip and count malformed lines rather than
   crashing the whole run.
3. Build an aggregate table: counts per `check_id`, top N by risk score.

**Gotchas:**
- Do not hold every token string in memory if the file is huge. Stream it.
- A malformed line is data, not a crash. Log it and keep going.

**Success criteria:**
- [ ] Handles a file with a mix of valid and invalid tokens.
- [ ] Prints per finding counts and the highest risk tokens.
- [ ] Exits non-zero if any token reaches the fail level.

### Challenge 7: SARIF output for CI integration

**What to build:** emit findings in SARIF, the format code scanning tools use, so
results show up in a CI dashboard.

**What you'll learn:** how findings map to a standard interchange format, the same
idea the `secrets-scanner` project in this repo uses.

**Implementation approach:** add `report_to_sarif(report)` alongside
`report_to_dict` in `output.py`, and a `--sarif` flag.

## Expert Challenges

### Challenge 8: A safe, sandboxed forging demo

**What to build:** a `forge` command that, given a token you cracked the secret
for, produces a new token with edited claims, purely to demonstrate impact in an
authorized test.

**Estimated time:** a day, mostly on the guardrails.

**Prerequisites:** finish Challenge 4 so you understand signing versus verifying.

**What you'll learn:**
- Turning an audit finding into a proof of concept, the way a pentest report does.
- The ethics and mechanics of building a tool that can also be misused.

**Planning this feature:**

Before coding, think through:
- How do you make it obvious this is for authorized testing only?
- Should it refuse to run unless the secret was actually recovered first?
- What warning does it print, and does it require a confirmation flag?

**Success criteria:**
- [ ] Only forges when given a known secret, never guesses silently.
- [ ] Requires an explicit `--i-am-authorized` style flag.
- [ ] Prints a clear notice about legal use.

## Real World Integration Challenges

### Integrate with a running app

**The goal:** pull a token from your own app's login response and audit it in one
pipeline.

**Steps:**
1. `curl` the login endpoint, extract the token with `jq`.
2. Pipe it into `jwt-auditor audit`.
3. Add it to your CI so a regression in token config fails the build.

**Watch out for:** never do this against a service you are not authorized to test.

## Security Challenges

### Challenge: harden the sensitive data check

**What to implement:** move from matching claim *names* to also scanning claim
*values* for patterns like credit card numbers (Luhn check) and JWTs nested
inside claims.

**Testing the security:**
- Put a card number in a claim called `data` and confirm the name based check
  misses it but the value based check catches it.
- Verify you do not print the sensitive value itself in the finding.

## Challenge Completion

Track your progress:

- [ ] Easy Challenge 1: kid injection check
- [ ] Easy Challenge 2: short key warning
- [ ] Easy Challenge 3: quiet flag
- [ ] Intermediate Challenge 4: asymmetric verification
- [ ] Intermediate Challenge 5: JWE detection
- [ ] Advanced Challenge 6: batch scan
- [ ] Advanced Challenge 7: SARIF output
- [ ] Expert Challenge 8: sandboxed forging demo

Finished them all? You understand JWT security better than most people shipping
tokens to production. Build something new, or contribute a check back to this
project.

## Getting Help

Stuck on a challenge?

1. **Debug systematically.** What token did you build, what finding did you
   expect, what did you get? Print the `DecodedToken` and look at it.
2. **Read the existing checks.** Your new check almost certainly resembles one
   that already exists.
3. **Run one test in isolation.** `uv run pytest tests/test_checks.py::your_test -v`.
