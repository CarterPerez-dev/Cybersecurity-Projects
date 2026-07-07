# Core Security Concepts

This document explains the security ideas behind each check the tool runs. The
goal is that by the end you could re-derive every finding yourself, without the
tool.

## What a JWT Actually Is

### What It Is

A JSON Web Token is three pieces joined by dots:

```
eyJhbGciOiJIUzI1NiJ9 . eyJzdWIiOiJhZG1pbiJ9 . PGnRccPTXeax...
      header                  payload              signature
```

The header and payload are JSON objects, each base64url encoded. The signature
is computed over the string `header.payload`. The whole thing is a JWS, a
signed token. Decode the first two parts and you can read everything in them.

### Why It Matters

The single most important fact about a JWT is that the payload is **encoded,
not encrypted**. base64url is reversible by anyone. If you put a password or a
Social Security number in a claim, every party that touches the token can read
it: the browser, proxies, logs, error trackers.

### How It Works

```
header  = {"alg": "HS256", "typ": "JWT"}
payload = {"sub": "admin", "exp": 1767225600}

signing_input = base64url(header) + "." + base64url(payload)
signature     = HMAC_SHA256(secret, signing_input)

token = signing_input + "." + base64url(signature)
```

Verification recomputes the signature and compares. That is the whole model,
and every attack below is an attack on one step of it.

### Common Attacks

1. **Read the claims** - decode the payload and harvest anything sensitive.
2. **Tamper and re-sign** - if the secret is weak, change the claims and sign
   again with the guessed secret.
3. **Tamper without re-signing** - trick the verifier into skipping or
   weakening the signature check (the `none` and confusion attacks below).

### Defense Strategies

Keep the secret strong and private, pin the algorithm, set a short expiry, and
never put anything in the payload you would not print in a log. The checks in
`checks.py` map one to one onto these defenses.

## The alg none Downgrade

### What It Is

The JWT header names the algorithm used to sign the token. One legal value in
early implementations was `none`, meaning "this token is unsigned". A verifier
that reads the algorithm from the token and honors `none` will accept a token
with an empty signature.

### Why It Matters

The attacker takes a valid token, rewrites the header to `{"alg":"none"}`,
edits the payload to say `"role":"admin"`, deletes the signature, and sends it.
A vulnerable server treats it as authentic.

This is not hypothetical. In 2015, a wide range of JWT libraries were found to
accept `alg: none` by default, tracked as **CVE-2015-9235** for the popular
`jsonwebtoken` Node library and echoed across many others. The disclosure by
Auth0 that year is the reason "always pin the algorithm" became standard advice.

### How It Works

```
Original (HS256, signed):
  {"alg":"HS256"}.{"sub":"alice","role":"user"}.<valid signature>

Forged (none, unsigned):
  {"alg":"none"}.{"sub":"alice","role":"admin"}.
                                                 ^ empty signature segment
```

The tool flags this in `check_alg_none` (`src/jwt_auditor/checks.py:68`). It
compares `token.algorithm.lower()` to `"none"` and, when it matches, returns a
critical finding.

### Defense Strategies

Never let the token choose the algorithm. Decide server side which algorithms
are acceptable and reject everything else, including `none`:

```python
# the safe pattern, expressed in pseudocode
ALLOWED = {"HS256"}
if token.header["alg"] not in ALLOWED:
    reject()
```

## Weak HMAC Secrets

### What It Is

HS256, HS384, and HS512 sign with HMAC, which uses a shared secret. The
security of the token rests entirely on that secret being unguessable. When a
developer picks the secret by hand, they pick something like `secret`,
`changeme`, or the placeholder `your-256-bit-secret` from the jwt.io debugger.

### Why It Matters

Because the attacker holds the token, they can guess the secret **offline**.
There is no server to rate limit them. They try a candidate, recompute the
HMAC, and compare it to the signature already in the token. A match means they
found the key and can now forge any token they want.

### How It Works

```
for candidate in wordlist:
    if HMAC(candidate, signing_input) == token.signature:
        print("secret is", candidate)
        break
```

The tool does exactly this in `crack_hmac_secret`
(`src/jwt_auditor/signatures.py:76`). The built in wordlist in `wordlist.py`
holds the secrets that actually appear in the wild.

### Common Pitfalls

**Mistake: a short or human chosen secret**
```python
# Bad
SECRET = "myappsecret"

# Good
SECRET = secrets.token_bytes(32)  # 32 random bytes from a CSPRNG
```

**Mistake: timing the comparison with ==**
```python
# Bad, leaks how many leading bytes matched via timing
if computed == token.signature:
    ...

# Good, constant time
if hmac.compare_digest(computed, token.signature):
    ...
```

That second mistake is why `verify_hmac` uses `hmac.compare_digest`
(`src/jwt_auditor/signatures.py:73`).

## Algorithm Confusion (RS256 to HS256)

### What It Is

RS256 signs with a private key and verifies with a public key. The public key
is meant to be public. Algorithm confusion happens when a server verifies with
"whatever algorithm the token says", and an attacker changes the algorithm from
RS256 to HS256.

### Why It Matters

Now the server runs HMAC verification. The HMAC secret it uses is the only key
it has: the RSA public key. That key is not secret. The attacker downloads it,
signs a forged HS256 token with it, and the server accepts the forgery.

This class of bug has appeared repeatedly, including in widely used libraries,
and is catalogued as **CWE-347: Improper Verification of Cryptographic
Signature**. It is subtle because RS256 by itself is fine. The bug is in the
verifier accepting the header's choice.

### How It Works

```
Server has: rsa_public_key  (published, not secret)

Attacker builds:
  header  = {"alg":"HS256"}
  payload = {"sub":"admin"}
  signature = HMAC(rsa_public_key, header.payload)

Server, trusting the header, verifies with HMAC(rsa_public_key, ...) -> match
```

The tool proves this when you pass `--public-key`. `key_confusion_secret`
(`src/jwt_auditor/signatures.py:95`) tries the public key bytes as an HMAC
secret across the HS algorithms and reports a match.

### Defense Strategies

Pin the algorithm on the verifier so an RS256 endpoint only ever runs RSA
verification. Do not derive the algorithm from the token.

## How These Concepts Relate

```
alg is attacker controlled
        ↓
   enables  →  alg none (no signature at all)
        ↓
   enables  →  RS to HS confusion (public key becomes the HMAC secret)

secret is weak
        ↓
   enables  →  offline secret cracking, then arbitrary forgery
```

Every one of these traces back to the same root cause: trusting data inside the
token to decide how to verify the token.

## Industry Standards and Frameworks

### OWASP

- **OWASP API Security Top 10, API2:2023 Broken Authentication** - weak or
  misconfigured token verification is the core of this category.
- **OWASP JWT Cheat Sheet** - the source for "always use an allowlist of
  algorithms" and "do not accept `none`".

### CWE

- **CWE-347: Improper Verification of Cryptographic Signature** - the `none`
  and confusion attacks both live here.
- **CWE-321: Use of Hard coded Cryptographic Key** - the weak secret case.
- **CWE-522: Insufficiently Protected Credentials** - secrets or PII in the
  payload.

## Real World Examples

### Case Study 1: alg none in JWT libraries (2015)

Security researchers at Auth0 published a widely cited writeup showing that many
JWT libraries accepted `alg: none` and, separately, were vulnerable to the RS to
HS confusion. What made it dangerous was the default behavior: a developer
calling `verify(token)` with no extra arguments got the insecure path. The fix
across the ecosystem was to require the caller to state the expected algorithm.

### Case Study 2: secrets in the payload

A recurring finding in API assessments is a JWT payload that includes an email,
a phone number, or an internal role map. The developers assumed the token was
opaque because it looks like random text. It is not. Anyone who captured the
token from a log or a proxy read the data directly. This is why
`check_sensitive_data` (`src/jwt_auditor/checks.py:345`) exists.

## Testing Your Understanding

Before moving on, make sure you can answer:

1. Why can an attacker crack an HMAC secret offline, when a login form would
   rate limit them?
2. In the RS to HS confusion attack, what is the "secret" the attacker signs
   with, and why do they have it?
3. A colleague says the JWT is safe to store a password in because "it is
   signed". What is wrong with that reasoning?

If any of these are fuzzy, re-read the matching section. The implementation
will make more sense once these click.

## Further Reading

**Essential:**

- OWASP JSON Web Token Cheat Sheet - the practical do and do not list.
- RFC 7519 (JWT) and RFC 7515 (JWS) - the actual specifications. Short and
  readable.

**Deep dives:**

- The Auth0 2015 writeup on critical JWT vulnerabilities - the origin of the
  standard advice.
- PortSwigger Web Security Academy, JWT attacks - hands on labs for `none`,
  weak secrets, and confusion.
