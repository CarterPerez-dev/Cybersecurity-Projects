# Demo

Real output from the tool against sample tokens. Every token here is built
locally, so you can reproduce these runs yourself.

## Decode a token

`decode` shows what a token carries without checking the signature.

```
$ jwt-auditor decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIi...

╭───── Header ──────╮
│ {                 │
│   "alg": "HS256", │
│   "typ": "JWT"    │
│ }                 │
╰───────────────────╯
╭─────────── Payload ────────────╮
│ {                              │
│   "sub": "1234567890",         │
│   "name": "John Doe",          │
│   "user_password": "P@ssw0rd", │
│   "admin": true                │
│ }                              │
╰────────────────────────────────╯
╭──── Signature ────╮
│ algorithm : HS256 │
│ present   : True  │
│ bytes     : 32    │
╰───────────────────╯
```

Notice the `user_password` claim. Anyone holding this token can read it. The
payload is base64url, not encryption.

## Audit a weak token

This token is signed with the secret `secret`, carries a password claim, and
has no expiration. The audit finds all three.

```
$ jwt-auditor audit eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

╭─── JWT Audit Summary ────╮
│ algorithm    : HS256     │
│ risk score   : 10.0 / 10 │
│ worst finding: critical  │
│                          │
│ critical : 1             │
│     high : 1             │
│   medium : 1             │
│      low : 0             │
│     info : 1             │
╰──────────────────────────╯
                                    Findings
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Issue                           ┃ Evidence                        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CRITICAL │ HMAC secret recovered from      │ secret = 'secret'               │
│          │ wordlist                        │                                 │
│ HIGH     │ Payload may contain sensitive   │ suspicious claim names =        │
│          │ data                            │ ['user_password']               │
│ MEDIUM   │ No expiration claim             │ payload has no 'exp'            │
│ INFO     │ Recommended claims are missing  │ missing = ['iss', 'aud']        │
└──────────┴─────────────────────────────────┴─────────────────────────────────┘

$ echo $?
1
```

The exit code is 1 because a finding reached the default `--fail-level` of
`high`. That is what makes it usable as a CI gate.

## Crack the secret directly

```
$ jwt-auditor crack eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

Secret found: 'secret'
The token can now be forged. Rotate this key.
```

## The alg none downgrade

An attacker takes a real token, changes the header to `{"alg": "none"}`, and
drops the signature. A library that honors the header accepts it.

```
$ jwt-auditor audit eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0...

CRITICAL  Algorithm is 'none' (unsigned token)   header.alg = 'none'
```

## RS256 to HS256 confusion, proven

When you have the server's public key, the tool proves the confusion attack
instead of only warning about it. The forged token below was signed with the
public key bytes used as an HMAC secret.

```
$ jwt-auditor audit <forged-token> --public-key server_pub.pem

CRITICAL  Token verifies with the public key      public key PEM as stored
          as an HMAC secret                        (verified as HS256)
```

## JSON output

Add `--json` to feed another tool.

```
$ jwt-auditor audit <token> --json

{
  "algorithm": "none",
  "risk_score": 10.0,
  "highest_severity": "critical",
  "finding_counts": {
    "critical": 1, "high": 0, "medium": 1, "low": 0, "info": 1
  },
  "findings": [
    {
      "id": "alg-none",
      "title": "Algorithm is 'none' (unsigned token)",
      "severity": "critical",
      "detail": "The header declares alg 'none' ...",
      "evidence": "header.alg = 'none'",
      "recommendation": "Reject 'none' outright ..."
    }
  ]
}
```
