# 04 - Challenges

Every honest limitation called out in the README and the architecture doc is also an exercise here. Hints, not solutions; the point is to go read the RFC, the Unicode spec, or the relevant library docs yourself.

## Easy

**1. Add a `--min-severity` flag to `scan-file` and `stream`.**
Only print/store findings at or above a given severity. `Finding.severity` is already a plain string (`"low"`, `"medium"`, `"high"`, `"critical"`); you need an ordering over it and a CLI argument to compare against.

**2. Add a JSON output mode to `scan-file`.**
Right now findings only print as formatted text. Add `--json` that emits one JSON object per finding (or a single JSON array) to stdout instead, so the output can feed into another tool. Look at how `server.py` already serializes a `Finding`-derived row for the `/api/findings` route for the shape to reuse.

**3. Add a `Makefile` or `justfile`.**
Most other advanced-tier projects in this repo ship a `justfile` with recipes for `test`, `lint`, `run`. This project does not have one yet; add one that wraps the commands in the README's Quick Start.

## Medium

**4. Real public-suffix-list lookups.**
`watchlist.py`'s `_core_name_from_domain()` guesses the brand name by stripping the last DNS label, which is wrong for `.co.uk`, `.com.au`, and every other multi-part suffix. The [Public Suffix List](https://publicsuffix.org/) is the real answer; a Python package like `publicsuffix2` can look up the correct registrable domain. Swap the guess for a real lookup, and update `learn/02-ARCHITECTURE.md` to remove the caveat once it is fixed.

**5. Generalize apex-prefix detection beyond a strict prefix.**
`score_domain()` only catches the brand's domain as the *leading* labels of a longer one. `mail.paypal.com.evil.io` (brand domain starting at label index 1, not 0) currently is not flagged by the apex-prefix rule at all, only by whatever the per-label homoglyph/typo checks happen to catch. Generalize the check to any contiguous position in the label list, and think about what false positives that opens up (a legitimate domain that happens to contain the brand's labels somewhere in the middle) before you ship it.

**6. Multi-log fan-out.**
`stream` watches one log at a time. Write a small supervisor (a `stream-all` subcommand, or a separate script) that spawns one `stream` process per currently-usable log, all writing to the same `--db`. Watch what happens to the SQLite dedup logic under concurrent writers, if anything, needs to change (SQLite's default locking may already be enough; verify it rather than assuming).

**7. Webhook alerting.**
`cmd_stream()` already knows the instant a finding is new (`is_new = store.record(...)`). Add an optional `--webhook URL` that POSTs new findings there (Slack-compatible JSON, a generic webhook, your choice). Think about retry behavior and what happens if the webhook endpoint is slow or down; a hung HTTP call should not stall the scan of the next certificate.

## Hard

**8. STH signature verification.**
Right now `get_sth()` trusts TLS plus the fact that the log's URL came from Google's list. A real CT monitor verifies the STH's signature against the log's public key (also published in `log_list.json`, base64-encoded DER `SubjectPublicKeyInfo`) using the signature algorithm the log advertises. Implement that verification, and reject an STH that does not check out instead of trusting it blindly.

**9. Consistency proof verification.**
Beyond trusting an individual STH, a rigorous monitor verifies that each new STH is *consistent* with the last one it saw, using `ct/v1/get-sth-consistency` and the Merkle audit-path math from RFC 6962 §2.1.2. This is the mechanism that makes CT logs tamper-evident instead of just "a log someone promises not to edit." Implementing it properly means understanding how Merkle audit paths are constructed for a non-power-of-two tree size, which is the genuinely tricky part.

**10. A real confusables *algorithm*, not a single-pass table lookup.**
`skeletonize()` does one pass through `CONFUSABLES`. Unicode's own TR39 skeleton algorithm is recursive: mapping a character can produce a string that itself contains further-confusable characters, and the real algorithm applies the transform to a fixed point. Our filtered table only keeps entries whose *target* is already pure ASCII, which sidesteps the need for recursion but also means any confusable chain longer than one hop is invisible to this project. Find (or construct) an example where that matters, then implement the recursive version and see whether it changes any real-world result.

**11. Rate-limit-aware, resumable multi-day backfill.**
`--backfill` is capped by whatever `--batch-size` and your patience allow in one run. A log with billions of entries cannot reasonably be backfilled in full in one sitting. Design (and implement) a resumable backfill: persist the cursor position across restarts, respect whatever rate limiting a log operator documents, and make it safe to interrupt and resume without re-scanning or skipping entries.
