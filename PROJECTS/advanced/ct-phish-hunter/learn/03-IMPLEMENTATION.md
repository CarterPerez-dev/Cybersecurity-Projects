# 03 - Implementation

This walks through the two hardest pieces: decoding the RFC 6962 wire format by hand, and the domain-scoring algorithm. Both are read most easily with the source file open next to this doc.

## Decoding a MerkleTreeLeaf

RFC 6962 §3.4 defines the leaf format in TLS presentation language:

```
struct {
    Version version;
    MerkleLeafType leaf_type;
    select (leaf_type) {
        case timestamped_entry: TimestampedEntry;
    }
} MerkleTreeLeaf;

struct {
    uint64 timestamp;
    LogEntryType entry_type;
    select(entry_type) {
        case x509_entry: ASN1Cert;
        case precert_entry: PreCert;
    } signed_entry;
} TimestampedEntry;   // CtExtensions omitted here; unused by glasswatch
```

Translated to bytes, big-endian, no padding: 1 byte version, 1 byte leaf_type, 8 bytes timestamp, 2 bytes entry_type, then either a 3-byte-length-prefixed certificate (`x509_entry`) or a 32-byte issuer key hash plus a 3-byte-length-prefixed TBS certificate (`precert_entry`).

[`glasswatch/ctlog.py:108`](../glasswatch/ctlog.py) reads exactly that, field by field:

```python
def parse_merkle_leaf(leaf_input_b64: str) -> tuple[int, int, bytes | None]:
    buf = base64.b64decode(leaf_input_b64)
    offset = 0

    version, offset = _read_uint(buf, offset, 1)
    leaf_type, offset = _read_uint(buf, offset, 1)
    if version != 0 or leaf_type != 0:
        raise ProtocolError(...)

    timestamp_ms, offset = _read_uint(buf, offset, 8)
    entry_type, offset = _read_uint(buf, offset, 2)

    if entry_type == ENTRY_TYPE_X509:
        cert_der, _ = _read_length_prefixed(buf, offset, 3)
        return entry_type, timestamp_ms, cert_der

    if entry_type == ENTRY_TYPE_PRECERT:
        return entry_type, timestamp_ms, None
    ...
```

Two small helpers carry the whole thing: `_read_uint(buf, offset, size)` reads a big-endian integer of a given byte width and returns the new offset, and `_read_length_prefixed(buf, offset, prefix_size)` reads an N-byte length followed by that many bytes of payload. Every length-prefixed field in the CT wire format, at every nesting level, is one call to one of these two functions.

**Why `precert_entry` returns `None` for the cert bytes**: the TBS (to-be-signed) certificate bytes in the leaf are not a complete, loadable X.509 `Certificate` structure; they are missing the outer `SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }` wrapper that `cryptography.x509.load_der_x509_certificate` requires. Trying to parse them directly just raises. The actual, structurally complete pre-certificate lives in the entry's `extra_data` instead.

## Pulling the pre-certificate out of extra_data

For a precert entry, `extra_data` is a `PrecertChainEntry` (RFC 6962 §3.4): a length-prefixed pre-certificate followed by a length-prefixed chain. `parse_precert_extra_data()` at [`glasswatch/ctlog.py:140`](../glasswatch/ctlog.py) only needs the first field:

```python
def parse_precert_extra_data(extra_data_b64: str) -> bytes:
    buf = base64.b64decode(extra_data_b64)
    pre_certificate, _ = _read_length_prefixed(buf, 0, 3)
    return pre_certificate
```

That pre-certificate *is* a complete, parseable X.509 structure (real SAN extension, real dates, a critical poison extension standing in for a real signature check), which is why `load_certificate()` and `extract_dns_names()` work on it identically to a normal `x509_entry` certificate. `tests/test_ctlog.py::test_precert_extra_data_yields_a_parseable_certificate` proves this against a certificate captured live from Cloudflare's Nimbus2026 log, not a synthetic one.

## The scoring algorithm

`score_domain()` at [`glasswatch/detect.py:111`](../glasswatch/detect.py) is the whole detector. Walking through it in order:

1. **Bail out early on the legitimate case.** `is_legitimate(domain, brand.domain)` checks whether `domain` *is* the brand's apex or a real subdomain of it (string suffix match on `"." + brand_root`, not a raw substring search, so `paypal.com.evil.io` does not accidentally pass). If so, return `None` immediately; nothing else runs.

2. **Apex-prefix check, once per domain, not per label.** Before looping over labels, `labels[:len(brand_labels)] == brand_labels` checks whether the brand's whole domain sits as the leading labels of a longer one. This has to happen outside the per-label loop because it is a property of the *label sequence*, not any single label.

3. **Per-label homoglyph and typosquat check.** For every label, `decode_and_skeletonize()` (from `glasswatch/confusables.py`) first resolves punycode if present, then folds the result through the Unicode confusables table. If the resulting skeleton exactly equals the brand's skeleton but the raw Unicode text differs, that is a homoglyph hit (`SCORE_HOMOGLYPH_EXACT = 60`). Otherwise, `levenshtein()` between the two skeletons drives the typosquat score, with distance 1 scoring higher (45) than distance 2 (28); distances of 3+ are treated as unrelated on purpose, since flagging every three-character-different string would bury real findings in noise.

4. **Per-label combosquat/substring check.** If the brand's core name literally appears inside a label (and the label is not just the brand name itself), that label either contains a phishing keyword (`SCORE_COMBOSQUAT = 25`) or it does not (`SCORE_BRAND_SUBSTRING = 12`, a much smaller bump, since "brand name shows up somewhere" alone is weak evidence by itself).

5. **Punycode bonus, once per domain.** If *any* label in the domain used punycode, add a flat bonus (`SCORE_PUNYCODE_BONUS = 15`) on top of whatever else fired. Punycode encoding is itself a mild signal (plenty of legitimate internationalized domains use it too, which is why it is a bonus, not a standalone trigger) but it meaningfully raises confidence when combined with a homoglyph hit, since it means someone deliberately encoded a lookalike character rather than glasswatch's own skeleton logic producing a coincidental match.

6. **Cap and deduplicate.** Scores are capped at 100 (`SCORE_CAP`) and reasons are de-duplicated while preserving order, since a domain with several labels can otherwise generate the same reason string more than once.

The severity bands (`SEVERITY_THRESHOLDS` at `glasswatch/detect.py:49`) are a simple ordered tuple of `(minimum_score, label)` pairs, checked from highest to lowest. Changing the thresholds or weights is a one-line change per constant; `tests/test_detect.py` pins the current values with known-answer tests, so a weight change that shifts a domain's severity band will fail loudly instead of silently.

## Common pitfalls

- **Forgetting `.casefold()` instead of `.lower()`.** Unicode has characters where lowercasing and casefolding differ (German ß, for example). `skeletonize()` uses `.casefold()` specifically so two differently-cased-but-equivalent labels always produce the same skeleton.
- **Comparing raw Unicode instead of the skeleton.** It is tempting to compare `unicode_label == brand.core_name` directly for the homoglyph check. That misses the entire point: a homoglyph domain's raw text is different from the brand's by definition (that is what makes it a homoglyph), so the comparison has to happen on the *skeleton*, with the raw-text difference as the confirming signal, not the rejecting one.
- **Running the apex-prefix check per label instead of once.** An earlier version of this logic lived inside the label loop and never fired correctly, since no single label equals `"paypal.com"`, only a label *sequence* does. It has to run once, over the whole label list, before the loop starts.

## Debugging tips

- `glasswatch scan-file` with `--all` prints every finding, not just new ones, which is the fastest way to check whether a specific domain scores the way you expect without touching SQLite or the network.
- To see exactly what a real leaf looks like on the wire, `tests/fixtures/sample_leaves.json` has two full, real `get-entries` responses saved. Load one, base64-decode `leaf_input`, and step through `parse_merkle_leaf()` by hand in a REPL.
- If `stream` seems to hang, it is almost always a slow `get-entries` response from a large, busy log rather than a bug; try `--log-url` pointed at a smaller or less busy operator to confirm, and lower `--batch-size`.
