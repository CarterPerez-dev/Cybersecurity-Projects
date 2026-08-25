# 01 - Concepts

## Certificate Transparency, in plain terms

Before 2013, a Certificate Authority (CA) could issue a certificate for any domain, and the only way anyone would find out about a mis-issued or malicious one was by accident. In 2011, a breach at the Dutch CA DigiNotar led to fraudulent certificates being issued for `*.google.com`, used to intercept traffic for an estimated 300,000 Iranian users. Nobody caught it through the CA system itself; it surfaced because Chrome had a hardcoded backup check (certificate pinning) that happened to catch the fake.

Certificate Transparency, specified in RFC 6962 (2013) and its successor RFC 9162 (2021), is Google's answer: every publicly trusted certificate has to be submitted to at least one public, append-only, cryptographically verifiable log before a browser will accept it. Chrome has enforced this since 2018. The logs cannot be edited or have entries removed without the tampering being mathematically detectable, because of how they are built.

## Merkle trees, briefly

A CT log is a Merkle hash tree. Every certificate that gets submitted becomes a leaf; each pair of leaves gets hashed together into a parent node; parent nodes get hashed together again, all the way up to a single **root hash**. The log periodically signs the current root hash plus the tree size into a **Signed Tree Head (STH)**.

The property that matters here: given an old STH and a new STH, anyone can request a **consistency proof**, a small set of hashes that proves the new tree is the old tree with more leaves appended, and *nothing else changed*. You do not have to trust the log operator; you can verify it. glasswatch does not implement consistency-proof verification (see `04-CHALLENGES.md`), but that verifiability is the entire reason CT logs are trustworthy enough to build a phishing detector on top of, instead of just scraping a website.

```
                    root hash
                   /          \
              hash(1,2)      hash(3,4)
              /    \          /    \
          leaf1   leaf2   leaf3   leaf4
           |        |       |       |
         cert1    cert2   cert3   cert4
```

## Leaf entries vs. precertificates

A subtlety that trips people up the first time: a CT log entry is not always a normal, fully issued certificate.

Before a CA can issue a real certificate, it has to get an SCT (Signed Certificate Timestamp) from a log to embed in the final cert (so the browser can verify, without a network round trip, that the cert really is logged). To get that SCT, the CA submits a **precertificate**: a real, complete, correctly-formed X.509 certificate with a special critical extension (the CT "poison" extension, OID `1.3.6.1.4.1.11129.2.4.3`) in place of where verification would happen, so nothing accidentally treats it as a trusted cert on its own.

That means a CT log's tree of leaves contains a mix of `x509_entry` (a fully issued cert) and `precert_entry` (a precertificate, logged before the real cert existed). Both carry the same Subject Alternative Names, so for the purpose of "what domain is this for", they are interchangeable, they just need slightly different parsing. `glasswatch/ctlog.py` handles both; see `03-IMPLEMENTATION.md` for exactly how.

## Homoglyph attacks (CWE-1007)

[CWE-1007](https://cwe.mitre.org/data/definitions/1007.html), "Insufficient Visual Distinction of Homoglyphs Presented to User", covers any character that looks identical or nearly identical to another. Unicode has thousands of them: Cyrillic а (U+0430) next to Latin a, Greek ο (U+03BF) next to Latin o, fullwidth forms, and more.

Domain names are allowed to contain non-ASCII characters through **IDNA** (Internationalized Domain Names in Applications, RFC 5891), which encodes them as ASCII using **punycode** (RFC 3492) prefixed with `xn--`. `аpple.com` (Cyrillic а) becomes `xn--pple-43d.com` on the wire. A browser decodes it back to `аpple.com` for display, and in most fonts it is genuinely indistinguishable from the real thing.

This is not theoretical. In 2017, a proof-of-concept registered `xn--80ak6aa92e.com`, which every mainstream browser at the time rendered as a perfect visual copy of `apple.com`, complete with a valid certificate. Browsers have since added mitigations (Chrome shows the punycode form when a label mixes scripts in suspicious ways), but the underlying attack surface has not gone away, and plenty of homoglyph domains never trigger those heuristics because they use a single consistent script.

**How glasswatch catches it:** every domain label gets normalized to an ASCII "skeleton" via Unicode's own confusables table (see `01-CONCEPTS.md`'s companion code in `glasswatch/confusables.py`), so `pаypal` (Cyrillic а) and `paypal` produce the identical skeleton string. If a label's skeleton matches a watched brand's skeleton but the raw characters differ, that is a homoglyph hit.

## Typosquatting

The simpler cousin: no special characters, just a domain one or two edits away from the real one. `gooogle.com` (extra o), `paypa1.com` (1 for l), `mircosoft.com` (transposed letters). These rely on nobody proofreading a URL carefully, which turns out to be most people most of the time.

**How glasswatch catches it:** Levenshtein (edit) distance between a label's skeleton and the brand's skeleton. Distance 1 (one insertion, deletion, or substitution) scores higher than distance 2, since a single typo is both more common and harder to notice than two.

## Combosquatting and apex-prefix spoofing

Combosquatting keeps the real brand name intact and adds words around it: `paypal-login-verify.net`, `secure-paypal-account.com`. A widely cited 2017 academic study of combosquatting (Kintis et al., "Hiding in Plain Sight: A Longitudinal Study of Combosquatting Abuse", ACM CCS) measured millions of such domains actively used for phishing and malware distribution over a multi-year window, most of them alive far longer than typosquats before takedown, since a human skimming the domain sees the real brand name sitting right there.

A related trick targets how browsers and messaging apps truncate long URLs: `paypal.com.account-verify.net` puts the real brand's full domain as the *leading* labels of a much longer one. On a narrow screen or in a shortened link preview, everything after `paypal.com` may simply be cut off.

**How glasswatch catches it:** a label containing the brand name plus one of a curated list of phishing-adjacent keywords (`login`, `verify`, `secure`, `account`, `payment`, and others, see `COMBOSQUAT_KEYWORDS` in `glasswatch/detect.py`) scores as a combosquat. Separately, the brand's full domain appearing as the first N labels of a longer domain scores as apex-prefix spoofing, regardless of keywords.

## Testing your understanding

1. Why can't a naive string comparison (`domain == brand`) ever catch a punycode homoglyph attack, even in principle?
2. A domain scores a homoglyph-exact hit against brand "acmepay" only if the skeleton matches *and* the raw label differs. What legitimate domain would that exclusion accidentally protect, and why does that matter?
3. `paypal.com` used as a subdomain of an attacker's domain (`paypal.com.evil.io`) and `paypal.com` used as a real subdomain (`api.paypal.com`) both contain the exact string `paypal.com`. What in `glasswatch/detect.py` tells them apart, and could an attacker construct a domain that fools it?
4. The combosquat keyword list is fixed and English-language. What kind of phishing domain would slip past it entirely, and how would you extend the detector to catch it?
