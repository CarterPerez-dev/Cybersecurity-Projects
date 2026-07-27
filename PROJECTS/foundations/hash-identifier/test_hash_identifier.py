"""
©AngelaMos | 2026
test_hash_identifier.py

Tests for hash_identifier — focused on the most-relied-on cases

────────────────────────────────────────────────────────────────────
What "tests" are and why we write them
────────────────────────────────────────────────────────────────────
A test is a tiny Python function that calls our real code with a
known input and then ASSERTS that the result is what we expected.
If the assertion fails, pytest prints a red FAIL message — which
means we changed something and broke a behavior we cared about

Tests are insurance. The first time you write the code, the test
just confirms it works. But six months later when you refactor or
add a new feature, the existing tests catch any accidental breakage.
This is why every senior codebase has tests: not because the code is
hard to write, but because the code is hard to keep WORKING over time

────────────────────────────────────────────────────────────────────
The shape of a pytest test
────────────────────────────────────────────────────────────────────
  def test_<what_we_are_checking>() -> None:
      result = some_function(some_input)
      assert result == expected

Three rules
  1. The function name must start with `test_` — pytest only collects
     functions that match that pattern
  2. The function takes no arguments (unless using fixtures)
  3. Use the `assert` keyword to declare what should be true. If the
     condition is false, the test fails

We follow the "Arrange-Act-Assert" structure inside each test
  - Arrange: set up inputs (the `sample = ...` line)
  - Act:     call the real code (`candidates = identify(sample)`)
  - Assert:  check the result (`assert candidates[0]...`)

────────────────────────────────────────────────────────────────────
Coverage strategy
────────────────────────────────────────────────────────────────────
We do NOT try to test every algorithm in the table — that would be
hundreds of nearly identical tests. Instead we exercise each BRANCH
of identify() at least once

  - prefix matches (one bcrypt, one Argon2id, one Django, one crypt)
  - special MySQL5 format
  - hex length matches (MD5, SHA-1, SHA-256 lengths)
  - the empty / garbage / whitespace fallbacks
  - HashCandidate's immutability

Together these give us confidence that every code path runs without
explosion, and that the most-common inputs produce the expected
top-ranked candidate
"""

# Importing from `hash_identifier` (NOT `hash_identifier.py`) tells
# Python to load the module that lives in this same directory. We
# pull in three things:
#   - `identify`     — the function under test
#   - `HashCandidate`— the return-type dataclass (used in the
#                      immutability test)
#   - `PREFIX_RULES` — the prefix lookup table (used by the
#                      parametrized "every row is covered" test
#                      at the bottom of this file)
# `pytest` is also imported so we can use the @pytest.mark.parametrize
# decorator to expand one test function into many test cases
# Third-party: the test runner itself. We also need it imported here
# so we can use its `@pytest.mark.parametrize` decorator below.
import pytest

# Local: our own module. We pull in the public pieces under test —
# the prefix-rule table, the result dataclass, and the entry function.
from hash_identifier import PREFIX_RULES, HashCandidate, identify

# =============================================================================
# Prefix matches (high confidence)
# =============================================================================
# These tests verify Step 1 of identify(): when the input starts with a
# known prefix, we report HIGH confidence. The exact hash payload after
# the prefix does not matter to identify() — it only inspects the
# leading characters


def test_bcrypt_prefix_is_recognized() -> None:
    """
    A real bcrypt hash starts with `$2b$` and should be reported as bcrypt
    """
    # Sample: an actual bcrypt hash for the password "password" with cost 12.
    # The interesting part for our test is just `$2b$` — we never even
    # decode the rest
    sample = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"

    # Call the function under test. `candidates` is a list of HashCandidate
    candidates = identify(sample)

    # First assert the list is non-empty. `assert <thing>` fails when
    # <thing> is falsy — empty lists are falsy, so this catches the
    # "no candidates returned" bug
    assert candidates
    # Then check the FIRST candidate (highest-priority guess) is bcrypt.
    # `candidates[0]` is the first item; `.algorithm` is the field we
    # check. `==` compares for equality
    assert candidates[0].algorithm == "bcrypt"
    # And confidence must be "high" — prefix matches are definitive
    assert candidates[0].confidence == "high"


def test_argon2id_prefix_is_recognized() -> None:
    """
    Argon2id PHC strings begin with `$argon2id$`
    """
    # PHC format for Argon2id: $argon2id$v=<version>$m=...,t=...,p=...$<salt>$<hash>
    sample = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA"
    candidates = identify(sample)
    # `any(...)` returns True if at least one element of the iterable
    # makes the inner expression true. We check that AT LEAST ONE
    # candidate is Argon2id — using any() instead of [0] keeps the test
    # robust if we ever add a second guess to the same prefix
    assert any(c.algorithm == "Argon2id" for c in candidates)


def test_sha512_crypt_prefix_is_recognized() -> None:
    """
    `$6$` is the marker for SHA-512 crypt — what /etc/shadow uses on Linux
    """
    sample = "$6$rounds=10000$salt$hashedpasswordhere"
    candidates = identify(sample)
    # `[0]` because we want the TOP candidate. If anything else was
    # ranked first, this assertion would fail loudly
    assert candidates[0].algorithm == "SHA-512 crypt"


def test_django_pbkdf2_prefix_is_recognized() -> None:
    """
    Django stores passwords as `pbkdf2_sha256$<iter>$<salt>$<hash>`
    """
    sample = "pbkdf2_sha256$260000$salt$hash"
    candidates = identify(sample)
    assert candidates[0].algorithm == "Django PBKDF2-SHA256"


def test_kerberos_tgs_prefix_is_recognized() -> None:
    """
    Kerberoasting hashes start with `$krb5tgs$` and should be
    reported as a Kerberos TGS-REP with HIGH confidence

    Sample is a real-shaped RC4 (`etype 23`) service ticket hash,
    the format Impacket's GetUserSPNs.py and Rubeus both emit.
    identify() never decodes the ticket payload, so a short
    fake tail after the two known `$`-delimited fields is enough
    """
    # $krb5tgs$<etype>$*<user>$<realm>$<spn>*$<checksum>$<edata2>
    sample = "$krb5tgs$23$*user$REALM.COM$cifs/host.realm.com*$checksumhere$edata2here"
    candidates = identify(sample)
    assert candidates
    assert candidates[0].algorithm == "Kerberos TGS-REP (Kerberoasting)"
    assert candidates[0].confidence == "high"


def test_kerberos_asrep_prefix_is_recognized() -> None:
    """
    AS-REP roasting hashes start with `$krb5asrep$` and should be
    reported as a Kerberos AS-REP with HIGH confidence

    Sample mirrors what Impacket's GetNPUsers.py and Rubeus's
    `asreproast` output for an account with Kerberos pre-auth
    disabled. As with TGS-REP, identify() only inspects the prefix
    """
    # $krb5asrep$<etype>$<user>@<realm>:<checksum>$<edata2>
    sample = "$krb5asrep$23$user@REALM.COM:checksumhere$edata2here"
    candidates = identify(sample)
    assert candidates
    assert candidates[0].algorithm == "Kerberos AS-REP (AS-REP Roasting)"
    assert candidates[0].confidence == "high"


def test_apr1_prefix_is_recognized() -> None:
    """
    Apache `.htpasswd` MD5 hashes start with $apr1$

    The htpasswd tool generates these by default with the `-m` flag.
    Same MD5 family as the Unix $1$ format but with Apache's own salt
    handling — and FAR more common in the wild because every Apache
    basic-auth tutorial ends with one of these in a .htpasswd file
    """
    # Real-looking apr1 hash. The trailing payload after the second
    # `$` is the base64-flavored encoding of the MD5 digest + salt.
    # identify() never decodes it — only the leading `$apr1$` matters
    sample = "$apr1$rsalt$mp7TYYDvbgvNCJN3JTd6q1"
    candidates = identify(sample)
    assert candidates[0].algorithm == "Apache MD5-crypt"
    assert candidates[0].confidence == "high"


# =============================================================================
# Special formats
# =============================================================================
# Step 2 of identify(): formats that are NOT PHC strings but still have
# unmistakable shapes. Today we recognize NetNTLMv1, NetNTLMv2, and
# MySQL5 — three structurally-distinct records that all benefit from
# the same "check the literal shape before falling back to length" path


def test_mysql5_format_is_recognized() -> None:
    """
    MySQL5 = literal `*` followed by 40 uppercase hex chars

    MySQL5 stores SHA-1(SHA-1(password)) printed in uppercase hex with
    a leading asterisk. So the whole hash is exactly 41 characters
    """
    # The * matters — without it, this would just be 40 hex chars
    # and would fall through to the SHA-1 length rule
    sample = "*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
    candidates = identify(sample)

    # MySQL5 is a definitive shape, so we expect HIGH confidence
    assert candidates[0].algorithm == "MySQL5"
    assert candidates[0].confidence == "high"


def test_mysql5_rejects_lowercase_body() -> None:
    """
    Lowercase hex after the leading `*` is not real MySQL5 output

    MySQL emits uppercase via `%02X`, so a `*` followed by lowercase
    hex is almost certainly hand-edited junk rather than a real
    MySQL5 hash. We would rather return nothing than return a
    confident WRONG answer here
    """
    # Lowercase version of the previous test's body. The leading `*`
    # is the only thing it shares with real MySQL5 output, and the
    # case mismatch alone should disqualify it
    lowercase_body = "23ae809ddacaf96af0fd78ed04b6a265e05aa257"
    candidates = identify("*" + lowercase_body)

    # Either the list is empty (preferred, what we expect today) OR
    # whatever did match must NOT be labeled MySQL5. The `if`
    # guard makes the test robust to future rules that might catch
    # this shape under a different (correct) label — what matters is
    # that we do not LIE and call it MySQL5
    if candidates:
        assert candidates[0].algorithm != "MySQL5"


def test_netntlmv2_format_is_recognized() -> None:
    """
    NetNTLMv2 records from Responder look like
    `user::domain:challenge:hmac:blob`

    The hmac field is exactly 32 hex chars. The leading `::` (empty
    LM-hash slot) is the giveaway that this is an AD challenge-
    response record, not a stored password hash
    """
    # Build a realistic NetNTLMv2 record:
    #   alice :: CORP : <16-char challenge> : <32 hex hmac> : <64 hex blob>
    # The actual hash values do not matter — only the structural
    # shape (colon count + hex field lengths) is what identify() checks
    sample = "alice::CORP:1122334455667788:" + "a" * 32 + ":" + "b" * 64
    candidates = identify(sample)

    # NetNTLMv2 is a definitive shape — HIGH confidence
    assert candidates[0].algorithm == "NetNTLMv2"
    assert candidates[0].confidence == "high"


def test_netntlmv1_format_is_recognized() -> None:
    """
    NetNTLMv1 records have 48-hex-char lmhash AND nthash before the challenge

    Layout: `user::domain:lm(48 hex):nt(48 hex):challenge`. We
    recognize this by looking at field index 3 — in NetNTLMv1 it is
    exactly 48 hex chars, while in NetNTLMv2 it is the (shorter)
    challenge field
    """
    # Build a realistic NetNTLMv1 record. The 48-char lmhash and
    # nthash are the load-bearing signal; identify() never decodes
    # them — only their length and charset matter
    sample = "alice::CORP:" + "a" * 48 + ":" + "b" * 48 + ":1122334455667788"
    candidates = identify(sample)
    assert candidates[0].algorithm == "NetNTLMv1"
    assert candidates[0].confidence == "high"


def test_descrypt_format_is_recognized() -> None:
    """
    Traditional DES crypt has NO prefix — only length and charset identify it

    Legacy /etc/passwd from pre-shadow Unix systems used this format:
    13 characters drawn from the alphabet `./0-9A-Za-z`. Rare today
    but still turns up in retro CTFs, and hashcat still ships a mode
    (1500) for cracking it
    """
    # A realistic 13-char DES crypt output. Content does not matter
    # for the test — only the length and the all-valid-charset
    # property are what _is_descrypt checks
    sample = "kRq14pmccuMOA"
    candidates = identify(sample)

    assert candidates[0].algorithm == "DES crypt"
    # MEDIUM (not HIGH) confidence because a 13-char `./0-9A-Za-z`
    # string CAN technically be other things (session IDs, random
    # tokens). An honest medium beats a confident false-positive
    assert candidates[0].confidence == "medium"


# =============================================================================
# Hex length matches (medium / low confidence)
# =============================================================================
# Step 3 of identify(): when the input is pure hex, length narrows down
# the algorithm. The FIRST listed algorithm for each length gets
# medium confidence (the modern default); the rest are low


def test_mysql323_length_returns_mysql323_first() -> None:
    """
    16 hex chars points at MySQL323 (legacy MySQL OLD_PASSWORD output)

    MySQL versions before 4.1 stored passwords as a 16-char hex string
    from a custom (now-broken) hash function. The OLD_PASSWORD() SQL
    function still produces this format on modern MySQL for legacy
    compatibility, so these still show up in CTFs and old MySQL
    breach dumps
    """
    # A 16-hex-char string. The content does not matter — only the
    # length and the all-hex charset are what identify() checks
    sample = "5d2e19393cc5ef67"
    candidates = identify(sample)

    # MySQL323 ranks ABOVE CRC-64 because in a security context (a
    # CTF challenge, a breach dump, a password column) MySQL323 is
    # by far the more likely source. A 64-bit CRC almost never
    # arrives at a hash-identifier tool
    assert candidates[0].algorithm == "MySQL323"
    # MEDIUM confidence: length alone is suggestive but cannot rule
    # out CRC-64 with certainty without seeing the surrounding context
    assert candidates[0].confidence == "medium"


def test_md5_length_returns_md5_first() -> None:
    """
    32 hex chars matches MD5, NTLM, MD4, RIPEMD-128

    MD5 is BY FAR the most common 32-hex hash in the wild, so it must
    be the top candidate. NTLM (a Windows hash) is also 32 hex but
    far less common in pasted hash dumps, so it should appear later
    """
    # The literal MD5 of the string "password". A useful sample because
    # any reader can verify it: `echo -n password | md5sum`
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"
    candidates = identify(sample)

    # Top candidate is MD5
    assert candidates[0].algorithm == "MD5"
    # And we report MEDIUM confidence — length alone is suggestive
    # but not definitive (no prefix to confirm)
    assert candidates[0].confidence == "medium"

    # NTLM should appear in the candidate list as a less-likely option.
    # We pull just the algorithm names into a list using a comprehension,
    # then check membership with `in`
    algorithms = [c.algorithm for c in candidates]
    assert "NTLM" in algorithms


def test_sha256_length_returns_sha256_first() -> None:
    """
    64 hex chars points at SHA-256 first

    SHA3-256 and BLAKE2s also produce 64 hex chars but are rarer in
    real systems, so SHA-256 takes the top spot
    """
    # `"a" * 64` is Python shorthand for "the character 'a' repeated 64
    # times" — a quick way to make a 64-char string for length tests.
    # The actual content does not matter; only the length does
    sample = "a" * 64
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-256"


def test_sha1_length_returns_sha1_first() -> None:
    """
    40 hex chars = SHA-1 (RIPEMD-160 as a backup guess)
    """
    sample = "a" * 40
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-1"


# =============================================================================
# No-match / edge cases
# =============================================================================
# Always test the boring edge cases. Empty inputs, whitespace-only,
# garbage. These caused real bugs in real codebases more than once


def test_empty_input_returns_no_candidates() -> None:
    """
    Empty string returns an empty list — never blows up
    """
    # Two checks because both of these have caused crashes elsewhere:
    # truly empty AND whitespace-only (which strips down to empty)
    assert identify("") == []
    assert identify("   ") == []


def test_garbage_returns_no_candidates() -> None:
    """
    A string with neither a known prefix nor a hex shape returns []
    """
    # Sentence with spaces and punctuation: cannot be hex, has no
    # PHC prefix. identify() should return an empty list, not guess
    assert identify("hello, this is not a hash") == []


def test_input_is_trimmed_of_whitespace() -> None:
    """
    Trailing newlines and leading spaces should not block recognition

    This matters because copy-paste from a terminal often picks up
    invisible whitespace. We strip it inside identify()
    """
    # Note the leading spaces and trailing \n — escaped newline character
    sample = "   5f4dcc3b5aa765d61d8327deb882cf99\n"
    candidates = identify(sample)
    # If trim works, we still recognize MD5 despite the surrounding noise
    assert candidates[0].algorithm == "MD5"


# =============================================================================
# Soft-match fallbacks (shape hints, LOW confidence)
# =============================================================================
# Steps 4 and 5 of identify(): when nothing in the PREFIX_RULES table
# or the special-formats step or the hex-length table fires, we still
# try two soft matches — generic PHC string shape, then "this looks
# like a JWT / base64 blob, not a hash." Both return LOW confidence
# because shape alone is a weaker signal than a known prefix


def test_unknown_phc_string_falls_back_to_generic() -> None:
    """
    A PHC string from an algorithm we don't have a specific rule for
    is still reported as a PHC string with the extracted algorithm name

    This is a SOFT match (LOW confidence) but still beats the
    alternative of returning nothing on an obviously-PHC-shaped input
    """
    # Passlib's pbkdf2-sha512 PHC encoding. We have no specific rule
    # for it in PREFIX_RULES — but the `$pbkdf2-sha512$...` shape is
    # unambiguous, so the generic fallback should pick it up
    sample = "$pbkdf2-sha512$25000$cnNhbHQ$aGFzaA"
    candidates = identify(sample)

    assert candidates
    # The algorithm column should say "PHC string (pbkdf2-sha512)" —
    # both the marker word "PHC" and the extracted algorithm name
    # should appear so the user knows WHAT kind of thing they pasted
    assert "PHC" in candidates[0].algorithm
    assert "pbkdf2-sha512" in candidates[0].algorithm
    # LOW confidence because we matched on shape only, not on a
    # specific rule that would let us confirm the algorithm
    assert candidates[0].confidence == "low"


def test_jwt_input_is_called_out_as_not_a_hash() -> None:
    """
    JWTs start with `eyJ` and should be called out as not-a-hash

    Beginners often paste JWTs into a hash identifier because they
    look hash-like. Saying "this is a JWT, not a hash" is more
    useful than silence — it teaches the user what they have
    """
    # A short but real-shaped JWT (header.payload.signature). The
    # signature here is intentionally not real — identify() never
    # validates it, only the leading `eyJ` matters
    sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"
    candidates = identify(sample)

    assert candidates
    # The algorithm column should contain "JWT" so the user knows
    # exactly what kind of thing they pasted
    assert "JWT" in candidates[0].algorithm
    # LOW confidence is honest: we are not 100% sure this is a JWT,
    # we are 100% sure it starts with `eyJ` and JWTs start with `eyJ`
    assert candidates[0].confidence == "low"


def test_base64_blob_is_called_out_as_not_a_hash() -> None:
    """
    A string containing base64-only chars (`+`, `/`, `=`) is not hex

    Hex hashes never contain those characters, so their presence is a
    strong signal that the input is base64-encoded data of some kind
    rather than a hash — even when we cannot say what it decodes to
    """
    # A base64-looking blob with the `=` padding character
    sample = "VGhpcyBpcyBub3QgYSBoYXNoLCBpdHMgYmFzZTY0Lg=="
    candidates = identify(sample)

    assert candidates
    # "Base64 blob" should appear in the algorithm name so the user
    # knows we did identify SOMETHING, just not a hash
    assert "Base64" in candidates[0].algorithm


# =============================================================================
# HashCandidate is immutable
# =============================================================================
# We declared HashCandidate with @dataclass(frozen=True). Frozen means
# you cannot reassign fields after construction — like a sealed envelope.
# This test makes sure the seal actually holds, so future refactors do
# not accidentally drop the `frozen` flag


def test_hash_candidate_is_frozen() -> None:
    """
    Attempting to mutate a HashCandidate must raise an error
    """
    # First, construct a normal instance
    candidate = HashCandidate(
        algorithm = "MD5",
        confidence = "medium",
        reason = "test",
    )

    # try/except is Python's "guard against an error" syntax. Inside
    # `try`, we attempt the operation we EXPECT to fail. The `except`
    # block runs ONLY if the listed exception types fire — and our
    # frozen dataclass raises one of these on assignment
    try:
        # `# type: ignore[misc]` tells mypy "I know this is a type error;
        # I am doing it on purpose to verify it actually fails at runtime"
        candidate.algorithm = "SHA-1"  # type: ignore[misc]
    except (AttributeError, TypeError):
        # Got the expected exception — the test passes by returning
        return

    # If we reached this line, no exception was raised — frozen is
    # broken. Fail the test loudly with a clear message
    raise AssertionError(
        "HashCandidate should be frozen; assignment should have raised"
    )


# =============================================================================
# Comprehensive PREFIX_RULES table coverage
# =============================================================================
# The individual prefix tests above (bcrypt, Argon2id, etc.) double as
# readable EXAMPLES of how identify() handles known prefixes. This last
# test plays a different role: it is the safety-net that guarantees
# EVERY row of PREFIX_RULES is exercised, so a typo in any single row's
# algorithm name or note string fails its own test case rather than
# slipping through silently.
#
# `@pytest.mark.parametrize(name, values)` is pytest's mechanism for
# expanding ONE test function into MANY test cases. Here we hand it
# the entire PREFIX_RULES list. Pytest unpacks each `(prefix, algorithm,
# note)` tuple into the three parameters of the test function and runs
# the body once per row. The leading `_` in `_note` tells linters
# (and the next reader) that we intentionally do not assert on the
# note string — we accept whatever the table author wrote


@pytest.mark.parametrize("prefix,algorithm,_note", PREFIX_RULES)
def test_every_prefix_rule_is_recognized_with_high_confidence(
    prefix: str,
    algorithm: str,
    _note: str,
) -> None:
    """
    Every entry in PREFIX_RULES produces a HIGH-confidence candidate
    with the matching algorithm when its prefix sits at the start
    of the input

    The body of the hash after the prefix does not matter to
    identify() — it only inspects the leading characters — so we
    just glue any junk onto the end to form a syntactically-plausible
    input
    """
    sample = prefix + "fakebodydoesntmatter"
    candidates = identify(sample)

    # If identify() returned nothing, the prefix-loop branch is
    # broken — fail with a message that names the offending prefix
    # so the failure is debuggable at a glance
    assert candidates, f"no candidates returned for prefix `{prefix}`"
    assert candidates[0].algorithm == algorithm
    assert candidates[0].confidence == "high"
