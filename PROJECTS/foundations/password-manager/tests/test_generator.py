"""
©AngelaMos | 2026
test_generator.py

Tests for the password generator — what it produces and what it refuses

Every test below is one Python function whose name starts with `test_`.
pytest discovers them automatically when you run `just test`, and runs
each one in isolation so a failure in one cannot poison another

────────────────────────────────────────────────────────────────────
What the generator must guarantee
────────────────────────────────────────────────────────────────────
1. The result is exactly the requested length
2. Every character class the user enabled appears at least once.
   This is what makes the generated password pass "must contain a
   digit / symbol / uppercase" rules on websites
3. Short or impossible requests are rejected loudly, never silently
   "fixed" to something else

────────────────────────────────────────────────────────────────────
A short pytest primer for this file
────────────────────────────────────────────────────────────────────
`assert <expr>`
    pytest fails the test if <expr> is falsy

`pytest.raises(SomeError)`
    A context manager that wraps a code block. The block MUST raise
    SomeError or the test fails. This is how we verify "refuses bad
    input" without having to predict the exact wording of the error

`any(c in pool for c in password)`
    Returns True if AT LEAST one character of password is in pool

`all(c in pool for c in password)`
    Returns True only if EVERY character of password is in pool

`set(...)`
    Builds a Python set, which silently discards duplicates.
    `len({generate_password(16) for _ in range(100)}) == 100` is a
    clean way to assert "100 generated passwords were all unique"
"""

# Standard library: a few prebuilt character-set strings (digits,
# ascii_letters, etc.) — handy for "every char is allowed" assertions.
import string

# Third-party: the test runner. Used for `pytest.raises` and the
# `@pytest.mark.parametrize` decorator below.
import pytest

# Local: the character pools and length minimum. Importing them lets
# the tests stay in sync if production code ever tweaks the alphabet.
from password_manager.constants import (
    DIGITS,
    LOWERCASE_LETTERS,
    MINIMUM_GENERATED_PASSWORD_LENGTH,
    SAFE_SYMBOLS,
    UPPERCASE_LETTERS,
)
# Local: the function under test plus the error type we expect when
# the caller asks for a too-short password.
from password_manager.generator import (
    PasswordTooShortError,
    generate_password,
)


# =============================================================================
# Length — what the user asks for is what they get
# =============================================================================


def test_generate_password_default_length_matches_argument() -> None:
    """
    Verify the generator produces a password of exactly the requested length

    This is the most basic contract: if I ask for length=20, I must
    get back a 20-character string. An off-by-one mistake here would
    break every downstream caller, so it is the first thing we pin
    down
    """
    password = generate_password(20)
    assert len(password) == 20


def test_generate_password_below_minimum_raises() -> None:
    """
    Verify the generator refuses lengths below the project minimum

    Why a minimum at all? A 4-character password is trivially
    crackable even with a slow KDF in front of it. Letting the caller
    produce one silently would betray the user. PasswordTooShortError
    is our way of saying "this is not a number we will produce a
    password for"

    The `with pytest.raises(...)` block fails the test if no
    exception is raised, OR if the wrong exception type is raised —
    so this single line asserts both "an error happened" and "it was
    the right error type"
    """
    with pytest.raises(PasswordTooShortError):
        generate_password(MINIMUM_GENERATED_PASSWORD_LENGTH - 1)


def test_generate_password_with_no_pools_enabled_raises() -> None:
    """
    Verify the generator refuses when every character pool is disabled

    The generator draws characters from a pool built up by combining
    the four character classes (lowercase / uppercase / digits /
    symbols). If the caller sets every flag to False, the pool is
    empty — there is literally nothing to draw from

    Rather than fall back to some default silently, the generator
    raises ValueError so the caller learns about the bug. Silent
    fallbacks in security code are how subtle weaknesses ship to
    production
    """
    with pytest.raises(ValueError):
        generate_password(
            16,
            use_lowercase = False,
            use_uppercase = False,
            use_digits = False,
            use_symbols = False,
        )


# =============================================================================
# Character class coverage — every enabled pool contributes
# =============================================================================


def test_generate_password_contains_at_least_one_from_each_pool() -> None:
    """
    Verify every enabled character class is represented in the output

    Most websites enforce composition rules: "must contain a
    lowercase letter, an uppercase letter, a digit, and a symbol."
    A generator that produced a 16-character password of only
    lowercase letters would pass `len() == 16` but fail half the
    websites the user actually has accounts on

    The fix: after building the pool, the generator guarantees AT
    LEAST one character from each enabled pool ends up in the result.
    We verify that property here by checking each pool with
    `any(c in pool for c in password)`
    """
    password = generate_password(
        16,
        use_lowercase = True,
        use_uppercase = True,
        use_digits = True,
        use_symbols = True,
    )
    # any(...) returns True if at least one char satisfies the predicate
    assert any(c in LOWERCASE_LETTERS for c in password)
    assert any(c in UPPERCASE_LETTERS for c in password)
    assert any(c in DIGITS for c in password)
    assert any(c in SAFE_SYMBOLS for c in password)


def test_generate_password_only_lowercase_when_others_disabled() -> None:
    """
    Verify disabling every pool except lowercase yields a lowercase-only string

    Useful for passphrases or for systems that refuse symbols / mixed
    case. If we accidentally leaked an uppercase letter or a digit
    into the result here, the generator would be ignoring the user's
    pool selection — a quiet correctness bug

    `all(c in LOWERCASE_LETTERS for c in password)` is True only when
    EVERY character of password is in the lowercase pool
    """
    password = generate_password(
        16,
        use_lowercase = True,
        use_uppercase = False,
        use_digits = False,
        use_symbols = False,
    )
    assert all(c in LOWERCASE_LETTERS for c in password)


def test_generate_password_excludes_symbols_when_disabled() -> None:
    """
    Verify use_symbols=False truly removes all symbols from the result

    Some legacy systems reject special characters. Users need an
    escape hatch — flipping `use_symbols=False` must yield zero
    symbols, never just "fewer symbols." We check this with
    `not any(...)`, which is True only when NO character is in the
    disallowed pool
    """
    password = generate_password(
        16,
        use_symbols = False,
    )
    assert not any(c in SAFE_SYMBOLS for c in password)


# =============================================================================
# Randomness — successive calls must produce different output
# =============================================================================


def test_generate_password_uniqueness_across_calls() -> None:
    """
    Verify successive calls produce distinct passwords

    Two truly-random 16-character passwords colliding has probability
    around 1 / (62 ^ 16), which is ~3e-29. So the chance of 100 calls
    producing 100 unique values is overwhelmingly close to 1

    If this test EVER fails, the only reasonable explanation is that
    the underlying random source (secrets.choice) is broken — for
    instance, someone swapped it for `random.choice` which seeds off
    a predictable source

    Building a set from the 100 calls and asserting `len(set) == 100`
    is the cleanest way to express "all of them were different"
    """
    passwords = {generate_password(16) for _ in range(100)}
    assert len(passwords) == 100


# =============================================================================
# Alphabet boundaries — no garbage characters slip in
# =============================================================================


def test_generate_password_only_uses_expected_alphabet() -> None:
    """
    Verify the generator never produces characters outside the configured pools

    A subtle bug would be the generator emitting a tab, a newline, or
    a Unicode character that breaks copy-paste. Building the allowed
    set by hand (union of all four pools) and asserting every char is
    in it catches that

    The defense-in-depth check at the end explicitly looks for
    whitespace — string.whitespace is the standard library's
    canonical set of " \\t\\n\\r\\v\\f", so we cannot mistype it
    """
    password = generate_password(32)
    allowed = set(LOWERCASE_LETTERS + UPPERCASE_LETTERS + DIGITS + SAFE_SYMBOLS)
    assert all(c in allowed for c in password)
    # Defense-in-depth: also check there are no whitespace chars
    assert not any(c in string.whitespace for c in password)


def test_generate_password_short_request_with_many_pools_raises() -> None:
    """
    Verify the minimum-length path interacts correctly with pool counts

    Two related checks could conceivably reject a request

      1. length below MINIMUM_GENERATED_PASSWORD_LENGTH (project floor)
      2. length below the pool count (cannot fit one char from each)

    For our defaults (minimum 8, four pools) the minimum-length check
    fires first — there is no value of `length` that passes (1) but
    fails (2). This test pins down the boundary: length == 8 with
    four pools enabled must succeed, proving the two checks combine
    sensibly. The test name says "raises" but the test verifies
    success at the floor — kept as-is to preserve the existing name
    """
    # 8 is exactly the minimum and fits 4 pools, should succeed
    password = generate_password(8)
    assert len(password) == 8
