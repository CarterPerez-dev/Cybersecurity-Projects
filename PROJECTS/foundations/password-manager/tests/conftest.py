"""
©AngelaMos | 2026
conftest.py

Shared pytest fixtures for the test suite

A "fixture" is a setup function pytest runs before a test that needs
it. The test asks for a fixture by listing its name as a parameter,
and pytest wires the result in automatically — no manual `setUp` or
`tearDown` like older unittest-style frameworks. Fixtures defined in
conftest.py are auto-discovered and available to every test file in
the same directory, with no `import` statement needed

────────────────────────────────────────────────────────────────────
Why conftest.py specifically
────────────────────────────────────────────────────────────────────
pytest treats `conftest.py` as a magic filename. Anything defined
there is shared across every test file in the directory (and
subdirectories). This is the canonical place to put

  - Shared fixtures (`@pytest.fixture` functions)
  - Shared test constants (like TEST_KDF_PARAMETERS below)
  - Test-suite-wide hooks (e.g. autouse fixtures)

Tests in test_crypto.py or test_vault.py can reference `vault_path`,
`master_password`, or `fresh_vault` by listing them as parameters,
and pytest finds them here automatically

────────────────────────────────────────────────────────────────────
Two costs we balance when choosing fixture scope
────────────────────────────────────────────────────────────────────
  1. Time — Argon2 derivation is intentionally slow (~0.3 sec/call
     in production). If every test created a new vault with real
     parameters, the suite would take minutes
  2. Isolation — tests must NOT share writable state, or one test
     can corrupt another (especially dangerous with disk-based
     tests where leftover files leak across runs)

We solve both: a "fast" KDF parameter set just for tests (so
derivation runs in milliseconds, not seconds) and a fresh temporary
vault path per test (`tmp_path` is a built-in pytest fixture that
auto-creates and auto-cleans a unique temp directory each time)
"""

# Standard library: object-oriented filesystem paths — used here as
# a type hint for the `tmp_path` fixture pytest hands us.
from pathlib import Path

# Third-party: the test runner. We need it here to declare fixtures
# with the `@pytest.fixture` decorator.
import pytest

# Local: the KDF parameter record — fixtures build a fast variant of
# this so tests do not wait seconds on real Argon2 work.
from password_manager.crypto import KdfParameters
# Local: the main vault class — one fixture spins up a freshly
# created vault that individual tests can mutate.
from password_manager.vault import UnlockedVault


# =============================================================================
# Fast Argon2 parameters — for tests only, never use these in production
# =============================================================================
# These values are well below OWASP recommendations but they cut test
# runtime from minutes to milliseconds. The cryptographic correctness
# of the code is the same regardless of parameter strength — Argon2
# does the same operations, just fewer of them
#
# memory_cost = 8 KiB is the absolute floor that Argon2 accepts when
# parallelism = 1 (the algorithm requires memory_cost >= 8 *
# parallelism — see the Argon2 spec). If you change parallelism here,
# bump memory_cost too or Argon2 will reject the parameter set

TEST_KDF_PARAMETERS = KdfParameters(
    time_cost = 1,
    memory_cost = 8,
    parallelism = 1,
)


# =============================================================================
# Fixtures
# =============================================================================
# Each `@pytest.fixture` below defines a setup helper. Pytest sees a
# test like `def test_x(vault_path): ...` and matches the parameter
# name against a fixture name — when it finds one, the fixture runs
# first and its return value is wired into the test


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    """
    Provide a path to a fresh, non-existent vault file

    `tmp_path` is a built-in pytest fixture that creates a fresh
    empty temp directory for each test. Combined with our filename,
    every test gets a unique vault path that is auto-cleaned after
    the test ends. No global state, no cleanup code in test bodies
    """
    return tmp_path / "test-vault.json"


@pytest.fixture
def master_password() -> str:
    """
    A reasonable test master password

    Pulled into a fixture so every test uses the same value and a
    future refactor can swap it in one place. The xkcd-inspired
    string is long enough that the empty-password check below
    cannot accidentally accept it
    """
    return "correct horse battery staple"


@pytest.fixture
def fresh_vault(
    vault_path: Path,
    master_password: str,
) -> UnlockedVault:
    """
    Create an empty UnlockedVault using fast test KDF parameters

    Notice we pass kdf_parameters explicitly into create() — no
    monkey-patching of `KdfParameters.defaults` anywhere. The
    constructor takes what it needs as an argument, the test pays
    no global-state tax, and the production code path is untouched

    `fresh_vault` depends on TWO other fixtures (`vault_path` and
    `master_password`). pytest figures out the dependency chain
    automatically — it builds them in the right order so this
    fixture receives an already-resolved path and password
    """
    return UnlockedVault.create(
        vault_path,
        master_password,
        kdf_parameters = TEST_KDF_PARAMETERS,
    )
