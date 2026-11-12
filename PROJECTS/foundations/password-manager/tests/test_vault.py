"""
©AngelaMos | 2026
test_vault.py

Tests for the vault module — file format, persistence, entry CRUD

These tests DO touch the filesystem (via pytest's `tmp_path` fixture)
because the vault's whole job is reading and writing files. Every
fixture cleans up after itself when the test ends, so the suite
leaves no debris behind

────────────────────────────────────────────────────────────────────
What is being verified, organized by section
────────────────────────────────────────────────────────────────────
1. Vault creation — `UnlockedVault.create()` writes a file at the
   given path with the right format, the right permissions, and
   refuses to clobber an existing vault

2. Round-trip — save a vault, reopen it, get back exactly what was
   stored. Verify wrong-password, missing-file, malformed-file,
   and out-of-range KDF parameters all raise the right exceptions

3. Entry dataclass — Entry is frozen (cannot be mutated after
   construction); from_dict refuses corrupted input loudly instead
   of silently filling in defaults for required fields

4. Entry operations — add / get / delete / names. Duplicate
   detection, the `force` overwrite flag, sort order, entry-name
   validation that rejects leading/trailing whitespace

5. Master password rotation — change_master_password rotates BOTH
   the salt AND the key. After rotation the old password no longer
   works; the new password unlocks; all entries survive

6. Lifecycle — close() and the context-manager `with` block both
   drop the key + entries from memory when done

7. Persistence — every save produces a fresh nonce, never leaves a
   stale .tmp file, and uses the secure 0600 file mode from the
   very first syscall

────────────────────────────────────────────────────────────────────
A short pytest primer for this file
────────────────────────────────────────────────────────────────────
`tmp_path` (built-in fixture)
    Pytest creates a fresh empty temporary directory for each test
    and passes its Path here. Auto-cleaned at test end

`monkeypatch` (built-in fixture)
    Lets you temporarily replace attributes on objects (functions,
    modules, classes) for the duration of one test. We use it to
    spy on `os.open` and to simulate `os.replace` failing. After
    the test ends, the original attributes are restored

`@pytest.mark.parametrize("name", [v1, v2, v3])`
    Runs the same test function once per value. So a single
    `test_x(name)` becomes 3 separate tests, each with a different
    name. Cleaner than writing 3 near-identical test functions

`fresh_vault` and `master_password` (from conftest.py)
    Fixtures we defined ourselves. Pytest sees them in the test
    function's parameters and wires them in automatically
"""

# Standard library: `dataclasses.replace` lets us copy an Entry with
# one field changed — handy for building "tampered" inputs.
import dataclasses
# Standard library: parse the on-disk vault file so we can assert
# its structure looks right (versions, key names, etc.).
import json
# Standard library: `os.stat` reads filesystem metadata — we use it
# to check the vault file's permission bits.
import os
# Standard library: symbolic names for permission bits (S_IRUSR
# etc.) — makes the perm check read like English.
import stat
# Standard library: object-oriented filesystem paths — type hint
# for the `tmp_path` fixture and our own helpers.
from pathlib import Path

# Third-party: the test runner. Used for `pytest.raises` and
# `@pytest.mark.parametrize`.
import pytest

# Local: file-mode and format-version constants. Tests assert
# against these so the values stay defined in exactly one place.
from password_manager.constants import (
    VAULT_FILE_MODE,
    VAULT_FORMAT_VERSION,
)
# Local: the one crypto error we expect when an unlock attempt
# uses the wrong master password.
from password_manager.crypto import WrongPasswordError
# Local: the full surface of the vault module — entry record,
# main class, and every error type tests need to raise or catch.
from password_manager.vault import (
    Entry,
    EntryAlreadyExistsError,
    EntryNotFoundError,
    UnlockedVault,
    VaultAlreadyExistsError,
    VaultFormatError,
    VaultNotFoundError,
)
# Local: fast KDF parameters from conftest, so Argon2 work in
# tests stays in milliseconds.
from tests.conftest import TEST_KDF_PARAMETERS


# =============================================================================
# Helpers
# =============================================================================


def _sample_entry(password: str = "s3cret") -> Entry:
    """
    Return a fully-populated Entry that tests can drop into a vault

    Centralizing this means every test that wants "an entry" gets a
    consistent shape with username, password, url, and notes set.
    Tests that care about a specific password override it by passing
    one in
    """
    return Entry(
        username = "alice",
        password = password,
        url = "https://example.com",
        notes = "primary account",
    )


def _create_test_vault(
    path: Path,
    master_password: str,
) -> UnlockedVault:
    """
    Tiny convenience wrapper that always uses TEST_KDF_PARAMETERS

    The whole point of test fixtures is to keep noise out of test
    bodies — this exists so every test that needs to call create()
    directly can do so without restating the kdf_parameters kwarg
    every time
    """
    return UnlockedVault.create(
        path,
        master_password,
        kdf_parameters = TEST_KDF_PARAMETERS,
    )


# =============================================================================
# Vault creation
# =============================================================================


def test_create_writes_file_at_path(
    vault_path: Path,
    master_password: str,
) -> None:
    """
    Verify UnlockedVault.create() puts a real file at the path we gave it

    The most basic post-condition: after `create(path, ...)` returns,
    `path` exists on disk. If a future refactor accidentally returned
    an in-memory-only vault that forgot to save, this test catches
    it before the user loses data on the next process restart
    """
    _create_test_vault(vault_path, master_password)
    assert vault_path.exists()


def test_create_refuses_to_overwrite_existing_file(
    vault_path: Path,
    master_password: str,
) -> None:
    """
    Verify create() refuses to clobber a vault that already exists

    `pv init` is a destructive-feeling operation: if it silently
    overwrote an existing vault, a user who mistyped a command could
    lose every credential they had stored. Refusing with
    VaultAlreadyExistsError forces the user to make a conscious
    choice (delete the old file first if they really mean to start
    over)
    """
    _create_test_vault(vault_path, master_password)
    with pytest.raises(VaultAlreadyExistsError):
        _create_test_vault(vault_path, master_password)


def test_create_sets_file_mode_to_0600(
    vault_path: Path,
    master_password: str,
) -> None:
    """
    Verify the vault file is created with restrictive POSIX permissions

    0600 means "the owner can read/write, nobody else can read OR
    write." Even though the contents are encrypted, broadcasting
    metadata (file size, timestamps, even that the file exists at
    all) to other local users is sloppy. Pin permissions tight at
    creation time

    `stat.S_IMODE` masks off file-type bits, leaving just the
    permission bits we care about. On Windows POSIX modes do not
    apply at all, so we skip the assertion there
    """
    _create_test_vault(vault_path, master_password)
    mode = stat.S_IMODE(os.stat(vault_path).st_mode)
    # On Windows, POSIX modes do not apply. Skip that platform's check
    if os.name != "nt":
        assert mode == VAULT_FILE_MODE


def test_create_writes_valid_envelope_json(
    vault_path: Path,
    master_password: str,
) -> None:
    """
    Verify the file create() writes is a valid JSON envelope with the expected fields

    We do not crack open the encrypted payload here — that is
    `unlock`'s job. We just confirm the OUTER envelope has the right
    shape: version field, kdf section naming argon2id, cipher
    section naming aes-256-gcm. If this drifts we lose forward
    compatibility with existing vaults
    """
    _create_test_vault(vault_path, master_password)
    envelope = json.loads(vault_path.read_text(encoding = "utf-8"))
    assert envelope["version"] == VAULT_FORMAT_VERSION
    assert envelope["kdf"]["name"] == "argon2id"
    assert envelope["cipher"]["name"] == "aes-256-gcm"


def test_create_makes_parent_directory_if_missing(
    tmp_path: Path,
    master_password: str,
) -> None:
    """
    Verify create() auto-creates intermediate directories on the way to the vault path

    Users specify vault paths like `~/.config/pv/vault.json` where
    `~/.config/pv` may not exist yet. We make the parent tree on
    their behalf (with `parents=True, exist_ok=True`) so they do not
    have to mkdir first. This test pins down that convenience
    """
    nested = tmp_path / "deep" / "nested" / "dir" / "vault.json"
    _create_test_vault(nested, master_password)
    assert nested.exists()


def test_create_rejects_empty_master_password(
    vault_path: Path,
) -> None:
    """
    Verify create() refuses an empty master password

    Empty master password = no real lock on the vault. derive_key
    refuses internally (see test_crypto.py for the underlying
    check), and create() lets that ValueError bubble up unchanged.
    We confirm here that the rejection makes it all the way out
    """
    with pytest.raises(ValueError):
        _create_test_vault(vault_path, "")


# =============================================================================
# Round-trip — create, save, unlock, read
# =============================================================================


def test_unlock_reads_back_what_was_saved(
    fresh_vault: UnlockedVault,
    master_password: str,
) -> None:
    """
    Verify the canonical save → unlock round-trip preserves entry data

    This is THE end-to-end happy-path test: add an entry, save,
    reopen with the same password, every field of the entry
    survives. If this test ever fails the password manager is
    fundamentally broken
    """
    fresh_vault.add_entry("github", _sample_entry())
    fresh_vault.save()

    reopened = UnlockedVault.unlock(fresh_vault.path, master_password)
    assert "github" in reopened.entries
    assert reopened.entries["github"].username == "alice"
    assert reopened.entries["github"].password == "s3cret"


def test_unlock_with_wrong_password_raises(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify unlock() raises WrongPasswordError when the master password is wrong

    The primary security guarantee of the whole project. We create a
    vault with one password, attempt to unlock with a different
    password, and expect a clean WrongPasswordError. NOT a garbled
    plaintext, NOT a silent empty vault, NOT a crypto-library
    InvalidTag exception leaking out — a clean named error
    """
    with pytest.raises(WrongPasswordError):
        UnlockedVault.unlock(fresh_vault.path, "not the right password")


def test_unlock_missing_file_raises(tmp_path: Path) -> None:
    """
    Verify unlock() on a nonexistent file raises VaultNotFoundError

    Distinct from "wrong password" so the CLI can show a different
    message ("no vault at this path" vs "wrong password"). This is
    the only file-related error that does NOT need to be ambiguous
    with the wrong-password case — confirming "this file does not
    exist" is safe information to give attackers
    """
    with pytest.raises(VaultNotFoundError):
        UnlockedVault.unlock(tmp_path / "nope.json", "any-password")


def test_unlock_invalid_json_raises(
    vault_path: Path,
) -> None:
    """
    Verify unlock() raises VaultFormatError when the file is not valid JSON

    Someone hand-edited the vault, or a disk error corrupted it. We
    cannot proceed but we also should not show a Python traceback —
    catch json.JSONDecodeError internally and re-raise as our own
    typed error
    """
    vault_path.write_text("this is not json")
    with pytest.raises(VaultFormatError):
        UnlockedVault.unlock(vault_path, "any-password")


def test_unlock_unsupported_version_raises(
    vault_path: Path,
) -> None:
    """
    Verify unlock() refuses a vault with an unknown format version

    Future-proofing. If a future build of pv writes vaults with
    `version: 2`, today's build needs to refuse cleanly (rather than
    try to parse a v2 file with v1 rules and fail mysteriously).
    `VaultFormatError` is the contract — the CLI can render it as
    "this vault was created by a newer version of pv"
    """
    vault_path.write_text(json.dumps({"version": 99, "kdf": {}, "cipher": {}}))
    with pytest.raises(VaultFormatError):
        UnlockedVault.unlock(vault_path, "any-password")


def test_unlock_rejects_zero_time_cost(
    vault_path: Path,
) -> None:
    """
    Verify a corrupted vault with time_cost=0 surfaces as VaultFormatError

    Without parameter validation, time_cost=0 would crash deep
    inside argon2-cffi with a confusing low-level message. Catching
    invalid KDF parameters at parse time means the user sees a clean
    "invalid vault" message and the cryptography library never gets
    handed garbage

    The base64 fields below (`AAAA...==`) are dummy placeholders —
    we never get far enough to use them because the parameter check
    fires first
    """
    vault_path.write_text(
        json.dumps(
            {
                "version": 1,
                "kdf": {
                    "name": "argon2id",
                    "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                    "time_cost": 0,
                    "memory_cost": 8,
                    "parallelism": 1,
                },
                "cipher": {
                    "name": "aes-256-gcm",
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAA",
                },
            }
        )
    )
    with pytest.raises(VaultFormatError):
        UnlockedVault.unlock(vault_path, "any-password")


def test_unlock_rejects_memory_cost_below_lane_floor(
    vault_path: Path,
) -> None:
    """
    Verify a vault that violates Argon2's "memory_cost >= 8 * parallelism" rule is rejected

    Argon2 algorithmically requires memory_cost >= 8 * parallelism.
    A vault file that violates this invariant cannot decrypt; we
    surface that as VaultFormatError BEFORE handing the parameters
    to argon2-cffi. Same reasoning as the time_cost=0 test: validate
    at the boundary so internal libraries never see bad input
    """
    vault_path.write_text(
        json.dumps(
            {
                "version": 1,
                "kdf": {
                    "name": "argon2id",
                    "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                    "time_cost": 1,
                    "memory_cost": 4,
                    "parallelism": 2,
                },
                "cipher": {
                    "name": "aes-256-gcm",
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAA",
                },
            }
        )
    )
    with pytest.raises(VaultFormatError):
        UnlockedVault.unlock(vault_path, "any-password")


# =============================================================================
# Entry — frozen + strict from_dict
# =============================================================================


def test_entry_is_immutable() -> None:
    """
    Verify Entry instances reject attribute assignment after construction

    Frozen dataclass instances raise FrozenInstanceError on any
    attempted attribute write. The whole point is to force every
    "edit" through `UnlockedVault.add_entry`, which is the ONLY
    method that knows how to update the `updated_at` timestamp
    correctly. Making the wrong move impossible at the type level
    beats writing a comment saying "do not do that"

    `# type: ignore[misc]` tells mypy "yes I know this is illegal,
    that is the point of the test"
    """
    entry = Entry(username = "alice", password = "x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.password = "y"  # type: ignore[misc]


def test_entry_from_dict_missing_password_raises() -> None:
    """
    Verify Entry.from_dict refuses a dict without a `password` field

    The required fields are username and password. If a vault on
    disk has been corrupted or hand-edited so an entry is missing
    its password, the right answer is to refuse the whole load loud
    enough that the user notices — NOT to invent an empty password
    and pretend everything is fine
    """
    with pytest.raises(VaultFormatError):
        Entry.from_dict({"username": "alice"})


def test_entry_from_dict_missing_username_raises() -> None:
    """
    Verify Entry.from_dict refuses a dict without a `username` field

    Mirror of the missing-password test. Required fields cannot be
    invented from defaults; the load must fail loudly
    """
    with pytest.raises(VaultFormatError):
        Entry.from_dict({"password": "x"})


def test_entry_from_dict_non_string_password_raises() -> None:
    """
    Verify Entry.from_dict refuses a non-string password

    JSON allows numbers, booleans, nulls, and nested objects in any
    field. If somebody hand-edited the decrypted vault to put 12345
    (an int) in the password field, we must refuse rather than try
    to use the int as a password. VaultFormatError is the contract
    """
    with pytest.raises(VaultFormatError):
        Entry.from_dict({"username": "alice", "password": 12345})


def test_entry_from_dict_uses_empty_string_for_missing_timestamps() -> None:
    """
    Verify Entry.from_dict defaults missing timestamps to "" rather than _now_iso()

    The two non-required fields, `created_at` and `updated_at`,
    default to empty strings when absent. Inventing a current
    timestamp on read would make an OLD entry look freshly created,
    which is actively misleading — better to admit "we do not know
    when this was created" with an empty string
    """
    entry = Entry.from_dict({"username": "alice", "password": "x"})
    assert entry.created_at == ""
    assert entry.updated_at == ""


# =============================================================================
# Entry operations
# =============================================================================


def test_add_entry_appears_in_names(fresh_vault: UnlockedVault) -> None:
    """
    Verify an added entry shows up in names()

    The minimum contract for `add_entry`: after calling it, the
    entry name appears in the names() list. If this ever fails, the
    add path is silently dropping data
    """
    fresh_vault.add_entry("github", _sample_entry())
    assert "github" in fresh_vault.names()


def test_names_returns_sorted(fresh_vault: UnlockedVault) -> None:
    """
    Verify names() returns entries in alphabetical order, not insertion order

    Users grep / scan a list of names; alphabetical is what they
    expect. We add entries in scrambled order (zebra, apple, mango)
    and confirm names() yields them in alphabetical order. If we
    accidentally returned insertion order, this test would catch it
    """
    fresh_vault.add_entry("zebra", _sample_entry())
    fresh_vault.add_entry("apple", _sample_entry())
    fresh_vault.add_entry("mango", _sample_entry())
    assert fresh_vault.names() == ["apple", "mango", "zebra"]


def test_add_entry_refuses_duplicate(fresh_vault: UnlockedVault) -> None:
    """
    Verify add_entry refuses a duplicate name when force is False

    Default behavior: do not let the user accidentally overwrite an
    existing entry. They must pass `force=True` explicitly to
    overwrite. EntryAlreadyExistsError is the cleanly-typed signal
    so the CLI can prompt the user with "did you mean to overwrite?"
    """
    fresh_vault.add_entry("github", _sample_entry())
    with pytest.raises(EntryAlreadyExistsError):
        fresh_vault.add_entry("github", _sample_entry())


def test_add_entry_with_force_overwrites(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify add_entry with force=True replaces an existing entry

    The intentional-overwrite path. After a force-replace, the
    entry's data should reflect the NEW values, not the old. We
    confirm the password specifically because that is the field
    users rotate most often
    """
    fresh_vault.add_entry("github", _sample_entry(password = "old"))
    fresh_vault.add_entry(
        "github",
        _sample_entry(password = "new"),
        force = True,
    )
    assert fresh_vault.get_entry("github").password == "new"


def test_overwrite_preserves_created_at(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify a force-overwrite preserves the original created_at timestamp

    When a user rotates a password, the entry's CREATION date should
    not change — only the LAST-UPDATED date. Otherwise the user
    cannot answer "how old is this credential" after a rotation.
    This invariant is a small detail but it is the kind of polish
    that distinguishes a real tool from a homework assignment
    """
    fresh_vault.add_entry("github", _sample_entry())
    original_created = fresh_vault.get_entry("github").created_at

    fresh_vault.add_entry(
        "github",
        _sample_entry(password = "rotated"),
        force = True,
    )

    assert fresh_vault.get_entry("github").created_at == original_created


def test_get_entry_missing_raises(fresh_vault: UnlockedVault) -> None:
    """
    Verify get_entry on a name that does not exist raises EntryNotFoundError

    Returning None on miss would be a quieter API — but quiet
    failures make for hard-to-debug bugs. EntryNotFoundError is
    impossible to ignore: either the caller catches it and handles
    the miss, or it propagates and the CLI shows a clean error
    """
    with pytest.raises(EntryNotFoundError):
        fresh_vault.get_entry("does-not-exist")


def test_delete_entry_removes_it(fresh_vault: UnlockedVault) -> None:
    """
    Verify delete_entry actually removes the entry from names()

    Round-trip: add, delete, confirm it is gone. If delete were
    accidentally a no-op, this test catches it before the user finds
    out the hard way
    """
    fresh_vault.add_entry("github", _sample_entry())
    fresh_vault.delete_entry("github")
    assert "github" not in fresh_vault.names()


def test_delete_entry_missing_raises(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify delete_entry on a name that does not exist raises EntryNotFoundError

    Mirror of the get_entry missing test. We do not silently succeed
    on a delete that had nothing to delete — that is the kind of
    forgiving behavior that masks real bugs in calling code
    """
    with pytest.raises(EntryNotFoundError):
        fresh_vault.delete_entry("does-not-exist")


@pytest.mark.parametrize(
    "bad_name",
    ["",
     "  ",
     "\t",
     "\n",
     " github",
     "github ",
     " github "],
)
def test_add_entry_rejects_invalid_names(
    fresh_vault: UnlockedVault,
    bad_name: str,
) -> None:
    """
    Verify add_entry rejects empty, whitespace-only, or whitespace-surrounded names

    `@pytest.mark.parametrize` runs this test ONCE PER VALUE in the
    list — so pytest reports 7 separate test results, one per bad
    name. Cleaner than seven near-identical test functions

    The trailing-whitespace case is the subtle one: without this
    check, "github" and "github " would silently become two
    different keys, which looks identical on screen and wastes
    hours of debugging time
    """
    with pytest.raises(ValueError):
        fresh_vault.add_entry(bad_name, _sample_entry())


# =============================================================================
# Master password rotation
# =============================================================================


def test_change_master_password_rotates_key_and_salt(
    fresh_vault: UnlockedVault,
    master_password: str,
) -> None:
    """
    Verify change_master_password generates a fresh salt AND a fresh key

    Rotation is not just "encrypt with a new password" — it is
    "generate a NEW salt, derive a NEW key from (new password +
    new salt), re-encrypt." Reusing the old salt would let an
    attacker who got both versions of the file run their guesses
    twice as cheaply. Fresh salt → independent key → independent
    cracking work for each
    """
    fresh_vault.add_entry("github", _sample_entry())
    original_salt = fresh_vault.salt
    original_key = fresh_vault.key

    fresh_vault.change_master_password(
        "an entirely new master pass",
        kdf_parameters = TEST_KDF_PARAMETERS,
    )
    fresh_vault.save()

    assert fresh_vault.salt != original_salt
    assert fresh_vault.key != original_key


def test_change_master_password_old_password_no_longer_unlocks(
    fresh_vault: UnlockedVault,
    master_password: str,
) -> None:
    """
    Verify the previous master password stops working after rotation

    The whole point of rotation is "if the old password leaked,
    rotating to a new one kills the leak." We confirm the old
    password is dead by attempting an unlock with it and expecting
    WrongPasswordError
    """
    fresh_vault.add_entry("github", _sample_entry())
    fresh_vault.change_master_password(
        "the new one",
        kdf_parameters = TEST_KDF_PARAMETERS,
    )
    fresh_vault.save()

    with pytest.raises(WrongPasswordError):
        UnlockedVault.unlock(fresh_vault.path, master_password)


def test_change_master_password_new_password_unlocks_with_entries_intact(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify the new master password unlocks the vault AND all entries are preserved

    The other half of the rotation contract: the user keeps their
    data. Reopen with the new password, every entry that was there
    before is still there with the same password field
    """
    fresh_vault.add_entry("github", _sample_entry())
    fresh_vault.change_master_password(
        "the new one",
        kdf_parameters = TEST_KDF_PARAMETERS,
    )
    fresh_vault.save()

    reopened = UnlockedVault.unlock(fresh_vault.path, "the new one")
    assert reopened.entries["github"].password == "s3cret"


def test_change_master_password_rejects_empty(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify change_master_password refuses an empty new password

    The same "empty password = no real lock" rule that applies to
    creation also applies to rotation. We refuse before generating
    a salt — both because there is no reason to generate one we
    will throw away, and because raising sooner gives a cleaner
    error
    """
    with pytest.raises(ValueError):
        fresh_vault.change_master_password("")


# =============================================================================
# Lifecycle — context manager + close()
# =============================================================================


def test_close_zeroes_key_and_drops_entries(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify close() wipes the in-memory secrets

    After `close()`, the AES key field becomes 32 zero bytes and
    the entries dict becomes empty. This is best-effort — Python's
    bytes are immutable so the ORIGINAL key bytes may still live in
    memory until GC runs — but the discipline of "explicitly drop
    secrets when done" matters. A test that pins the post-close
    state guards against accidental refactoring that skips the wipe
    """
    fresh_vault.add_entry("github", _sample_entry())
    fresh_vault.close()
    assert fresh_vault.entries == {}
    assert fresh_vault.key == bytes(32)


def test_unlocked_vault_works_as_context_manager(
    vault_path: Path,
    master_password: str,
) -> None:
    """
    Verify `with UnlockedVault.create(...) as vault:` triggers close() on exit

    The recommended call site pattern is the with-block, because it
    guarantees secrets get dropped even if the caller forgets to
    call close(). We confirm here that exiting the `with` block
    actually triggers the close behavior (empty entries, zeroed key)
    """
    with _create_test_vault(vault_path, master_password) as vault:
        vault.add_entry("github", _sample_entry())
        assert vault.entries["github"].username == "alice"
    # On block exit, sensitive material is dropped
    assert vault.entries == {}
    assert vault.key == bytes(32)


def test_context_manager_cleans_up_on_exception(
    vault_path: Path,
    master_password: str,
) -> None:
    """
    Verify the context manager wipes secrets even when the body raises

    The HAPPY path is easy — close() runs at normal end-of-block.
    The interesting case is the EXCEPTION path: if user code inside
    the `with` block raises, does Python still invoke __exit__? Yes
    it does, and we confirm here that __exit__ drops secrets all
    the same. Without this guarantee, an unexpected error in user
    code could leave plaintext credentials sitting in memory
    """
    with (
            pytest.raises(RuntimeError),
            _create_test_vault(vault_path,
                               master_password) as vault,
    ):
        vault.add_entry("github", _sample_entry())
        raise RuntimeError("boom")
    assert vault.entries == {}
    assert vault.key == bytes(32)


# =============================================================================
# Atomicity / persistence
# =============================================================================


def test_save_uses_fresh_nonce_each_time(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify two consecutive saves produce different ciphertext (because the nonce is fresh)

    The save path internally regenerates a nonce on every call.
    Save once → record the nonce + ciphertext. Save again with NO
    entry change → record again. Both fields must differ. If they
    did not, we would either be reusing a nonce (security bug) or
    using a counter (different security bug)
    """
    fresh_vault.save()
    cipher_a = json.loads(fresh_vault.path.read_text())["cipher"]
    fresh_vault.save()
    cipher_b = json.loads(fresh_vault.path.read_text())["cipher"]

    assert cipher_a["nonce"] != cipher_b["nonce"]
    assert cipher_a["ciphertext"] != cipher_b["ciphertext"]


def test_save_does_not_leave_temp_file(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify the .tmp file used during save is gone after save() returns

    The save flow writes vault.json.tmp first, then renames it onto
    vault.json. After the rename, the .tmp name no longer exists —
    the same inode is now reachable under the final name. We
    confirm by stat-ing the .tmp path after a successful save and
    expecting "does not exist." If anyone refactored save() to copy
    instead of rename, the leftover .tmp would fail this test
    """
    fresh_vault.save()
    tmp = fresh_vault.path.with_suffix(fresh_vault.path.suffix + ".tmp")
    assert not tmp.exists()


def test_save_creates_temp_file_with_secure_mode_only(
    fresh_vault: UnlockedVault,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Verify the .tmp file is created with mode 0600 from the very first syscall

    Plain `Path.write_bytes` would create the file with the
    process's default umask (often 0644 = world-readable). Even if
    we chmod 0600 afterward, there is a microsecond window where
    the .tmp is world-readable, and on a shared system that is
    enough for an attacker to grab a copy

    The fix in vault.py is to use raw `os.open(..., O_CREAT, 0o600)`
    so the file's mode is correct from the first syscall. To VERIFY
    that behavior in a test we use `monkeypatch.setattr` to swap in
    a spy version of `os.open` that records the mode argument used
    for any .tmp file. After save() runs, we assert every recorded
    mode is exactly VAULT_FILE_MODE (0o600)

    `monkeypatch` is a built-in pytest fixture that undoes its
    patches automatically when the test ends — no manual cleanup
    """
    if os.name == "nt":
        pytest.skip("POSIX-only check — Windows ignores Unix file modes")

    captured_modes: list[int] = []
    real_open = os.open

    def spy_open(  # type: ignore[no-untyped-def]
        path,
        flags,
        mode = 0o777,
        *,
        dir_fd = None,
    ):
        # Record the mode used for .tmp files, then defer to the real
        # os.open so the actual write still happens normally
        if str(path).endswith(".tmp"):
            captured_modes.append(mode)
        return real_open(path, flags, mode, dir_fd = dir_fd)

    monkeypatch.setattr(os, "open", spy_open)
    fresh_vault.save()

    assert captured_modes, "no .tmp file was opened during save()"
    assert all(m == VAULT_FILE_MODE for m in captured_modes)


def test_save_cleans_up_temp_file_on_replace_failure(
    fresh_vault: UnlockedVault,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Verify save() removes the .tmp file when os.replace fails partway through

    Simulated failure mode: we monkey-patch `os.replace` to raise
    OSError. The save flow is "write .tmp, replace .tmp onto
    vault.json." If the replace step blows up, the .tmp is still
    sitting there — left behind it would clutter the directory and
    confuse the NEXT save (which would then try to write to a
    .tmp that already exists). The cleanup in save()'s except
    branch is what we are verifying here

    We save once cleanly first so vault.json itself exists, then
    install the broken replace, then save() again and confirm
    the .tmp does not survive the failed save
    """
    def explode(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated replace failure")

    # Save once cleanly so the vault file exists
    fresh_vault.save()

    monkeypatch.setattr(os, "replace", explode)
    with pytest.raises(OSError, match = "simulated replace failure"):
        fresh_vault.save()

    tmp = fresh_vault.path.with_suffix(fresh_vault.path.suffix + ".tmp")
    assert not tmp.exists()
