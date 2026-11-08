"""
©AngelaMos | 2026
vault.py

The vault — how we store entries on disk safely

This file is the bridge between two worlds. On one side is the
user's data: a dictionary of entries like {"github": <username,
password, url, ...>}. On the other side is a single file on disk
that needs to be encrypted, tamper-evident, and survive crashes
without corruption

────────────────────────────────────────────────────────────────────
The on-disk format
────────────────────────────────────────────────────────────────────
We store the vault as a JSON file. Plain JSON is human-inspectable
and trivially portable. Inside, the structure looks like this

  {
    "version": 1,
    "kdf": {
      "name": "argon2id",
      "salt": "<base64 random bytes>",
      "time_cost": 3,
      "memory_cost": 65536,
      "parallelism": 4
    },
    "cipher": {
      "name": "aes-256-gcm",
      "nonce": "<base64 random bytes>",
      "ciphertext": "<base64 encrypted blob>"
    }
  }

The cleartext (un-encrypted) plaintext that gets fed to AES looks
like another JSON document — a dictionary of entries

  {
    "github": {
      "username": "alice",
      "password": "...",
      "url": "https://github.com",
      "notes": "",
      "created_at": "2026-05-10T12:34:56",
      "updated_at": "2026-05-10T12:34:56"
    },
    "...": {...}
  }

So the file is "JSON envelope wrapping encrypted JSON." Nice and
boring. Boring is good in security — fewer custom things to
get wrong

────────────────────────────────────────────────────────────────────
Atomic + durable writes — never corrupt or lose a vault on a crash
────────────────────────────────────────────────────────────────────
If we wrote directly to vault.json and the process died halfway
through, the file would be half-old, half-new — corrupt. We use the
"write to temp file, fsync, then rename" pattern

  1. open vault.json.tmp with mode 0600 (never world-readable)
  2. write the encrypted bytes
  3. fsync the file's bytes to disk (otherwise they live only in the
     kernel page cache, which a power loss erases)
  4. os.replace vault.json.tmp onto vault.json (atomic rename)
  5. fsync the parent directory (otherwise the rename itself can
     evaporate on power loss, leaving us with stale content)

At any instant after step 4, readers see either the OLD complete
file or the NEW complete file — never half of either

────────────────────────────────────────────────────────────────────
File locking — never let two `pv` processes overwrite each other
────────────────────────────────────────────────────────────────────
Two `pv add` invocations against the same vault could otherwise
race: each unlocks, each adds a different entry, each saves. Whoever
saves second wipes the first one's entry. We hold an advisory
fcntl lock on a sidecar `.lock` file during the encrypt-and-write
window, so the second process blocks until the first finishes

On Windows fcntl is unavailable; we skip the lock there. NTFS still
gives us atomic os.replace, we just lose cross-process serialization

────────────────────────────────────────────────────────────────────
What this file exposes
────────────────────────────────────────────────────────────────────
  Entry              — one credential row (username, password, etc.)
  UnlockedVault      — an opened, in-memory vault (holds the key)
  VaultError + subclasses — errors callers can catch by type

UnlockedVault is a context manager: use `with vault.unlock(...) as v:`
so the AES key and plaintext entries are dropped at block exit

Connects to
  crypto.py — calls derive_key, encrypt, decrypt
  constants.py — file format keys, default paths, file mode
  main.py — the CLI uses UnlockedVault.create / .unlock / .save
"""

# Future-import: makes all type hints in this file evaluate as
# strings, so forward references like `-> UnlockedVault` work
# without needing quotes.
from __future__ import annotations

# Standard library: encode raw bytes (ciphertexts, salts, nonces)
# as ASCII text so we can store them in a JSON file.
import base64
# Standard library: `contextlib.suppress` lets us swallow a specific
# exception in one line — used here when deleting temp files.
import contextlib
# Standard library: serialize/deserialize the vault to and from
# JSON — the on-disk format is plain JSON wrapping base64 blobs.
import json
# Standard library: low-level filesystem operations — we call
# `os.replace` for atomic saves and `os.chmod` to lock down perms.
import os
# Standard library: type hint for "any iterable that yields items
# one at a time" — used in the entries() generator method.
from collections.abc import Iterator
# Standard library: dataclass helpers — turn classes into data
# records, convert them to dicts, and copy them immutably.
from dataclasses import asdict, dataclass, field, replace
# Standard library: timestamps. We store created/updated times in
# UTC to dodge timezone bugs across machines.
from datetime import datetime, UTC
# Standard library: object-oriented filesystem paths — safer than
# gluing strings with `os.path.join`.
from pathlib import Path
# Standard library: the traceback type — needed only as a type hint
# for the `__exit__` method that powers `with UnlockedVault(...)`.
from types import TracebackType
# Standard library: `Any` for opaque JSON shapes, `Self` so methods
# can declare a return type of "instance of this same class".
from typing import Any, Self

# Local: every JSON key name, magic string, file mode, and Argon2
# minimum lives in constants — vault.py never holds them inline.
from password_manager.constants import (
    ARGON2_MEMORY_KIB_PER_LANE_MIN,
    ARGON2_PARALLELISM_MIN,
    ARGON2_TIME_COST_MIN,
    CIPHER_KEY_CIPHERTEXT,
    CIPHER_KEY_NAME,
    CIPHER_KEY_NONCE,
    CIPHER_NAME_AES_256_GCM,
    KDF_KEY_MEMORY_COST,
    KDF_KEY_NAME,
    KDF_KEY_PARALLELISM,
    KDF_KEY_SALT,
    KDF_KEY_TIME_COST,
    KDF_NAME_ARGON2ID,
    KEY_LENGTH_BYTES,
    VAULT_FILE_MODE,
    VAULT_FORMAT_VERSION,
    VAULT_KEY_CIPHER,
    VAULT_KEY_KDF,
    VAULT_KEY_VERSION,
)
# Local: the crypto primitives we drive — key derivation, the
# authenticated encrypt/decrypt pair, and salt generation. vault.py
# only ever calls these helpers; the raw crypto stays in crypto.py.
from password_manager.crypto import (
    KdfParameters,
    decrypt,
    derive_key,
    encrypt,
    generate_salt,
)

# fcntl is POSIX-only. On Windows we fall back to no advisory lock
# during save — NTFS still gives us atomic os.replace, we just lose
# the protection against two pv processes racing on the same vault.
# Importing inside a try/except lets the module load cleanly on
# both platforms; the runtime check happens inside save()
try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover — exercised only on Windows
    _fcntl = None  # type: ignore[assignment]


# =============================================================================
# Custom exceptions
# =============================================================================
# Defining specific error types lets the CLI handle each case with the
# right message. `pass` is the keyword for "this class has no body" —
# we inherit everything we need from the parent


class VaultError(Exception):
    """
    Base class for every vault-related error
    """


class VaultNotFoundError(VaultError):
    """
    Raised when the vault file does not exist on disk
    """


class VaultAlreadyExistsError(VaultError):
    """
    Raised when init is called on a path that already has a vault
    """


class VaultFormatError(VaultError):
    """
    Raised when the vault file is unreadable or has unexpected fields
    """


class EntryNotFoundError(VaultError):
    """
    Raised when looking up an entry by name that does not exist
    """


class EntryAlreadyExistsError(VaultError):
    """
    Raised when adding an entry name that already exists
    """


# =============================================================================
# Helpers — base64 encoding for binary data inside JSON
# =============================================================================
# JSON has no native way to represent raw bytes. The standard fix is
# base64: a way to write any binary data as a string of printable
# ASCII characters. It expands the data by ~33% but lets us round-trip
# bytes through JSON cleanly


def _b64encode(data: bytes) -> str:
    """
    Encode raw bytes to a base64 ASCII string suitable for JSON
    """
    # base64.b64encode returns bytes (e.g. b"YWJj"); decode to str for JSON
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str) -> bytes:
    """
    Decode a base64 ASCII string back to raw bytes

    Raises VaultFormatError if `text` is not valid base64
    """
    try:
        return base64.b64decode(text, validate = True)
    except (ValueError, TypeError) as exc:
        raise VaultFormatError(f"Invalid base64 in vault: {exc}") from exc


def _now_iso() -> str:
    """
    Return the current UTC time as an ISO 8601 string

    UTC (instead of local time) means timestamps are unambiguous
    even if the user moves between time zones
    """
    return datetime.now(UTC).isoformat(timespec = "seconds")


def _validate_entry_name(name: str) -> None:
    """
    Reject entry names that would cause subtle bugs

    Three failure modes
      1. Empty string — produces an entry with no name, almost
         impossible to delete from the CLI later
      2. Whitespace-only — same problem with extra confusion
      3. Leading or trailing whitespace — "github" and "github "
         would silently become two different keys, which is the
         kind of bug that wastes hours

    Raises ValueError on any of the above
    """
    if not name or not name.strip():
        raise ValueError("Entry name cannot be empty or whitespace")
    if name != name.strip():
        raise ValueError("Entry name must not have leading or trailing whitespace")


@contextlib.contextmanager
def _file_lock(target_path: Path) -> Iterator[None]:
    """
    Acquire an advisory exclusive lock on a sidecar `.lock` file

    We use a sidecar file (vault.json.lock) instead of locking the
    vault file itself, because some tools care about the vault file's
    fd state (atomic-rename, fsync) and we would have to juggle the
    lock around them. A sidecar is simpler and the lock semantics
    are identical

    Advisory means processes have to opt in by also calling flock —
    a process that ignores the lock can still write the file. Every
    write inside this codebase goes through save(), which DOES opt
    in, so two `pv` instances cannot race against each other. An
    external editor (vim, sed) does not, but that is the user
    knowingly stepping outside the tool's contract

    On Windows fcntl is unavailable; the lock is a no-op there.
    NTFS still gives us atomic os.replace, we just lose the cross-
    process serialization

    Yields control to the caller while the lock is held; releases
    on context-manager exit (normal or exception)
    """
    if _fcntl is None:  # pragma: no cover — Windows path
        yield
        return

    lock_path = target_path.with_suffix(target_path.suffix + ".lock")
    # The lock file's CONTENTS do not matter — fcntl tracks the lock
    # by inode. We open in append mode so we never truncate, and so
    # the file exists even if a previous process crashed mid-write
    target_path.parent.mkdir(parents = True, exist_ok = True)
    fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT,
        VAULT_FILE_MODE,
    )
    try:
        # LOCK_EX = exclusive lock; blocks until acquired. For a
        # single-user CLI tool, blocking is fine — the user is going
        # to wait a fraction of a second behind another `pv` invocation
        _fcntl.flock(fd, _fcntl.LOCK_EX)
        try:
            yield
        finally:
            _fcntl.flock(fd, _fcntl.LOCK_UN)
    finally:
        os.close(fd)


# =============================================================================
# Entry — one credential row
# =============================================================================


@dataclass(slots = True, frozen = True)
class Entry:
    """
    A single credential record

    Beginners often build this kind of thing as a plain dictionary
    But a dataclass gives us name-checked attribute access (entry.username
    instead of entry["username"]) and free __init__ / __repr__ /
    __eq__ methods. It is the same data, just safer to handle

    `frozen=True` makes Entry instances immutable — once built, you
    cannot do `entry.password = "x"`. That feels strict but it is the
    point: every "edit" of an entry must go through UnlockedVault's
    add_entry, which is the ONLY method that knows how to bump
    updated_at correctly. Making the wrong move impossible at the
    type level beats writing a comment that says "do not do that"

    Fields
    ------
    username
        The login name. May be empty for entries that only have a key
    password
        The plaintext credential. ONLY exists in memory while the
        vault is unlocked — it is encrypted at rest
    url
        Optional URL the credential goes with
    notes
        Optional free-text notes
    created_at
        ISO 8601 timestamp of when the entry was first added.
        Empty string if the original vault file did not record it
    updated_at
        ISO 8601 timestamp of the last modification.
        Empty string if the original vault file did not record it
    """
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: str = field(default_factory = _now_iso)
    updated_at: str = field(default_factory = _now_iso)

    def to_dict(self) -> dict[str, str]:
        """
        Convert to a plain dict for JSON serialization
        """
        # asdict() walks the dataclass and produces a dict
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entry:
        """
        Reconstruct an Entry from a JSON-loaded dict

        Required fields (username, password) MUST be present — if the
        vault on disk has been corrupted or hand-edited so that an
        entry is missing its password, the right answer is to refuse
        the whole load with VaultFormatError, not to silently invent
        an empty password and pretend everything is fine

        Optional fields (url, notes) default to empty strings.
        Timestamps default to empty strings (NOT to "now") — inventing
        a current timestamp on read would make an old entry look
        freshly created, which is misleading
        """
        try:
            username = data["username"]
            password = data["password"]
        except KeyError as exc:
            raise VaultFormatError(f"Entry missing required field: {exc}") from exc
        if not isinstance(username, str) or not isinstance(password, str):
            raise VaultFormatError("Entry username and password must be strings")
        return cls(
            username = username,
            password = password,
            url = data.get("url",
                           ""),
            notes = data.get("notes",
                             ""),
            created_at = data.get("created_at",
                                  ""),
            updated_at = data.get("updated_at",
                                  ""),
        )


# =============================================================================
# UnlockedVault — the open, in-memory representation
# =============================================================================
# An UnlockedVault holds the entries AND the cryptographic context
# (key, salt, kdf params) needed to write changes back to disk
#
# Lifecycle
#   1. UnlockedVault.create(path, password) — make a NEW empty vault
#   2. UnlockedVault.unlock(path, password) — open an EXISTING vault
#   3. vault.add_entry(...) / get_entry / delete_entry / names()
#   4. vault.save() — encrypt + atomic write back to disk


@dataclass(slots = True)
class UnlockedVault:
    """
    An opened vault, ready to read and modify

    The `key` field holds the 32-byte AES key derived from the master
    password. Holding it (instead of re-deriving every save) avoids
    paying the slow Argon2 cost on every write. The trade-off is that
    the key sits in process memory for the duration of the session —
    same as the entries themselves, which contain plaintext passwords

    Fields
    ------
    path
        Where this vault lives on disk
    salt
        The vault's salt (16 random bytes). Created once at init time
        and never changes for the life of the vault
    kdf_parameters
        Which Argon2 settings were used to derive the key. Stored in
        the file so old vaults still open after defaults change
    key
        The 32-byte AES key. Treat as sensitive
    entries
        The user's credential rows, keyed by entry name
    """
    path: Path
    salt: bytes
    kdf_parameters: KdfParameters
    key: bytes
    entries: dict[str, Entry]

    # -------------------------------------------------------------------------
    # Constructors
    # -------------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Path,
        master_password: str,
        *,
        kdf_parameters: KdfParameters | None = None,
    ) -> Self:
        """
        Create a brand-new empty vault at `path` and write it to disk

        Generates a fresh salt, derives the key, and saves an empty
        entries dict so the file exists immediately. Refuses to
        overwrite an existing vault — the caller must delete the old
        file first if they really mean to start over

        The `kdf_parameters` argument exists for two reasons. In
        production, callers leave it None and we use the recommended
        defaults from KdfParameters.defaults(). In tests, callers
        pass weaker parameters so that Argon2 derivation finishes in
        milliseconds instead of seconds. Threading the value through
        the constructor keeps test code from having to reach in and
        monkeypatch defaults() at runtime

        Parameters
        ----------
        path
            Where to write the new vault file
        master_password
            The user's master password. Must not be empty
        kdf_parameters
            Argon2 tuning knobs. None means "use the production
            defaults"

        Raises
        ------
        VaultAlreadyExistsError
            If a file already exists at `path`
        ValueError
            If `master_password` is the empty string
        """
        if path.exists():
            raise VaultAlreadyExistsError(f"Vault already exists at {path}")

        salt = generate_salt()
        kdf_parameters = kdf_parameters or KdfParameters.defaults()
        # derive_key itself rejects empty passwords. We let that
        # exception bubble up — this is a programming-error floor,
        # not a UX policy (UX policy lives in main.py)
        key = derive_key(master_password, salt, kdf_parameters)

        # Build the in-memory vault, then immediately save so the file
        # exists. Empty entries dict to start
        vault = cls(
            path = path,
            salt = salt,
            kdf_parameters = kdf_parameters,
            key = key,
            entries = {},
        )
        vault.save()
        return vault

    @classmethod
    def unlock(
        cls,
        path: Path,
        master_password: str,
    ) -> Self:
        """
        Open an existing vault at `path` using the master password

        Reads the file, parses the envelope, derives the key from the
        password and the stored salt, then decrypts the ciphertext
        and parses the resulting JSON into Entry objects

        Raises
        ------
        VaultNotFoundError
            If no file exists at `path`
        VaultFormatError
            If the file exists but is not a valid vault
        WrongPasswordError
            If the master password is wrong (or the file is tampered)
        """
        if not path.exists():
            raise VaultNotFoundError(f"No vault at {path}")

        # Read the JSON envelope. utf-8 is the right default for any
        # text-based format on disk
        try:
            envelope = json.loads(path.read_text(encoding = "utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VaultFormatError(
                f"Vault file at {path} is not valid JSON: {exc}"
            ) from exc

        salt, kdf_parameters, nonce, ciphertext = _parse_envelope(envelope)

        # Derive the key using the salt and parameters that were
        # ACTUALLY used at encryption time — not today's defaults.
        # This is the magic that lets old vaults keep working
        key = derive_key(master_password, salt, kdf_parameters)

        # decrypt() raises WrongPasswordError on tag mismatch, which
        # we let bubble up to the caller
        plaintext_bytes = decrypt(ciphertext, nonce, key)

        # The plaintext is a JSON-encoded entries dict. Parse it back
        try:
            entries_data = json.loads(plaintext_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            # If the JSON is invalid AFTER successful decryption, the
            # ciphertext was tampered in a way GCM did not catch (very
            # unlikely) or — more likely — the file was corrupted
            # before encryption somehow. Either way, treat as format
            raise VaultFormatError(
                f"Decrypted plaintext is not valid JSON: {exc}"
            ) from exc

        # Convert each row from raw dict to Entry dataclass instance
        entries = {name: Entry.from_dict(row) for name, row in entries_data.items()}

        return cls(
            path = path,
            salt = salt,
            kdf_parameters = kdf_parameters,
            key = key,
            entries = entries,
        )

    # -------------------------------------------------------------------------
    # Persistence
    # -------------------------------------------------------------------------

    def save(self) -> None:
        """
        Encrypt entries and write the vault to disk atomically and
        durably

        Every save uses a FRESH nonce — never reuse a nonce with the
        same key in GCM mode. The nonce is generated inside encrypt()
        so we do not have to think about it here

        The write is "atomic + durable + concurrent-safe":

          1. Atomic — we write to vault.json.tmp first, then
             os.replace it onto vault.json. At any instant the file
             on disk is either the OLD complete file or the NEW
             complete file. Never half of either
          2. Durable — we fsync the data before the rename and
             fsync the parent directory after, so a power loss cannot
             leave us with a 0-byte file or a stale-content-with-new-mtime
             outcome. Without these fsyncs, "atomic" is a story the
             page cache tells us, not a guarantee on disk
          3. Concurrent-safe — we hold an advisory file lock on a
             sidecar .lock file for the whole encrypt-and-write
             window, so two `pv add` processes cannot race and have
             one's save silently overwrite the other's
          4. Secure-by-creation — we open the tmp file with mode 0600
             from the very first syscall, so it is never briefly
             visible to other users with broader permissions
        """
        # Serialize entries to JSON bytes (the plaintext we will encrypt).
        # sort_keys=True makes the output deterministic, which is nice
        # when diffing or debugging encrypted files
        entries_json = json.dumps(
            {
                name: entry.to_dict()
                for name, entry in self.entries.items()
            },
            sort_keys = True,
            indent = 2,
        ).encode("utf-8")

        nonce, ciphertext = encrypt(entries_json, self.key)

        envelope = _build_envelope(
            salt = self.salt,
            kdf_parameters = self.kdf_parameters,
            nonce = nonce,
            ciphertext = ciphertext,
        )
        envelope_bytes = json.dumps(envelope, indent = 2).encode("utf-8")

        # Make sure the parent directory exists. parents=True creates
        # intermediate directories. exist_ok=True means "no error if
        # already there"
        self.path.parent.mkdir(parents = True, exist_ok = True)

        # Hold the advisory lock for the entire write — protects two
        # pv processes from racing on the same vault. _file_lock is a
        # context manager that no-ops cleanly on Windows
        with _file_lock(self.path):
            self._atomic_write(envelope_bytes)

    def _atomic_write(self, envelope_bytes: bytes) -> None:
        """
        Write `envelope_bytes` to self.path atomically and durably

        Internal helper — not part of the public API. Lives outside
        save() so the locking layer above stays readable
        """
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")

        # Open with mode 0600 from the very first syscall. Using
        # os.open + os.write (instead of Path.write_bytes) lets us
        # specify the mode atomically; write_bytes would create the
        # file with the process umask (often 0644) and require a
        # separate chmod call, opening a brief race window where the
        # tmp file is world-readable
        fd = os.open(
            tmp_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            VAULT_FILE_MODE,
        )
        try:
            try:
                os.write(fd, envelope_bytes)
                # fsync flushes the file's bytes from the kernel page
                # cache to the underlying disk. Without this the bytes
                # are "written" only in the sense that read() can see
                # them — a power loss at this moment loses everything
                os.fsync(fd)
            finally:
                os.close(fd)

            # Atomic rename. After this call, readers see the new file
            os.replace(tmp_path, self.path)
        except BaseException:
            # If anything blew up between create and rename, clean up
            # the leftover tmp file so we do not litter the directory
            # with junk that confuses the next save
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_path)
            raise

        # fsync the parent directory so the rename itself is durable.
        # POSIX requires this for the rename to survive power loss.
        # Windows does not have directory fsync; NTFS gives us atomic
        # replace without it, so we skip the call there
        if os.name != "nt":
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    # -------------------------------------------------------------------------
    # Entry operations — small, focused methods
    # -------------------------------------------------------------------------

    def names(self) -> list[str]:
        """
        Return entry names in alphabetical order
        """
        return sorted(self.entries.keys())

    def get_entry(self, name: str) -> Entry:
        """
        Return the entry with the given name

        Raises EntryNotFoundError if there is no such entry
        """
        try:
            return self.entries[name]
        except KeyError as exc:
            raise EntryNotFoundError(f"No entry named: {name}") from exc

    def add_entry(
        self,
        name: str,
        entry: Entry,
        *,
        force: bool = False,
    ) -> None:
        """
        Add or replace an entry

        By default refuses to overwrite an existing entry — pass
        force=True to replace. The * in the signature forces `force`
        to be a keyword argument: callers must write `force=True` not
        just `True`. That makes call sites self-documenting

        Entry names are validated: empty strings, whitespace-only
        strings, and names with leading or trailing whitespace are
        rejected. The trailing-whitespace check is the subtle one —
        without it, "github" and "github " would be two different
        entries that look identical on screen, which is a bug factory

        Raises
        ------
        ValueError
            If `name` is empty, whitespace-only, or has surrounding
            whitespace
        EntryAlreadyExistsError
            If `name` already exists and force is False
        """
        _validate_entry_name(name)
        if name in self.entries and not force:
            raise EntryAlreadyExistsError(f"Entry already exists: {name}")
        # When overwriting, preserve the original creation time and
        # bump the updated_at timestamp
        if name in self.entries:
            old = self.entries[name]
            entry = replace(
                entry,
                created_at = old.created_at,
                updated_at = _now_iso(),
            )
        self.entries[name] = entry

    def delete_entry(self, name: str) -> Entry:
        """
        Remove and return the entry with the given name

        Returns the deleted entry so the caller can echo its details
        for confirmation

        Raises EntryNotFoundError if there is no such entry
        """
        try:
            return self.entries.pop(name)
        except KeyError as exc:
            raise EntryNotFoundError(f"No entry named: {name}") from exc

    # -------------------------------------------------------------------------
    # Master password rotation
    # -------------------------------------------------------------------------

    def change_master_password(
        self,
        new_master_password: str,
        *,
        kdf_parameters: KdfParameters | None = None,
    ) -> None:
        """
        Rotate the master password by deriving a new key with a new salt

        Generates a fresh salt, derives a new key from `new_master_password`,
        and replaces our salt + key + kdf_parameters. The next save()
        will re-encrypt every entry under the new key. This is also
        the natural place to upgrade KDF parameters if the project's
        recommended defaults have moved since the vault was created

        The whole reason the on-disk format stores the KDF parameters
        and salt next to the ciphertext (instead of just hard-coding
        them in this codebase) is exactly this method — without it,
        rotation would not be possible at all

        Note: this method only mutates in-memory state. Call save()
        afterward to persist the new ciphertext

        Parameters
        ----------
        new_master_password
            The replacement password. Must not be empty
        kdf_parameters
            Argon2 tuning. None means "use the current production
            defaults" — useful for upgrading parameters at the same
            time as rotating the password
        """
        # derive_key handles the empty-password rejection itself, but
        # checking here too gives a clearer error (and avoids the cost
        # of generating a salt that we then throw away)
        if not new_master_password:
            raise ValueError("new_master_password must not be empty")

        new_salt = generate_salt()
        new_kdf_parameters = (kdf_parameters or KdfParameters.defaults())
        new_key = derive_key(
            new_master_password,
            new_salt,
            new_kdf_parameters,
        )

        self.salt = new_salt
        self.kdf_parameters = new_kdf_parameters
        self.key = new_key

    # -------------------------------------------------------------------------
    # Lifecycle — context-manager support
    # -------------------------------------------------------------------------
    # An UnlockedVault holds a 32-byte AES key plus the plaintext of
    # every credential. We want a clear "I am done with this vault"
    # signal so the secret material does not sit in memory longer
    # than it has to. Python's immutable bytes mean we cannot truly
    # zero the original key bytes (the GC may keep copies), but we
    # can rebind self.key to an all-zeros bytes object and clear the
    # entries dict. That narrows the window without overclaiming
    #
    # Using `with UnlockedVault.unlock(...) as vault:` is the
    # recommended pattern at every call site

    def close(self) -> None:
        """
        Drop sensitive material from this vault instance

        Best-effort cleanup. After calling close():
          - self.entries is replaced by an empty dict
          - self.key is replaced by KEY_LENGTH_BYTES of zero bytes

        Python bytes are immutable, so the ORIGINAL key bytes may
        still live in memory until garbage collection runs. This is
        a fundamental Python limitation — true wipe-on-free requires
        bytearray + ctypes tricks that this teaching project
        deliberately avoids. The discipline of "explicitly drop
        secrets when done" is what matters
        """
        self.entries = {}
        self.key = bytes(KEY_LENGTH_BYTES)

    def __enter__(self) -> Self:
        """
        Allow `with UnlockedVault.unlock(...) as vault:` syntax
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """
        On block exit (normal or exception), drop sensitive material
        """
        self.close()


# =============================================================================
# Envelope build / parse — internal helpers
# =============================================================================
# These are module-private (the leading underscore is a convention
# meaning "do not import me from outside this module")


def _build_envelope(
    salt: bytes,
    kdf_parameters: KdfParameters,
    nonce: bytes,
    ciphertext: bytes,
) -> dict[str,
          Any]:
    """
    Build the JSON envelope dict that will be written to disk
    """
    return {
        VAULT_KEY_VERSION: VAULT_FORMAT_VERSION,
        VAULT_KEY_KDF: {
            KDF_KEY_NAME: KDF_NAME_ARGON2ID,
            KDF_KEY_SALT: _b64encode(salt),
            KDF_KEY_TIME_COST: kdf_parameters.time_cost,
            KDF_KEY_MEMORY_COST: kdf_parameters.memory_cost,
            KDF_KEY_PARALLELISM: kdf_parameters.parallelism,
        },
        VAULT_KEY_CIPHER: {
            CIPHER_KEY_NAME: CIPHER_NAME_AES_256_GCM,
            CIPHER_KEY_NONCE: _b64encode(nonce),
            CIPHER_KEY_CIPHERTEXT: _b64encode(ciphertext),
        },
    }


def _parse_envelope(
    envelope: dict[str,
                   Any],
) -> tuple[bytes,
           KdfParameters,
           bytes,
           bytes]:
    """
    Pull the fields we need out of the JSON envelope

    Validates the version and algorithm names. Returns
    (salt, kdf_parameters, nonce, ciphertext)

    Raises VaultFormatError if anything is missing or wrong
    """
    # Top-level required keys
    if not isinstance(envelope, dict):
        raise VaultFormatError("Vault envelope is not a JSON object")

    version = envelope.get(VAULT_KEY_VERSION)
    if version != VAULT_FORMAT_VERSION:
        raise VaultFormatError(
            f"Unsupported vault version: {version} "
            f"(this build supports version {VAULT_FORMAT_VERSION})"
        )

    kdf = envelope.get(VAULT_KEY_KDF)
    cipher = envelope.get(VAULT_KEY_CIPHER)
    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise VaultFormatError("Vault envelope missing kdf or cipher section")

    # KDF section
    if kdf.get(KDF_KEY_NAME) != KDF_NAME_ARGON2ID:
        raise VaultFormatError(f"Unsupported KDF: {kdf.get(KDF_KEY_NAME)}")
    try:
        salt = _b64decode(kdf[KDF_KEY_SALT])
        kdf_parameters = KdfParameters(
            time_cost = int(kdf[KDF_KEY_TIME_COST]),
            memory_cost = int(kdf[KDF_KEY_MEMORY_COST]),
            parallelism = int(kdf[KDF_KEY_PARALLELISM]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultFormatError(f"Invalid KDF section: {exc}") from exc

    # Validate the parsed KDF parameters against Argon2's algorithmic
    # minimums. A vault file that has been corrupted or hand-edited
    # so it contains, say, time_cost=0 would otherwise crash deep
    # inside argon2-cffi with a confusing message. We catch it here
    # and surface a clean VaultFormatError instead
    if kdf_parameters.time_cost < ARGON2_TIME_COST_MIN:
        raise VaultFormatError(
            f"Invalid Argon2 time_cost: "
            f"{kdf_parameters.time_cost} (minimum {ARGON2_TIME_COST_MIN})"
        )
    if kdf_parameters.parallelism < ARGON2_PARALLELISM_MIN:
        raise VaultFormatError(
            f"Invalid Argon2 parallelism: "
            f"{kdf_parameters.parallelism} "
            f"(minimum {ARGON2_PARALLELISM_MIN})"
        )
    memory_floor = (ARGON2_MEMORY_KIB_PER_LANE_MIN * kdf_parameters.parallelism)
    if kdf_parameters.memory_cost < memory_floor:
        raise VaultFormatError(
            f"Invalid Argon2 memory_cost: "
            f"{kdf_parameters.memory_cost} KiB "
            f"(minimum {memory_floor} KiB for "
            f"parallelism={kdf_parameters.parallelism})"
        )

    # Cipher section
    if cipher.get(CIPHER_KEY_NAME) != CIPHER_NAME_AES_256_GCM:
        raise VaultFormatError(f"Unsupported cipher: {cipher.get(CIPHER_KEY_NAME)}")
    try:
        nonce = _b64decode(cipher[CIPHER_KEY_NONCE])
        ciphertext = _b64decode(cipher[CIPHER_KEY_CIPHERTEXT])
    except KeyError as exc:
        raise VaultFormatError(f"Cipher section missing field: {exc}") from exc

    return salt, kdf_parameters, nonce, ciphertext
