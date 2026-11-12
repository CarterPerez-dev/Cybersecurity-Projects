"""
©AngelaMos | 2026
constants.py

Every "magic number" and fixed string the project uses, in one place

A "constant" is a value that never changes while the program runs
Beginners often hard-code numbers like `length = 16` directly into
the code that uses them — and then six months later, nobody remembers
why 16. By collecting every constant up here with a name and a
comment explaining its meaning, the rest of the codebase becomes
self-documenting

Three big buckets live here

1. Crypto parameters — sizes and tuning knobs for Argon2id (the key
   derivation function) and AES-256-GCM (the encryption). These are
   chosen based on current OWASP and NIST guidance. If you ever
   need to bump them in five years, you change them HERE and nowhere
   else

2. Vault file format — the schema version, JSON keys, and default
   file location. Storing the format version means future versions
   of this code can still read today's vaults

3. CLI strings — prompts, error messages, success messages. Kept
   here so they are easy to translate or re-word later

Connects to
  crypto.py — imports KDF and cipher constants
  vault.py — imports format constants and vault path defaults
  main.py — imports prompt and message strings
"""

# Standard library: object-oriented filesystem paths — safer and
# more readable than gluing strings with `os.path.join`.
from pathlib import Path
# Standard library: a type hint that marks a variable as a constant —
# mypy will reject any later attempt to reassign it.
from typing import Final


# =============================================================================
# Argon2id — Key Derivation Function parameters
# =============================================================================
# Argon2id turns a human password into a cryptographic key
# It is deliberately slow and memory-hungry to defeat brute-force
# attacks. These three knobs control HOW slow and HOW memory-hungry
#
# These values are informed by the OWASP Password Storage Cheat
# Sheet, but tuned for a single-user local password manager. OWASP's
# server-oriented configurations use parallelism=1 because a server
# parallelizes ACROSS many simultaneous logins. We use parallelism=4
# because a single user benefits from the speedup on their own
# machine — and an attacker gets the same speedup, so the security
# trade-off is net-neutral. Memory at 64 MiB is comfortably above
# every OWASP profile, which is what makes GPU brute-force expensive

# Number of passes Argon2 makes over its memory buffer
# More passes = slower derivation = harder to brute-force
# 3 is a strong choice for interactive use on modern CPUs
ARGON2_TIME_COST: Final[int] = 3

# Memory used per derivation, in kibibytes (1 KiB = 1024 bytes)
# 65536 KiB = 64 MiB. This defeats GPU/ASIC attackers because
# they have lots of compute but limited fast memory per core
ARGON2_MEMORY_KIB: Final[int] = 65536

# How many parallel threads Argon2 may use
# 4 is a safe default that works on every modern CPU
ARGON2_PARALLELISM: Final[int] = 4

# Salt length in bytes. The salt is random data mixed in with the
# password before hashing — it makes two identical passwords produce
# DIFFERENT keys, so attackers cannot precompute results
# 16 bytes (128 bits) is the standard recommendation
SALT_LENGTH_BYTES: Final[int] = 16

# Argon2 algorithmic invariants — the values below which the math
# does not even make sense. We use these to validate parameters
# loaded from a vault file on disk, so a corrupted or hand-edited
# file cannot make us call Argon2 with nonsense
#   - time_cost >= 1: at least one pass over memory
#   - parallelism >= 1: at least one lane
#   - memory_cost >= 8 * parallelism: Argon2's hard floor (each lane
#     needs at least 8 KiB of memory to function)
ARGON2_TIME_COST_MIN: Final[int] = 1
ARGON2_PARALLELISM_MIN: Final[int] = 1
ARGON2_MEMORY_KIB_PER_LANE_MIN: Final[int] = 8


# =============================================================================
# AES-256-GCM — Symmetric encryption parameters
# =============================================================================
# AES-256-GCM is the encryption algorithm we use to scramble vault
# contents. "256" means a 256-bit key. "GCM" is a "mode" that adds
# tamper-detection — if anyone changes one byte of the ciphertext,
# decryption will refuse and raise an error

# Key size in bytes. AES-256 wants exactly 32 bytes (256 bits)
# This is also what we ask Argon2 to produce when deriving the key
KEY_LENGTH_BYTES: Final[int] = 32

# Nonce ("number used once") size in bytes
# A nonce is a random value generated FRESH for every encryption
# Reusing a nonce with the same key is catastrophic for GCM —
# it leaks plaintext. So we generate a new 12-byte nonce every save
# 12 bytes is the GCM-recommended size (NIST SP 800-38D)
NONCE_LENGTH_BYTES: Final[int] = 12


# =============================================================================
# Vault file format
# =============================================================================
# The vault is stored as a single JSON file. The structure looks
# roughly like this (base64 fields shown as <...>)
#
#   {
#     "version": 1,
#     "kdf": {
#       "name": "argon2id",
#       "salt": "<base64>",
#       "time_cost": 3,
#       "memory_cost": 65536,
#       "parallelism": 4
#     },
#     "cipher": {
#       "name": "aes-256-gcm",
#       "nonce": "<base64>",
#       "ciphertext": "<base64>"
#     }
#   }
#
# Storing kdf params IN the file (not just in code) lets us bump
# defaults later without breaking old vaults — the file says how
# it was encrypted, and we believe it

# Bump this when the on-disk format changes incompatibly
VAULT_FORMAT_VERSION: Final[int] = 1

# Top-level JSON keys
VAULT_KEY_VERSION: Final[str] = "version"
VAULT_KEY_KDF: Final[str] = "kdf"
VAULT_KEY_CIPHER: Final[str] = "cipher"

# KDF section keys
KDF_KEY_NAME: Final[str] = "name"
KDF_KEY_SALT: Final[str] = "salt"
KDF_KEY_TIME_COST: Final[str] = "time_cost"
KDF_KEY_MEMORY_COST: Final[str] = "memory_cost"
KDF_KEY_PARALLELISM: Final[str] = "parallelism"

# Cipher section keys
CIPHER_KEY_NAME: Final[str] = "name"
CIPHER_KEY_NONCE: Final[str] = "nonce"
CIPHER_KEY_CIPHERTEXT: Final[str] = "ciphertext"

# Algorithm names written into the file (for self-documentation
# and so future versions can switch without breaking old vaults)
KDF_NAME_ARGON2ID: Final[str] = "argon2id"
CIPHER_NAME_AES_256_GCM: Final[str] = "aes-256-gcm"

# File mode: 0o600 means "owner can read+write, nobody else can
# touch it." Octal in Python is written 0o<digits>. We set this on
# the vault file the moment we create it
VAULT_FILE_MODE: Final[int] = 0o600

# Default location: ~/.password-vault/vault.json
# Path.home() resolves to /home/<user> on Linux, C:/Users/<user>
# on Windows, /Users/<user> on macOS
DEFAULT_VAULT_DIRECTORY: Final[Path] = Path.home() / ".password-vault"
DEFAULT_VAULT_FILENAME: Final[str] = "vault.json"
DEFAULT_VAULT_PATH: Final[Path] = (DEFAULT_VAULT_DIRECTORY / DEFAULT_VAULT_FILENAME)


# =============================================================================
# Password generator defaults
# =============================================================================
# When the user runs `pv gen` to generate a random password, these
# are the defaults. Everything is overridable on the command line

# Default length when the user does not specify one
DEFAULT_GENERATED_PASSWORD_LENGTH: Final[int] = 24

# Minimum length we will allow. Passwords shorter than this are
# weak enough to brute-force in reasonable time
MINIMUM_GENERATED_PASSWORD_LENGTH: Final[int] = 8

# Minimum length for the MASTER password (the one that locks the
# whole vault). This is a floor, not a recommendation — users
# should pick something much longer. We reject anything shorter
# than this to prevent the obvious footgun of an empty or trivial
# master password silently "encrypting" the vault under no real
# secret. 8 mirrors NIST SP 800-63B's minimum for memorized secrets
MINIMUM_MASTER_PASSWORD_LENGTH: Final[int] = 8

# Character pools the generator can pick from
LOWERCASE_LETTERS: Final[str] = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_LETTERS: Final[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS: Final[str] = "0123456789"

# Symbols deliberately exclude characters that confuse copy-paste
# (quotes, backticks) or get eaten by shells (backslash, dollar)
SAFE_SYMBOLS: Final[str] = "!@#$%^&*()-_=+[]{};:,.<>/?"


# =============================================================================
# CLI prompt and message strings
# =============================================================================
# Putting human-readable text here means we can tweak wording without
# hunting through source code, and it sets us up for future
# translation if we ever want to ship a non-English version

PROMPT_MASTER_PASSWORD: Final[str] = "Master password: "
PROMPT_MASTER_PASSWORD_NEW: Final[str] = "New master password: "
PROMPT_MASTER_PASSWORD_CONFIRM: Final[str] = "Confirm master password: "
PROMPT_ENTRY_PASSWORD: Final[str] = "Password for {entry}: "
PROMPT_ENTRY_USERNAME: Final[str] = "Username for {entry}: "
PROMPT_ENTRY_URL: Final[str] = "URL (optional, press Enter to skip): "
PROMPT_ENTRY_NOTES: Final[str] = "Notes (optional, press Enter to skip): "

MSG_VAULT_CREATED: Final[str] = "Vault created at {path}"
MSG_VAULT_ALREADY_EXISTS: Final[str] = "Vault already exists at {path}"
MSG_VAULT_NOT_FOUND: Final[str] = ("No vault at {path}. Run `pv init` to create one")
MSG_ENTRY_ADDED: Final[str] = "Added entry: {name}"
MSG_ENTRY_DELETED: Final[str] = "Deleted entry: {name}"
MSG_ENTRY_NOT_FOUND: Final[str] = "No entry named: {name}"
MSG_ENTRY_ALREADY_EXISTS: Final[str] = (
    "Entry already exists: {name}. Use --force to overwrite"
)
MSG_PASSWORDS_DO_NOT_MATCH: Final[str] = "Passwords did not match"
MSG_WRONG_MASTER_PASSWORD: Final[str] = (
    "Wrong master password (or vault file is corrupted)"
)
MSG_VAULT_EMPTY: Final[str] = "Vault is empty. Add an entry with `pv add`"

MSG_MASTER_PASSWORD_EMPTY: Final[str] = ("Master password cannot be empty")
MSG_MASTER_PASSWORD_TOO_SHORT: Final[str] = (
    "Master password must be at least {minimum} characters"
)
MSG_MASTER_PASSWORD_CHANGED: Final[str] = (
    "Master password changed. Vault re-encrypted at {path}"
)
