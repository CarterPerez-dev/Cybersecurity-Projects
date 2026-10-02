<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```
██╗  ██╗███████╗███╗   ███╗    ███████╗███╗   ███╗██╗   ██╗██╗      █████╗ ████████╗ ██████╗ ██████╗
██║  ██║██╔════╝████╗ ████║    ██╔════╝████╗ ████║██║   ██║██║     ██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║███████╗██╔████╔██║    █████╗  ██╔████╔██║██║   ██║██║     ███████║   ██║   ██║   ██║██████╔╝
██╔══██║╚════██║██║╚██╔╝██║    ██╔══╝  ██║╚██╔╝██║██║   ██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║███████║██║ ╚═╝ ██║    ███████╗██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝    ╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2333-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/hsm-emulator)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-F7A41D?style=flat&logo=zig&logoColor=white)](https://ziglang.org)
[![PKCS#11](https://img.shields.io/badge/PKCS%2311-v2.40-4B7BEC?style=flat)](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os.html)
[![Verified with](https://img.shields.io/badge/verified-pkcs11--tool-green?style=flat)](https://github.com/OpenSC/OpenSC)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> A software **Hardware Security Module** that compiles to a real Cryptoki (PKCS#11) shared object. Load it with `pkcs11-tool`, OpenSSL, or any PKCS#11 host the same way you would a real smartcard or HSM. It speaks the C ABI byte for byte, generates and stores keys, signs and encrypts, and keeps private key material sealed on disk and zeroized in RAM.

## Why PKCS#11 in Zig

PKCS#11 (Cryptoki) is the C-ABI standard that smartcards, YubiKeys, and cloud HSMs all speak. A conforming module is a `.so` that exports one function, `C_GetFunctionList`, returning a 68-entry table of function pointers in a *fixed canonical order*. Get one struct offset or one pointer slot wrong and the host loads garbage.

That makes it a near-perfect showcase for Zig's C interop: `extern struct` with natural alignment, `callconv(.c)`, a version script that exports exactly one symbol, and a hand-written ABI that is **machine-checked against the official OASIS headers at build time**. On top of that ABI sits a real HSM: a login model, an attribute-bag object store, a full set of cryptographic mechanisms, and encrypted-at-rest key storage.

## What Works Today

This is not a stub. A host can drive the module through a complete key lifecycle, and every capability below is exercised by a cross-process `pkcs11-tool` run, an in-process smoke harness against the built `.so`, and unit tests.

**The ABI and the module**
- Loads under OpenSC `pkcs11-tool` 0.26.1, enumerates the slot and token (`-L`), advertises **21 mechanisms** (`-M`)
- Exports **only** `C_GetFunctionList` (verified with `objdump -T`); 34 `__ubsan_*` symbols are kept out of the dynamic table
- The full v2.40 ABI hand-written in `src/ck.zig`: every type, 200+ constants, every struct, and the 68-entry `CK_FUNCTION_LIST` in canonical order
- A build-time cross-check (`zig build test`) translates the vendored OASIS headers and asserts `@sizeOf` / `@offsetOf` / constant equality **and per-function C-ABI signatures** against `ck.zig`. Spec compliance is a compile-time invariant, not a hope

**Tokens, sessions, login**
- `C_InitToken` / `C_InitPIN` / `C_SetPIN` / `C_Login` / `C_Logout` with a real Security Officer and User role split
- PINs are stretched with **Argon2id** (t=3, m=64 MiB, p=1); only salt and hash touch disk, never the PIN
- Three wrong attempts trip a lockout (`CKR_PIN_LOCKED`), reflected in the token flags
- Read-only versus read-write session enforcement and the full session state machine

**Objects**
- `C_CreateObject` / `C_CopyObject` / `C_DestroyObject` / `C_GetObjectSize`
- Two-call `C_GetAttributeValue`, per-attribute, with `CKR_ATTRIBUTE_SENSITIVE` for sealed key material
- `C_FindObjects` triad with `CKA_PRIVATE` login gating (private objects are invisible before login)
- `CKA_MODIFIABLE` / `CKA_DESTROYABLE` honored

**Cryptography**
- Digest: SHA-256 / SHA-384 / SHA-512, single-shot and multi-part
- HMAC: HMAC-SHA-256 / 384 / 512, with constant-time tag verification
- AES: CBC, CBC-PAD, and GCM (128 and 256-bit keys), encrypt and decrypt, with streaming GCM that buffers until the tag verifies
- ECDSA: P-256 and P-384 keygen, `CKM_ECDSA` and `CKM_ECDSA_SHA256`, cross-verified against OpenSSL
- RSA via libcrypto: 2048 to 4096-bit keygen, PKCS#1 v1.5, PSS, and OAEP; sign / verify / encrypt / decrypt and Sign / VerifyRecover
- Key management: `C_GenerateKey` (AES), `C_GenerateKeyPair` (RSA / EC), `C_WrapKey` / `C_UnwrapKey` (AES-KEY-WRAP RFC 3394 and RSA-OAEP), `C_DeriveKey` (ECDH), `C_DigestKey`
- RNG: `C_GenerateRandom` drawn from `std.Io.randomSecure` (the OS CSPRNG)

**Encrypted at rest, zeroized in RAM**
- Token objects persist to a file. Sensitive attribute *values* are sealed with AES-256-GCM under a per-token master key
- The master key is wrapped under a single User-PIN keyslot (Argon2id-derived KEK). There is no Security-Officer keyslot for user secrets by design
- On `C_Logout`, `C_CloseAllSessions`, and `C_Finalize`, sealed secrets are re-sealed and the master key is wiped with `std.crypto.secureZero`. A failed re-seal fails closed (the plaintext is scrubbed in place)

See [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md) for the precise return code at every deliberate boundary.

## Quick Start

```bash
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd Cybersecurity-Projects/PROJECTS/advanced/hsm-emulator
./install.sh
```

`install.sh` checks for Zig 0.16, OpenSC, and OpenSSL, builds the module in ReleaseSafe, runs the ABI cross-check plus the smoke test, and confirms `pkcs11-tool` can load it. Then drive it like any real token. Point both storage paths at a scratch directory so you do not write into `$HOME`:

```bash
export ANGELAMOS_HSM_TOKEN=/tmp/hsm-token
export ANGELAMOS_HSM_OBJECTS=/tmp/hsm-objects
MOD=zig-out/lib/libhsm.so

pkcs11-tool --module $MOD -L                    # list slots and token
pkcs11-tool --module $MOD -M                    # list 21 mechanisms

pkcs11-tool --module $MOD --init-token --label demo --so-pin 12345678
pkcs11-tool --module $MOD --init-pin --so-pin 12345678 --pin 1234
pkcs11-tool --module $MOD -l --pin 1234 \
    --keypairgen --key-type rsa:2048 --label signer
pkcs11-tool --module $MOD -l --pin 1234 \
    --sign --mechanism SHA256-RSA-PKCS --label signer \
    --input-file message.bin --output-file sig.bin
```

```
Available slots:
Slot 0 (0x0): AngelaMos HSM Emulator Slot 0
  token state:   uninitialized
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see everything. `just spy -L` wraps the module in `pkcs11-spy.so` and logs every Cryptoki call with its arguments and return code. It is the fastest way to watch the ABI work.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Learn

This project ships a full teaching track. Read it in order, or jump to what you need.

| Doc | What it covers |
|-----|----------------|
| [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) | What an HSM is, why it exists, and a 10-minute tour |
| [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) | Key sensitivity, the login model, encryption at rest, constant-time, padding oracles, with real breaches |
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | The three-layer design, object model, locking, the threat model |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | A code walkthrough of the ABI, an end-to-end operation, and the secret-handling patterns |
| [`learn/MECHANICS.md`](learn/MECHANICS.md) | How each cryptographic mechanism actually works, byte by byte |
| [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md) | The v2.40 conformance statement: every narrowed behavior and its exact return code |
| [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) | Extension ideas from beginner to expert |

## Architecture

The same three-layer split SoftHSM2 uses: a thin C-ABI façade over typed core state over the store and crypto backends.

```
   PKCS#11 host (pkcs11-tool, OpenSSL, p11-kit)
                      │  C ABI
                      ▼
   ┌───────────────────────────────────────────┐
   │  C_GetFunctionList  (src/main.zig)          │   one exported symbol,
   │  68-entry CK_FUNCTION_LIST                  │   one version script
   └───────────────────────┬─────────────────────┘
                           │
   ┌───────────────────────┴─────────────────────┐
   │  ABI façade   src/ck.zig  +  src/api/*.zig   │   hand-written Cryptoki ABI
   │  general · slot_token · session · object ·   │   + per-call entry points,
   │  crypto_ops · keymgmt · random               │   argument and FSM validation
   └───────────────────────┬─────────────────────┘
                           │
   ┌───────────────────────┴─────────────────────┐
   │  core state   src/core/*.zig                 │   global instance behind a lock,
   │  state · session · object_store · token      │   sessions, objects, PIN, master key
   └───────────────────────┬─────────────────────┘
                           │
   ┌───────────────────────┴─────────────────────┐
   │  crypto   src/crypto/*.zig                   │   pure-Zig std.crypto for AES/EC/
   │  digest · mac · cipher · ecdsa · rsa ·       │   hash/HMAC/ECDH, libcrypto for RSA,
   │  keystore · pin · openssl                    │   Argon2id KDF, GCM envelope at rest
   └───────────────────────────────────────────────┘
```

**Design decisions:** non-RSA crypto is pure-Zig `std.crypto`. RSA links libcrypto (OpenSSL EVP) because `std.crypto` has no public RSA. The RSA binding is hand-written `extern` declarations, not `@cImport`, so the production `.so` exports nothing but `C_GetFunctionList`. The RNG is `std.Io.randomSecure`, which draws fresh entropy from the OS on every call (`getrandom(2)` on Linux) and keeps no CSPRNG state in process memory. The ABI is structured for v2.40 with room to add the v3.0 `C_GetInterface` surface later.

## Build and Test

```bash
zig build               # build the module → zig-out/lib/libhsm.so (Debug)
zig build --release=safe # the shipped artifact: ReleaseSafe, UB checks as traps
zig build test          # ABI cross-check vs OASIS headers + the unit suite
zig build smoke         # dlopen the built .so and exercise the whole ABI as a host would
just ci                 # fmt-check + test + smoke
```

The smoke harness in `examples/smoke.zig` is not a unit test. It `dlopen`s the *actual built shared object* and calls through the function list exactly like an external host, so it catches export and ABI-shape bugs that in-process tests cannot. It walks a full lifecycle: init, login, keygen, sign, encrypt, wrap, derive, GCM streaming, dual-function, recover, operation-state, and the conformance edges.

> [!NOTE]
> Plain `zig build` produces a **Debug** binary. The shipped artifact is `--release=safe` (ReleaseSafe), which keeps every undefined-behavior check live and turns it into a fail-closed trap rather than silent corruption. Set both `ANGELAMOS_HSM_TOKEN` and `ANGELAMOS_HSM_OBJECTS` to a scratch path for tests and tool runs, or the module falls back to `$HOME/.angelamos-hsm-*`.

## Run in Docker

No Zig or OpenSC on the host? The container builds the module and drives it end to end through `pkcs11-tool`: token init, RSA and EC keygen and signing, AES-CBC round-trip, all inside the image.

```bash
just docker-demo        # build the image, then run the full pkcs11-tool demo
```

Or with Docker directly:

```bash
docker build -t angelamos-hsm:latest .
docker run --rm angelamos-hsm:latest
```

A multi-stage build compiles the module in ReleaseSafe in a `debian-slim` builder, then ships only the `.so` plus `opensc` and `libssl3` in a roughly 96 MB runtime image. The demo exits non-zero if any signature fails to verify.

## Project Structure

```
hsm-emulator/
├── build.zig              # addLibrary(.dynamic), version script, sanitize_c=.trap,
│                          #   libcrypto link, translate-c ABI cross-check, test + smoke
├── build.zig.zon          # package manifest
├── pkcs11.map             # version script: exports only C_GetFunctionList
├── src/
│   ├── ck.zig             # the hand-written Cryptoki v2.40 ABI (types, constants, structs, list)
│   ├── config.zig         # identity strings, key-size bounds, mechanism list (no magic numbers)
│   ├── util.zig           # comptime helpers (space-padded fixed fields)
│   ├── main.zig           # exported C_GetFunctionList + the wired 68-slot table
│   ├── core/
│   │   ├── state.zig       # global instance behind a lock, init-args parsing, generation counter
│   │   ├── lock.zig        # spinlock wrapper over std.atomic.Mutex
│   │   ├── env.zig         # reads std.c.environ for storage paths at the C boundary
│   │   ├── token.zig       # token record: PIN slots, fail counters, wrapped master key
│   │   ├── session.zig     # session table, op-state unions, the RUP-safe GCM buffer
│   │   └── object_store.zig# attribute-bag objects, the selective-sealing codec
│   ├── api/
│   │   ├── general.zig     # C_Initialize / Finalize / GetInfo / WaitForSlotEvent
│   │   ├── slot_token.zig  # slot + token + mechanism queries, InitToken / InitPIN / SetPIN
│   │   ├── session.zig     # OpenSession / Login / Logout / Get+SetOperationState
│   │   ├── object.zig      # CreateObject / Find / GetAttributeValue
│   │   ├── crypto_ops.zig  # the digest / sign / verify / encrypt / decrypt / dual surface
│   │   ├── keymgmt.zig     # GenerateKey(Pair) / WrapKey / UnwrapKey / DeriveKey
│   │   └── random.zig      # GenerateRandom / SeedRandom
│   └── crypto/
│       ├── openssl.zig     # hand-written extern EVP/BN/OSSL_PARAM declarations
│       ├── pin.zig         # Argon2id derive / verify (constant-time)
│       ├── digest.zig      # SHA-2 hasher union + serializable op-state
│       ├── mac.zig         # HMAC-SHA-2 union
│       ├── cipher.zig      # AES-CBC/CBC-PAD/GCM + RFC 3394 key wrap
│       ├── ecdsa.zig       # P-256/384 keygen, sign, verify, ECDH, curve OID + EC point DER
│       ├── rsa.zig         # the stateless libcrypto RSA bridge
│       └── keystore.zig    # master-key gen, wrap/unwrap, seal/unseal envelope
├── tests/abi_test.zig     # @sizeOf/@offsetOf/constant/signature cross-check vs OASIS
├── examples/smoke.zig     # loads the built .so via dlopen and drives the whole lifecycle
└── vendor/pkcs11/         # unmodified OASIS v2.40 headers (build-time cross-check only)
```

## Roadmap

Each milestone ends with a proof from a real external tool. No feature is "done" until `pkcs11-tool` or OpenSSL exercises it.

| Milestone | Scope | Proof |
|-----------|-------|-------|
| **M0** ✅ | Scaffold + hand-written ABI + loadable `.so` | `pkcs11-tool -L/-M`, `objdump -T` |
| **M1** ✅ | Sessions + login + PIN (Argon2id, lockout) | `--init-token --init-pin --login --change-pin` |
| **M2** ✅ | Objects + find, `CKA_PRIVATE` gating | `-O --read-object`, two-call attribute fetch |
| **M3** ✅ | RNG + SHA-2 + HMAC + AES-CBC/CBC-PAD/GCM | `--hash --sign --encrypt --decrypt --generate-random` |
| **M4** ✅ | ECDSA P-256/384 + keygen | `--keypairgen EC --sign`, cross-verify with OpenSSL |
| **M5** ✅ | RSA via libcrypto (v1.5 / PSS / OAEP) | sign / verify / encrypt / decrypt through the module |
| **M6** ✅ | Encrypted store at rest (AES-256-GCM under Argon2id KEK) | survives restart; wrong PIN and tamper fail closed |
| **M7** ✅ | Hardening (secret zeroization, fail-closed relock) + Docker | leak-checked build, `just docker-demo` exits 0 |
| **M9** ✅ | Key management: wrap / unwrap, ECDH derive, digest-key | RFC 3394 KAT, ECDH matches `openssl pkeyutl -derive` |
| **M10** ✅ | Crypto surface: GCM streaming, dual-function, Sign/VerifyRecover, op-state | chunked GCM equals one-shot, recover round-trips |
| **M11** ✅ | Conformance pass + `CONFORMANCE.md` | every N/A boundary asserted against the built `.so` |
| **M12** ✅ | Learn modules + mechanism reference | this `learn/` track |

## License

[AGPL 3.0](LICENSE). The vendored OASIS headers under `vendor/pkcs11/` keep their original copyright and are used only for the build-time cross-check.
