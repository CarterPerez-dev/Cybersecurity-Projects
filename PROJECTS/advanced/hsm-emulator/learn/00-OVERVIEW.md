<!-- ©AngelaMos | 2026 -->
<!-- 00-OVERVIEW.md -->

# HSM Emulator: Overview

## What This Is

A software **Hardware Security Module** written in Zig that compiles to a real PKCS#11 (Cryptoki) shared object. Any program that already knows how to talk to a smartcard, a YubiKey, or a cloud HSM (OpenSSL, `pkcs11-tool`, Java's SunPKCS11, p11-kit) can load this `.so` and use it to generate keys, sign, encrypt, and store secrets. It speaks the same C ABI a real HSM speaks, so to the host it is indistinguishable from hardware until you look at where the bytes actually live.

The point of the project is to understand, by building it, what an HSM actually does and why the interface to one looks the way it does. You get a working module you can poke at with standard tools, and a codebase small enough to read in an afternoon.

## Why This Matters

A cryptographic key is the whole game. If an attacker reads your TLS private key, your code-signing key, or your CA root key out of a file or out of process memory, every signature and every certificate that key ever produced is now forgeable. The defense the industry settled on is to never let the application touch the key. The key lives inside a separate trust boundary (a chip, a card, a network appliance) and the application sends it *requests*: "sign this", "decrypt that". The key goes in once and never comes back out.

The cost of getting this wrong is not hypothetical.

- **RSA SecurID, 2011.** Attackers breached RSA and exfiltrated seed records tied to SecurID tokens, then used them to attack Lockheed Martin. The lesson the industry took from it: the secrets that authenticate everything else must sit behind a hardware boundary, not in a database an intruder can read.
- **Stuxnet, 2010.** The worm carried drivers signed with legitimate code-signing keys stolen from Realtek and JMicron. Valid signatures from stolen keys let malware sail past trust checks. Code-signing keys are exactly the kind of thing that belongs in an HSM, where the key signs but never leaves.
- **DigiNotar, 2011.** A certificate authority was compromised and issued rogue certificates for `*.google.com`, used to intercept traffic in Iran. The company did not survive it. CA root and issuing keys are the canonical HSM use case: the key must be usable for signing yet impossible to copy.

**Real world scenarios where this applies:**
- **Certificate authorities and PKI.** A CA's signing keys live in an HSM. The CA software calls `C_Sign`; the key never exists in the CA server's memory in usable form.
- **Code signing.** Apple, Microsoft, and Linux distros sign release artifacts with keys held in HSMs so a server breach cannot mint signed malware.
- **Payment and KMS backends.** AWS KMS and CloudHSM, payment HSMs (PIN translation, card issuance), and database TDE all delegate the actual crypto to a module that exposes an interface very much like this one.

## What You'll Learn

This project teaches how key custody actually works under the hood. By building it yourself, you will understand:

**Security concepts:**
- **Key custody and the trust boundary.** Why "the application never sees the key" is the entire design goal, and how an attribute like `CKA_SENSITIVE` turns into a hard refusal to ever hand `CKA_VALUE` back to the caller.
- **Authentication and lockout.** How a PIN is stretched with Argon2id so the value on disk is useless to a thief, and why three wrong tries must lock the token rather than let an attacker grind.
- **Encryption at rest with key wrapping.** The envelope pattern: a random master key encrypts your secrets, and the master key is itself wrapped under a key derived from your PIN. Change the PIN and you re-wrap one small key instead of re-encrypting everything.
- **Release of unverified plaintext (RUP).** Why a streaming AEAD decrypt that hands back bytes before the authentication tag is checked is dangerous, and how buffering until the tag verifies removes the problem.
- **Side channels.** Why comparing a PIN or a MAC with a normal byte-by-byte compare leaks information through timing, and what constant-time comparison fixes.

**Technical skills:**
- **Writing a C ABI by hand.** Laying out `extern struct` types so they match a C header byte for byte, and proving it with compile-time `@sizeOf` / `@offsetOf` assertions instead of hoping.
- **Calling a C library safely from Zig.** Binding OpenSSL's `libcrypto` through hand-written `extern` declarations (RSA lives there because Zig's standard library has none), without leaking its symbols out of your module.
- **Concurrency at a C boundary.** Holding a global instance behind a lock, and using a generation counter so a slow operation that started before the token was reinitialized cannot commit stale results.
- **Secret hygiene in a systems language.** Zeroizing key material with `std.crypto.secureZero`, understanding what the `volatile` trick buys you, and freeing heap secrets without leaving copies behind.

**Tools and techniques:**
- **`pkcs11-tool`** (from OpenSC), the standard command-line host for any PKCS#11 module. You will use it to init the token, log in, generate keys, and sign.
- **`pkcs11-spy`**, a shim that sits in front of any module and logs every call with its arguments and return code. It is the single best debugging tool for ABI work.
- **OpenSSL as an oracle.** Verifying that a signature this module produces validates under OpenSSL, and that an ECDH secret it derives matches `openssl pkeyutl -derive` byte for byte.

## Prerequisites

You do not need prior HSM experience. You do need some comfort with the following.

**Required knowledge:**
- **C ABI basics.** What a struct's memory layout is, what a function pointer is, what "calling convention" means. The whole module is an exercise in matching a C interface exactly.
- **Symmetric versus asymmetric crypto.** The difference between AES (one shared key) and RSA/EC (a keypair). You do not need the math, but you should know which is which and what "sign" versus "encrypt" means.
- **Basic Zig or a willingness to read it.** The code uses tagged unions, `comptime`, error unions, and slices. If you know Rust, Go, or modern C++, you can follow it.

**Tools you'll need:**
- **Zig 0.16.0** to build the module. The exact version matters; the `std.Io` interface and the build API changed in 0.16.
- **OpenSC** for `pkcs11-tool` and `pkcs11-spy`. On Debian or Ubuntu: `apt install opensc`.
- **OpenSSL development headers** (`libssl-dev`) so the module can link `libcrypto` for RSA.

**Helpful but not required:**
- A reading of the [PKCS#11 v2.40 base specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html). You can also just read [`01-CONCEPTS.md`](./01-CONCEPTS.md) and pick up the spec when something is unclear.
- Familiarity with how SoftHSM2 (the reference open-source software HSM) is structured. This project borrows its three-layer split.

## Quick Start

```bash
cd PROJECTS/advanced/hsm-emulator

# Build, cross-check the ABI, and confirm pkcs11-tool can load it
./install.sh

# Keep all state in a scratch directory instead of $HOME
export ANGELAMOS_HSM_TOKEN=/tmp/hsm-token
export ANGELAMOS_HSM_OBJECTS=/tmp/hsm-objects
MOD=zig-out/lib/libhsm.so

# Look at the empty token, then bring it to life
pkcs11-tool --module $MOD -L
pkcs11-tool --module $MOD --init-token --label demo --so-pin 12345678
pkcs11-tool --module $MOD --init-pin --so-pin 12345678 --pin 1234

# Generate a keypair and sign with it
pkcs11-tool --module $MOD -l --pin 1234 --keypairgen --key-type EC:prime256v1 --label k1
echo "hello hsm" > msg.bin
pkcs11-tool --module $MOD -l --pin 1234 --sign --mechanism ECDSA-SHA256 --label k1 \
    --input-file msg.bin --output-file sig.bin
```

Expected output: `-L` shows one slot whose token starts `uninitialized`. After `--init-token` the token reports `flags: ... token initialized`. The keypair generation prints the new public and private object handles, and `--sign` writes a 64-byte signature to `sig.bin`. If you want to *watch* every Cryptoki call the tool makes, run any command through `just spy` (for example `just spy --keypairgen ...`) and read the spy log.

## Project Structure

```
hsm-emulator/
├── src/
│   ├── ck.zig             # the hand-written Cryptoki ABI (the contract with the host)
│   ├── main.zig           # the one exported symbol and the 68-entry function table
│   ├── config.zig         # every tunable constant in one place
│   ├── core/              # global state, sessions, the object store, the token record
│   ├── api/               # one file per group of C_ functions (the entry points)
│   └── crypto/            # the actual cryptography (AES, EC, RSA, hashing, the keystore)
├── tests/abi_test.zig     # proves ck.zig matches the OASIS headers at build time
├── examples/smoke.zig     # loads the built .so and drives it like a real host
└── vendor/pkcs11/         # the official OASIS headers, used only for the cross-check
```

The single most important file to understand first is `src/ck.zig`. Everything else exists to fill in the function pointers that file declares.

## Next Steps

1. **Understand the ideas.** Read [01-CONCEPTS.md](./01-CONCEPTS.md) for key custody, the login model, encryption at rest, and the side-channel defenses, each grounded in a real incident.
2. **See the design.** Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) for the three-layer split, the object model, and how concurrency is handled.
3. **Walk the code.** Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) to trace a full operation from the C call down to the crypto and back.
4. **Learn the crypto.** Read [MECHANICS.md](./MECHANICS.md) for how each mechanism (AES modes, GCM, key wrap, ECDSA, ECDH, RSA, Argon2id) works byte by byte.
5. **Check the contract.** Read [CONFORMANCE.md](./CONFORMANCE.md) for the exact return code at every boundary.
6. **Extend it.** Read [04-CHALLENGES.md](./04-CHALLENGES.md) for projects from "add a mechanism" to "implement the v3.0 interface".

## Common Issues

**`pkcs11-tool` writes files into my home directory**
```
~/.angelamos-hsm-token
~/.angelamos-hsm-objects
```
Solution: set `ANGELAMOS_HSM_TOKEN` and `ANGELAMOS_HSM_OBJECTS` before every command. The module falls back to `$HOME/.angelamos-hsm-*` only when those are unset.

**`error: unable to find dynamic system library 'crypto'`**
Solution: install the OpenSSL development package (`libssl-dev` on Debian or Ubuntu, `openssl-devel` on Fedora). RSA is the one mechanism family that links a C library.

**`C_Login` returns `CKR_PIN_LOCKED` and nothing works**
Solution: you tried the wrong PIN three times and the token locked. Re-run `--init-token` (with the Security Officer PIN) to reset it, which also clears all objects. This is the intended behavior; an attacker should not get unlimited tries.

**A plain `zig build` behaves differently from the installed module**
Solution: `zig build` with no flags is a Debug build. The shipped module is `zig build --release=safe`. Debug and ReleaseSafe differ in how freed and nulled memory is poisoned, which matters when you are inspecting zeroized secrets. Use `--release=safe` to match the artifact.

## Related Projects

If you found this interesting, look at:
- **api-rate-limiter**: another advanced project where the security property (correctness under concurrency) lives in carefully designed state handling, here with Lua scripts instead of a Zig mutex.
- **bug-bounty-platform**: shows how key material and credentials are handled in a full application, the layer that would *call* an HSM like this one.
