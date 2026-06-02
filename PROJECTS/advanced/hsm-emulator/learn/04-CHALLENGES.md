<!-- ©AngelaMos | 2026 -->
<!-- 04-CHALLENGES.md -->

# Extension Challenges

You have a working software HSM. Now make it yours. These challenges are ordered by difficulty, and each one names the real files and functions you will touch so you are not hunting. Start easy to learn the codebase's shape, then go deeper.

The golden rule of this project applies to every challenge: nothing is done until an external tool exercises it. Add a unit test against a published vector, then prove it through `pkcs11-tool` or the smoke harness.

## Easy Challenges

### Challenge 1: Add SHA-224 as a digest mechanism

**What to build:** Support `CKM_SHA224` alongside the existing SHA-256/384/512 digests.

**Why it's useful:** SHA-224 is still required by some compliance profiles, and adding it teaches you the exact path a new mechanism takes through the layers.

**What you'll learn:**
- The four-step "add a mechanism" path described in [02-ARCHITECTURE.md](./02-ARCHITECTURE.md)
- How the ABI test cross-checks a new constant for free

**Hints:**
- Add `CKM_SHA224` to `ck.zig`. The "every hand-coded constant equals its OASIS value" test in `tests/abi_test.zig` will check the value against the header automatically.
- Add a `sha224` arm to the `Hasher` union in `crypto/digest.zig` (Zig's std has `sha2.Sha224`), and give it a new state tag for operation-state serialization.
- Add it to `config.supported_mechanisms` and to the digest arm of `C_GetMechanismInfo` in `slot_token.zig`.

**Test it works:**
```bash
pkcs11-tool --module zig-out/lib/libhsm.so --hash --mechanism SHA224 --input-file msg.bin
```
Compare against `sha224sum msg.bin`. Add a unit test in `digest.zig` against the `SHA-224("abc")` vector.

### Challenge 2: Expose a token-info detail you control

**What to build:** Make the token model string or serial number configurable through an environment variable instead of a fixed constant.

**Why it's useful:** Real deployments label tokens. It is a gentle introduction to the config and slot-token layers.

**What you'll learn:**
- How `config.zig` centralizes every constant
- How `env.zig` reads the environment at the C boundary (there is no `std.process` arena here)

**Hints:**
- `C_GetTokenInfo` in `slot_token.zig` fills the `model` and `serialNumber` fields from `config.token_model` and `config.token_serial` through `util.padded`.
- Add an env lookup in `env.zig` and fall back to the constant when it is unset, mirroring how the storage paths work.
- Remember the fields are space-padded fixed arrays, not NUL-terminated strings.

**Test it works:** `pkcs11-tool -T` should show your value, and an unset variable should show the default.

### Challenge 3: Add a `just` recipe that signs and then verifies with OpenSSL

**What to build:** A recipe that generates an EC key in the module, signs a file, exports the public key, and verifies the signature with the `openssl` command line.

**Why it's useful:** Cross-verifying against an independent implementation is exactly how this project proves correctness. You are turning that into a one-liner.

**What you'll learn:**
- How `pkcs11-tool` and `openssl` interoperate through the module
- Why an independent oracle is stronger proof than a self-test

**Hints:**
- Look at the existing `justfile` recipes and the smoke flow for the command sequence.
- `pkcs11-tool --read-object --type pubkey` exports the public key; `openssl dgst -verify` checks the signature.

**Test it works:** The recipe exits 0 and prints `Verified OK`.

## Intermediate Challenges

### Challenge 4: AES-192

**What to build:** Support 192-bit AES keys for `CKM_AES_KEY_GEN`, `CKM_AES_CBC`, `CKM_AES_CBC_PAD`, and `CKM_AES_GCM`.

**Why it's useful:** It is currently unsupported because Zig's standard library exposes no 192-bit AES (see [CONFORMANCE.md](./CONFORMANCE.md) section 3.3). Solving it teaches you the same libcrypto-bridge pattern RSA uses.

**Real world application:** Some FIPS profiles and legacy systems require AES-192 specifically.

**Implementation approach:**
1. Decide the backend. Zig std has no Aes192, so route 192-bit keys through libcrypto's EVP AES, the way `rsa.zig` routes RSA.
2. Add the extern declarations you need to `openssl.zig` (the EVP cipher functions).
3. Branch on key length in `cipher.zig`'s block and GCM functions, calling libcrypto for 24-byte keys and keeping std for 16 and 32.
4. Update `cipher.validKeyLen` and the `CKR_KEY_SIZE_RANGE` checks to accept 24.

**Hints:**
- The `encBlockRaw` / `decBlockRaw` functions currently `switch (key.len)` over 16 and 32 with `unreachable` otherwise. That switch is where the 24-byte arm goes.
- Keep the constant-time and zeroization patterns identical to the existing arms.

**Test it works:** A NIST AES-192-CBC vector in `cipher.zig`, plus a `pkcs11-tool` round-trip with a 24-byte key.

### Challenge 5: A per-object file backend

**What to build:** Replace the single object file with a directory where each token object is its own file, the way SoftHSM2 does it.

**Why it's useful:** A single file means rewriting everything on every change. Per-object files let you write only what changed and make backup a per-object copy.

**What you'll learn:**
- Storage design trade-offs (one file versus many)
- How the persistence codec in `object_store.zig` separates serialization from I/O

**Implementation approach:**
1. Keep the existing `serialize` / `parse` for a single object's attributes; you are changing only how they are grouped on disk.
2. Give each object a stable on-disk id (the handle is monotonic and never reused, which helps).
3. Write the sealing logic unchanged; each object file still seals its sensitive values under the master key.

**Hints:**
- The seal-on-write and mark-sealed-on-read logic in `object_store.zig` does not care how many files there are. Keep it.
- `env.zig` resolves a path today; you will resolve a directory.

**Test it works:** Create several objects, restart the process, and confirm they all reload. Corrupt one object file and confirm only that object is lost, not the whole store.

## Advanced Challenges

### Challenge 6: Implement the PKCS#11 v3.0 interface discovery

**What to build:** Export `C_GetInterface` alongside `C_GetFunctionList`, returning a `CK_FUNCTION_LIST_3_0` for hosts that ask for v3.0.

**Why this is hard:** You are extending the ABI itself, the part that must match the host byte for byte. A mistake here means hosts crash, not just misbehave.

**What you'll learn:**
- How v3.0 interface discovery works and why hosts fall back to `C_GetFunctionList` when `C_GetInterface` is absent (the OpenJDK fallback path)
- How `CK_FUNCTION_LIST_3_0` shares a prefix with `CK_FUNCTION_LIST` and appends the new pointers

**Architecture changes needed:**
```
   C_GetInterface(name, version, &iface, flags)
        │
        ▼
   CK_INTERFACE { pInterfaceName, pFunctionList -> CK_FUNCTION_LIST_3_0, flags }
        │
   (C_GetFunctionList still returns the v2.40 CK_FUNCTION_LIST prefix)
```

**Implementation steps:**
1. Add `CK_FUNCTION_LIST_3_0` and `CK_INTERFACE` to `ck.zig`, with the 24 new v3.0 function-pointer typedefs.
2. Build one larger table and hand out a pointer typed either way, setting the version field correctly per caller.
3. Export `C_GetInterface` in `main.zig` and add it to the version script in `pkcs11.map`.
4. Extend `tests/abi_test.zig` to cross-check the new structs against the v3.0 OASIS headers (vendor them alongside the v2.40 ones).

**Gotchas:**
- The first N members of `CK_FUNCTION_LIST_3_0` must be byte-identical to `CK_FUNCTION_LIST`. The cross-check test is your safety net.
- New v3.0 functions you do not implement still need real, correctly-typed stub functions in the table. Never null.

**Resources:** The PKCS#11 v3.1 specification, and the `08-pkcs11.md` research note in `docs/zig/reference/` which covers the v3.0 surface.

### Challenge 7: The v3.0 message-based AEAD API

**What to build:** Implement `C_EncryptMessage` / `C_DecryptMessage` (and the begin/next/final variants) for AES-GCM.

**Why this is hard:** The message API is how the OpenSSL 3.x provider increasingly prefers to do GCM, and it has a different nonce-management contract than the classic `C_Encrypt`.

**What you'll learn:**
- The v3.0 message API shape and how it differs from the v2.40 single-shot and update/final flows
- How to keep your RUP-safe stance under the new API

**Implementation approach:**
1. Requires Challenge 6 first (the v3.0 table).
2. The message API passes the nonce and AAD through `CK_MESSAGE`-family parameters rather than the mechanism parameter.
3. Keep the buffered, verify-before-release behavior for decrypt that the classic path already has in `GcmStream`.

**Hints:** Your existing GCM accumulator and the strict parameter validation in `buildCipher` are most of the work; the new part is the message-API parameter parsing.

### Challenge 8: Fork safety

**What to build:** Detect a `fork()` and refuse to operate in the child with stale state inherited from the parent, or re-initialize cleanly.

**Why this is hard:** A child process inherits the parent's initialized state, including an unwrapped master key, which is a real hazard. The PKCS#11 answer is the `CKF_INTERFACE_FORK_SAFE` flag, but only if you actually handle it.

**What you'll learn:**
- Why inherited crypto state across a fork is dangerous
- How to track the process id and invalidate state on change

**Implementation approach:**
1. Record the pid in the `Instance` at `C_Initialize`.
2. In `state.acquire()`, compare the current pid; on a mismatch, treat the library as not initialized in the child (force a re-init) rather than operating on the parent's secrets.
3. Only then advertise `CKF_INTERFACE_FORK_SAFE` (a v3.0 interface flag, so this pairs with Challenge 6).

**Gotchas:** The master key inherited by a child must be wiped, not used. Be careful that the detection happens before any operation can touch `inst.mk`.

## Expert Challenges

### Challenge 9: A SQLite storage backend with multi-token support

**What to build:** Replace the file backend with SQLite, and lift the one-token limit so the module can host several tokens across several slots.

**Estimated time:** A week or more.

**Prerequisites:** You should have done Challenge 5 (per-object storage) first, because this builds on separating the codec from the I/O.

**What you'll learn:**
- How a real software HSM (SoftHSM2 has exactly this) structures multi-token storage
- How to shard the global state per slot without losing the single-lock simplicity, or how to move to per-slot locks

**Planning this feature:**

Before you code, think through:
- How does multi-slot change the global `Instance`? Today it is one token, one session table, one object store. You need a collection keyed by slot.
- Does the single global mutex still serve, or do you want per-slot locks? Per-slot locks add real concurrency but also real deadlock risk.
- How do you migrate an existing single-file token into the database on first run?

**High level architecture:**
```
   slots: [N] of Token
     each Token: its own PIN state, master key, object store
   storage: SQLite (one table for tokens, one for objects, sealed values as BLOBs)
   locking: either the one global mutex (simple) or per-slot (concurrent)
```

**Implementation phases:**

**Phase 1: Multi-token in memory.** Turn the single token/store/sessions in `Instance` into slot-indexed collections. Keep the file backend. Get `C_GetSlotList` returning several slots and the per-slot operations routing correctly.

**Phase 2: The SQLite backend.** Link SQLite (the libcrypto bridge in `openssl.zig` is your template for binding a C library cleanly). Move serialize/parse to read and write rows. Keep the sealing logic untouched; values are still GCM-sealed BLOBs.

**Phase 3: Migration and concurrency.** Migrate an existing file token on first open. Decide and implement the locking model.

**Phase 4: Polish.** Error handling for a locked or corrupt database, and the full test pass through `pkcs11-tool` against multiple tokens.

**Success criteria:**
- [ ] `C_GetSlotList` returns more than one slot
- [ ] Two tokens hold independent keys and PINs
- [ ] Keys survive a restart, loaded from SQLite
- [ ] A corrupt or locked database fails closed, never returns a wrong key
- [ ] The ABI test and smoke harness still pass unchanged

## Mix and Match

Combine challenges into bigger projects:

**A v3.0-native module.** Challenge 6 (interface) plus Challenge 7 (message API) plus Challenge 8 (fork safety) gives you a module a modern OpenSSL 3.x provider talks to natively.

**A production-shaped store.** Challenge 5 (per-object) plus Challenge 9 (SQLite, multi-token) gives you something with SoftHSM2's storage capabilities.

## Real World Integration Challenges

### Drive the module from the OpenSSL pkcs11 provider

**The goal:** Use this module as the key store behind OpenSSL itself, so `openssl` commands sign and decrypt through it.

**What you'll need:**
- The `pkcs11-provider` (the modern OpenSSL 3.x provider) configured to point at `libhsm.so`
- An OpenSSL config that loads the provider

**Watch out for:** The provider exercises corners `pkcs11-tool` does not, especially around RSA-PSS parameters and GCM. This is a great way to find conformance gaps. Anything it trips is a real bug or a documented narrowing in [CONFORMANCE.md](./CONFORMANCE.md).

### Use the module from Java via SunPKCS11

**The goal:** Have a Java program generate a key and sign through the module using `java.security` and the SunPKCS11 provider.

**What you'll learn:** SunPKCS11 is the classic `C_GetInterface`-fallback consumer, so this also validates that your `C_GetFunctionList` path is solid (and motivates Challenge 6 if you want the v3.0 path).

## Performance Challenges

### Reduce lock contention under concurrent sessions

**The goal:** Let many sessions do crypto in parallel instead of serializing on the one global mutex.

**Current bottleneck:** Every entry point takes `state.mutex`. Two sessions signing at once serialize, even though their operations are independent.

**Approaches:**
- **Per-session operation state, lock only for shared state.** The op-state already lives in the `Session`; you could do the crypto outside the lock and only lock to fetch and commit, the way `C_Login` already does for Argon2id.
- **Per-slot locks.** Pairs with the multi-slot work in Challenge 9.

**Benchmark it:** Drive N threads each signing in a loop and measure throughput before and after. Watch for races; the generation-counter pattern in `state.zig` is your model for safe lock-release-relock.

## Security Challenges

### Prove constant-time behavior with Valgrind

**The goal:** Use Valgrind's memcheck and Zig's `classify` / `declassify` to detect any branch or memory access that depends on a secret.

**What you'll learn:** The closest thing to a constant-time verifier Zig has. `classify` marks secret memory as uninitialized to Valgrind, which then flags any conditional that depends on it.

**Implementation:** Add a debug build that classifies the PIN hash and key material before the crypto, run it under `valgrind --tool=memcheck --track-origins=yes`, and chase down any "conditional jump depends on uninitialised value" reports. The `16-constant-time-security.md` research note in `docs/zig/reference/` walks through the API.

**Testing the security:** A clean run with no conditional-on-secret warnings through a full sign and decrypt is the goal.

### Fuzz the persistence codec

**The goal:** Throw malformed token and object files at `parse` and confirm it always fails closed (clears to empty) and never crashes or reads out of bounds.

**Threat model:** This protects against a malicious or corrupted store file. The codec already has length and bounds checks; fuzzing proves they are complete.

**Implementation:** Generate random and mutated record bytes, feed them to `object_store.parse` and `token.loadFrom`, and assert the result is either a valid parse or a clean empty store, never a panic. The existing "rejects a bad magic" and "fails safe on a truncated record" tests are your starting points.

## Contribution Ideas

Finished something? Share it back:

1. Fork the repo.
2. Implement your extension in a branch, with unit tests against a published vector and a smoke-harness or `pkcs11-tool` proof.
3. Document it: update [CONFORMANCE.md](./CONFORMANCE.md) if you changed a boundary, and add a note to the relevant learn doc.
4. Open a PR with the implementation, the tests, and the external-tool proof.

Good extensions (a new mechanism with vectors, a real storage backend, the v3.0 surface) are exactly the kind of thing that makes the project more useful to the next person.

## Challenge Yourself Further

### Build something new

Use what you learned here to build:
- A **PKCS#11 provider for a different key type**, like Ed25519 or ML-DSA (both are in Zig's std), following the ECDSA path.
- A **minimal host** that loads any PKCS#11 module and exercises it, the consumer side of the interface you just implemented.

### Study real implementations

Read these and steal their good ideas:
- **SoftHSMv2** for the per-token directory store and the OpenSSL/Botan crypto abstraction.
- **OpenSC `pkcs11-spy`** for how a transparent shim logs every call, which is a clean piece of ABI engineering in its own right.

## Getting Help

Stuck on a challenge?

1. **Debug systematically.** What did you expect, what happened, what is the smallest input that reproduces it? Run the failing case through `just spy` and read the exact call and return code.
2. **Read the existing code.** The mechanism you are adding almost certainly has a sibling already implemented. The path is the same.
3. **Lean on the cross-check.** If you touched `ck.zig`, run `zig build test`; the ABI test will tell you precisely which field or constant diverged from the OASIS headers.

## Challenge Completion

Track your progress:

- [ ] Easy 1: SHA-224 digest
- [ ] Easy 2: configurable token info
- [ ] Easy 3: OpenSSL cross-verify recipe
- [ ] Intermediate 4: AES-192 via libcrypto
- [ ] Intermediate 5: per-object file backend
- [ ] Advanced 6: v3.0 `C_GetInterface`
- [ ] Advanced 7: v3.0 message API
- [ ] Advanced 8: fork safety
- [ ] Expert 9: SQLite, multi-token

Finished them all? You have built a multi-token, v3.0-capable software HSM with a real database backend and proven constant-time behavior. At that point you understand key custody at a level most working engineers never reach. Go read a real HSM vendor's PKCS#11 docs; you will recognize every design decision they made and why.
