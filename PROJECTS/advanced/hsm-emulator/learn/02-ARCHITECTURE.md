<!-- ©AngelaMos | 2026 -->
<!-- 02-ARCHITECTURE.md -->

# System Architecture

This document explains how the module is built and why it is built that way. It assumes you have read [01-CONCEPTS.md](./01-CONCEPTS.md).

## High Level Architecture

The module is three layers. A thin C-ABI façade takes calls from the host and validates them. A core-state layer owns the live token, sessions, and objects behind a single lock. A crypto layer does the actual mathematics and the storage codec. Calls flow down, results flow back up, and the only thing the host ever sees is the function table at the top.

```
   ┌──────────────────────────────────────────────────────────────┐
   │  HOST: pkcs11-tool, OpenSSL, p11-kit, Java SunPKCS11           │
   └───────────────────────────────┬──────────────────────────────┘
                                    │  C ABI, through a function-pointer table
                                    ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  LAYER 1  ABI façade                                           │
   │  main.zig          one exported symbol, the 68-slot table      │
   │  ck.zig            every CK_ type, constant, struct            │
   │  api/general       Initialize / Finalize / GetInfo             │
   │  api/slot_token    slot + token + mechanism queries, PIN admin │
   │  api/session       OpenSession / Login / Logout / op-state     │
   │  api/object        CreateObject / Find / GetAttributeValue     │
   │  api/crypto_ops    digest / sign / verify / encrypt / decrypt  │
   │  api/keymgmt       GenerateKey(Pair) / Wrap / Unwrap / Derive  │
   │  api/random        GenerateRandom / SeedRandom                 │
   └───────────────────────────────┬──────────────────────────────┘
                                    │  acquire() the instance under the lock
                                    ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  LAYER 2  core state  (one global Instance, one mutex)         │
   │  state             the Instance, init-args, generation counter │
   │  lock              the mutex (std.atomic.Mutex + spin/yield)   │
   │  session           session Table, op-state unions, GCM buffer  │
   │  object_store      attribute-bag objects, the persist codec    │
   │  token             the token record: PINs, fail counts, MK     │
   │  env               reads storage paths from std.c.environ      │
   └───────────────────────────────┬──────────────────────────────┘
                                    │  call the primitives
                                    ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  LAYER 3  crypto                                               │
   │  digest / mac      SHA-2, HMAC (pure Zig std.crypto)           │
   │  cipher            AES-CBC/CBC-PAD/GCM, RFC 3394 wrap (pure)    │
   │  ecdsa             P-256/384 sign/verify/keygen, ECDH (pure)   │
   │  rsa + openssl     RSA via libcrypto (hand-written extern)     │
   │  pin               Argon2id derive/verify (pure)               │
   │  keystore          master-key wrap, value seal/unseal (pure)   │
   └──────────────────────────────────────────────────────────────┘
```

### Component breakdown

**`main.zig` (the entry point).** Exports exactly one symbol, `C_GetFunctionList`, which hands the host a pointer to a static `CK_FUNCTION_LIST`. That table's 68 function pointers are wired to the `api/*` functions in canonical order. A `comptime` block asserts the table is `69 * @sizeOf(usize)` bytes (version plus 68 pointers) and that `CK_ATTRIBUTE` is 24 bytes, so an ABI regression cannot compile.

**`ck.zig` (the contract).** The hand-written Cryptoki v2.40 ABI: scalar typedefs, 200+ constants, every struct laid out for the Linux LP64 ABI with natural alignment, the function-pointer typedefs, and the `CK_FUNCTION_LIST` struct. Nothing in here executes; it is pure shape, and that shape is the agreement with the host.

**`api/*` (the entry points).** One file per group of `C_*` functions. Every entry point follows the same skeleton: acquire the instance under the lock, validate the session handle and arguments, do the work or dispatch into the crypto layer, set the in/out length, return the precise `CKR_*` code. These functions are where the spec's rules live (two-call length queries, the operation state machine, login gating).

**`core/state.zig` (the spine).** Owns the single global `Instance`: the allocator, the `std.Io` backend, the locking mode, the token, the session table, the object store, the current login role, and the unwrapped master key. It exposes `acquire()` (the only way to touch the instance), the init-args parser, and the generation counter used to make slow operations safe.

**`core/session.zig`, `core/object_store.zig`, `core/token.zig`.** The three data stores. Sessions hold per-session operation state. The object store holds objects and the persistence codec. The token holds authentication state and the wrapped master key.

**`crypto/*` (the math).** Stateless or self-contained primitives. Everything except RSA is pure-Zig `std.crypto`. RSA is `libcrypto` reached through hand-written `extern` declarations in `openssl.zig`.

## Data Flow

### Signing with an RSA key, end to end

Here is what happens when a host calls `C_Sign` after a `C_SignInit` with an RSA key. It shows every layer.

```
1. host: C_SignInit(session, {CKM_SHA256_RSA_PKCS}, hRsaPriv)
   api/crypto_ops C_SignInit
     state.acquire()                      -> lock, get the *Instance
     sessions.get(hSession)               -> the Session, or CKR_SESSION_HANDLE_INVALID
     signInitOp(...)                       -> classify the mechanism as RSA-sign,
                                             parse the scheme/digest params,
                                             fetch+validate the private key object
     sess.sign_op = .{ .rsa = { key, params, sig_len } }   (just the handle + params)
     return CKR_OK                         (unlock via defer)

2. host: C_Sign(session, data, dataLen, NULL, &sigLen)     (length query)
   api/crypto_ops C_Sign
     signLen(&sess.sign_op.?)             -> modulus length
     *pulSignatureLen = that; return CKR_OK

3. host: C_Sign(session, data, dataLen, sigBuf, &sigLen)   (real call)
   api/crypto_ops C_Sign, the .rsa arm
     rsaPrivateComponents(inst, op.key, CKA_SIGN)   -> re-fetch the components,
                                                       refuse if sealed or usage-denied
     rsa.sign(components, params, data, out)        -> crypto layer
       openssl.zig: rebuild EVP_PKEY from the components,
                    EVP_DigestSign (hash-then-sign) for SHA256-RSA-PKCS
     *pulSignatureLen = n
     sess.endSign()                       -> zeroize the op union, clear it
     return CKR_OK                         (unlock via defer)
```

Two design points stand out. First, the operation state stores only the key *handle* and the parsed parameters, never the key material; the components are re-fetched under the lock for the actual sign. Second, the two-call pattern (NULL buffer to learn the length, then the real buffer) is handled at the top, and a buffer-too-small answer does not consume the operation, exactly as the spec requires.

### Logging in, end to end

`C_Login` is the most interesting flow because it does an expensive Argon2id derivation that must not be done while holding the lock, and it has to defend against the token being reinitialized underneath it.

```
1. acquire(), validate the session, read the salt/hash and (for User) the wrapped MK
2. gen = cryptoBegin(); grab io + allocator; UNLOCK   <- release the lock for the slow part
3. pin.verify(...)                 -> Argon2id, the expensive part, no lock held
   keystore.unwrap(...)            -> if User, derive the KEK and unwrap the MK
4. LOCK again; cryptoEnd()
   if generation changed since step 2  -> someone reinitialized the token: abort
   commit: set logged_in, install the MK, object_store.unlock() to unseal secrets
   token.save(...); return CKR_OK
```

The `generation` counter is the safety net. `C_InitToken` and `C_InitPIN` bump it. If a second thread reinitialized the token during the long Argon2id call, the committing thread sees the generation has changed and refuses to apply its now-stale result. This is the classic time-of-check-to-time-of-use defense, made explicit.

## Design Patterns

### The acquire-and-defer template

Every fast entry point uses the same shape:

```zig
pub fn C_SomeOp(hSession: ck.CK_SESSION_HANDLE, ...) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    // ... do the work, return a precise CKR_* ...
}
```

`acquire()` locks the mutex and returns the instance only if the library is initialized; if not, it unlocks and returns null so the caller can answer `CKR_CRYPTOKI_NOT_INITIALIZED`. The `defer` guarantees the unlock on every return path. This pattern is used at roughly sixty entry points and is the reason the locking is uniform and hard to get wrong.

**Why this and not a lock-free instance accessor?** An earlier version exposed a lock-free `current()` that read the instance pointer without the lock. That had a window: `C_Finalize` could tear down the allocator and session table between the present-check and the actual lock. The fix was to make `acquire()` the only accessor and to verify `present` *under* the lock. There is now no way to touch the instance without holding the mutex.

### The snapshot-unlock-recheck template (for slow operations)

Argon2id takes real time (it is supposed to). Holding the global lock across it would serialize the whole module behind one login. So slow entry points (`C_Login`, `C_InitToken`, `C_InitPIN`, `C_SetPIN`) snapshot what they need, record the generation, release the lock, do the slow work, then re-lock and verify the generation before committing. This is the only safe way to run a long computation against shared state without freezing the world or risking a stale write.

### Tagged unions for operation state

A session can have one active operation of each kind. Each is a Zig tagged union that holds exactly the state that operation needs and nothing more:

```zig
pub const SignOp = union(enum) {
    mac: mac.Mac,         // HMAC: the running hash state
    ec:  ecdsa.SignState, // ECDSA: the curve, scalar, and accumulator
    rsa: RsaSig,          // RSA: just the key handle + parsed params
};
```

This keeps the operation state inline in the `Session` (no heap allocation for sign/verify/digest), makes "wrong mechanism for this call" a simple `switch` arm, and lets teardown zeroize the whole union in one `secureZero`. The one exception is GCM, which needs a growable buffer and so carries a heap slice (`GcmStream`).

## Layer Separation

```
┌────────────────────────────────────────────────────────┐
│  Layer 1: ABI façade  (ck.zig, api/*)                    │
│  - Validates handles, arguments, and the operation FSM   │
│  - Translates between the C ABI and Zig types            │
│  - Does NOT do cryptography or own state                 │
└────────────────────────────────────────────────────────┘
              ↓ may call into
┌────────────────────────────────────────────────────────┐
│  Layer 2: core state  (state, session, object_store,     │
│           token, lock, env)                              │
│  - Owns the single Instance behind the mutex             │
│  - Knows objects, sessions, login, persistence           │
│  - Does NOT speak the C ABI or pick return codes         │
└────────────────────────────────────────────────────────┘
              ↓ may call into
┌────────────────────────────────────────────────────────┐
│  Layer 3: crypto  (digest, mac, cipher, ecdsa, rsa,      │
│           pin, keystore, openssl)                        │
│  - Pure primitives: takes bytes, returns bytes/errors    │
│  - Does NOT know about sessions, handles, or the ABI     │
└────────────────────────────────────────────────────────┘
```

### Why layers

- **The crypto layer is testable in isolation.** Every file in `crypto/` has unit tests that run without a session or a token, against published vectors (NIST SP800-38A for AES-CBC, RFC 4231 for HMAC, RFC 3394 for key wrap, RFC 6979 for ECDSA). A bug in the math is caught there, not in an integration test.
- **The ABI layer can be cross-checked mechanically.** Because `ck.zig` is pure shape with no logic, `tests/abi_test.zig` can compare it field by field against the translated OASIS headers.
- **Return codes live in exactly one layer.** The crypto layer returns Zig errors; the ABI layer maps them to `CKR_*`. There is one `mapCipherErr`, one `mapSetErr`. A reader looking for "where does `CKR_DATA_LEN_RANGE` come from" has one place to look.

### What lives where

- **Layer 1** may import Layer 2 and Layer 3. It owns no mutable state of its own.
- **Layer 2** may import Layer 3. It never imports an `api/*` file (no upward dependency).
- **Layer 3** imports only `std`, `ck` (for constants and types), `config`, and for RSA the `openssl` bindings. It never reaches up.

## Data Models

### Object

An object is a bag of attributes. Each attribute is a type tag, a byte value, and a flag that says whether the value is currently sealed.

```zig
pub const Attribute = struct {
    type: ck.CK_ATTRIBUTE_TYPE,  // CKA_*
    value: []u8,                  // owned bytes
    sealed: bool = false,         // true when the value is GCM ciphertext at rest
};

pub const Object = struct {
    attrs: std.ArrayList(Attribute),
    // get / set / has / getBool / isToken / isPrivate / shouldSeal / clone / deinit
};
```

The `sealed` flag is the in-memory analogue of the at-rest envelope. While the User is logged in, sensitive values are plaintext and `sealed = false`. On logout they are re-encrypted in place and `sealed = true`. A crypto operation that finds a sealed value it needs returns `CKR_USER_NOT_LOGGED_IN`, which covers the case where a sensitive token key was loaded sealed and the user has not logged in to unseal it.

### Object store

A fixed array of 256 slots, each optionally holding an entry, with a monotonic handle counter that never reuses a handle.

```zig
pub const Store = struct {
    slots: [config.max_objects]?Entry = @splat(null),
    next_handle: ck.CK_OBJECT_HANDLE = 1,  // never reused, so stale handles stay invalid
};
```

Handle `0` is reserved as `CK_INVALID_HANDLE`. A host that holds a handle after `C_DestroyObject` and passes it back gets `CKR_OBJECT_HANDLE_INVALID`, not a recycled object, because the counter only ever moves forward.

### Session

```zig
pub const Session = struct {
    slot: ck.CK_SLOT_ID,
    flags: ck.CK_FLAGS,               // CKF_RW_SESSION, CKF_SERIAL_SESSION
    find: Find,                        // the active C_FindObjects cursor
    digest_op:  ?digest.Hasher,        // one active op of each kind, at most
    sign_op:    ?SignOp,
    verify_op:  ?VerifyOp,
    encrypt_op: ?EncryptOp,
    decrypt_op: ?DecryptOp,
    sign_recover_op:   ?RsaRecover,
    verify_recover_op: ?RsaRecover,
};
```

The session table is a fixed array of 64 slots. Opening a session scrubs the slot before reuse; closing it frees any heap (the GCM buffer) and zeroizes the slot. The whole table is wiped on `C_Finalize`.

### Token record

The token's authentication state is a small fixed struct, serialized to a fixed-size `extern struct` record on disk:

```zig
pub const Token = struct {
    initialized: bool,
    label: [32]u8,
    so:   PinSlot,           // SO salt + Argon2id hash
    user: ?PinSlot,          // User salt + hash, null until C_InitPIN
    so_fail: u32,            // failure counters for lockout
    user_fail: u32,
    user_mk: ?keystore.Wrapped,  // the master key, wrapped under the User KEK
};
```

`PinSlot` is a salt and a hash; the PIN itself is never present. `user_mk` is the wrapped master key: a salt, a nonce, the ciphertext, and a GCM tag. This is the entire authentication and at-rest-key state, and it fits in a few hundred bytes.

## Security Architecture

### Threat model

What the module is built to resist:

1. **Disk theft.** An attacker copies the token and object files. Sensitive values are sealed under a master key that is wrapped under the User PIN; the files are ciphertext without the PIN.
2. **Offline PIN attack.** The attacker has the files and runs a dictionary against the PIN. Argon2id (64 MiB, t=3) makes each guess expensive.
3. **Online PIN attack.** The attacker guesses against the live module. Three failures lock the token.
4. **Key export through the API.** A logged-in attacker tries to read or wrap out the key. Sensitive and unextractable refuse.
5. **Tampering at rest.** The attacker flips bytes in a sealed value. The GCM tag fails on unseal and the module fails closed.
6. **Privilege confusion.** An SO tries to read User secrets. There is no SO keyslot for them.
7. **Stale-result race.** A slow login races a token reinit. The generation counter rejects the stale commit.
8. **Memory residue.** A crash dump or cold-boot read tries to recover keys from freed or idle memory. Zeroization and the logout relock shrink that window.

What is explicitly out of scope:

- **Physical side channels.** Power analysis, electromagnetic emanation, and microarchitectural attacks like cachebleed are hardware problems. The software constant-time work addresses timing, not power. A real HSM adds physical countermeasures this software cannot.
- **A malicious host while the User is logged in.** PKCS#11's model trusts the calling process during a logged-in session. If the host is compromised while logged in, it can ask the module to sign anything. The module protects the *key*, not the host's intentions.
- **The Windows ABI.** The struct layout is the Linux/macOS LP64 natural-alignment ABI. Windows uses 1-byte packing and a 4-byte `CK_ULONG`, a separate build that is not targeted here.

### Defense in depth

```
   On disk:     sealed values (AES-256-GCM) + wrapped MK (AES-256-GCM under Argon2id KEK)
        ↓ C_Login unseals into RAM
   In RAM:      plaintext only while User-logged-in; relocked + MK wiped on logout/close/finalize
        ↓ a sensitive value needed by an op while sealed
   At the API:  CKR_USER_NOT_LOGGED_IN; sensitive reads -> CKR_ATTRIBUTE_SENSITIVE
        ↓ every comparison of a secret
   In compute:  constant-time PIN and MAC checks; uniform error codes on RSA decrypt
```

## Storage Strategy

There are two files, both paths resolved from the environment.

- **The token file** (`ANGELAMOS_HSM_TOKEN`, default `$HOME/.angelamos-hsm-token`). A single fixed-size record holding the auth state and the wrapped master key. Written with a temp-file-then-rename so a crash mid-write cannot leave a half-record.
- **The object file** (`ANGELAMOS_HSM_OBJECTS`, default `$HOME/.angelamos-hsm-objects`). A variable-length record holding only *token* objects (`CKA_TOKEN = CK_TRUE`); session objects are never persisted. Sensitive attribute values are sealed; public values are stored plaintext.

Both records carry a magic number and a version. The version was bumped when sealing was introduced, so an old plaintext-era file is rejected rather than misread. A corrupt object file parses to empty rather than crashing, so a damaged store degrades to "no objects" instead of undefined behavior.

This is the one place the design diverges from SoftHSM2, which uses a directory per token and a file per object (or a SQLite database). A single file is simpler and sufficient for an emulator; the per-object directory layout is noted as an extension in [04-CHALLENGES.md](./04-CHALLENGES.md).

## Configuration

Every tunable lives in `config.zig`. There are no magic numbers scattered through the code; a value like the GCM buffer cap or the Argon2id memory cost is named once and referenced everywhere.

```bash
ANGELAMOS_HSM_TOKEN     # path to the token record (default: $HOME/.angelamos-hsm-token)
ANGELAMOS_HSM_OBJECTS   # path to the object store (default: $HOME/.angelamos-hsm-objects)
```

Reading the environment at a C boundary is its own small problem: there is no `std.process` arena to lean on, so `env.zig` walks `std.c.environ` directly. Notable constants in `config.zig`: PIN length 4 to 255, Argon2id t=3 / m=64 MiB / p=1, three login attempts, AES 16 or 32-byte keys, RSA 2048 to 4096 bits, the 16 MiB GCM stream cap, 256 objects, 64 sessions.

## Performance Considerations

This is an emulator, so correctness and clarity are weighted above throughput. That said, the design avoids the obvious traps:

- **The global lock is released across Argon2id.** A login does not freeze every other session for the duration of the KDF. The lock is held only for the quick state reads and the final commit.
- **AES-NI when present.** `std.crypto.core.aes` selects the hardware AES path at compile time when the target has it, so CBC and GCM run on the CPU's AES unit, which is also constant-time by design.
- **Operation state is inline.** Sign, verify, and digest state live in the `Session` struct with no per-operation heap allocation. Only GCM, which must buffer the whole message, touches the heap.

The bottleneck under load is the single global mutex: this is a serial design, which matches PKCS#11's serial execution model (`C_GetFunctionStatus` and `C_CancelFunction` exist only for the long-dead parallel model and return `CKR_FUNCTION_NOT_PARALLEL`). Sharding by slot is possible but pointless here, since there is one slot.

## Design Decisions

### libcrypto for RSA, pure Zig for everything else

**What we chose:** AES, SHA-2, HMAC, ECDSA, ECDH, and Argon2id come from `std.crypto`. RSA links OpenSSL's `libcrypto`.

**Alternatives considered:** A pure-Zig RSA. Rejected because `std.crypto` has no public RSA (it exists privately inside the TLS code), and the available third-party Zig RSA libraries are either blind-signature-focused or not safe to trust. Hand-rolling RSA, with its padding schemes and constant-time requirements, is exactly the kind of thing you should not hand-roll.

**Trade-offs:** A C dependency and a slightly larger build. Mitigated by binding `libcrypto` through hand-written `extern` declarations rather than `@cImport`, and by a version script that exports only `C_GetFunctionList`, so none of OpenSSL's symbols leak out of the module.

### Selective sealing, not whole-file encryption

**What we chose:** Only sensitive attribute *values* are encrypted at rest. Public material stays plaintext.

**Alternatives considered:** Encrypting the entire object file under the master key. Rejected because public objects and public key material are meant to be visible before login (you can read a public key's modulus without a PIN). Encrypting everything would break that and force a login just to list the token.

**Trade-offs:** The codec is more complex (it has to decide per attribute), but the behavior is spec-correct and the public surface stays usable pre-login.

### A single User keyslot, no SO keyslot for secrets

**What we chose:** The master key is wrapped only under the User PIN. The SO can administer and reset, but has no path to the User's secret values.

**Alternatives considered:** A second keyslot wrapping the MK under the SO PIN, so the SO could recover. Rejected on principle: an SO who can read User keys is a backdoor. The cost is that there is no key recovery if the User PIN is lost, which is the correct trade for a security module.

### GCM buffered, not streamed through libcrypto

**What we chose:** AES-GCM accumulates the whole message and runs the authenticated operation once at `*Final`. Covered in [01-CONCEPTS.md](./01-CONCEPTS.md) and [MECHANICS.md](./MECHANICS.md).

**Alternatives considered:** Using libcrypto's EVP streaming-decrypt. Rejected because it releases unverified plaintext before the tag check. Buffering removes the RUP class of bug entirely, at the cost of a 16 MiB per-message bound.

## Error Handling Strategy

Errors come in two flavors and are handled in two places.

1. **Zig errors in the crypto layer.** A cipher failure, an out-of-memory, a malformed record. These are Zig `error` values. The crypto layer never picks a `CKR_*` code; it returns the error.
2. **`CKR_*` codes at the ABI layer.** Each entry point maps the Zig error to the precise return code the spec wants, through one of a handful of mappers (`mapCipherErr`, `mapSetErr`, the per-call switches). RSA decryption failures collapse to a single code so they cannot be used as a padding oracle.

The guiding rule is **fail closed**. If a re-seal at logout fails (say, out of memory), the plaintext is scrubbed in place anyway (`scrubUnsealed`) so a failed cleanup never leaves a secret in the clear. If a slow operation cannot prove its result is still current, it returns `CKR_FUNCTION_FAILED` rather than commit stale state.

## Extensibility

### Adding a new mechanism

The mechanism list is data, not code. To add one:

1. Add the `CKM_*` constant to `ck.zig` (the ABI test will cross-check it against the OASIS header automatically).
2. Add it to `config.supported_mechanisms` and give it a `CK_MECHANISM_INFO` arm in `slot_token.zig`'s `C_GetMechanismInfo`.
3. Implement the primitive in a `crypto/*` file with unit tests against a published vector.
4. Wire it into the relevant `crypto_ops.zig` or `keymgmt.zig` dispatch (the `modeOf` / `hashModeOf` / `isRsa*Mech` helpers).

The layered design means each step is local: the math lands in Layer 3 with its own tests, the dispatch in Layer 1.

### Where v3.0 would go

PKCS#11 v3.0 adds a second entry point, `C_GetInterface`, and 24 functions including the message-based AEAD family. The ABI is laid out so a `CK_FUNCTION_LIST_3_0` (the same prefix plus the new pointers) can be added beside the existing table, and `C_GetInterface` exported alongside `C_GetFunctionList`. This is the largest of the [04-CHALLENGES.md](./04-CHALLENGES.md) extensions.

## Limitations

These are conscious trade-offs, not bugs.

1. **One slot, one token.** A real HSM exposes many slots. Here there is exactly one, always present. Multi-slot would mean sharding the global state per slot.
2. **Single-file storage.** No per-object files, no database. Fine for an emulator; a directory backend is the SoftHSM2 approach and a listed extension.
3. **AES-128 and AES-256 only.** Zig's standard library has no 192-bit AES. Supporting it would mean routing AES-192 through libcrypto like RSA.
4. **No v3.0 surface.** v2.40 only, by scope. The structure leaves room for it.
5. **Linux/macOS ABI.** The Windows packed layout is a separate build.

## Comparison to Similar Systems

### SoftHSM2

The reference open-source software HSM, and the model this project follows.

- **Same:** the three-layer façade / store / crypto split, the two-call attribute handling, the per-token PIN with encrypted private-key material, the OpenSSL crypto backend for RSA.
- **Different:** SoftHSM2 stores each object as a file under a per-token directory (or in SQLite); this uses one object file. SoftHSM2 supports multiple tokens and slots; this has one. SoftHSM2 is C++; this is Zig with a machine-checked ABI, which SoftHSM2 does not have.

### A real hardware HSM (Thales Luna, AWS CloudHSM, YubiHSM)

- **Same interface.** A host cannot tell the difference at the API level; that is the point of PKCS#11.
- **Different boundary.** A hardware HSM enforces custody with a physical chip and tamper response. This enforces it with process boundaries and software discipline. The software version resists the threats in the model above; it does not resist an attacker with physical access and an oscilloscope.

## Key Files Reference

Quick map of where to find things:

- `src/ck.zig`: the ABI. Start here.
- `src/main.zig`: the exported symbol and the wired table.
- `src/core/state.zig`: the instance, `acquire()`, the generation counter.
- `src/api/session.zig`: login, the snapshot-unlock-recheck pattern in `C_Login`.
- `src/api/crypto_ops.zig`: the whole sign/verify/encrypt/decrypt surface.
- `src/core/object_store.zig`: objects and the sealing codec.
- `src/crypto/keystore.zig`: the envelope (wrap/unwrap, seal/unseal).
- `src/crypto/cipher.zig`: AES modes and RFC 3394 key wrap.

## Next Steps

Now that you understand the design:
1. Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) to walk the actual code of the ABI, an end-to-end operation, and the secret-handling patterns.
2. Read [MECHANICS.md](./MECHANICS.md) for the cryptographic details of each mechanism.
3. Try modifying `config.supported_mechanisms` and watch the ABI test and `C_GetMechanismInfo` respond.
