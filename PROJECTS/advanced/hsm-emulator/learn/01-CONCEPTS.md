<!-- ©AngelaMos | 2026 -->
<!-- 01-CONCEPTS.md -->

# Core Security Concepts

This document explains the security ideas the project is built on. These are not just definitions. Each one is tied to a real failure and to the exact code in this module that defends against it.

## Key Custody: the application must never see the key

### What it is

An HSM exists to enforce one rule: the secret key goes in once and never comes back out in usable form. The application that needs a signature does not get the key and compute the signature itself. It hands the HSM a request, and the HSM computes the signature inside its own boundary and returns only the result. The key material never crosses back over the line.

In PKCS#11 this rule is expressed through two attributes on a key object:

- `CKA_SENSITIVE = CK_TRUE` means the value of the key cannot be read back through the API. Asking for `CKA_VALUE` returns `CKR_ATTRIBUTE_SENSITIVE`, not the bytes.
- `CKA_EXTRACTABLE = CK_FALSE` means the key cannot be wrapped out (encrypted and exported) either.

### Why it matters

If the key is just a variable in your process, then any bug that reads process memory reads the key. The 2014 **Heartbleed** bug (CVE-2014-0160) was exactly this: a missing bounds check in OpenSSL let a remote attacker read up to 64 KB of server memory per request, and private TLS keys were among the things people pulled out. Servers whose keys lived in an HSM were not exposed the same way. The key was never in the web server's address space to leak.

### How it works here

When you generate a key, the module marks the secret material sensitive and unextractable by default, and it computes the two "always" flags the spec requires. From `keymgmt.zig`:

```zig
if (!obj.has(ck.CKA_SENSITIVE)) try obj.set(allocator, ck.CKA_SENSITIVE, &[_]u8{ck.CK_TRUE});
if (!obj.has(ck.CKA_EXTRACTABLE)) try obj.set(allocator, ck.CKA_EXTRACTABLE, &[_]u8{ck.CK_FALSE});
const always_sensitive: u8 = if (obj.getBool(ck.CKA_SENSITIVE)) ck.CK_TRUE else ck.CK_FALSE;
const never_extractable: u8 = if (!obj.getBool(ck.CKA_EXTRACTABLE)) ck.CK_TRUE else ck.CK_FALSE;
```

When a host then tries to read that value, `object.zig`'s `sensitiveProtected` check fires before any bytes are copied, and `C_GetAttributeValue` reports the value length as `CK_UNAVAILABLE_INFORMATION` and returns `CKR_ATTRIBUTE_SENSITIVE`. The key is usable for signing (you pass its *handle* to `C_SignInit`) but its bytes are unreachable.

You can watch this in the smoke harness: after generating an AES key, the harness asks for `CKA_VALUE` and asserts the answer is `CKR_ATTRIBUTE_SENSITIVE`, not the key.

### Common attacks

1. **Memory disclosure.** A buffer over-read (Heartbleed), an uninitialized-memory leak, or a crash dump that ships off-box. If the key was never in your memory in plaintext, the leak yields nothing useful.
2. **Key export through the API.** An attacker who gains a session tries to simply read the key out. `CKA_SENSITIVE` refuses. They try to wrap it out with `C_WrapKey`. `CKA_EXTRACTABLE = CK_FALSE` refuses with `CKR_KEY_UNEXTRACTABLE`.
3. **Cold disk theft.** Someone copies the token file. The sensitive values in it are sealed (see encryption at rest, below), so the file is ciphertext.

### Defense strategies

The whole module is the defense, but the core moves are: mark secrets sensitive and unextractable by default, gate every read through one chokepoint (`sensitiveProtected`), and never construct a code path that returns raw secret bytes to the caller. Operations take *handles*, not keys.

## The Login Model: public objects, private objects, and roles

### What it is

A PKCS#11 token has two roles: the **Security Officer** (SO), who administers the token and sets up the User, and the **User**, who actually uses the keys. Objects are either *public* (visible to anyone with a session) or *private* (`CKA_PRIVATE = CK_TRUE`, visible only after the User logs in).

### Why it matters

The role split is what lets you hand someone a token without handing them the keys on it. The SO can initialize and reset, but in a correct design the SO cannot read the User's secrets. If the administrator role could read user key material, "administrator" would just be a second word for "attacker who got admin".

### How it works here

Visibility is one function, `object_store.visible`:

```zig
pub fn visible(obj: *const Object, logged_in: ?ck.CK_USER_TYPE) bool {
    if (!obj.isPrivate()) return true;
    return logged_in == ck.CKU_USER;
}
```

Every object-facing entry point (`C_FindObjects`, `C_GetAttributeValue`, `C_DestroyObject`, the key fetches inside `crypto_ops.zig`) calls this first. A private object simply does not exist to a caller who has not logged in as User. The smoke harness proves it: it creates a private object, logs out, runs `C_FindObjects`, and asserts the private object does not appear and that fetching it returns `CKR_OBJECT_HANDLE_INVALID`. The object is not just hidden from listings; it is unreachable by handle.

Critically, this module gives the SO **no keyslot for user secrets**. The master key that protects sensitive values is wrapped only under the User PIN (see below). An SO who resets the token can wipe it, but cannot read what was there. That is a deliberate design choice, documented in [CONFORMANCE.md](./CONFORMANCE.md) section 4.

### Common attacks

1. **Privilege confusion.** An attacker with SO access tries to read User keys. The absence of an SO keyslot means there is nothing for the SO to decrypt with.
2. **Pre-login enumeration.** An attacker without credentials lists objects hoping private keys leak into the listing. `visible` keeps them out.

## Authentication: stretching the PIN, and locking the door

### What it is

The User and SO authenticate with a PIN. A PIN is short and low-entropy by nature (often four to eight digits), so two things must be true: the stored form must be expensive to attack offline, and online guessing must be rate-limited to a hard stop.

### Why it matters

If you store the PIN itself, or a fast hash of it, an attacker who steals the token file runs a dictionary in seconds. The 2012 **LinkedIn breach** leaked 6.5 million unsalted SHA-1 password hashes; because SHA-1 is fast and the hashes were unsalted, most were cracked almost immediately. A PIN protected by a fast hash is no better.

### How it works here

The PIN is stretched with **Argon2id**, the memory-hard KDF that won the Password Hashing Competition. From `config.zig` and `pin.zig`:

```zig
const params: argon2.Params = .{
    .t = config.pin_kdf_t,      // 3 iterations
    .m = config.pin_kdf_m_kib,  // 64 MiB of memory
    .p = config.pin_kdf_p,      // 1 lane
};
```

Each guess costs 64 MiB of memory and three passes over it, which collapses the throughput of a brute-force rig. Only a random 16-byte salt and the 32-byte derived hash ever touch disk. The PIN is never stored in any form. Verification is constant-time:

```zig
pub fn verify(io: std.Io, allocator: std.mem.Allocator, pin: []const u8, salt: *const Salt, expected: *const Hash) !bool {
    var got: Hash = undefined;
    defer std.crypto.secureZero(u8, &got);
    try derive(io, allocator, pin, salt, &got);
    return std.crypto.timing_safe.eql(Hash, got, expected.*);
}
```

For online guessing, the token counts failures and locks after three. From `slot_token.zig`, the token info reflects the count low / final try / locked flags, and `C_Login` refuses once the counter reaches the limit:

```zig
if (inst.token.user_fail >= config.login_max_attempts) {
    state.mutex.unlock();
    return ck.CKR_PIN_LOCKED;
}
```

The smoke harness drives three wrong PINs and asserts the fourth attempt returns `CKR_PIN_LOCKED` and that `CKF_USER_PIN_LOCKED` is set in the token flags.

### Common pitfalls

**Mistake: comparing the hash with a normal equality check**
```zig
// Bad: std.mem.eql returns as soon as it finds a mismatched byte.
// The time it takes leaks how many leading bytes matched.
return std.mem.eql(u8, &got, expected);

// Good: timing_safe.eql looks at every byte before deciding.
return std.crypto.timing_safe.eql(Hash, got, expected.*);
```

**Mistake: a fast hash for the PIN**
```zig
// Bad: a thief with the file runs billions of SHA-256 guesses per second.
var h: [32]u8 = undefined;
std.crypto.hash.sha2.Sha256.hash(pin, &h, .{});

// Good: Argon2id makes each guess cost 64 MiB and three passes.
try argon2.kdf(allocator, &h, pin, &salt, params, .argon2id, io);
```

## Encryption at Rest and the Envelope Pattern

### What it is

The token persists to a file so keys survive a restart. The sensitive values in that file are encrypted. The clever part is *how* the encryption key is managed: a random per-token **master key** (MK) encrypts the secrets, and the MK is itself encrypted ("wrapped") under a key derived from the User PIN. This two-level scheme is the **envelope** pattern.

### Why it matters

Encrypting each secret directly under a PIN-derived key sounds simpler, but it means changing the PIN requires re-encrypting every secret. With the envelope, changing the PIN re-wraps one 32-byte master key and nothing else. It also means the expensive Argon2id derivation happens once per login, not once per object. AWS KMS, Google Tink, and every serious secrets system use envelope encryption for these reasons.

The threat it answers is plaintext storage of secrets, CWE-312 (cleartext storage of sensitive information). A token file that is just key bytes on disk is a single `cat` away from total compromise.

### How it works here

```
   User PIN ──Argon2id──▶ KEK ──AES-256-GCM wrap──▶ wrapped MK (on disk, in the token record)
                                                          │
                                                  C_Login unwraps with the KEK
                                                          ▼
   random master key (MK) ──AES-256-GCM seal──▶ sealed secret values (on disk, in the object file)
```

`keystore.zig` holds the two halves. `wrap` derives the KEK from the PIN and GCM-encrypts the MK; `unwrap` reverses it, and a wrong PIN fails the GCM tag and returns false rather than garbage:

```zig
pub fn unwrap(io: std.Io, allocator: std.mem.Allocator, pin_bytes: []const u8, w: *const Wrapped, out: *MasterKey) !bool {
    var kek: MasterKey = undefined;
    defer std.crypto.secureZero(u8, &kek);
    try deriveKek(io, allocator, pin_bytes, &w.salt, &kek);
    gcm.decrypt(out, &w.ct, w.tag, "", w.nonce, kek) catch {
        std.crypto.secureZero(u8, out);
        return false;
    };
    return true;
}
```

`seal` and `unseal` protect the individual attribute values, binding each one to its attribute type as associated data so a sealed `CKA_PRIVATE_EXPONENT` cannot be swapped in where a `CKA_VALUE` was expected. The object store seals *selectively*: only the sensitive values (the AES key bytes, the RSA private exponent and CRT factors, the EC scalar) are encrypted. Public material (the modulus, the EC point, labels) stays plaintext so it is visible before login, which is spec-correct.

### Common attacks

1. **Disk theft.** The file is sealed under a key the thief does not have. Without the PIN, the MK stays wrapped.
2. **Tampering.** Flipping a byte in a sealed value breaks the GCM tag on unseal, and the module fails closed. The store-level tests flip a byte and assert `error.AuthFailed`.
3. **Downgrade.** An attacker swaps in an old token file from before a PIN change. The MK in that file is wrapped under the old KEK, so the new PIN cannot unwrap it. The record version is also bumped, so an old plaintext-era file is rejected outright.

## Release of Unverified Plaintext (RUP)

### What it is

AES-GCM is an authenticated cipher: decryption both decrypts and verifies a 128-bit tag, and the tag is what tells you the ciphertext was not tampered with. A *streaming* decrypt that returns plaintext chunk by chunk has a problem: it hands you bytes before it has seen the tag. If you act on those bytes and the tag later turns out to be wrong, you acted on attacker-controlled data. That is release of unverified plaintext.

### Why it matters

For an HSM this is unacceptable. The whole point is to be trustworthy about what it returns. Returning plaintext that has not been authenticated, even briefly, is a foothold for chosen-ciphertext attacks. The cryptographic community treats RUP resistance as a property a serious AEAD usage must have.

### How it works here

The module makes RUP impossible by construction. GCM is implemented as a **buffered** operation: `C_EncryptUpdate` and `C_DecryptUpdate` append to an internal buffer and emit zero bytes, and the real work happens once at `C_*Final`, where decrypt verifies the tag before any plaintext is released. The accumulator lives in `session.zig` as `GcmStream`, and it is bounded to 16 MiB so a host cannot exhaust memory by streaming forever:

```zig
pub fn append(self: *GcmStream, allocator: std.mem.Allocator, bytes: []const u8) error{ OutOfMemory, TooLarge }!void {
    if (bytes.len == 0) return;
    const needed = self.len + bytes.len;
    if (needed > config.max_gcm_stream_len) return error.TooLarge;
    ...
}
```

The smoke harness streams a multi-block message through `C_DecryptUpdate` in 19-byte chunks, asserts that every update emits zero bytes, and only gets the plaintext at `C_DecryptFinal`. It then flips a byte and confirms decryption returns `CKR_ENCRYPTED_DATA_INVALID` with no plaintext released.

## Side Channels: timing, and zeroizing memory

### What it is

A side channel is information that leaks through *how* a computation runs rather than its output: how long it took, what memory it touched, what the cache state is afterward. Two side channels matter most for a key-handling module: timing (a comparison that exits early reveals where it stopped) and residue (a secret left in freed memory after use).

### Why it matters

**Timing.** The 1998 **Bleichenbacher attack** and its 2017 revival **ROBOT** recovered RSA-encrypted secrets by measuring how a server responded to malformed PKCS#1 v1.5 ciphertexts. **Lucky Thirteen** (2013) did the same against TLS CBC padding using timing alone. The lesson: any branch whose timing depends on a secret is a leak.

**Residue.** The 2008 **cold boot attack** (Halderman et al.) showed that DRAM retains its contents for seconds to minutes after power loss, long enough to dump and recover keys. If a key sits in freed memory, a crash dump, a swapped-out page, or a cold-boot read can recover it.

### How it works here

Comparisons of secrets are constant-time. PIN verification uses `std.crypto.timing_safe.eql`; MAC verification in `crypto_ops.zig` uses a hand-rolled `ctEql` that ORs every byte difference before deciding:

```zig
fn ctEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}
```

Secrets are zeroized when they go out of scope. Stack secrets use `defer std.crypto.secureZero(...)`; the session operation unions zeroize themselves on teardown; the object store frees every secret value through `secureFree`, which scrubs before releasing:

```zig
fn secureFree(allocator: std.mem.Allocator, value: []u8) void {
    std.crypto.secureZero(u8, value);
    allocator.free(value);
}
```

`secureZero` takes a `[]volatile` slice precisely so the compiler is forbidden from optimizing the write away as dead (it has no subsequent read). On logout the whole store re-seals and the master key is wiped, so an idle, logged-out token holds no plaintext secrets in RAM. [MECHANICS.md](./MECHANICS.md) covers the constant-time and zeroization mechanics in more depth.

### Common pitfalls

**Mistake: zeroizing through a non-volatile slice**
```zig
// Bad: with no later read, the optimizer may delete this @memset entirely.
@memset(&key, 0);

// Good: secureZero forces the store to happen.
std.crypto.secureZero(u8, &key);
```

**Mistake: a padding oracle through distinct error codes**
```zig
// Bad: returning a different error for "bad padding" vs "bad MAC" tells an
// attacker which step failed, which is what Bleichenbacher/Lucky13 exploit.

// Good: this module maps RSA decrypt failures to one uniform CKR code and
// lets libcrypto handle the padding check in constant time. CBC-PAD padding
// verification ORs all the pad bytes before deciding, no early exit.
```

## How These Concepts Relate

The concepts are layers of one system. Each depends on the one below it.

```
   Key custody (sensitive, unextractable)
            │ requires
            ▼
   The login model (who may see what)
            │ requires
            ▼
   Authentication (Argon2id PIN + lockout)
            │ unlocks
            ▼
   Encryption at rest (envelope: PIN -> KEK -> MK -> sealed secrets)
            │ relies on
            ▼
   Authenticated encryption done safely (GCM, no RUP)
            │ relies on
            ▼
   Side-channel hygiene (constant-time compares, zeroized memory)
```

If the constant-time compare leaks, the PIN falls. If the PIN falls, the envelope opens. If the envelope opens, the login model is moot and key custody is broken. The strength of the chain is the strength of its weakest link, which is why the module is uniform about all of them.

## Industry Standards and Frameworks

### OWASP Top 10 (2021)

- **A02:2021 Cryptographic Failures.** The headline category. This project is a study in not committing them: strong KDF for the PIN, AES-256-GCM for storage, fresh nonces, authenticated encryption, no home-grown primitives except where they are textbook (CBC mode assembly, RFC 3394 wrap) and tested against published vectors.
- **A04:2021 Insecure Design.** The envelope pattern, the SO-cannot-read-User-secrets decision, and RUP-safe GCM are design-level choices, not bolt-ons.
- **A07:2021 Identification and Authentication Failures.** The PIN lockout and the role model address brute force and privilege confusion.

### MITRE ATT&CK

- **T1552 Unsecured Credentials** and **T1555 Credentials from Password Stores.** An HSM is the countermeasure: credentials that authenticate everything else are not sitting in a readable store.
- **T1003 OS Credential Dumping.** Zeroization and never-in-plaintext-memory custody reduce what a memory dump yields.
- **T1588.004 / T1649 Obtain or Forge Certificates.** Keeping signing keys unextractable is what stops a breach from minting forged certificates, the DigiNotar failure mode.

### CWE

- **CWE-312 Cleartext Storage of Sensitive Information.** Defended by the encrypted-at-rest envelope.
- **CWE-316 Cleartext Storage in Memory.** Defended by zeroization and the logout relock.
- **CWE-208 Observable Timing Discrepancy.** Defended by constant-time comparison.
- **CWE-326 Inadequate Encryption Strength** and **CWE-327 Use of a Broken or Risky Cryptographic Algorithm.** Defended by AES-256-GCM, Argon2id, and standard signature schemes.
- **CWE-522 Insufficiently Protected Credentials.** Defended by Argon2id stretching and lockout.

## Real World Examples

### Case study: Heartbleed (CVE-2014-0160, 2014)

A missing bounds check in OpenSSL's TLS heartbeat let a remote attacker read server memory in 64 KB chunks. Private keys, session cookies, and passwords all leaked. The defense that worked was custody: organizations whose private keys lived in an HSM did not leak those keys, because the keys were never in the vulnerable process's memory. This project's `CKA_SENSITIVE` enforcement and zeroization are the same principle in miniature.

### Case study: the Bleichenbacher family (1998, ROBOT 2017)

Daniel Bleichenbacher showed that an RSA decryption oracle which reveals whether PKCS#1 v1.5 padding was valid lets an attacker decrypt a ciphertext with about a million queries. Nineteen years later ROBOT found the same flaw still live in major TLS stacks because the "fixes" were not uniform. The takeaway baked into this module: never let the error you return depend on which internal check failed, and prefer OAEP, whose design resists the attack. RSA decrypt failures here collapse to one return code.

## Testing Your Understanding

Before moving on, make sure you can answer these.

1. A host generates an AES key, then immediately calls `C_GetAttributeValue` for `CKA_VALUE`. What does it get back, and which function decided that? What would the answer be for `CKA_MODULUS_BITS` on an RSA public key, and why is that different?
2. Walk the envelope from a User PIN to a decrypted secret value. Name each key in the chain and what encrypts what. Why does changing the PIN not require re-encrypting every object?
3. Why does `C_DecryptUpdate` for AES-GCM return zero bytes every time, and where does the plaintext actually appear? What attack would a chunk-by-chunk release enable?
4. The SO can reset the token. Why can the SO not read the User's keys? Point to the design decision that makes that true.

If any of these are fuzzy, re-read the matching section. The implementation will make far more sense once these click.

## Further Reading

**Essential:**
- [PKCS#11 v2.40 Base Specification (OASIS)](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html). The contract this module implements. Read the function semantics and the object model sections.
- [SoftHSMv2](https://github.com/softhsm/SoftHSMv2). The reference open-source software HSM. This project borrows its three-layer split and its object store idea.

**Deep dives:**
- Bleichenbacher, "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1" (CRYPTO 1998), and the ROBOT writeup at robotattack.org for the modern recurrence.
- Halderman et al., "Lest We Remember: Cold Boot Attacks on Encryption Keys" (USENIX Security 2008), the motivation for `secureZero`.
- The Argon2 paper and RFC 9106 for why a memory-hard KDF beats a fast hash for low-entropy secrets.

**Historical context:**
- The original RSA Security PKCS#11 documents (pre-OASIS) for how the standard came to look the way it does, and why "the function list is the API".
