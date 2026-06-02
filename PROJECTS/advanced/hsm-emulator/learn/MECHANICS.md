<!-- ©AngelaMos | 2026 -->
<!-- MECHANICS.md -->

# How the Mechanisms Actually Work

The [conformance statement](./CONFORMANCE.md) tells you *what* each mechanism does and which return code it gives. This document tells you *how* each one works under the hood, byte by byte, and why the implementation looks the way it does. If [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) is the tour of the plumbing, this is the tour of the water.

Everything here except RSA is pure-Zig `std.crypto`, tested against published vectors. RSA is libcrypto. Each section names the file you can open to read the real thing.

## The Short Version

| Family | Mechanisms | Where the math is | Backed by |
|--------|-----------|-------------------|-----------|
| Digest | SHA-256 / 384 / 512 | `digest.zig` | `std.crypto.hash.sha2` |
| MAC | HMAC-SHA-256 / 384 / 512 | `mac.zig` | `std.crypto.auth.hmac` |
| AES | CBC, CBC-PAD, GCM | `cipher.zig` | `std.crypto.core.aes`, `aead.aes_gcm` |
| Key wrap | AES-KEY-WRAP (RFC 3394) | `cipher.zig` | the AES block on top |
| ECDSA | P-256, P-384, raw and SHA-256 | `ecdsa.zig` | `std.crypto.sign.ecdsa` |
| ECDH | P-256, P-384, `CKD_NULL` | `ecdsa.zig` | `std.crypto.ecc` |
| RSA | PKCS#1 v1.5, PSS, OAEP | `rsa.zig` + `openssl.zig` | OpenSSL `libcrypto` |
| KDF | Argon2id (PIN stretching) | `pin.zig` | `std.crypto.pwhash.argon2` |
| Envelope | AES-256-GCM seal/wrap | `keystore.zig` | `std.crypto.aead.aes_gcm` |

A theme runs through all of them: the dangerous part of each primitive is handled by a tested standard-library function, and the module's own code is the wiring, the validation, and the constant-time and memory hygiene around it.

## AES-CBC: chaining blocks

CBC (Cipher Block Chaining) turns a block cipher, which only encrypts one 16-byte block, into something that encrypts a whole message. The trick is that each plaintext block is XORed with the previous ciphertext block before encryption, so identical plaintext blocks do not produce identical ciphertext.

```
   P0        P1        P2
   │         │         │
IV─XOR    ┌─►XOR    ┌─►XOR        (IV seeds the very first XOR)
   │      │  │      │  │
  AES     │ AES     │ AES
   │      │  │      │  │
   ▼      │  ▼      │  ▼
   C0─────┘  C1─────┘  C2
```

In `cipher.zig`, one encrypt step is exactly that XOR-then-encrypt, with the chain value updated to the new ciphertext:

```zig
fn cbcEncStep(self: *Cipher, in16: *const [block]u8, out16: *[block]u8) void {
    var x: [block]u8 = undefined;
    defer std.crypto.secureZero(u8, &x);     // the XOR scratch held plaintext, scrub it
    for (0..block) |j| x[j] = in16[j] ^ self.chain[j];
    encBlockRaw(self.key(), &x, out16);
    self.chain = out16.*;                      // chain forward
}
```

Decryption reverses it: decrypt the block, then XOR with the previous ciphertext (held in `chain`). The chain advances to the input block, not the output.

Plain `CKM_AES_CBC` has no padding, so the input must be a whole number of blocks. A partial trailing block is an error (`CKR_DATA_LEN_RANGE`), because there is nothing to do with 5 leftover bytes. The IV arrives in the mechanism parameter and seeds `chain`.

## AES-CBC-PAD: padding, and the held-back block

`CKM_AES_CBC_PAD` adds PKCS#7 padding so any length encrypts. PKCS#7 is simple: if you need `n` bytes of padding, append `n` copies of the byte `n`. If the message is already block-aligned, you add a whole block of `0x10` (16) so there is always padding to remove.

```
   message ...... |  pad
   "ABCDE"  (5)   |  0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B   (11 bytes of 0x0B)
                     └──────────── 11 = pad length ────────────┘
```

`encryptFinal` writes the padding into the last partial block and encrypts it:

```zig
const padlen: u8 = @intCast(block - self.partial_len);
for (self.partial_len..block) |j| self.partial[j] = padlen;
self.cbcEncStep(&self.partial, out[0..block]);
```

Decryption is where it gets subtle. The decryptor cannot strip padding until it knows it has the *last* block, but in streaming mode it does not know which block is last until the stream ends. So CBC-PAD decrypt **holds back one block**: each time a full block arrives, it emits the *previous* held block and holds the new one. `decryptFinal` decrypts the final held block and strips the padding. This held-back behavior is exactly why CBC-PAD cannot participate in the decrypt side of a dual function (the digest would miss the last block); see [CONFORMANCE.md](./CONFORMANCE.md) section 2.2.

The padding check is constant-time. A naive check returns as soon as a pad byte is wrong, which leaks where it failed (the Vaudenay padding-oracle attack, and Lucky Thirteen against TLS). This module ORs all the differences first, then decides once:

```zig
const padlen = pt[block - 1];
if (padlen == 0 or padlen > block) return Error.EncryptedDataInvalid;
var bad: u8 = 0;
for (0..block) |j| {
    const is_pad = j >= block - padlen;
    if (is_pad) bad |= pt[j] ^ padlen;     // accumulate, do not branch out early
}
if (bad != 0) return Error.EncryptedDataInvalid;
```

## AES-GCM: authenticated, and why it is buffered here

GCM (Galois/Counter Mode) does two things at once: it encrypts with AES in counter mode, and it computes an authentication tag over the ciphertext and the associated data using multiplication in a Galois field. The tag is the whole value of GCM: decryption verifies it, and a wrong tag means the ciphertext was tampered with (or you used the wrong key or nonce).

```
   nonce(12) + counter ──► AES ──► keystream ──XOR──► ciphertext
                                                          │
   AAD + ciphertext ──► GHASH (GF(2^128) mult) ──► tag(16)
```

This module uses the standard library's one-shot GCM, with a 12-byte (96-bit) nonce and a 128-bit tag, and up to 256 bytes of associated data:

```zig
aesgcm.Aes256Gcm.encrypt(out[0..input.len], tag, input, ad, self.iv, self.key_buf[0..32].*);
```

The 96-bit nonce is the standard choice: it is used directly as the initial counter without the extra hashing a different length would require. The fixed 128-bit tag is the full-strength tag; truncated tags weaken authentication.

**Why buffered.** A streaming GCM decrypt that releases plaintext block by block would hand back unverified bytes before it has seen the tag. That is release of unverified plaintext, and it is an anti-pattern for a security module (see [01-CONCEPTS.md](./01-CONCEPTS.md)). This module accumulates the whole message in `GcmStream` and runs the authenticated operation once at `*Final`, where decrypt verifies the tag before returning a single byte. The buffer is capped at 16 MiB so a host cannot exhaust memory. The cost is that GCM is single-message-bounded; the benefit is that RUP is impossible by construction.

On a bad tag, decryption returns `error.EncryptedDataInvalid` and no plaintext. The standard library zeroes the output buffer internally before returning the error, so failed decryption leaves nothing usable behind.

## AES Key Wrap (RFC 3394): encrypting a key with a key

You cannot just AES-encrypt a key and call it wrapped; you want the result to be tamper-evident, so a corrupted wrapped key is *rejected* rather than unwrapped into garbage. RFC 3394 AES Key Wrap does this with a fixed initial value (the integrity check value, ICV) and six passes over the data.

The ICV is the constant `A6 A6 A6 A6 A6 A6 A6 A6`. Wrapping prepends it, then runs 6 rounds where each 64-bit block of the key is mixed with a running `A` register through the AES block cipher and a counter:

```zig
var a: [8]u8 = key_wrap_iv;                 // A6 A6 ... A6
// for j in 0..6, for each 64-bit block i:
@memcpy(blk[0..8], &a);
@memcpy(blk[8..16], r[i * 8 ..][0..8]);
encBlockRaw(kek, &blk, &enc);                // B = AES(A | R[i])
@memcpy(&a, enc[0..8]);                       // A = MSB64(B)
xorCounter(&a, n * j + i + 1);                // A ^= t (the round counter)
@memcpy(r[i * 8 ..][0..8], enc[8..16]);       // R[i] = LSB64(B)
```

Unwrapping runs the rounds backward and then checks that the recovered `A` equals the ICV. If a single bit of the wrapped key was flipped, `A` will not match `A6...A6`, and the unwrap fails. The check is done by ORing the differences (not an early-exit compare), and on failure the partial output is scrubbed:

```zig
var diff: u8 = 0;
for (a, key_wrap_iv) |x, y| diff |= x ^ y;
if (diff != 0) {
    std.crypto.secureZero(u8, out[0..plain_len]);
    return WrapError.Integrity;             // -> CKR_WRAPPED_KEY_INVALID at the API
}
```

The implementation is verified against the RFC 3394 section 4.1 known-answer test: wrapping the test key under the test KEK produces the exact published ciphertext, and unwrapping round-trips. The 8-byte ICV is why a wrapped key is 8 bytes longer than the key it wraps.

## SHA-2 and HMAC: hashing and keyed hashing

SHA-256, SHA-384, and SHA-512 are the digest mechanisms. The `Hasher` in `digest.zig` is a tagged union over the three, and multi-part hashing (`C_DigestUpdate` repeatedly) just feeds the running state:

```zig
pub const Hasher = union(enum) {
    sha256: sha2.Sha256,
    sha384: sha2.Sha384,
    sha512: sha2.Sha512,
};
```

A digest is verified against the classic `SHA-256("abc")` vector in the unit tests and again in the smoke harness through the real `.so`.

The interesting part is **operation-state serialization**. `C_GetOperationState` lets a host snapshot a digest mid-stream and resume it later with `C_SetOperationState`. The module serializes the raw hasher state with a version byte and a type tag:

```
   [version=1][tag: 1=sha256 2=sha384 3=sha512][raw hasher state bytes]
```

```zig
out[0] = config.op_state_version;
out[1] = d.stateTag();
d.writeState(out[config.op_state_header_len..]);
```

This blob is **same-build only**: it carries the in-memory layout of the standard library's hasher, which is not promised stable across builds or implementations. The spec allows exactly this (operation state is not portable), and restore validates the version, the tag, and the exact length, failing closed on anything else. Only digest state is saveable; trying to save a sign or encrypt operation returns `CKR_STATE_UNSAVEABLE`.

HMAC (`mac.zig`) is the keyed-hash construction `H(key ⊕ opad || H(key ⊕ ipad || message))`, but you do not implement that by hand; the standard library's `HmacSha256` and friends do. The module's job is to verify the tag in constant time, which `crypto_ops.zig` does with `ctEql`. HMAC-SHA-256 is checked against RFC 4231 test case 2.

## ECDSA: signing on a curve

ECDSA signs over an elliptic curve. This module supports NIST P-256 and P-384, with two mechanisms: `CKM_ECDSA` (you supply an already-hashed value) and `CKM_ECDSA_SHA256` (the module hashes the message with SHA-256 first).

### The curve and the key encoding

The curve is identified by an OID in DER, stored in `CKA_EC_PARAMS`. P-256 is `06 08 2A 86 48 CE 3D 03 01 07`, P-384 is `06 05 2B 81 04 00 22`. `curveFromParams` matches the bytes:

```zig
pub fn curveFromParams(ec_params: []const u8) ?Curve {
    if (std.mem.eql(u8, ec_params, &oid_p256)) return .p256;
    if (std.mem.eql(u8, ec_params, &oid_p384)) return .p384;
    return null;
}
```

The public key is a point in SEC1 uncompressed form: a `0x04` byte followed by the X and Y coordinates. For P-256 that is `1 + 32 + 32 = 65` bytes; the `CKA_EC_POINT` attribute wraps it in a DER `OCTET STRING`, so the stored value is 67 bytes (the `0x04 0x41` DER header plus the 65-byte point). `wrapEcPoint` and `unwrapEcPoint` handle that wrapping, including the long-form DER length encoding for P-384's larger point.

### Prehash, reduce, sign

The message (or its hash) is reduced to a scalar by taking the leftmost bytes equal to the curve's order size, which is what ECDSA does with a hash that may be a different width than the curve:

```zig
fn reduce(curve: Curve, dgst: []const u8, out: *[max_scalar]u8) []const u8 {
    const n = curve.scalarLen();
    if (dgst.len >= n) @memcpy(out[0..n], dgst[0..n])     // take the leftmost n bytes
    else // left-pad with zeros
}
```

The actual signing uses `signPrehashed`. One subtlety worth knowing: Zig's deterministic ECDSA is not plain RFC 6979. It mixes in a noise field, so the signature is not a fixed function of the message and key. That means you cannot pin a sign-output known-answer test (two signatures of the same message differ), so the test suite uses an RFC 6979 vector as a *verify* known-answer test instead, and round-trips its own signatures. The noise comes from `randomSecure`, with a fallback to deterministic if entropy is unavailable:

```zig
const nz: ?[slen]u8 = if (io.randomSecure(&noise)) |_| noise else |_| null;
const sig = kp.signPrehashed(ph, nz) catch return Error.Crypto;
```

A P-256 signature is 64 bytes (r and s, 32 each); P-384 is 96. Verification reconstructs the public key from the SEC1 point, validates the point is on the curve, and checks the signature. The smoke harness signs over the module, verifies, then flips a byte and confirms `CKR_SIGNATURE_INVALID`.

## ECDH: agreeing on a shared secret

ECDH (`CKM_ECDH1_DERIVE`) lets two parties with EC keypairs compute the same shared secret without ever transmitting it. Each multiplies their own private scalar by the other's public point; the math guarantees both arrive at the same point, and the secret is that point's X coordinate.

```
   Alice:  secret = X-coordinate of (alice_private * bob_public)
   Bob:    secret = X-coordinate of (bob_private * alice_public)
   alice_private * bob_public == bob_private * alice_public   (same point)
```

The implementation multiplies the peer point by the scalar and takes the affine X coordinate:

```zig
const peer = Pt.fromSec1(peer_point_sec1) catch return Error.Crypto;  // validates on-curve
const shared = peer.mul(s, .big) catch return Error.Crypto;
const xb = shared.affineCoordinates().x.toBytes(.big);
@memcpy(out[0..n], xb[0..n]);
```

`fromSec1` rejects a point that is not on the curve, which is the defense against invalid-curve attacks (feeding a carefully chosen off-curve point to leak the private scalar). The module supports only the `CKD_NULL` key-derivation function, meaning the raw shared X coordinate is the derived key with no further KDF, and it accepts the peer point either as raw SEC1 or DER-wrapped. The derived value is correct to the bit: the smoke harness derives on both sides and asserts they match, and a cross-process test confirms it equals `openssl pkeyutl -derive` byte for byte. The smoke harness even derives one side with a raw peer point and the other with a DER-wrapped one and confirms both agree.

## RSA: three schemes, one modular exponentiation

RSA is the one family this module does not implement itself. Zig's standard library has no public RSA, so `rsa.zig` calls OpenSSL's `libcrypto` through the hand-written `extern` declarations in `openssl.zig`. Every RSA operation is a single modular exponentiation over the whole input, so RSA has no multi-part form (no `C_SignUpdate`); you use the one-shot calls.

Keys are stored PKCS#11-native: the modulus and public exponent are public, and the private side keeps the private exponent plus the four CRT (Chinese Remainder Theorem) values that make private operations about four times faster. The public exponent is fixed at 65537 (the F4 prime), the universal default. `rsa.zig` is stateless: it rebuilds an `EVP_PKEY` from these components on every call rather than holding one.

The three schemes differ in how they pad before the exponentiation:

**PKCS#1 v1.5** (`CKM_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`). The classic padding. For signing, the message (or its hash, wrapped in a DigestInfo) is padded with `00 01 FF FF ... FF 00` up to the modulus size. Simple and everywhere, but its decryption form is the one vulnerable to the Bleichenbacher oracle, which is why decryption failures here collapse to one uniform return code.

**PSS** (`CKM_RSA_PKCS_PSS`, `CKM_SHA256_RSA_PKCS_PSS`). Probabilistic Signature Scheme. It mixes a random salt into the padding, so signing the same message twice gives different signatures, and it has a security proof PKCS#1 v1.5 lacks. The module requires the MGF hash to equal the content hash and rejects mismatches:

```zig
if (mgfHash(pp.mgf) != h) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
```

**OAEP** (`CKM_RSA_PKCS_OAEP`). Optimal Asymmetric Encryption Padding, for encryption and key wrapping. It is the encryption counterpart to PSS: randomized, with a proof, and the recommended replacement for PKCS#1 v1.5 encryption precisely because it resists Bleichenbacher.

The split between hash-then-sign and raw is visible in `sign`. When a digest is specified, it uses `EVP_DigestSign` (which hashes then signs); when the input is already a hash, it uses `EVP_PKEY_sign` directly:

```zig
if (p.digest != .none) {
    // EVP_DigestSignInit + EVP_DigestSign: hash the message, then sign
} else {
    // EVP_PKEY_sign: sign the pre-hashed value as-is
}
```

Sign/VerifyRecover (`C_SignRecover` / `C_VerifyRecover`) use PKCS#1 v1.5's property that the message is recoverable from the signature. The module offers recover only for `CKM_RSA_PKCS`, and it checks the data fits the modulus with the 11-byte v1.5 overhead before signing.

## Argon2id: turning a weak PIN into a strong key

A PIN is low-entropy, so the stored form has to be expensive to attack and the derived KEK has to be strong. Argon2id, the winner of the Password Hashing Competition, is memory-hard: each guess must allocate and traverse a large block of memory, which defeats the massive parallelism a GPU or ASIC brings to a fast hash.

The parameters in `config.zig` are `t = 3` iterations, `m = 64 MiB`, `p = 1` lane. Each PIN guess costs 64 MiB of memory and three passes over it. `pin.zig` derives the 32-byte output from the PIN and a random 16-byte salt:

```zig
pub fn derive(io: std.Io, allocator: std.mem.Allocator, pin: []const u8, salt: *const Salt, out: *Hash) !void {
    try argon2.kdf(allocator, out, pin, salt, params, .argon2id, io);
}
```

The same derivation does double duty. For authentication, the output is compared (constant-time) against the stored hash. For the envelope, the output is the key-encryption key that wraps the master key. The `id` variant blends the data-independent and data-dependent modes, giving resistance to both side-channel and time-memory-tradeoff attacks.

## The Envelope: sealing values and wrapping the master key

The at-rest scheme has two GCM operations, both in `keystore.zig`.

**Wrapping the master key.** The master key (32 random bytes) is encrypted under the KEK derived from the PIN. The wrapped form is salt, nonce, ciphertext, and tag, stored in the token record. A wrong PIN derives a wrong KEK, the GCM tag fails, and `unwrap` returns false rather than a bogus key:

```zig
gcm.decrypt(out, &w.ct, w.tag, "", w.nonce, kek) catch {
    std.crypto.secureZero(u8, out);
    return false;
};
```

**Sealing a value.** Each sensitive attribute value is GCM-encrypted under the master key, with the attribute *type* as associated data, and a fresh nonce per seal:

```zig
pub fn seal(io: std.Io, mk: *const MasterKey, ad: []const u8, plain: []const u8, out: []u8) !usize {
    var nonce: [nonce_len]u8 = undefined;
    try io.randomSecure(&nonce);            // fresh nonce every time
    @memcpy(out[0..nonce_len], &nonce);
    const ct = out[nonce_len..][0..plain.len];
    const tag = out[nonce_len + plain.len ..][0..tag_len];
    gcm.encrypt(ct, tag, plain, ad, nonce, mk.*);
    return sealedLen(plain.len);
}
```

The associated data binds the ciphertext to its attribute type. Unseal of a value whose `ad` does not match the type it is being loaded into fails the tag, so a sealed `CKA_PRIVATE_EXPONENT` cannot be swapped into a `CKA_VALUE` slot. The fresh nonce per seal is what keeps GCM safe; reusing a nonce under the same key is GCM's one catastrophic foot-gun, and the design never does.

A sealed value is `nonce_len + plaintext_len + tag_len` bytes, which is `12 + n + 16`. The on-disk record stores that length so unseal knows where the ciphertext ends and the tag begins.

## Constant-Time and Zeroization: the cross-cutting mechanics

These are not mechanisms a host calls, but they are the machinery that makes the mechanisms safe.

**Constant-time comparison.** Any compare of a secret has to look at every byte regardless of where the first mismatch is, or the time it takes leaks the position. Fixed-size secrets (the PIN hash) use `std.crypto.timing_safe.eql`, which XORs all elements into one accumulator and tests it branchlessly. Variable-length MACs use `ctEql`, the same idea by hand. The CBC-PAD and RFC 3394 checks fold all their differences before deciding, for the same reason.

**Zeroization.** A secret left in freed or idle memory can be recovered from a crash dump, a swapped page, or a cold-boot read. The module zeroes secrets with `std.crypto.secureZero`, which takes a `[]volatile` slice:

```zig
pub fn secureZero(comptime T: type, s: []volatile T) void {
    @memset(s, 0);
}
```

The `volatile` is the whole point. A plain `@memset(&key, 0)` with no subsequent read is a dead store the optimizer is free to delete. Marking the slice volatile tells the compiler the write is an observable side effect that must happen. This is the same technique every serious C crypto library uses, and Zig builds it into one auditable function. Stack secrets pair it with `defer`; heap secrets go through `secureFree`; session operation state zeroes itself on teardown; logout re-seals and wipes the master key. The net effect is that an idle, logged-out token holds no plaintext key material anywhere.

One Zig-specific wrinkle: in Debug and ReleaseSafe builds, setting an optional to null poisons its payload to `0xAA`, and `Allocator.free` memsets freed memory to `0xAA`. So after a `secureZero`-then-null you see `0xAA`, not zeros. The secret is destroyed (it is `0xAA`, not the key), it is simply not zero. The tests therefore assert "the secret pattern is gone", not "all bytes are zero". In a release build without those safety memsets, the explicit `secureZero` is what does the work.

## Picking a Mechanism

Most of the time the choice is dictated by what you are interoperating with, but here is the guidance the design encodes:

- **Symmetric encryption:** prefer GCM (`CKM_AES_GCM`). It authenticates, so tampering is detected. Use CBC-PAD only when a peer requires unauthenticated CBC, and pair it with a separate MAC if you do.
- **RSA encryption / key transport:** prefer OAEP (`CKM_RSA_PKCS_OAEP`). PKCS#1 v1.5 encryption is the Bleichenbacher target; OAEP is the modern replacement.
- **RSA signatures:** prefer PSS (`CKM_RSA_PKCS_PSS`). It has a security proof v1.5 lacks. Use v1.5 (`CKM_SHA256_RSA_PKCS`) for compatibility with systems that expect it.
- **Signatures in general:** ECDSA gives you the same security as RSA with far smaller keys and signatures (a P-256 signature is 64 bytes versus 256 for RSA-2048). Prefer it when both ends support it.
- **Key wrapping:** AES-KEY-WRAP (RFC 3394) for wrapping a symmetric key under another symmetric key; RSA-OAEP for wrapping under a public key.
- **Key agreement:** ECDH (`CKM_ECDH1_DERIVE`) to derive a shared secret from two EC keypairs.

## The Detail Behind ECDSA Determinism

If you are curious why the test suite verifies an external vector but cannot assert its own sign output:

Plain RFC 6979 ECDSA is fully deterministic: the nonce is a function of the message and the private key, so signing the same message twice yields the same signature, and you can pin a known-answer test on the output. Zig's `signPrehashed`, however, mixes an optional noise field into the nonce derivation (a hedged-signature design that adds defense against fault attacks). That makes the output non-deterministic, so two signatures of the same message differ.

The consequence for testing is that you verify against RFC 6979 (a known signature must validate under the known key) but you cannot assert that your own signing reproduces the RFC 6979 signature byte for byte. The suite does both of the things you *can* do: it uses the RFC 6979 vector as a verify known-answer test, and it round-trips its own signatures (sign, then verify, then tamper and confirm rejection). This is the correct way to test a hedged signature scheme, and it is worth understanding so the test design does not look like a gap.

## Next Steps

1. Read [CONFORMANCE.md](./CONFORMANCE.md) for the exact parameter rules and return codes at every boundary of these mechanisms.
2. Open `src/crypto/cipher.zig` and read the RFC 3394 test, then `src/crypto/ecdsa.zig` and read the ECDH both-sides test. The tests are short and show each mechanism end to end.
3. Try the extensions in [04-CHALLENGES.md](./04-CHALLENGES.md), several of which add a mechanism and walk you through the same wiring you have now seen for the existing ones.
