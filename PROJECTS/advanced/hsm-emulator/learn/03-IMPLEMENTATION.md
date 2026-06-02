<!-- ©AngelaMos | 2026 -->
<!-- 03-IMPLEMENTATION.md -->

# Implementation Guide

This document walks the actual code. It assumes you have read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md). Code is referenced by file and function name so you can open the file and search for it. Snippets are real, lightly trimmed for focus.

## File Structure Walkthrough

```
src/
├── ck.zig             # the hand-written ABI: types, constants, structs, the function list
├── main.zig           # exports C_GetFunctionList, wires the 68-slot table, comptime asserts
├── config.zig         # every constant: sizes, KDF params, the mechanism list
├── util.zig           # padded(): space-pad a fixed C string field at comptime
├── core/
│   ├── state.zig       # the global Instance, acquire(), the generation counter, finalize()
│   ├── lock.zig        # the mutex
│   ├── env.zig         # storage-path resolution from std.c.environ
│   ├── token.zig       # the token record + atomic save/load
│   ├── session.zig     # the session Table, op-state unions, the GcmStream buffer
│   └── object_store.zig# the Object/Store types + the persistence codec with sealing
├── api/
│   ├── general.zig     # Initialize / Finalize / GetInfo / WaitForSlotEvent
│   ├── slot_token.zig  # slot/token/mechanism queries + InitToken / InitPIN / SetPIN
│   ├── session.zig     # OpenSession / Login / Logout / Get+SetOperationState
│   ├── object.zig      # CreateObject / Find / GetAttributeValue / SetAttributeValue
│   ├── crypto_ops.zig  # the digest/sign/verify/encrypt/decrypt/dual surface (the big one)
│   ├── keymgmt.zig     # GenerateKey(Pair) / WrapKey / UnwrapKey / DeriveKey
│   └── random.zig      # GenerateRandom / SeedRandom
└── crypto/
    ├── openssl.zig     # hand-written extern EVP/BN/OSSL_PARAM declarations
    ├── pin.zig         # Argon2id derive / verify
    ├── digest.zig      # the SHA-2 Hasher union + serializable state
    ├── mac.zig         # the HMAC-SHA-2 Mac union
    ├── cipher.zig      # AES-CBC/CBC-PAD/GCM + RFC 3394 key wrap
    ├── ecdsa.zig       # P-256/384 keygen, sign, verify, ECDH
    ├── rsa.zig         # the stateless libcrypto RSA bridge
    └── keystore.zig    # the envelope: master-key wrap/unwrap, value seal/unseal
```

## Building the ABI: the contract with the host

### The hand-written types

`ck.zig` is the whole agreement with the host, and it is pure shape. The scalar types map to the Linux LP64 ABI:

```zig
pub const CK_BYTE = u8;
pub const CK_ULONG = c_ulong;   // 8 bytes on LP64 Linux/macOS; this is the #1 ABI hazard
pub const CK_RV = CK_ULONG;
pub const CK_SESSION_HANDLE = CK_ULONG;
pub const CK_OBJECT_HANDLE = CK_ULONG;
```

Using `c_ulong` (not `u64`) is deliberate: it is whatever the platform's C `unsigned long` is, which is exactly what the host's headers use. Get this wrong and every struct field after the first `CK_ULONG` is at the wrong offset, and the host silently reads garbage.

The structs are plain `extern struct` with natural alignment. No `packed`, no `align(1)`:

```zig
pub const CK_ATTRIBUTE = extern struct {
    type: CK_ATTRIBUTE_TYPE,
    pValue: ?*anyopaque,
    ulValueLen: CK_ULONG,
};
```

The spec text says structures are 1-byte packed, but on Linux and macOS the real headers set no packing pragma and use natural alignment. That is the de-facto ABI every Linux host actually uses, so `extern struct` is correct and `packed` would be wrong.

### The function list and the one exported symbol

The heart of the ABI is `CK_FUNCTION_LIST`: a version followed by 68 function pointers in a fixed order that you cannot reorder. `main.zig` builds one static instance of it and exports the single symbol that hands out its address:

```zig
export fn C_GetFunctionList(ppFunctionList: *?*ck.CK_FUNCTION_LIST) callconv(.c) ck.CK_RV {
    ppFunctionList.* = &function_list;
    return ck.CKR_OK;
}

var function_list: ck.CK_FUNCTION_LIST = .{
    .version = ck.CK_VERSION{ .major = 2, .minor = 40 },
    .C_Initialize = general.C_Initialize,
    .C_Finalize = general.C_Finalize,
    // ... every one of the 68 slots, in canonical order ...
    .C_WaitForSlotEvent = general.C_WaitForSlotEvent,
};
```

Every slot points at a real `callconv(.c)` function. None is null, because a host calls through these pointers without checking, and a null slot segfaults inside the host. Operations that are deliberately unsupported point at a real function that returns the right `CKR_*` code, never at null.

### Proving the layout at compile time

`main.zig` will not compile if the table is the wrong size:

```zig
comptime {
    std.debug.assert(@sizeOf(ck.CK_FUNCTION_LIST) == 69 * @sizeOf(usize));
    std.debug.assert(@sizeOf(ck.CK_ATTRIBUTE) == 24);
}
```

The table is the version plus 68 pointers, so 69 pointer-widths. `CK_ATTRIBUTE` is three eight-byte fields, so 24. These are cheap, but the real proof is the build-time cross-check against the OASIS headers, covered later.

### The version script

`pkcs11.map` is what keeps everything else hidden:

```
PKCS11_2_40 {
    global:
        C_GetFunctionList;
    local:
        *;
};
```

`build.zig` applies it with `lib.setVersionScript`. Everything except `C_GetFunctionList` is `local`, so `objdump -T zig-out/lib/libhsm.so` shows exactly one exported symbol. The other `C_*` functions are reachable only through the table, and none of libcrypto's symbols leak.

## Building an entry point: the acquire-and-defer template

Every fast entry point has the same skeleton. `C_GetSessionInfo` from `api/session.zig` is a clean example:

```zig
pub fn C_GetSessionInfo(hSession: ck.CK_SESSION_HANDLE, pInfo: *ck.CK_SESSION_INFO) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const s = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    pInfo.* = .{
        .slotID = s.slot,
        .state = sessionState(s.flags, inst.logged_in),
        .flags = s.flags,
        .ulDeviceError = 0,
    };
    return ck.CKR_OK;
}
```

`state.acquire()` is the only way to touch the instance. Its implementation locks the mutex, verifies the library is initialized *under the lock*, and unlocks-and-returns-null if not:

```zig
pub fn acquire() ?*Instance {
    mutex.lock();
    if (!@atomicLoad(bool, &present, .acquire)) {
        mutex.unlock();
        return null;
    }
    return &storage;
}
```

The `defer state.mutex.unlock()` in the caller guarantees the lock is released on every path, including the early `CKR_SESSION_HANDLE_INVALID` return. This is why there is no lock-leak: you cannot forget the unlock because `defer` runs it for you.

### The two-call length pattern

Variable-length outputs use the spec's two-call dance: pass a null buffer to learn the size, then pass a real buffer. Here is the encrypt path from `crypto_ops.zig`, the AES arm:

```zig
const need: ck.CK_ULONG = @intCast(cipher.encryptOutLen(c.mode, in.len));
if (pEncryptedData == null) {
    pulEncryptedDataLen.* = need;          // first call: report the size
    return ck.CKR_OK;
}
if (pulEncryptedDataLen.* < need) {
    pulEncryptedDataLen.* = need;          // buffer too small: report size again
    return ck.CKR_BUFFER_TOO_SMALL;        // and do NOT consume the operation
}
```

The important subtlety is that a `CKR_BUFFER_TOO_SMALL` does not tear down the operation. The host is expected to retry with a bigger buffer, and the operation state must still be there when it does. A successful single-shot call, on the other hand, *does* end the operation (you will see `sess.endEncrypt(...)` after the bytes are written).

## Logging in: the snapshot-unlock-recheck pattern

`C_Login` in `api/session.zig` is the most careful function in the codebase, because it does an expensive Argon2id derivation that must not run while holding the global lock, and it must not commit a stale result if the token was reinitialized during that derivation.

Step one: acquire, validate, and read out what the slow part needs. Then record the generation, grab the io and allocator, and release the lock:

```zig
const gen = state.cryptoBegin();   // returns the current generation, marks an op in flight
const io = inst.io();
const allocator = inst.allocator();
state.mutex.unlock();              // release the lock for the slow part
defer std.crypto.secureZero(u8, &hash);
```

Step two: the slow work, with no lock held. Verify the PIN, and if this is a User login, unwrap the master key:

```zig
const ok = pin.verify(io, allocator, pinSlice(pPin, ulPinLen), &salt, &hash) catch {
    state.cryptoAbort();
    return ck.CKR_FUNCTION_FAILED;
};
// ... if ok and userType == CKU_USER, keystore.unwrap(...) the master key ...
```

Step three: re-lock, and refuse if the world changed underneath us:

```zig
state.mutex.lock();
defer state.mutex.unlock();
state.cryptoEnd();
if (state.currentGeneration() != gen) return ck.CKR_FUNCTION_FAILED;  // token was reinitialized
if (inst.logged_in != null) return ck.CKR_USER_ALREADY_LOGGED_IN;
if (ok) {
    inst.logged_in = userType;
    if (have_mk) {
        inst.mk = mk;
        object_store.unlock(allocator, &inst.objects, mk) catch {
            inst.relock();
            inst.logged_in = null;
            return ck.CKR_FUNCTION_FAILED;
        };
    }
    token.save(inst.io(), inst.token) catch {};
    return ck.CKR_OK;
}
```

The `generation` check is the time-of-check-to-time-of-use defense made explicit. `C_InitToken` and `C_InitPIN` call `state.bumpGeneration()`. If one of them ran while this login was deriving Argon2id, the committing thread sees `currentGeneration() != gen` and throws its stale result away rather than logging into a token that no longer exists in the form it checked.

On success, `object_store.unlock` walks every sealed sensitive value and decrypts it in place with the now-unwrapped master key. If that fails (a corrupt sealed value), the function relocks and refuses the login, so a damaged store cannot leave you half-unsealed.

## The object store and the sealing codec

### Objects are attribute bags

`object_store.zig` models an object as a list of attributes, each with a `sealed` flag. `set` replaces or appends, securely freeing the old value and clearing any stale sealed flag:

```zig
pub fn set(self: *Object, allocator: std.mem.Allocator, t: ck.CK_ATTRIBUTE_TYPE, bytes: []const u8) !void {
    if (bytes.len > config.max_attr_value_len) return error.AttrTooLarge;
    if (self.findPtr(t)) |a| {
        const dup = try allocator.dupe(u8, bytes);
        secureFree(allocator, a.value);   // scrub the old value before freeing
        a.value = dup;
        a.sealed = false;                  // a fresh plaintext value is not sealed
        return;
    }
    // ... append a new attribute ...
}
```

### What gets sealed

`shouldSeal` decides whether a given attribute on a given object is secret material that must be encrypted at rest. It is secret if the type is one of the key-material attributes (the AES/HMAC value, or the RSA private exponent and CRT factors) and the object is marked sensitive or unextractable:

```zig
pub fn shouldSeal(self: *const Object, t: ck.CK_ATTRIBUTE_TYPE) bool {
    if (!isSecretMaterial(t)) return false;
    if (self.getBool(ck.CKA_SENSITIVE)) return true;
    return self.has(ck.CKA_EXTRACTABLE) and !self.getBool(ck.CKA_EXTRACTABLE);
}
```

A public value (a modulus, an EC point, a label) returns false and is stored plaintext, so it stays readable before login.

### The codec: seal on the way out, mark sealed on the way in

`serialize` writes only token objects, and seals each sensitive value as it writes it:

```zig
if (!a.sealed and e.obj.shouldSeal(a.type)) {
    const key = mk orelse return error.NoMasterKey;
    const scratch = try allocator.alloc(u8, keystore.sealedLen(a.value.len));
    defer allocator.free(scratch);
    const wrote = try keystore.seal(io, &key, std.mem.asBytes(&a.type), a.value, scratch);
    // append the sealed bytes
} else {
    // append the plaintext value
}
```

Note `std.mem.asBytes(&a.type)` as the associated data: the attribute's type is bound into the GCM tag, so a sealed `CKA_PRIVATE_EXPONENT` cannot be moved into a slot expecting a `CKA_VALUE` without breaking authentication.

`parse` reads the values back and, after loading, marks the sensitive ones sealed so they are not treated as usable plaintext until `C_Login` unseals them. The whole load is fail-safe: a bad magic, a bad version, a truncated record, or too many attributes all cause the store to clear to empty rather than crash.

## The RUP-safe GCM buffer

`GcmStream` in `session.zig` is the accumulator that makes streaming GCM safe. `append` grows a heap buffer, secure-zeroing the old backing on every realloc, and enforces the 16 MiB cap:

```zig
pub fn append(self: *GcmStream, allocator: std.mem.Allocator, bytes: []const u8) error{ OutOfMemory, TooLarge }!void {
    if (bytes.len == 0) return;
    const needed = self.len + bytes.len;
    if (needed > config.max_gcm_stream_len) return error.TooLarge;
    if (self.buf == null or self.buf.?.len < needed) {
        var new_cap: usize = if (self.buf) |b| b.len else 256;
        while (new_cap < needed) new_cap *|= 2;
        if (new_cap > config.max_gcm_stream_len) new_cap = config.max_gcm_stream_len;
        const fresh = try allocator.alloc(u8, new_cap);
        if (self.buf) |old| {
            @memcpy(fresh[0..self.len], old[0..self.len]);
            std.crypto.secureZero(u8, old);   // scrub the old buffer, it held plaintext
            allocator.free(old);
        }
        self.buf = fresh;
    }
    @memcpy(self.buf.?[self.len..][0..bytes.len], bytes);
    self.len += bytes.len;
}
```

In `crypto_ops.zig`, `C_EncryptUpdate` and `C_DecryptUpdate` for the GCM arm append and report zero bytes written. The real GCM call happens in `C_*Final`, where for decrypt the tag is verified before any plaintext is returned. The smoke harness drives a multi-block message through `C_DecryptUpdate` in 19-byte chunks and asserts every update emits zero, then gets the plaintext only at `C_DecryptFinal`.

## The RSA bridge to libcrypto

`rsa.zig` is stateless. It never holds an `EVP_PKEY` across calls; it rebuilds one from the PKCS#11-native components each time. `generate` extracts the components out of a freshly generated key:

```zig
pub fn generate(bits: u32) Error!Generated {
    const ctx = ossl.EVP_PKEY_CTX_new_id(ossl.pkey_rsa, null) orelse return Error.Crypto;
    defer ossl.EVP_PKEY_CTX_free(ctx);
    if (ossl.EVP_PKEY_keygen_init(ctx) <= 0) return Error.Crypto;
    if (ossl.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, @intCast(bits)) <= 0) return Error.Crypto;
    var pkey: ?*ossl.EVP_PKEY = null;
    if (ossl.EVP_PKEY_generate(ctx, &pkey) <= 0) return Error.Crypto;
    defer ossl.EVP_PKEY_free(pkey);
    // extract n, e, d, p, q, dmp1, dmq1, iqmp into a Generated struct
}
```

`sign` rebuilds the key from the stored components, then either hash-then-signs (for `CKM_SHA256_RSA_PKCS` and the PSS variants) or signs a pre-hashed value directly (`CKM_RSA_PKCS` raw). The components are passed in fresh each call; the operation state in the session held only the handle.

The bindings in `openssl.zig` are hand-written `extern fn` declarations, not `@cImport`. This is what keeps the production `.so` clean: there is no translated header pulling symbols in, and the version script exports nothing but `C_GetFunctionList`. One detail worth seeing is the use of `BN_clear_free` rather than `BN_free` for the private BIGNUMs:

```zig
pub extern fn BN_clear_free(a: ?*BIGNUM) void;  // zeroes the BIGNUM before freeing
```

`BN_free` does not zero the memory; `BN_clear_free` does. The private components (d, p, q, the CRT values) are freed with `BN_clear_free` so they are not left in freed heap.

## Secret-handling patterns

The same handful of patterns appear everywhere a secret lives.

**Stack secrets: defer secureZero.** A derived hash, a master key on the stack, a decrypted buffer:

```zig
var hash: pin.Hash = undefined;
defer std.crypto.secureZero(u8, &hash);
```

`secureZero` takes a `[]volatile` slice, which forbids the compiler from deleting the write as dead store. A plain `@memset(&hash, 0)` with no later read can be optimized away; `secureZero` cannot.

**Heap secrets: secureFree.** Every attribute value is freed through one function that scrubs first:

```zig
fn secureFree(allocator: std.mem.Allocator, value: []u8) void {
    std.crypto.secureZero(u8, value);
    allocator.free(value);
}
```

**Operation state: zeroize on teardown.** The session op unions zero themselves when an operation ends. `endSign`, `endEncrypt`, and friends call into the union's `zeroize`/`deinit` (which `secureZero`s the whole union and frees any heap), then null the field. The session `Table` scrubs slots on open, close, and a full `wipeAll` at `C_Finalize`.

**Logout: relock and wipe.** `inst.relock()` re-seals every sensitive value and wipes the master key:

```zig
pub fn relock(self: *Instance) void {
    if (self.mk) |*mk| object_store.lock(self.io(), self.allocator(), &self.objects, mk.*) catch {
        object_store.scrubUnsealed(&self.objects);  // if re-seal fails, scrub in place: fail closed
    };
    self.wipeMasterKey();
}
```

If the re-seal fails (for example, out of memory), `scrubUnsealed` zeroes the plaintext values in place and marks them sealed, so a failed cleanup never leaves a secret in the clear. This is the fail-closed principle in code.

## The ABI cross-check

`tests/abi_test.zig` is what turns "the ABI matches the spec" from a hope into a build-time invariant. `build.zig` runs `addTranslateC` on a shim that includes the vendored OASIS headers, producing a `p11c` module. The test then compares the hand-written `ck.zig` against it.

Layout equality, field by field:

```zig
test "hand-coded structs match OASIS-translated layout byte-for-byte" {
    try expectSameLayout(ck.CK_ATTRIBUTE, p11c.CK_ATTRIBUTE);
    try expectSameLayout(ck.CK_FUNCTION_LIST, p11c.CK_FUNCTION_LIST);
    // ... every struct ...
}
```

Constant equality, every constant that exists in both:

```zig
test "every hand-coded constant equals its OASIS value" {
    inline for (@typeInfo(ck).@"struct".decls) |d| {
        if (@hasDecl(p11c, d.name)) {
            // assert ck.<name> == p11c.<name>, error.ConstantMismatch if not
        }
    }
    try std.testing.expect(checked >= 100);  // and we checked at least 100 of them
}
```

And the per-function C-ABI signatures: every entry in `CK_FUNCTION_LIST` is compared against the translated one for parameter count and parameter sizes/alignments. Add a constant to `ck.zig` that also exists in the OASIS headers and this loop picks it up automatically; get an offset wrong and the build fails with the exact field that diverged.

## The smoke harness

`examples/smoke.zig` is not a unit test. It `dlopen`s the *built* `.so` and calls through the function list exactly like an external host, which is the only way to catch export bugs and ABI-shape bugs that in-process tests miss:

```zig
var lib = try std.DynLib.open(default_module);
const getFunctionList = lib.lookup(GetFunctionList, "C_GetFunctionList") orelse return error.SymbolNotFound;
var list_ptr: ?*ck.CK_FUNCTION_LIST = null;
try check("C_GetFunctionList", getFunctionList(&list_ptr));
const f = list_ptr orelse return error.NullFunctionList;
```

From there it walks a full lifecycle: init the token, log in as SO, init the User PIN, set the PIN, create and find objects, prove a private object is hidden after logout, generate AES/EC/RSA keys, sign and verify (and tamper), encrypt and decrypt, derive an ECDH secret on both sides, wrap and unwrap, run GCM streaming and assert it equals the one-shot, exercise the dual functions, recover with RSA, round-trip operation state, and finally assert every conformance edge (`C_WaitForSlotEvent`, `C_GetFunctionStatus`, `C_SeedRandom`). It prints a summary block at the end so you can see at a glance what passed.

## Common Implementation Pitfalls

### Pitfall: a plain `zig build` does not match the shipped module

**Symptom:** you inspect a zeroized secret in a debugger and see `0xAA` bytes, not zeros, and conclude the zeroization is broken.

**Cause:** `zig build` with no flags is a Debug build. In Debug and ReleaseSafe, Zig poisons an optional's payload to `0xAA` when you set it to null, and `Allocator.free` memsets freed memory to `0xAA`. So `secureZero`-then-null leaves `0xAA` (the secret is gone, just not zero).

**Fix:** test for "the secret pattern is gone", not "all bytes are zero". The session tests assert the secret byte is absent, not that the buffer is zero. The shipped artifact is `zig build --release=safe`, where the explicit `secureZero` is what protects you (there is no poison in release builds without the safety check, so the explicit zero matters).

### Pitfall: comparing secrets with `std.mem.eql`

**Symptom:** a PIN or MAC check that works functionally but leaks timing.

**Cause:** `std.mem.eql` returns on the first mismatched byte.

**Fix:** `std.crypto.timing_safe.eql` for fixed-size arrays (the PIN hash), or the `ctEql` helper in `crypto_ops.zig` for variable-length MACs. Both look at every byte before deciding.

### Pitfall: leaving a function-list slot null

**Symptom:** the host segfaults the moment it calls an unsupported function.

**Cause:** a null pointer in the table.

**Fix:** every slot points at a real `callconv(.c)` function. Unsupported operations return a `CKR_*` code; they are never null. The `comptime` size assert in `main.zig` and the ABI test guard the shape.

## Debugging Tips

### Watch every call with pkcs11-spy

When a host call misbehaves, the fastest way to see what it actually sent is `pkcs11-spy`, which sits in front of your module and logs every call:

```bash
export PKCS11SPY=$PWD/zig-out/lib/libhsm.so
export PKCS11SPY_OUTPUT=/tmp/spy.log
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/pkcs11-spy.so -T
```

The `just spy` recipe wraps this. The log shows each `C_*` call, its arguments, and its return code, so you can find the exact call that returned the wrong thing and with what inputs.

### Read the return code, then read the spec

PKCS#11 return codes are specific. `CKR_OPERATION_NOT_INITIALIZED` means a `C_Sign` came without a `C_SignInit`. `CKR_OPERATION_ACTIVE` means a second `C_SignInit` while one was live. `CKR_ATTRIBUTE_SENSITIVE` means you asked for a sealed value. When a host fails, the code it got usually names the bug.

### Confirm the export surface

If a host cannot load the module at all, check that the one symbol is there and nothing else leaked:

```bash
objdump -T zig-out/lib/libhsm.so | grep ' g '   # should show only C_GetFunctionList
```

## Code Organization Principles

### Why one file per function group

The `api/*` split mirrors the spec's own grouping (slot/token, session, object, crypto, key management). A reader looking for "how does login work" opens `api/session.zig`; "how does signing work" opens `api/crypto_ops.zig`. Each file imports the core and crypto layers it needs and nothing it does not.

### Why the crypto layer never picks a return code

Crypto functions return Zig errors (`error.Crypto`, `cipher.Error.DataLenRange`). The ABI layer maps them to `CKR_*`. This keeps the crypto layer independently testable (a test asserts `error.AuthFailed`, not `CKR_*`) and keeps return-code policy in one layer. There is one `mapCipherErr`, one `mapSetErr`.

## Extending the Code

### Adding a mechanism, concretely

Say you want to add HMAC-SHA-512 (it is already there, but the steps are the same for any new one):

1. **Constant.** Add `CKM_FOO` to `ck.zig`. If the OASIS headers define it, the ABI test cross-checks the value for free.
2. **Advertise it.** Add `CKM_FOO` to `config.supported_mechanisms` and give it an arm in `slot_token.zig`'s `C_GetMechanismInfo` with the right key-size bounds and flags.
3. **Implement.** Add the primitive in the relevant `crypto/*` file. Write a unit test against a published vector and add the file to `test_all.zig`.
4. **Dispatch.** Wire it into the classifier helper it belongs to (`mac.macLenOf`, `cipher.modeOf`, `ecdsa.hashModeOf`, or the RSA `isRsa*Mech` checks) so the `*Init` functions route to it.

### Adding an entry point

Copy the acquire-and-defer skeleton from any `api/*` function. Validate the session handle first, then the arguments, then do the work, then set the in/out lengths and return the precise code. If the operation is slow (a KDF, a keygen that should not hold the lock), use the snapshot-unlock-recheck pattern from `C_Login`.

## Code Style

The project follows the repository conventions: a file header comment and no inline comments elsewhere, every constant in `config.zig` (no magic numbers in the logic), and `zig fmt` clean. Run the formatter check and the full suite together:

```bash
just ci    # zig fmt --check + zig build test + zig build smoke
```

## Build and Test

```bash
zig build --release=safe   # the shipped artifact
zig build test             # ABI cross-check + the crypto/core unit suite
zig build smoke            # dlopen the built .so and run the full lifecycle
```

`zig build test` runs two test binaries: `tests/abi_test.zig` (the OASIS cross-check) and `src/test_all.zig` (which pulls in every `crypto/*` and `core/*` test file). The crypto tests run against published vectors, so a regression in the math is caught at the unit level, and the ABI test catches any layout drift at the same step.

## Next Steps

1. Read [MECHANICS.md](./MECHANICS.md) for the cryptographic detail behind the dispatch you just saw: how AES-CBC chains, how PKCS#7 padding is verified, how RFC 3394 wrapping works, how ECDSA and ECDH compute, and how RSA's schemes differ.
2. Read [CONFORMANCE.md](./CONFORMANCE.md) for the exact return code at every deliberate boundary.
3. Open `examples/smoke.zig` and trace one operation from the `f.C_...` call down through the layers you now know.
