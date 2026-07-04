<!-- ©AngelaMos | 2026 -->
<!-- MECHANICS.md -->

# Mechanics

The byte-level and math-level deep dive. Where [03-IMPLEMENTATION.md](03-IMPLEMENTATION.md) says what each module does, this doc shows the arithmetic that makes it correct and fast. Everything here matches the source in `cookie.zig`, `packet.zig`, `targets.zig`, `numtheory.zig`, `dedup.zig`, and `ratelimit.zig`.

## The SYN cookie, byte by byte

The cookie is what lets zingela hold no state. `generate` builds a 12-byte message from the four-tuple, in network byte order, and hashes it:

```
  data[12]:
   0        4      6            10   12
   +--------+------+------------+----+
   | ip_them|p_them|   ip_me    |p_me|
   +--------+------+------------+----+
     u32 BE  u16 BE   u32 BE    u16 BE

  cookie64 = SipHash64(2,4)(data, key)      key = 16 random bytes per scan
  seq32    = low 32 bits of cookie64
```

SipHash is a keyed pseudo-random function. Without the key you cannot predict its output, so an attacker cannot forge a sequence number that will validate. The `(2, 4)` are the compression and finalization round counts of the standard SipHash-2-4. A unit test in `cookie.zig` reproduces the published SipHash empty-message vector, which proves the primitive is wired correctly.

On transmit, `seq32` goes into the TCP sequence field. A target that accepts the SYN answers with a SYN-ACK whose acknowledgement field is your sequence number plus one, because TCP acknowledges the next byte it expects. On receive, `validateSynAck` recomputes `seq32` from the reply's own addresses and ports and checks:

```
  ack  ==  seq32  +%  1
```

The `+%` is wrapping addition. It matters: `seq32` can be `0xFFFFFFFF`, and in a safe Zig build a plain `+ 1` on that would trap on overflow. Wrapping makes `0xFFFFFFFF + 1` become `0x00000000`, exactly as the target's TCP stack computes it.

Why this rejects spoofs. A packet that was not generated in response to one of our probes will, with overwhelming probability, carry an acknowledgement that does not equal the keyed hash of its own four-tuple plus one. An attacker would need the per-scan key to forge one. So validation is a single hash recompute and a compare, no table lookup, and it throws away strays, late duplicates, and injected spoofs for free.

For UDP, `udpSrcPort` derives the source port itself from the hash, so the reply's destination port carries the validating information even when the payload does not.

## The RFC 1071 checksum

The internet checksum is the one's-complement sum of 16-bit words. `checksum` in `packet.zig` implements it directly:

```
  sum = 0
  for each 16-bit big-endian word w in the buffer:
      sum += w                         (sum is 32-bit, so carries pile up high)
  if one odd byte remains:
      sum += byte << 8                 (pad on the right with zero)
  while sum >> 16 != 0:                (fold the carries back in)
      sum = (sum & 0xffff) + (sum >> 16)
  return ~sum                          (one's complement, low 16 bits)
```

The fold loop is the end-around carry that defines one's-complement arithmetic: any overflow above bit 15 is added back into the low word. A worked feel for it: if the running sum reached `0x1_2345`, one fold gives `0x2345 + 0x1 = 0x2346`, and the returned checksum is `~0x2346 = 0xDCB9`. The receiver runs the identical sum including the checksum field and expects `0xFFFF`, which is how a corrupt packet is caught.

`checksumSimd` computes the same value faster on large buffers. It reads the buffer in blocks the width of the machine's vector unit, reinterprets each block as a vector of 16-bit words, byte-swaps them on a little-endian CPU so the arithmetic is big-endian, and accumulates into a vector of 32-bit lanes. After the vectorized body it reduces the lanes to one sum, handles any tail bytes with the scalar loop, and folds and complements exactly as above. The result is identical to the scalar function, which the tests assert.

There is a third function, `incrementalUpdate`, from RFC 1624. When exactly one 16-bit field of a packet changes, you do not need to resum the whole thing. Given the old checksum, the old word, and the new word:

```
  sum = ~old_check + ~old_word + new_word
  fold carries
  return ~sum
```

This is why stamping a new destination address into a cached template does not cost a full checksum pass over every packet.

## The cyclic group permutation

The address engine visits every address and port exactly once, in scrambled order, with three numbers of state. The math is the multiplicative group of integers modulo a prime.

Pick a prime `p` just larger than the number of targets `N`. The set `{1, 2, ..., p-1}` under multiplication modulo `p` is a cyclic group of order `p-1`. A **primitive root** `g` is a generator of that group: the sequence

```
  g^1, g^2, g^3, ...  (mod p)
```

hits every one of the `p-1` nonzero residues exactly once before it repeats. So the engine keeps a current value and advances it:

```
  current = (current * g) mod p        one multiply, one modulo, per target
```

Each `current` is a distinct integer in `[1, p-1]`. If it happens to exceed `N` (there are only a handful of such values, since `p` is just above `N`), the engine simply advances again without emitting, which is the re-roll. Every value in `[1, N]` is produced exactly once, in an order that looks random because multiplication by a primitive root scrambles the sequence.

Encoding both address and port in one element is a division. For target index `idx` in `[1, N]`, let `idx0 = idx - 1`, then:

```
  ip_position   = idx0 / number_of_ports
  port_position = idx0 % number_of_ports
```

so one traversal of the group randomizes the entire address-and-port space at once, not port by port.

Finding a primitive root without brute force is the clever part, in `numtheory.findPrimitiveRoot`. A candidate `g` generates the whole group if and only if, for every distinct prime factor `q` of `p-1`, `g^((p-1)/q) mod p` is not one. If any of those powers is one, `g` only generates a proper subgroup and is rejected. So the code factors `p-1` once with `distinctPrimeFactors`, then tests random candidates with `modExp` and `isPrimitiveRoot` until one passes. Each scan gets a fresh generator, so each scan is a different permutation.

zingela differs from zmap here in a way worth stating. zmap hardcodes eleven prime and primitive-root pairs, one per supported space size, the largest being `2^48 + 23`. zingela calls `smallestPrimeAbove(N)` for the exact size of your scan and finds a generator at runtime. A scan of a `/24` on one port uses a prime near 256, not a prime near `2^48`, so it wastes no iterations re-rolling values that fall outside a giant fixed group.

## The dedup table

A host that answers on two ports, or answers a retransmitted probe twice, must be counted once. `dedup.zig` is an open-addressed hash set of 64-bit keys with linear probing.

The key packs the address and port: `(ip << 16) | port`. Its maximum value is `0x0000FFFFFFFFFFFF`, which can never equal the empty-slot sentinel `0xFFFFFFFFFFFFFFFF`, so the sentinel is safe.

The hash is an fmix64 finalizer:

```
  x ^= x >> 33
  x *= 0xff51afd7ed558ccd
  x ^= x >> 33
```

This spreads the low-entropy key across all 64 bits so that sequential addresses do not cluster into one probe chain. `insert` computes the slot from the hash masked to the table size, then probes forward linearly until it finds the key (a duplicate, return false) or an empty slot (insert, return true). The table grows and rehashes when it passes seven-tenths full, which keeps probe chains short. Because the table is owned by the single receive engine, it needs no locks.

## The token bucket

`ratelimit.zig` paces transmission with a nanosecond bank rather than a sleep. `init` computes a per-token cost `step_ns = 1_000_000_000 / rate` and a capacity for short bursts. `takeBatch` reads the monotonic clock, adds the elapsed nanoseconds since the last call into the bank up to the cap, and returns how many whole tokens (`bank / step_ns`) the sender may spend now, deducting them. The sender never busy-waits: it asks for a batch, sends that many, and asks again. `refund` returns tokens for sends that could not complete, and `withJitter` perturbs the step for Poisson timing. This is a true token bucket, which is a different mechanism from masscan's proportional-feedback controller over a 256-slot timestamp ring.

## Measured performance

These are the hot-path functions timed by `zig build bench` on an Intel Core i7-14700KF, single core, ReleaseFast. Each measurement varies its input every iteration and folds the result into a printed value so the optimizer cannot delete the work. Numbers scale with the CPU; run the bench on your own box.

| Operation | ns/op | Rate |
|---|---|---|
| RFC 1071 checksum, scalar, 40 B | 6.0 | 6.7 GB/s |
| RFC 1071 checksum, scalar, 1500 B | 185 | 8.1 GB/s |
| RFC 1071 checksum, SIMD, 1500 B | 30.4 | 49 GB/s |
| SipHash cookie generate | 14.0 | 71 M/s |
| SipHash cookie validate | 14.8 | 68 M/s |
| SYN frame stamp, full frame | 22.9 | 44 M/s |
| Cyclic-group permutation step | 4.6 | 216 M/s |
| Dedup insert | 15.4 | 65 M/s |

Two things are worth reading out of this table.

First, the frame-stamp rate against the ceiling. A single core stamps about 44 million complete SYN frames per second. The `AF_PACKET` kernel transmit path drains at 1.5 to 2.5 million packets per second. So the CPU builds frames roughly twenty times faster than the kernel can send them. The scanner is never CPU-bound on stock hardware. This is the whole basis of the honest positioning: since every scanner meets the same kernel ceiling, there is no raw-throughput win to claim there, and the only real path to more packets per second is bypassing the kernel with `AF_XDP`.

Second, the SIMD checksum is faster than scalar only on large buffers. On a 40-byte header the vector setup does not pay for itself, so scalar wins. On a 1500-byte frame the vector version is about six times faster. The scanner stamps small headers, so `template.stamp` uses the scalar `checksum`, and the benchmark makes that choice visible rather than assumed.
