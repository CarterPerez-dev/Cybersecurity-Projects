<!-- ©AngelaMos | 2026 -->
<!-- 03-IMPLEMENTATION.md -->

# Implementation Walkthrough

A guided tour of the code. It names functions and files, never line numbers, so it stays correct as the source moves. Read it with the source open beside you. For the byte-level and math-level details, follow the pointers into [MECHANICS.md](MECHANICS.md).

## Wire formats and the checksum: `packet.zig`

Everything the scanner puts on the wire starts here. The Ethernet, IPv4, TCP, UDP, and IPv6 headers are declared as `extern struct` so their field order and packing match the wire exactly, and each carries a compile-time size assertion so a mistaken field can never silently change the layout. Multi-byte fields are converted to network byte order explicitly at the point of writing, never left to chance.

The checksum lives in two functions. `checksum` is the scalar one's-complement sum from RFC 1071. `checksumSimd` is the same math over a vector accumulator for large buffers. Both are validated against the published RFC 1071 worked example. `tcpChecksum` and `tcpChecksum6` build the pseudo-header and run the sum over the TCP segment for IPv4 and IPv6. There is also `incrementalUpdate`, the RFC 1624 trick that patches a checksum when a single field changes without resumming the whole packet.

`ScanType` and `OsProfile` encode the stealth variations. `ScanType.probeFlags` returns the TCP flag byte for a syn, fin, null, xmas, maimon, ack, or window scan, and `OsProfile.options` returns the TCP option bytes of a realistic Linux, Windows, or macOS SYN so a fingerprint looks like a real client rather than a scanner.

The `Addr` union is how one result path serves both address families: it holds either a `u32` for IPv4 or a `[16]u8` for IPv6, so the classification, output, and dedup code is written once.

## The cookie: `cookie.zig`

This is statelessness in about sixty lines. A `Cookie` is a 16-byte key, created from per-scan random entropy. `generate` packs the four-tuple into a small buffer and returns `std.hash.SipHash64(2, 4).toInt` over it, a full 64-bit hash. `seq` truncates that to the 32 bits that fit in a TCP sequence number. `validateSynAck` recomputes `seq` from the reply's addresses and ports and returns whether the acknowledgement equals `seq +% 1`, using wrapping addition because the cookie can be `0xFFFFFFFF` and a plain add would overflow-trap in a safe build.

The IPv6 variants `generate6`, `seq6`, and `validateSynAck6` do the same over 16-byte addresses. `udpSrcPort` reuses the hash to derive a per-target source port for UDP, so the reply's destination port itself carries validating information. A unit test reproduces the canonical SipHash empty-message vector, so the primitive is proven, not assumed.

## The address engine: `targets.zig` and `numtheory.zig`

`parseCidr` turns `192.0.2.0/24` into a `Range` of start and end addresses. `IpPicker.build` takes your ranges, subtracts every reserved block through `subtractReserved`, sorts what remains, and builds a cumulative-prefix index so that a flat integer can be mapped to a concrete address with a binary search in `IpPicker.at`. This is where `10.0.0.0/8` collapses to nothing: the reserved subtraction removes the whole private block.

`Engine` is the permutation. `Engine.init` computes the total size of the address-and-port space, finds the smallest prime above it with `numtheory.smallestPrimeAbove`, and picks a fresh primitive root with `numtheory.findPrimitiveRoot`. Note the difference from zmap here: zmap hardcodes a table of eleven prime and primitive-root pairs, while zingela computes the prime for the exact size of your scan at runtime, so a small scan gets a small group and wastes no iterations re-rolling out-of-range values. `Engine.next` advances the group with `numtheory.mulMod`, decodes the resulting element into an address and port through the picker, and returns one `Target`. `initShard` slices the group into contiguous arcs so several machines can share one scan by seed.

`numtheory.findPrimitiveRoot` is the interesting one. Rather than brute-force testing, it factors `prime - 1` with `distinctPrimeFactors` and, for each random candidate, checks with `isPrimitiveRoot` that no `modExp(candidate, (prime-1)/q, prime)` equals one. A candidate that passes generates the whole group. The math is in [MECHANICS.md](MECHANICS.md).

## Stamping frames: `template.zig`

`SynTemplate.init` builds a base frame once from a `Config` (source and destination MAC, source address and port, cookie, OS profile, scan type), laying down the Ethernet, IPv4, and TCP headers with everything that does not change between targets. `stamp` is the per-target hot function: it copies the base, writes the destination address, varies the IP identification field, writes the destination port, computes the cookie with `cookie.seq` and places it in the sequence or acknowledgement field depending on the scan type, and finishes with the IP and TCP checksums. `stampVariant` layers decoy source addresses on top for the stealth suite. `SynTemplate6` is the IPv6 counterpart.

## Pacing: `ratelimit.zig`

`TokenBucket` is a nanosecond bank. `init` sets a per-token step in nanoseconds from your requested packets per second and a capacity for short bursts. `takeBatch` reads the monotonic clock, credits elapsed time into the bank, and returns how many tokens the transmit engine may spend right now, which is how the sender stays at rate without busy-waiting. `refund` returns tokens when a send could not be completed, and `withJitter` perturbs the timing for the Poisson jitter mode. This is a genuine token bucket, distinct from masscan's proportional-feedback controller over a timestamp ring.

## The engines: `tx.zig` and `rx.zig`

`tx.zig` is the transmit loop: prime the bucket, pull targets from the `Engine`, stamp them through the template, gate on the bucket, and batch them into the backend's transmit ring before kicking the kernel to send. It allocates nothing after startup. `rx.zig` opens the receive socket for the right ethertype and reads frames in a loop.

Classification lives in `classify.zig`. `classifyTcp` inspects a received TCP segment and decides open, closed, or filtered, gated on a valid cookie so that only genuine replies count, and maps relevant ICMP errors to filtered. `classifyTcp6` does the same for IPv6, including ICMPv6 unreachables. Deduplication lives in `dedup.zig`: `Dedup.insert` mixes the key with an fmix64 finalizer and places it in an open-addressed table with linear probing, returning whether the host was newly seen so each host is reported once.

## The backends: `packet_io.zig`, `afpacket.zig`, `afxdp.zig`, `connect.zig`

`packet_io.zig` defines the interface the engines call: open, reserve a transmit slot, submit, kick, poll for received frames, close. `afpacket.zig` implements it over an `AF_PACKET` socket with a memory-mapped `PACKET_TX_RING` and `PACKET_QDISC_BYPASS`, the universal path that needs no kernel modules. `afxdp.zig` implements the accelerated path over `AF_XDP` with its own user-memory region and rings, built only when `-Dxdp` is set. `connect.zig` is the unprivileged fallback: it makes raw non-blocking `connect` calls through `std.os.linux`, waits on them with `poll`, and reads the socket error to classify open, closed, or filtered. It has its own sized thread pool because a connect blocks a thread, so concurrency equals pool size.

This raw-socket approach is deliberate. The connect scanner drives non-blocking sockets and `poll` itself rather than going through the standard networking layer's connect-with-timeout, which `connect.zig` does not use for the scan path.

## UDP, service detection, stealth, and output

`udp.zig` holds the compile-time payload table and the UDP classification, where an ICMP type-3 code-3 unreachable means closed and silence is reported honestly as open-or-filtered because a UDP service may simply not answer a probe it does not recognize. `service.zig` is the opt-in second phase: on an open port it sends a NULL probe and an HTTP request, grabs the banner, and detects TLS without decrypting it. `stealth.zig` gathers the gated evasion features. `output.zig` renders the truecolor live dashboard and the results table to the terminal while writing NDJSON to standard output, so the visual and machine views never collide.

## Where the proofs live

Every one of these modules ships unit tests in the same file, run with `zig build test`. The checksum has its RFC vector, the cookie has its SipHash vector and a cookie-plus-one round trip, the address engine has a bijection property test over a small space, and the dedup table has growth and collision tests. The whole pipeline is exercised end to end inside a network namespace before release. That is the repository rule: no code without proof.
