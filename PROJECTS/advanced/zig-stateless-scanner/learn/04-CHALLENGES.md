<!-- ©AngelaMos | 2026 -->
<!-- 04-CHALLENGES.md -->

# Challenges and Extensions

Ways to take zingela further, ordered roughly from approachable to deep. Each names the code it touches and the idea it teaches. Some are genuine gaps in the current build, marked as such. Scan only what you are authorized to scan while testing any of these.

## Warm up

### Add a probe payload

`udp.zig` holds a compile-time table of per-protocol UDP payloads (the bytes that make a DNS, NTP, or SNMP service answer). Add one for a protocol it does not cover yet, for example a memcached stats request or an IKE handshake. You will learn why UDP scanning needs a real payload: unlike TCP, a bare UDP probe to an open port usually gets no reply, so silence is honestly reported as open-or-filtered. A good payload turns some of those into definite opens. This is the same reason the 2003 SQL Slammer worm fit its whole exploit in one 376-byte UDP packet to port 1434: UDP services answer content, not connection attempts.

### Extend service detection

`service.zig` runs a NULL probe and an HTTP request on open ports and grabs the banner. Add a probe for another common service, say an SSH version string or a TLS ClientHello that records the certificate. Note the boundary the project holds deliberately: it detects TLS but does not compute a JA4 fingerprint, because a dedicated Rust tool already does that. Respect that boundary or you are duplicating work.

## Build something real

### A real AF_XDP benchmark

This is the honest open question of the whole project. The `AF_XDP` transmit backend ships behind `-Dxdp`, but the head-to-head against masscan on 10GbE hardware has not been measured. Set up two machines with capable NICs, run zingela with `-Dxdp` against a sink, measure sustained packets per second with `perf`, and compare to masscan on the same hardware with and without PF_RING. Publish the real number. The Zippier ZMap paper measured zmap at 14.23 Mpps versus masscan at 6.4 Mpps on 10G, so there is a concrete target to reproduce and beat. Do not accept a veth or loopback figure as a line rate; those measure the kernel loopback, not the NIC.

### Rate warnings and a hard gate

The design calls for a prominent warning above one million packets per second and an explicit confirmation gate above ten million, so that fast scanning is always a deliberate choice. Wire that into `ratelimit.zig` and the argument parser. The reason is written in outages: masscan's aggressive defaults have gotten it null-routed by ISPs, and Slammer showed what an unpaced stateless sender does to a network. This teaches you where responsibility lives in a tool that can flood a link by accident.

### An atomic resume checkpoint

A long scan that dies halfway should be resumable. Because the address engine is a cyclic group with O(1) state (a current value, a generator, a prime, and a step count), the entire progress of a scan is a handful of integers. Periodically write them to disk atomically, and add a flag to resume from that file. This teaches why the stateless permutation is not just fast but operationally convenient: you can checkpoint an internet-wide scan in a few bytes, which a shuffled address list could never do.

## Go deep

### IPv6 UDP and IPv6 stealth

The current IPv6 support is TCP SYN only. UDP scanning and the stealth suite are IPv4 only. Extending them to IPv6 means reworking the UDP payload path and the evasion features to carry `packet.Addr` all the way through, the way the TCP path already does. The dedup key for IPv6 is a lossy hash of the 144-bit address-and-port down to 64 bits, so think about whether your extension needs an exact key. This is a real architecture exercise in how far a union type carries you.

### Embedded IPv4-in-IPv6 literals

Addresses like `::ffff:1.2.3.4` embed an IPv4 address in IPv6 notation. The parser in `netutil.zig` does not accept them yet. Adding it is a small, well-scoped parsing task with sharp edge cases, a good way to learn the IPv6 text format and to practice property-testing a parser against its inverse.

### Sharding across machines

`Engine.initShard` already slices the cyclic group into contiguous arcs by shard identifier and count, so several machines sharing one seed can each scan a disjoint slice of the same space with no coordination. Build the orchestration around it: a launcher that starts N shards, collects their NDJSON, and merges the results. This is how internet-scale scans are actually run, and it teaches why a seeded deterministic permutation is the right primitive for distribution.

### A results store and a detection view

zingela emits NDJSON to standard output. Feed it into a store (SQLite, or a columnar file) and build queries over it: new hosts since the last scan, services that changed, ports that opened. This is the measurement use case that internet scanning exists for. When Heartbleed broke in 2014, researchers scanned the whole internet repeatedly with zmap precisely to track which servers stayed vulnerable over time. A results store is what turns a scanner into a measurement instrument.

## Study, do not weaponize

### Detectability experiments

The stealth suite (jitter, decoys, OS-realistic fingerprints, alternate scan types), gated behind `--authorized-scan`, exists so that authorized testers can study how a scan looks to an intrusion detection system. Stand up a lab with your own IDS, scan your own targets, and measure which techniques change the alert profile and which do not. The 2016 Mirai botnet was caught in part because its scanning was loud and uniform. Understanding detectability is defensive knowledge. Using it to scan systems you do not own is not, and the gating is there to keep that distinction sharp.
