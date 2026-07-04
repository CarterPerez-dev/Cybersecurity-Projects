<!-- ©AngelaMos | 2026 -->
<!-- 00-OVERVIEW.md -->

# zingela: Overview

zingela is a stateless, line-rate mass port scanner. You give it a range of addresses and ports, it sends one crafted probe to each, and it classifies every reply as open, closed, or filtered without ever holding a connection table. It is written in Zig 0.16, ships as a single static binary with no libpcap and no libgmp, and it is the direct descendant of two tools: masscan (Robert Graham, 2013) and zmap (Durumeric, Wustrow, and Halderman, USENIX Security 2013).

This folder teaches how it works, from the security theory down to the bytes on the wire.

## Why stateless scanning exists

A normal TCP client tracks every connection: a socket, a state machine, a retransmit timer, a receive buffer. That is fine for a few thousand connections. It falls apart at internet scale. To probe all 3.7 billion routable IPv4 addresses on one port, a stateful scanner would need billions of live socket structures and the kernel bookkeeping to match. It cannot be done on one machine.

The stateless trick is to carry the state in the packet itself. zingela encodes the identity of each probe into the TCP initial sequence number using a keyed hash. When a reply comes back, the acknowledgement number carries that identity back, and a single hash recompute proves the reply is genuinely a response to a probe zingela sent. No table, no timers, no per-target memory. The transmit side and the receive side share almost nothing and run flat out.

This is the same design that let zmap scan the entire public IPv4 space in about 45 minutes from a single machine in 2013, a result that turned internet-wide scanning from a research curiosity into an everyday measurement tool.

## The honest positioning

Read this before you believe any speed claim, from us or anyone else.

On stock Linux hardware, masscan, zmap, and zingela all hit the same wall: the kernel `AF_PACKET` transmit path tops out around 1.5 to 2.5 million packets per second on a single core. Every one of these tools meets that ceiling. There is no raw-throughput bragging number to win on identical hardware, and zingela does not claim one.

The only road past that ceiling in masscan is proprietary: PF_RING ZC, which needs a paid ntop license, an out-of-tree kernel module, and specific Intel NICs. Its headline figures (10 Mpps on the README, higher in dual-NIC demos) are all PF_RING, never a stock kernel. zingela's road is `AF_XDP`, mainline in Linux since kernel 4.18, with no license and no proprietary module. That backend ships today behind the `-Dxdp` build flag. The full head-to-head against masscan on 10GbE hardware is future work, and these docs will never quote a line rate that has not been measured on real hardware.

So the defensible win is not "faster." It is: acceleration with no paywall, memory safety proven under Zig's ReleaseSafe checks, a single static binary, correctness that masscan never cleanly solved, and a modern interface. The [performance section of MECHANICS](MECHANICS.md) shows the measured hot-path numbers and explains why the CPU is never the bottleneck.

## What works today

- TCP SYN scan over IPv4 and IPv6, using a raw kernel-bypass transmit ring.
- UDP scan with per-protocol payloads and honest open-versus-filtered reporting.
- A TCP connect scan that needs no privileges, for locked-down or cloud environments.
- Automatic detection of hypervisors that silently drop raw sends, with a fallback to connect mode.
- Service and banner detection on open ports, opt-in and two-phase.
- A stealth and evasion suite, gated behind an explicit authorization acknowledgement.
- SipHash cookie statelessness, cyclic-group address permutation, token-bucket rate control, and a non-overridable exclusion of reserved address ranges.
- A truecolor live dashboard and greppable NDJSON output.

## Quick start

```
curl -fsSL https://angelamos.com/zingela/install.sh | bash
zingela scan --target 192.0.2.0/24 --ports 80,443 --rate 20000
```

The installer lands `zingela` on your PATH and grants the raw-socket capabilities so it runs without sudo. If you are on a box where you cannot or should not send raw packets, add `--connect` for the unprivileged scanner.

The target shown, `192.0.2.0/24`, is a reserved documentation range (RFC 5737) that zingela skips by design, so it reports zero targets. Substitute a range you own or are authorized to scan.

## Prerequisites for reading

You will get the most from these docs if you are comfortable with the TCP three-way handshake, the shape of IPv4 and TCP headers, and basic modular arithmetic. You do not need to know Zig; the walkthroughs name functions and files, not language trivia. Where a concept has a famous real-world example, we anchor it there.

## The rest of this folder

| Doc | What it covers |
|---|---|
| [01-CONCEPTS.md](01-CONCEPTS.md) | the security theory: statelessness, SYN cookies, what a scan can observe, responsible scanning, and the incidents that shaped all of it |
| [02-ARCHITECTURE.md](02-ARCHITECTURE.md) | the system design: the two-engine model, the module map, and the backend ladder, with diagrams |
| [03-IMPLEMENTATION.md](03-IMPLEMENTATION.md) | a guided walk through the code, module by module |
| [MECHANICS.md](MECHANICS.md) | the byte-level and math-level deep dive: the cookie, the checksum, the cyclic group, and the measured performance |
| [04-CHALLENGES.md](04-CHALLENGES.md) | ways to extend zingela, from a real AF_XDP benchmark to new probe modules |
