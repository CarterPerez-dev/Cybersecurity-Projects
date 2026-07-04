<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

```
 ________ _   _  ____ _____ _        _
|__  /_ _| \ | |/ ___| ____| |      / \
  / / | ||  \| | |  _|  _| | |     / _ \
 / /_ | || |\  | |_| | |___| |___ / ___ \
/____|___|_| \_|\____|_____|_____/_/   \_\
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2336-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/zig-stateless-scanner)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-F7A41D?style=flat&logo=zig&logoColor=white)](https://ziglang.org)
[![Backend](https://img.shields.io/badge/backend-AF__PACKET%20%2B%20AF__XDP-4B7BEC?style=flat)](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
[![Binary](https://img.shields.io/badge/binary-static%20musl-6d4aff?style=flat)](https://musl.libc.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> A stateless, line-rate mass TCP/UDP port scanner in the lineage of masscan and zmap. The name is Zulu for "to hunt." It holds no per-connection state, encodes probe identity in a SipHash cookie, walks the address space with a cyclic-group permutation, and ships as a single static binary with no libpcap, no libgmp, and no PCRE. It proves its packet logic against known-answer tests and stays memory-safe under Zig's ReleaseSafe.

## Why a stateless scanner in Zig

A normal TCP client tracks every connection: a socket, a state machine, a retransmit timer. That is fine for thousands of connections and impossible for billions. To sweep the routable IPv4 space you cannot keep a table, so the state moves into the packet itself. zingela encodes each probe's identity in the TCP sequence number with a keyed hash, and validates a reply with one hash recompute. No table, no timers, constant memory, and the transmit and receive engines share nothing and run flat out.

That makes it a sharp showcase for Zig: `extern struct` wire formats with compile-time size assertions, an RFC 1071 checksum in both scalar and `@Vector` form checked against the published vector, raw `AF_PACKET` and `AF_XDP` reached straight through `std.os.linux`, and every checksum and cookie pinned to a known-answer test. The result is a scanner that is fast where it can be, honest where it cannot, and safe by construction.

## The honest positioning

Read this before you believe any speed claim, from us or anyone else.

On stock Linux, masscan, zmap, and zingela all hit the same wall: the kernel `AF_PACKET` transmit path tops out around 1.5 to 2.5 million packets per second on a single core. Every one of these tools meets that ceiling. There is no raw-throughput number to win on identical hardware, and zingela does not claim one.

The only road past that ceiling in masscan is proprietary PF_RING ZC: a paid license, an out-of-tree kernel module, and specific NICs. Its headline figures, roughly 10 Mpps on a single 10GbE NIC and higher in dual-NIC demonstrations, are all PF_RING, never a stock kernel. zingela's road is `AF_XDP`, mainline in Linux since kernel 4.18, with no license and no proprietary module. That backend ships today behind the `-Dxdp` flag (pure syscalls, no libxdp). The head-to-head 10GbE benchmark against masscan is future work, and this README will not quote a line rate that has not been measured on real hardware.

The defensible win is the combination: `AF_XDP` acceleration with no PF_RING paywall, memory-safe Zig, a single static binary, correctness masscan never cleanly solved (RST suppression, validated-ICMP classification, accurate dedup), and a modern colorful interface.

## What Works Today

Every capability below is exercised by unit tests, an in-namespace end-to-end scan, and read-only audit passes.

**Scanning**
- Stateless TCP SYN scan over IPv4 and IPv6 via a raw `AF_PACKET` + `PACKET_TX_RING` + `PACKET_QDISC_BYPASS` datapath
- UDP scan with per-protocol payloads, ICMP type-3 code-3 classified as closed, silence reported honestly as `open|filtered`
- TCP connect() scan (`--connect`) for unprivileged or raw-blocked environments, IPv4 and IPv6
- Cloud and VM raw-send auto-detection (`--backend auto`): a two-socket self-probe detects hypervisors that silently drop raw sends and falls back to connect mode with a clear notice

**Statelessness and coverage**
- SipHash SYN-cookie identity in the TCP sequence number, validated by `ack == cookie +% 1`
- zmap-style multiplicative cyclic-group address permutation, seeded per scan from the OS CSPRNG, with the prime computed at runtime for the exact target space
- Token-bucket rate control, default 10,000 pps, responsible by default
- An RFC 6890 reserved-range exclusion floor that cannot be overridden

**Detection and evasion**
- Service and banner detection (`--banners`): a two-phase NULL-probe plus HTTP grab on open ports; TLS is detected, not decrypted; there is no JA4 (a dedicated Rust tool covers that)
- A stealth suite gated behind `--authorized-scan`: OS-realistic SYN templates, `fin|null|xmas|maimon|ack|window` scan types, Poisson jitter, source-port rotation, decoys, and scoped RST suppression

**Acceleration and output**
- An `AF_XDP` TX backend behind `-Dxdp` (pure-syscall UMEM and rings, with a zero-copy then `XDP_SKB` then `AF_PACKET` selection ladder)
- A truecolor live dashboard and a clean results table on stderr, with NDJSON on stdout (`--json`) so results stay greppable

## Quick Start

```bash
curl -fsSL https://angelamos.com/zingela/install.sh | bash
zingela scan --target 192.0.2.0/24 --ports 80,443 --rate 20000
```

One command takes a fresh Linux box to `zingela` on your PATH. The installer downloads a prebuilt static musl binary when a release is available and otherwise builds from source (fetching Zig 0.16 if it is missing), then grants `cap_net_raw,cap_net_admin` so raw scans run without sudo.

The target shown, `192.0.2.0/24`, is a reserved documentation range (RFC 5737) that zingela skips by design, so it reports zero targets. Substitute a range you own or are authorized to scan. For an unprivileged scan that needs no capabilities, add `--connect`.

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see every recipe grouped by area: `just safe` for a ReleaseSafe build, `just test-all` for the full matrix, `just bench` for the hot-path numbers, `just dist` for the musl release binaries, `just setcap` to grant capabilities.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Learn

This project ships a full teaching track. Read it in order, or jump to what you need.

| Doc | What it covers |
|-----|----------------|
| [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) | What a mass scanner is, why stateless scanning exists, and a quick tour |
| [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) | The handshake, SYN cookies, the permutation, responsible scanning, with real breaches |
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | The two-engine model, the module map, and the backend ladder, with diagrams |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | A code walkthrough, module by module |
| [`learn/MECHANICS.md`](learn/MECHANICS.md) | The cookie, checksum, cyclic group, dedup, and token bucket, byte by byte, with the measured numbers |
| [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) | Extension ideas, from a real AF_XDP benchmark to new probe modules |

## Architecture

Two cooperating machines: a stateless line-rate transmit and receive core that owns the packet hot path, and a memory-safe control plane that parses intent, paces the sending, and presents results.

```
   you  -->  cli / scancmd              control plane: parse, validate, select backend
                   |
         +---------+---------+
         v                   v
    tx (transmit)       rx (receive)          data plane: no heap alloc after startup
    targets.next()      read frame
    cookie.seq          classify open / closed / filtered
    template.stamp      cookie.validateSynAck    (ack == cookie + 1 ?)
    ratelimit gate           |
    packet_io                v
         |             dedup.insert  -->  output (dashboard / table / NDJSON)
         v
    AF_XDP  -->  AF_PACKET TX_RING  -->  the wire  -->  AF_PACKET RX
```

Nothing links the transmit column to the receive column except arithmetic: the cookie written into the sequence number is the same cookie recomputed on receipt. A reply without a valid cookie is dropped before it can pollute the results.

**Design decisions:** the address permutation is a multiplicative cyclic group (zmap's approach, uniform coverage), not masscan's BlackRock Feistel cipher, which the 2024 "Ten Years of ZMap" retrospective found finds fewer hosts due to randomization bias. The prime is computed at runtime for the exact scan size rather than drawn from a fixed table. Raw packet I/O goes straight through `std.os.linux`, never `std.posix`, which dropped its socket wrappers. The `AF_XDP` path is asymmetric: it accelerates transmit and pairs with an `AF_PACKET` receive, because replies are sparse and this avoids receive-side steering.

## Build and Test

```bash
zig build                 # debug build at zig-out/bin/zingela
zig build -Doptimize=ReleaseSafe   # the shipped artifact
zig build -Dxdp=true      # include the AF_XDP TX backend
zig build test            # unit tests (240)
zig build bench           # hot-path microbenchmarks
zig build release         # static musl binaries for x86_64 + aarch64
just ci                   # build + test
```

> [!NOTE]
> Plain `zig build` produces a **Debug** binary; the shipped artifact is `--release=safe` (ReleaseSafe), which keeps every undefined-behavior check live as a fail-closed trap rather than silent corruption. Sending raw packets needs `CAP_NET_RAW` and `CAP_NET_ADMIN`: run `just setcap` (or `sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela`) once, then run without sudo. The capability is cleared whenever the binary is rebuilt, so reapply it after every build.

## Performance

The hot path is CPU-cheap by design, which is the whole basis of the honest positioning above: the bottleneck is the kernel transmit path, never packet construction. These are measured with `zig build bench` on an Intel Core i7-14700KF, single core, ReleaseFast, with inputs varied per iteration and results folded into a printed sink so nothing is optimized away. Reproduce them with `just bench`.

| Operation | ns/op | Throughput |
|---|---|---|
| RFC 1071 checksum, scalar, 40 B header | 6.0 | 6.7 GB/s |
| RFC 1071 checksum, SIMD, 1500 B frame | 30.4 | 49 GB/s |
| SipHash SYN-cookie generate | 14.0 | 71 M/s |
| SipHash SYN-cookie validate | 14.8 | 68 M/s |
| SYN frame stamp (full Ethernet+IP+TCP) | 22.9 | 44 M/s |
| Cyclic-group address permutation step | 4.6 | 216 M/s |
| RX dedup insert | 15.4 | 65 M/s |

A single core builds about 44 million complete SYN frames per second, roughly twenty times faster than the `AF_PACKET` kernel can drain them at 1.5 to 2.5 Mpps. The CPU is never the wall. That is exactly why the only real path to higher throughput is bypassing the kernel with `AF_XDP`, and why there is no honest raw-pps advantage to claim on stock hardware.

## Project Structure

```
zig-stateless-scanner/
├── build.zig             # module graph, `release` (musl x2) + `bench` steps, version
├── build.zig.zon         # package manifest
├── install.sh            # one-shot curl|bash: prebuilt-first, source fallback, setcap
├── src/
│   ├── main.zig          # entry: parse args, dispatch smoke / tx / scan
│   ├── cli.zig           # argument parsing, help, the violet banner, --version
│   ├── scancmd.zig       # the scan command: validate, select backend, launch engines
│   ├── targets.zig       # cyclic-group permutation, primitive-root finder, exclusion floor
│   ├── numtheory.zig     # modexp, primality, primitive-root test for the permutation
│   ├── packet.zig        # wire headers, RFC 1071 checksum (scalar + @Vector), SYN presets
│   ├── cookie.zig        # SipHash SYN-cookie generate + validate, v4 and v6
│   ├── template.zig      # the SYN frame template stamped per target
│   ├── ratelimit.zig     # the token-bucket pacer
│   ├── tx.zig  rx.zig    # the transmit and receive engines
│   ├── classify.zig      # reply classification open / closed / filtered
│   ├── dedup.zig         # the lockless open-addressed dedup table
│   ├── packet_io.zig     # backend interface: afpacket.zig, afxdp.zig, connect.zig
│   ├── udp.zig           # UDP payloads and UDP classification
│   ├── service.zig       # opt-in banner and service detection (no JA4)
│   ├── stealth.zig       # the --authorized-scan gated evasion features
│   ├── output.zig        # live dashboard, results table, NDJSON
│   ├── netutil.zig ndp.zig rawprobe.zig  # iface + gateway resolution, NDP, cloud probe
│   └── bench.zig         # the hot-path microbenchmark harness
└── learn/                # the teaching track (this is public)
```

## License

[AGPL 3.0](LICENSE).
