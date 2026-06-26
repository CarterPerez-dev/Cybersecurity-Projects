<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

# zingela

A stateless, line-rate mass TCP port scanner written in Zig 0.16, in the lineage of masscan and zmap. The name is Zulu for "to hunt."

## Honest positioning

On stock Linux, masscan, zmap, and zingela all hit the same kernel `AF_PACKET` transmit ceiling, roughly 1.5 to 2.5 million packets per second on a single core. There is no raw-throughput win to be had there, and zingela does not claim one.

The difference is the road past that ceiling. masscan reaches higher rates only with proprietary PF_RING ZC: a paid license, an out-of-tree kernel module, and specific NICs. zingela's planned road is `AF_XDP`, which has been in the mainline Linux kernel since 4.18 and needs no proprietary dependency. Once that backend lands (a later milestone), zingela is designed to match masscan on bare Linux and pull ahead on XDP-capable hardware precisely where masscan needs a paywall, while shipping as a single static binary with no libpcap or libgmp dependency, proving its packet logic against known-answer tests, and being memory-safe.

## Status

Early development. The current milestone (M0) establishes the project scaffold, the Zig 0.16 module graph, the wire-format headers with a verified RFC 1071 checksum, and a ground-truth smoke that sends one hand-built SYN through a raw `AF_PACKET` socket.

## Build

Requires Zig 0.16.0.

```
zig build              # debug build at zig-out/bin/zingela
zig build test         # unit tests
zig build run          # run (prints help)
zig build run -- --version
```

## Smoke test (proves the raw-socket path)

Sending raw packets needs `CAP_NET_RAW` and `CAP_NET_ADMIN`. Grant the capabilities once, then run without sudo (running under sudo drops the environment that the colored output relies on):

```
zig build
sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela
./zig-out/bin/zingela smoke
```

Expected output: one SYN sent to 127.0.0.1:80 on the loopback interface. `zig build smoke` runs the same installed binary, so it works too once the capability is set. Without the capability the smoke prints the setcap instruction and exits cleanly. The capability must be reapplied after every rebuild, since rebuilding replaces the binary.

## Authorized use only

zingela sends unsolicited packets to hosts. Scan only systems you own or have explicit written permission to test. Unauthorized scanning may violate the Computer Fraud and Abuse Act and equivalent laws in other jurisdictions. The defaults are deliberately conservative and reserved address ranges are excluded by construction.
