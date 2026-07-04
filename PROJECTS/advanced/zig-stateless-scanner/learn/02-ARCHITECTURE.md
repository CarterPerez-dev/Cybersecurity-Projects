<!-- ©AngelaMos | 2026 -->
<!-- 02-ARCHITECTURE.md -->

# Architecture

zingela is two machines bolted together: a stateless line-rate transmit and receive core that owns the packet hot path, and a memory-safe control plane that parses your intent, paces the sending, and presents the results. This doc shows how they fit.

## The big picture

```
        you                       control plane                     data plane
   ------------      ------------------------------------      --------------------
   --target      ->  cli.zig  -> scancmd.zig                    tx.zig  (transmit)
   --ports           parse       validate, build Config    ->    pull target
   --rate            help        select backend                  stamp frame
   --backend         banner      launch engines                  rate-gate
                                   |          \                   push to ring
                                   |           \                       |
                                   v            v                      v
                              output.zig     rx.zig  (receive)   packet_io.zig
                              dashboard        read frame          AF_XDP or
                              table            validate cookie     AF_PACKET or
                              NDJSON           classify            connect
                                   ^            dedup
                                   |            push found host
                                   +---------------+
```

The control plane never touches a raw socket in the hot loop. The data plane never allocates after startup. That separation is what keeps the scanner both safe and fast.

## The stateless data flow

Follow one probe and its reply all the way through. This is the heart of the design.

```
  TRANSMIT                                            RECEIVE
  --------                                            -------
  targets.Engine.next()                               packet_io rxPoll()
     gives (ip, port)                                    reads a frame
        |                                                   |
        v                                                   v
  cookie.seq(ip,port,src,srcport)                     classify.classifyTcp()
     = low 32 bits of                                    is it SYN-ACK / RST / ICMP?
       SipHash(4-tuple)                                    |
        |                                                  v
        v                                             cookie.validateSynAck(ack,...)
  template.stamp(frame, ip, port)                        ack == cookie + 1 ?
     writes Eth+IP+TCP,                                    |
     puts cookie in TCP seq                          yes --+-- no
        |                                             |          |
        v                                             v          v
  ratelimit token gate                          dedup.insert   drop (stray/spoof)
        |                                          new host?
        v                                             |
  packet_io txSubmit + txKick  --- wire --->      output emit
```

Nothing links the left column to the right except arithmetic. The cookie written into the sequence number on transmit is the same cookie recomputed and checked on receive. There is no shared table, no correlation ID lookup, no per-probe memory. A reply that does not carry a valid cookie is discarded before it can pollute the results.

## The two engines

The transmit engine and the receive engine run as concurrent tasks launched with `io.concurrent` over Zig's `std.Io.Threaded`. This is not the old `async` keyword, which Zig removed, and it is not a future per probe. It is two long-lived workers.

The transmit engine runs hot. It pulls targets from the address permutation, stamps each into a preallocated frame buffer, passes it through the token-bucket rate gate, and hands it to the packet backend. After startup it does not allocate: the transmit ring is memory-mapped once, and per-packet scratch comes from a fixed buffer.

The receive engine reads frames from the backend, classifies each as SYN-ACK, RST, or a relevant ICMP error, validates the cookie, deduplicates against a lockless open-addressed hash table so a host that answers twice is reported once, and pushes newly found hosts to the output side. Replies are sparse compared to probes, so the receive engine is far less hot than the transmit engine, which is why the backend design below can afford to be asymmetric.

## The backend ladder

The packet input and output path is chosen at runtime through one interface (`packet_io.zig`) with several implementations. The scanner core does not know or care which one is active.

```
  --backend auto  picks the first that works:

   1. AF_XDP zero-copy      fastest, driver-dependent          -Dxdp build
   2. AF_XDP with XDP_SKB   copy mode, works on more drivers    -Dxdp build
   3. AF_PACKET + TX_RING   universal, kernel-bypass TX ring    always built
      + QDISC_BYPASS        the v1 default, matches masscan-stock
   4. AF_PACKET sendto      plain, used by the ground-truth smoke
   5. connect scan          TCP via the OS stack, no raw needed  --connect
```

The AF_XDP path is asymmetric: it accelerates transmit and pairs with an `AF_PACKET` receive path. Replies are sparse, so this trades a few percent of theoretical receive throughput for a much simpler design with no receive-side steering or map wiring. When `--backend auto` runs, a two-socket self-probe first checks whether raw sends actually leave the machine. On a cloud instance or a VM where the hypervisor silently drops raw frames, that probe fails and zingela falls back to the connect scanner with a clear notice, rather than reporting a scan that sent nothing.

## The module map

| Module | Responsibility |
|---|---|
| `main.zig` | entry point: parse arguments, build config, dispatch to a subcommand |
| `cli.zig` | argument parsing, help, the banner and version |
| `scancmd.zig` | the scan command: validate, select backend, launch transmit and receive, drive output |
| `txcmd.zig` | the transmit-only blast command |
| `targets.zig` | the cyclic-group permutation engine, primitive-root finder, address and port picker, exclusion floor |
| `numtheory.zig` | modular exponentiation, primality, primitive-root testing for the permutation |
| `packet.zig` | wire-format headers, the RFC 1071 checksum (scalar and SIMD), OS-realistic SYN presets |
| `cookie.zig` | SipHash SYN-cookie generation and validation, IPv4 and IPv6 |
| `template.zig` | the SYN frame template that gets stamped per target |
| `ratelimit.zig` | the token-bucket pacer |
| `tx.zig` | the transmit engine |
| `rx.zig` | the receive engine |
| `classify.zig` | reply classification into open, closed, filtered |
| `dedup.zig` | the lockless open-addressed dedup table |
| `packet_io.zig` | the backend interface, with `afpacket.zig`, `afxdp.zig`, and `connect.zig` implementations |
| `udp.zig` | UDP payloads and UDP-specific classification |
| `service.zig` | the opt-in banner and service detection phase |
| `stealth.zig` | the gated evasion features |
| `output.zig` | the live dashboard, results table, and NDJSON |
| `netutil.zig`, `ndp.zig`, `rawprobe.zig` | interface and gateway resolution, IPv6 neighbor discovery, the cloud self-probe |

## Why the split matters for safety

The 2003 SQL Slammer worm and every buffer-overflow scanning worm since share a root cause: hand-written packet code in C that corrupts memory under load. zingela builds and tests under Zig's ReleaseSafe mode first, where an out-of-bounds slice, an integer overflow, or a null dereference is a defined trap rather than silent memory corruption. The wire-format structs carry compile-time size assertions, every checksum and cookie is checked against a published test vector, and the whole scan is validated end to end inside a network namespace before any release. The [implementation walkthrough](03-IMPLEMENTATION.md) shows where each of these guards lives.
