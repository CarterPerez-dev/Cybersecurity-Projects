<!-- ©AngelaMos | 2026 -->
<!-- 01-CONCEPTS.md -->

# Concepts

This doc explains the ideas zingela is built on, and grounds each in a real event so the stakes are concrete.

## The three-way handshake, and what a probe can learn

A TCP connection opens with three packets. The client sends a SYN. If the port is open, the server answers with a SYN-ACK. The client completes the connection with an ACK. If the port is closed, the server answers the SYN with a RST instead. If a firewall is dropping the traffic, nothing comes back at all.

A stateless SYN scan sends only the first packet and reads the answer:

```
  zingela                target
    | ----- SYN -------->  |   open   ->  SYN-ACK comes back
    | ----- SYN -------->  |   closed ->  RST comes back
    | ----- SYN -------->  |   filtered -> silence
```

zingela never sends the final ACK, so the connection is never established and the target application never sees a completed session. This is why a SYN scan is fast and light. It is also why the classification has exactly three outcomes: open (SYN-ACK), closed (RST), and filtered (no reply within the wait window). UDP is murkier, and gets its own honest treatment below.

## Statelessness: carry the state in the packet

The central idea. A stateful scanner remembers every probe it sent so it can match a reply. A stateless scanner remembers nothing and instead makes each reply prove its own legitimacy.

zingela does this with a keyed hash called a SYN cookie. Before sending a probe to a target, it computes a value from the four-tuple (source address, source port, destination address, destination port) using SipHash keyed with per-scan random entropy, and writes the low 32 bits into the TCP sequence number field. A real target that answers a SYN echoes that sequence number plus one in the acknowledgement field of its SYN-ACK. When the reply arrives, zingela recomputes the same hash from the packet's addresses and ports and checks that the acknowledgement equals the cookie plus one. If it matches, the reply is genuine. If it does not, the packet is a stray, a spoof, or a stale echo, and it is dropped for free.

The payoff is enormous. There is no connection table, so memory use is constant no matter how many billions of targets you sweep. The transmit engine and receive engine share no per-probe state, so they run as independent threads at full speed. Spoofed replies are rejected by arithmetic rather than by a firewall rule.

The cost is subtle and worth understanding. Because the scanner holds no record of what it sent, it cannot know a probe was lost, so loss looks identical to a filtered port. Serious stateless scanners answer this with unconditional retransmission (send every probe a few times) rather than with response tracking, because tracking would reintroduce the state you worked so hard to remove.

## SYN cookies came from a real attack

The cookie idea is not a scanner invention. It was Daniel Bernstein's 1996 defense against SYN flood denial-of-service attacks, in which an attacker sends floods of SYNs and never completes the handshake, exhausting the server's half-open connection table. Bernstein's answer was to stop storing half-open connections and instead encode the needed state in the sequence number itself, validating it when the ACK returns. A stateless scanner runs that same trick from the other side of the wire: the scanner, not the server, is the party that refuses to hold state.

## Walking the address space without a list

To scan a range you must visit every address in it, ideally in a scrambled order so you do not hammer one subnet at a time and trip its intrusion detection. The naive way is to build a list, shuffle it, and iterate. At internet scale the list alone is tens of gigabytes.

zingela borrows zmap's answer: a multiplicative cyclic group over a prime just above the size of the target space. It keeps three numbers (a current value, a generator, and the prime) and advances with one multiply and one modulo per target. Because the generator is a primitive root of the prime, the sequence visits every element of the space exactly once before returning to the start. It is a perfect shuffle with O(1) memory: no list, no bitmap of remaining work, no per-address random number call.

masscan solves the same problem with a block cipher (a Feistel network it calls BlackRock2). The 2024 "Ten Years of ZMap" retrospective measured the consequence: masscan finds notably fewer hosts than zmap, likely because of biases in that randomization. zingela takes the cyclic-group road precisely to avoid that bias. The [cyclic group section of MECHANICS](MECHANICS.md) shows the math.

## Rate limiting, and why the default is slow

zingela defaults to 10,000 packets per second, and it warns loudly before you push into the millions. That conservatism is deliberate, and it is a lesson written in outages.

On 25 January 2003 the SQL Slammer worm (exploiting CVE-2002-0649 in Microsoft SQL Server on UDP port 1434) demonstrated stateless scanning at its most destructive. It was a single 376-byte UDP packet that, on infecting a host, immediately began blasting copies to random addresses as fast as the network card allowed. It infected around 75,000 hosts in ten minutes, doubling roughly every 8.5 seconds, and the sheer volume of scan traffic saturated links and knocked parts of the internet offline. Slammer held no state and rate-limited nothing. It is the cautionary twin of every stateless scanner.

The lesson is that a tool which can emit packets at line rate is a tool that can flood a network by accident. masscan's own aggressive defaults have gotten it null-routed by ISPs. zingela uses a token bucket to pace transmission and makes fast scanning an explicit, warned choice rather than the default.

## Reserved ranges are excluded by construction

Some address blocks must never be scanned: loopback, private RFC 1918 space, link-local, multicast, and the documentation ranges. zingela checks a reserved-range table before it crafts any packet, and that exclusion floor cannot be overridden by a flag. If you point it at a range that overlaps reserved space, the reserved portion is subtracted and simply never probed. This is why aiming the scanner at `10.0.0.0/8` yields zero targets: the entire block is RFC 1918 private space and is removed before the first packet.

## Source spoofing is gated, not default

You can forge the source IP of a scan. Doing it by default would be reckless, and it barely works: only about a fifth of autonomous systems on the internet permit spoofed egress, because most implement the anti-spoofing filtering described in BCP 38. The legitimate use is testing your own network's BCP 38 compliance. zingela therefore treats spoofing and every other evasion feature as gated behind an explicit `--authorized-scan` acknowledgement, never as a quiet default.

## The legal line

Scanning sends unsolicited packets to machines you may not own. In the United States that can fall under the Computer Fraud and Abuse Act, the same 1986 statute under which Robert Tappan Morris was convicted after his 1988 worm scanned and infected roughly 6,000 machines, about a tenth of the internet of the day. Courts have treated unauthorized scanning inconsistently, but the safe rule is simple and absolute: scan only systems you own or have explicit written permission to test.

The same techniques serve defense. When Heartbleed (CVE-2014-0160) broke in April 2014, researchers used zmap to scan the entire internet repeatedly, measuring how many servers were vulnerable and how fast operators patched. Internet-wide measurement, vulnerability tracking, and asset inventory are exactly what these tools are for, when you have the authority to run them. zingela's defaults, its gating, and its exclusion floor are there to keep the tool on the right side of that line.

## Why aggressive scanning gets you noticed

The 2016 Mirai botnet scanned TCP ports 23 and 2323 across the entire IPv4 space, trying about 60 default telnet credentials, and assembled a botnet large enough to take down Krebs on Security, OVH, and the Dyn DNS provider in October 2016. It was loud, fast, and indiscriminate, and it was trivially detectable precisely because of that. The stealth suite in zingela exists so that authorized testers can study detectability (jitter, decoys, OS-realistic fingerprints, alternate scan types), not so that anyone can be quieter while doing harm. That is why it is gated. See [04-CHALLENGES.md](04-CHALLENGES.md) for the evasion topics as study exercises.
