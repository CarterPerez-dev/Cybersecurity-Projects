# HTTP/2 and HTTP/3 in Haskell: Production Implementation Guide

**The Haskell ecosystem provides production-ready HTTP/2 support through the mature `http2` library and Warp web server, with experimental HTTP/3 capabilities emerging.** HTTP/2 delivers 14-30% performance improvements for most websites, while HTTP/3 adds another 12-50% boost particularly on mobile and high-latency networks. The protocol stack maintained by Kazu Yamamoto achieves nginx-comparable performance and powers major Haskell web applications today.

For Haskell developers, HTTP/2 is ready for immediate production deployment with Warp 3.1+, offering automatic ALPN negotiation and transparent multiplexing. HTTP/3 support exists through the `quic` and `http3` libraries, though it remains in active development (version 0.2.x) and is best deployed via reverse proxies for production systems. The elimination of head-of-line blocking and 0-RTT connection establishment make HTTP/3 particularly valuable for mobile-first applications and global audiences, while the unified architecture across all three libraries ensures smooth adoption paths.

## Understanding the protocol evolution and Haskell's position

HTTP/2 represented a fundamental shift from text-based to binary framing, introducing multiplexing that allows concurrent streams over a single TCP connection. This eliminated HTTP/1.1's "six connections per domain" bottleneck and reduced connection overhead. The `http2` Haskell library implements the complete RFC 7540 specification, including HPACK header compression that achieves 40-80% size reduction, sophisticated priority queues using custom-designed data structures, and comprehensive flow control mechanisms. First released in 2015 and now at version 5.3.10 (June 2025), the library has proven itself through 70+ releases and extensive production deployment in Warp, Yesod, and mighttpd2.

HTTP/3 takes this evolution further by replacing TCP entirely with QUIC, a UDP-based transport protocol developed initially by Google. This architectural change eliminates transport-layer head-of-line blocking that still affects HTTP/2, reduces connection establishment from 2 RTT to 1 RTT (or 0 RTT on reconnection), and enables connection migration when devices switch networks. The Haskell `quic` library (version 0.2.20, September 2025) implements the complete IETF QUIC specification including RFC 9000, 9001, 9002, and Version 2, while the `http3` library (version 0.1.1) provides the HTTP/3 protocol layer. All three libraries share the same maintainer and architectural philosophy based on Haskell lightweight threads, ensuring consistency across the stack.

## HTTP/2 protocol deep dive: what Haskell developers need to know

**Multiplexing operates through a binary framing layer** that sits between the socket and HTTP API. Every HTTP/2 communication splits into frames with a 9-byte header (length, type, flags, stream ID) plus variable payload. Streams represent bidirectional flows of frames within a single connection, with odd-numbered streams initiated by clients and even-numbered by servers. The critical insight is that frames from different streams can interleave freely—a DATA frame from stream 5, followed by a HEADERS frame from stream 3, then another DATA frame from stream 5—all without blocking.

This multiplexing eliminates the connection limit problem but introduces complexity in stream state management. Streams transition through states (idle → open → half-closed → closed) with specific rules about which frame types are valid in each state. The Haskell `http2` library handles this state machine internally, mapping each HTTP/2 stream to a Haskell lightweight thread. This design choice proves elegant: **one thread per stream (not per connection)** allows natural concurrent processing while maintaining clear isolation between streams.

Flow control prevents any single stream from monopolizing bandwidth. HTTP/2 implements credit-based flow control at both stream and connection levels, starting with 65,535 bytes for each window. Senders must track available window space and queue DATA frames when exhausted, while receivers send WINDOW_UPDATE frames as they consume data. The `http2` library manages these windows automatically, but developers should understand the implications: slow consumption in application code can cause flow control windows to close, throttling the entire connection.

**Priority mechanisms in HTTP/2 allow resource ordering through dependency trees and weights**, though real-world deployment shows limited effectiveness. The specification supports complex parent-child relationships with weights 1-256 determining proportional resource sharing among siblings. However, many implementations use simpler schemes—Chrome uses sequential exclusive dependencies, and research shows complex trees suffer from poor interoperability. The `http2` library implements priority queues using a custom "random heap" data structure invented specifically for this purpose, but developers should focus on simple weight-based prioritization rather than complex dependency trees.

**Server push, once considered HTTP/2's killer feature, is now deprecated** and removed from Chrome 106+ (October 2022) and Firefox 132+ (October 2024). The PUSH_PROMISE frame allowed servers to speculatively send resources before clients requested them, but practice revealed fatal flaws: servers cannot know client cache state, leading to wasted bandwidth; predicting what to push proved nearly impossible; and better alternatives like HTTP 103 Early Hints emerged. The Haskell `http2` library supports server push for compatibility, but new implementations should skip it entirely in favor of preload hints.

**HPACK compression achieves 40-80% header size reduction** through a combination of static tables (61 predefined common headers), dynamic tables (connection-specific learned patterns), and Huffman encoding. The static table includes entries like index 2 for `:method GET` and index 8 for `:status 200`, allowing entire headers to encode in 1-2 bytes. The dynamic table grows as the connection processes headers, building compression context. Four representation types handle different scenarios: indexed (both name and value in table), literal with incremental indexing (adds to table), literal without indexing (one-time use), and literal never indexed (for sensitive data like Authorization headers).

HPACK's design specifically mitigates the CRIME attack that plagued generic compression. By avoiding cross-message compression and using static Huffman coding instead of adaptive algorithms, HPACK prevents attackers from using compression ratios to guess secret values. The never-indexed flag ensures sensitive headers never enter the compression context. The Haskell implementation handles HPACK state carefully through STM for thread-safe dynamic table management and precomputed lookup tables for efficient encoding/decoding.

## HTTP/3 and QUIC: rebuilding the transport layer

**QUIC's use of UDP instead of TCP represents pragmatic engineering rather than technical preference.** TCP is ossified—implemented in operating system kernels across billions of devices, making updates essentially impossible. Network middleboxes (firewalls, load balancers, NAT devices) are hardcoded for TCP behavior, blocking attempts to deploy new transport protocols. By building on UDP, which already passes through all infrastructure, QUIC can be implemented in user space at the application layer. This enables rapid iteration: Google deployed 18 versions of QUIC in 2 years, something unthinkable with a kernel-level protocol.

QUIC reimplements all TCP's reliability features in the application layer with improvements. Monotonically increasing packet numbers eliminate retransmission ambiguity that affects TCP RTT calculations. Each packet has a unique number even across retransmissions, allowing precise loss detection. ACK frames can acknowledge multiple packet ranges efficiently with included delay information for accurate measurements. Loss detection uses both packet threshold (3 missing packets) and time threshold (based on smoothed RTT), with lost frames retransmitted in new packets with new numbers.

**Connection IDs represent QUIC's most innovative feature**, identifying connections independently of the network 4-tuple (source IP/port, destination IP/port). This enables connection migration when IP addresses change—mobile devices switching from WiFi to cellular, laptops roaming between access points, or NAT rebindings. Each endpoint selects Connection IDs for packets sent to it, and multiple IDs can exist per connection. Path validation ensures new paths work: PATH_CHALLENGE frames sent on the new path require PATH_RESPONSE confirmations before switching. New Connection IDs exchanged during migration prevent linkability by observers, enhancing privacy as connections move across networks.

**0-RTT connection establishment eliminates handshake overhead on resumption**, saving 25-200ms depending on network latency. After an initial 1-RTT connection where the server provides a session ticket, subsequent connections can send application data immediately in 0-RTT packets encrypted with keys derived from cached parameters. This proves particularly valuable for mobile networks where every round trip costs 50-150ms. However, 0-RTT introduces security concerns: the data lacks forward secrecy and is vulnerable to replay attacks. Mitigations include server-side anti-replay mechanisms, rejecting non-idempotent methods (POST, PUT, DELETE) in 0-RTT, and the Early-Data header allowing origin servers to detect and handle with `425 Too Early` status codes. Browsers typically only send safe requests (GET, HEAD) in 0-RTT.

**HTTP/3 eliminates the transport-layer head-of-line blocking that still affects HTTP/2.** With HTTP/2 over TCP, a lost packet blocks all streams until retransmitted because TCP guarantees ordered byte delivery. At 2% packet loss, HTTP/1.1 with 6 parallel connections can outperform HTTP/2 with its single connection. QUIC provides independent streams with per-stream loss recovery: a lost packet only affects its specific stream while others continue uninterrupted. This architectural difference shows most dramatically on lossy networks—the Kiwee study with 15% packet loss demonstrated HTTP/3 being 52% faster than HTTP/2.

Connection migration eliminates interruptions when network paths change. Traditional TCP connections identified by 4-tuple break when IP or port changes, requiring full reconnection (TCP + TLS handshakes). QUIC connections survive these changes seamlessly through Connection ID routing and path validation. While helpful for mobile users, research shows switching networks happens less frequently than initially assumed, and congestion control must still probe the new network's capacity. The feature proves most valuable for real-time applications like video conferencing, navigation apps, and gaming where connection continuity matters more than bulk transfer speed.

**QPACK modifies HPACK's compression approach to handle QUIC's out-of-order delivery.** HPACK assumes all dynamic table updates arrive in order, working perfectly over TCP but breaking over QUIC where header blocks might reference entries not yet received. QPACK introduces separate encoder and decoder streams for table management, required insert counts indicating the highest dynamic table index referenced, and acknowledgment tracking preventing references to unevicted entries. Encoders must balance three strategies: static table references (safe, no blocking), acknowledged dynamic references (safe, good compression), and unacknowledged dynamic references (best compression, may block stream). The `SETTINGS_QPACK_BLOCKED_STREAMS` setting controls this trade-off, with many implementations using only static tables for simplicity.

## Haskell library ecosystem: maturity and production readiness

**The `http2` library represents one of Haskell's most mature network implementations**, with production deployment proving its reliability at scale. Current version 5.3.10 (June 26, 2025) shows continuous maintenance through regular updates across 2024-2025. The library provides complete HTTP/2 frame support (DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION), comprehensive HPACK implementation without reference sets, sophisticated priority queue handling with random heaps, and both client and server components.

Performance benchmarks place Warp with `http2` at nginx-level performance despite being written in Haskell, a remarkable achievement validated by the "Experience Report: Developing High Performance HTTP/2 Server in Haskell" paper at the 2016 Haskell Symposium and the AOSA book chapter. The architecture maps HTTP/2 streams to Haskell lightweight threads using thread pools to minimize spawning overhead. Critical paths use hand-rolled parsers rather than combinator libraries, specialized date formatting with caching, and zero-copy ByteString operations where possible. DoS attack mitigations added in version 3.0+ protect against various HTTP/2-specific attack vectors.

Real-world usage proves the library's production readiness. Warp (one of the fastest HTTP servers in any language) uses it as the HTTP/2 implementation. Yesod web framework deploys it for all HTTP/2 support. The mighttpd2 production web server serves traffic with it. Dependency on http-semantics, time-manager, and network-control packages provides clean separation of concerns. Known limitations are minor: the library exposes low-level primitives requiring careful usage, HTTP/1.1 Upgrade to HTTP/2 is not supported (only direct HTTP/2 and ALPN), and some features like PING replies are hardcoded.

**The `quic` library implements complete IETF QUIC specifications** including RFC 9000 (QUIC transport), RFC 9001 (TLS integration), RFC 9002 (loss detection and congestion control), RFC 9287 (bit greasing), RFC 9369 (QUIC Version 2), and RFC 9368 (version negotiation). Current version 0.2.20 (September 3, 2025) shows active maintenance by the same author as `http2`, ensuring architectural consistency. The library provides both QUIC v1 and v2 support, implements RFC-compliant congestion control algorithms, supports both automatic and manual migration, and includes client and server implementations validated with h3spec compliance testing.

Production readiness assessment places `quic` at 4 out of 5 stars—very good but newer than `http2`. The library successfully deploys in mighttpd2 v4.0.0+ for production HTTP/3 serving. Documentation comes primarily through blog posts and examples rather than comprehensive guides, a gap that reflects the library's relative youth (first released around 2021, compared to `http2`'s 2015 debut). The smaller ecosystem compared to `http2` means fewer dependent packages and less extensive real-world testing, though the fundamental implementation is sound and RFC-compliant.

**The `http3` library bridges QUIC transport with HTTP/3 protocol**, building on both `quic` and `http2` for shared HTTP semantics. Version 0.1.1 (August 11, 2025) remains in 0.x territory, signaling ongoing development. The library handles HTTP/3 frame encoding/decoding, QPACK header compression, both client and server components, and TLS 1.3 integration (requiring tls library ≥2.1.10). Dependencies on quic ≥0.2.11 and http2 ≥5.3.4 ensure compatibility across the stack. Production readiness assessment gives it 3 out of 5 stars—good and functional but evolving, suitable for early production use with appropriate monitoring.

## Warp integration: HTTP/2 and HTTP/3 support

**Warp has supported HTTP/2 natively since version 3.1.0 (July 2015)**, making it one of the earliest HTTP/2 implementations in any language. Current version 3.4.9 (September 13, 2025) integrates http2 library versions 5.1-5.4 directly. The implementation supports direct HTTP/2 (h2c cleartext) and ALPN negotiation over TLS (h2 with warp-tls), but explicitly does not support the HTTP/1.1 Upgrade mechanism. This design choice reflects practical deployment: browsers only use ALPN for HTTP/2, and h2c serves primarily server-to-server communication like gRPC.

Configuration for HTTP/2 is remarkably simple—it works automatically when using warp-tls with TLS ALPN or when clients connect with the HTTP/2 preface for direct h2c. No special configuration flags are needed:

```haskell
import Network.Wai.Handler.Warp (run)
import Network.Wai.Handler.WarpTLS (runTLS, tlsSettings, defaultTlsSettings)

-- For TLS with automatic HTTP/2 ALPN negotiation
main = runTLS tlsSettings defaultSettings app

-- For cleartext with HTTP/2 support
main = run 3000 app
```

The Network.Wai.HTTP2 module provides HTTP/2-specific APIs including `HTTP2Application` for HTTP/2-aware application interfaces, `PushPromise` for server push support (though deprecated), and `promoteApplication` to upgrade HTTP/1.1 apps to support HTTP/2. Performance characteristics match the underlying `http2` library: better than HTTP/1.1 in throughput tests, one thread per stream (not per connection) architecture, efficient thread pool usage, and performance comparable to nginx based on AOSA book benchmarks.

**HTTP/3 support exists through the experimental warp-quic package** at version 0.0.3 (June 10, 2025). This provides a WAI handler built on `http3` and `quic` libraries, using the same WAI Application interface for consistency. Production readiness assessment gives warp-quic 3 out of 5 stars—experimental with limited deployment history. For production systems, the recommended approach uses an HTTP/3-capable reverse proxy (Nginx 1.25.0+ or Caddy 2.6.0+) in front of Warp:

```
Client → Nginx (HTTP/3 on UDP/443) → Warp (HTTP/2 on TCP/443)
```

This architecture provides HTTP/3 benefits to clients while maintaining Warp's proven HTTP/2 stability internally. The proxy handles protocol translation, UDP processing overhead, and provides mature HTTP/3 implementations while Haskell applications continue using Warp's production-tested interface.

## Performance analysis: when each protocol matters

**HTTP/2 delivers 14-30% performance improvements for most websites**, with benefits increasing for high-resource sites and mobile users. Google search saw 8% faster desktop performance and 3.6% faster mobile, with the slowest 1-10% of users experiencing up to 16% improvement. ImageKit's demo loading 100 image tiles showed dramatic visual differences, with HTTP/2's parallel loading versus HTTP/1.1's sequential batches limited by 6 parallel connections. The benefits emerge most clearly for websites with 100+ resources, multiple small files (CSS, JS, images), and high-latency networks where the single multiplexed connection eliminates repeated handshake overhead.

HTTP/1.1 can still perform better in specific scenarios: high packet loss environments where HTTP/2's head-of-line blocking at the TCP level causes worse performance than HTTP/1.1's multiple independent connections, simple static sites with fewer than 10-20 resources where migration overhead isn't justified, and API endpoints serving single JSON responses where multiplexing provides no benefit. The critical threshold is packet loss—at 2% loss, HTTP/1.1 with 6 connections can outperform HTTP/2's single connection, as lost packets block all streams until retransmitted.

**HTTP/3 adds another 12-50% improvement on top of HTTP/2, with the largest gains on problematic networks.** Cloudflare's real-world testing measured Time to First Byte improvements of 12.4% (176ms vs 201ms average), though page load times showed HTTP/3 trailing HTTP/2 by 1-4% in good network conditions, attributed to congestion algorithm differences (BBR v1 vs CUBIC). The real benefits emerge on high-latency and lossy networks: Request Metrics benchmarks from New York (1,000 miles) showed HTTP/3 200-300ms faster, while London (transatlantic) showed 600-1,200ms improvements, and Bangalore demonstrated the most dramatic gains with tightly grouped response times.

Mobile networks demonstrate HTTP/3's transformative impact. Wix's study across millions of websites showed connection setup improvements of up to 33% at the mean, with 75th percentile improvements exceeding 250ms in countries like the Philippines. Largest Contentful Paint (LCP) improved by up to 20% at the 75th percentile, reducing LCP by over 500ms in many cases—approximately one-fifth of Google's 2,500ms target. The Kiwee study with simulated poor conditions (15% packet loss, 100ms latency) measured 52% faster downloads with HTTP/3. YouTube reported 20% less video stalling in countries like India with QUIC.

The performance hierarchy becomes clear across network conditions: excellent networks (fiber, low latency, no loss) show HTTP/2 providing 14% improvement while HTTP/3 adds marginal 1-4% benefit; moderate networks (typical cellular, 50-100ms RTT, 1-5% loss) see HTTP/2 improving 30-50% with HTTP/3 adding substantial 15-25% more; poor networks (rural/satellite, 100-200ms+ RTT, 5-15% loss) can see HTTP/2 performing worse than HTTP/1.1 due to head-of-line blocking while HTTP/3 delivers dramatic 40-50%+ improvements.

**Overhead considerations reveal important trade-offs.** HTTP/2 uses approximately the same CPU as HTTP/1.1 without encryption, with the binary protocol reducing parsing overhead versus text-based HTTP/1.1. HTTP/3 and QUIC prove "much more expensive to host" due to UDP packet processing overhead, per-packet encryption versus bulk encryption in TLS over TCP, and user-space implementation versus kernel-space TCP. Memory usage increases with HTTP/2 (maintaining 40,000 sessions requires significant RAM) and further with HTTP/3's connection state management in user space. Connection setup costs decrease from 3 RTT (HTTP/1.1 with TLS 1.2) to 2 RTT (HTTP/2 with TLS 1.3) to 1 RTT (HTTP/3), with 0-RTT mode enabling immediate data transmission on reconnection.

The overhead justification depends on scale and use case. Facebook uses HTTP/3 client-to-edge but HTTP/2 for data center traffic due to overhead concerns. Netflix sticks with heavily optimized TCP+TLS at their scale. CDN providers like Cloudflare deploy HTTP/3 globally because the user experience benefits justify the CPU cost. The key insight: overhead matters most for internal microservices on reliable networks, while user-facing applications on diverse networks justify the cost through improved experience.

## Protocol comparison: HTTP/1.1 vs HTTP/2 vs HTTP/3

| Feature | HTTP/1.1 | HTTP/2 | HTTP/3 |
|---------|----------|--------|--------|
| **Transport** | TCP | TCP | QUIC over UDP |
| **Framing** | Text-based, newline-delimited | Binary frames | Binary frames |
| **Multiplexing** | No (6 connections) | Yes (streams in 1 connection) | Yes (streams in 1 connection) |
| **Head-of-line blocking** | Application layer (sequential) | Transport layer (TCP) | None (per-stream loss recovery) |
| **Connection setup** | 3 RTT (TCP + TLS 1.2) | 2 RTT (TCP + TLS 1.3) | 1 RTT (0 RTT on resume) |
| **Header compression** | None | HPACK (40-80% reduction) | QPACK (similar to HPACK) |
| **Server push** | No | Yes (deprecated 2022) | Yes (but discouraged) |
| **Priority** | No | Weight + dependency tree | Simplified (RFC 9218) |
| **Connection migration** | No | No | Yes (Connection IDs) |
| **Encryption** | Optional (HTTPS) | Required in browsers (ALPN) | Required (TLS 1.3 mandatory) |
| **Browser support** | 100% | 97% | 92% |
| **Web adoption** | ~20% | ~47% | ~30% |
| **Typical improvement** | Baseline | +14-30% | +12-50% on top of HTTP/2 |
| **Best for** | Simple sites, APIs | Modern websites, SPAs | Mobile, global audiences, lossy networks |
| **Haskell maturity** | Mature | Production-ready (Warp 3.1+) | Experimental (warp-quic 0.0.3) |

## Fallback strategies and protocol negotiation

**Graceful degradation happens automatically through protocol negotiation.** Servers listen simultaneously on TCP/443 for HTTP/1.1 and HTTP/2, and UDP/443 for HTTP/3. Clients discover HTTP/3 via the Alt-Svc header (`Alt-Svc: h3=":443"; ma=86400`) or DNS HTTPS records with ALPN parameters. Browsers race QUIC versus TCP connections, falling back silently within 200-500ms if QUIC fails. The fallback hierarchy flows naturally: HTTP/3 → HTTP/2 → HTTP/1.1, with clients driving selection and servers requiring no detection before connection establishment.

**Application-Layer Protocol Negotiation (ALPN) from RFC 7301 enables this seamlessness.** The client sends TLS ClientHello with an ALPN extension listing supported protocols in preference order (`["h3", "h2", "http/1.1"]`). The server selects the highest mutually supported protocol and returns it in TLS ServerHello. The connection proceeds with the negotiated protocol. Protocol identifiers are: `h3` for HTTP/3 over QUIC/UDP with TLS 1.3, `h2` for HTTP/2 over TCP with TLS, `h2c` for HTTP/2 cleartext (no TLS, uses Upgrade mechanism), and `http/1.1` for HTTP/1.1 with optional TLS. ALPN is mandatory for HTTP/2 over TLS, and servers must not respond with one protocol then use another.

The h2c alternative uses HTTP/1.1 Upgrade mechanism for cleartext HTTP/2, primarily serving server-to-server communication like gRPC. Browsers do not implement h2c, making it irrelevant for typical web applications. The Upgrade mechanism sends an HTTP/1.1 request with `Connection: Upgrade, HTTP2-Settings` and `Upgrade: h2c` headers, receiving `HTTP/1.1 101 Switching Protocols` if accepted.

**Client compatibility handling requires understanding current support status.** HTTP/2 has 97/100 browser compatibility (Chrome 41+, Firefox 36+, Safari 9.3+, Edge all versions), while HTTP/3 reaches 92/100 (Chrome 87+, Firefox 88+, Edge 87+, Safari 14+ with manual enable until 17.6). As of November 2025, 25-30% of web traffic uses HTTP/3, showing rapid adoption growth that doubled in 12 months (2021-2022). Feature detection should use server-side protocol logging rather than user-agent strings, which prove unreliable and easily spoofed.

Mobile versus desktop considerations prove important: mobile benefits more from HTTP/3 due to high latency and connection migration, with mobile HTTP/3 usage at 25-30% versus desktop's 20-25%. Intermediaries and proxies introduce complications—UDP blocking is common in corporate firewalls requiring TCP fallback, transparent proxies may downgrade to HTTP/1.1, and TLS inspection can break ALPN unless proxies support ALPN forwarding. Testing from mobile, desktop, and corporate networks becomes essential for production deployment.

## Implementation roadmap for Haskell projects

**Phase 1: HTTP/2 deployment (immediate, production-ready)**

Start with Warp 3.1+ and warp-tls for automatic HTTP/2 support. The minimal configuration requires TLS certificates and runs automatically:

```haskell
import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS

main :: IO ()
main = do
    let tlsSettings = tlsSettingsChain "cert.pem" ["intermediate.pem"] "key.pem"
        warpSettings = setPort 443 defaultSettings
    runTLS tlsSettings warpSettings app
```

Protocol detection happens transparently through ALPN during TLS handshake. Applications can access HTTP/2 data through `Warp.getHTTP2Data req` if needed, though most applications work unchanged across HTTP/1.1 and HTTP/2. Avoid implementing server push (deprecated), use preload hints instead: `<link rel="preload" href="/critical.css" as="style">`.

Configuration optimization follows HTTP/2 best practices: stop domain sharding (counterproductive with multiplexing), stop excessive bundling (leverage parallel loading), minimize buffering to enable prioritization, and set appropriate concurrent stream limits. Monitoring should track protocol distribution (% HTTP/1.1 vs HTTP/2), connection establishment time, Time to First Byte (TTFB), and successful ALPN negotiations.

**Phase 2: HTTP/3 experimentation (current state, use with caution)**

Deploy HTTP/3 through reverse proxy architecture for production systems. Nginx 1.25.0+ (May 2023) or Caddy 2.6.0+ (September 2022) provide mature HTTP/3 implementations:

```nginx
server {
    # HTTP/2 over TCP
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;

    # HTTP/3 over UDP
    listen 443 quic reuseport;
    listen [::]:443 quic reuseport;

    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    location / {
        proxy_pass http://localhost:3000;  # Warp
        proxy_http_version 1.1;
    }
}
```

Firewall configuration must allow UDP/443: `iptables -A INPUT -p udp --dport 443 -j ACCEPT`. The Alt-Svc header enables HTTP/3 discovery by clients. This architecture provides HTTP/3 benefits to users while maintaining Warp's proven stability internally.

Direct Haskell HTTP/3 deployment using warp-quic is possible for experimental projects:

```haskell
import Network.Wai.Handler.WarpQUIC

-- Uses same WAI Application interface
main = runWarpQUIC settings app
```

However, production use should wait for version 1.0+ and broader deployment validation. Current version 0.0.3 indicates experimental status with limited field testing.

**Phase 3: Production hardening**

Security considerations require TLS 1.3 for HTTP/3, TLS 1.2+ for HTTP/2, and careful 0-RTT handling (only safe requests, monitor for replay attacks). Implement rate limiting on UDP/443 to prevent amplification attacks. Monitor CPU usage, as QUIC processing overhead in user space exceeds kernel-space TCP.

Testing strategy should include WebPageTest with "3G Fast" profile to verify prioritization, http3check.net for HTTP/3 support verification, curl with `--http3` flag for command-line testing, and Chrome DevTools network tab with Protocol column added. Test from multiple network types: cellular (high latency, packet loss), enterprise (potential UDP blocking), and international (high RTT) to ensure fallback mechanisms work correctly.

Performance monitoring tracks protocol distribution showing fallback rates, connection establishment time by protocol, TTFB improvements, UDP packet loss rate on HTTP/3 connections, and HTTP/3 → HTTP/2 fallback frequency. Set up alerting for abnormal fallback rates indicating network issues, increased CPU usage from QUIC overhead, or client compatibility problems.

**Phase 4: Advanced optimization**

Type-safe protocol handling uses phantom types for compile-time guarantees:

```haskell
{-# LANGUAGE DataKinds, KindSignatures #-}

data Protocol = HTTP1 | HTTP2 | HTTP3

newtype Request (p :: Protocol) = Request RequestData

-- Only valid for HTTP2 (compile-time check)
pushResource :: Request 'HTTP2 -> PushPromise -> IO ()
```

Resource management uses ResourceT for automatic cleanup:

```haskell
import Control.Monad.Trans.Resource

app :: Application
app req respond = runResourceT $ do
    (releaseKey, handle) <- allocate
        (openFile "data.txt" ReadMode)
        hClose
    content <- liftIO $ hGetContents handle
    liftIO $ respond $ responseLBS status200 [] content
```

Custom priority handling implements application-specific prioritization by analyzing request patterns, identifying critical resources, and using HTTP/2 priority frames for time-sensitive content.

## Critical recommendations for production deployment

**Deploy HTTP/2 immediately for all public-facing Haskell web applications.** The benefits are proven (14-30% improvement), implementation is mature (Warp 3.1+ since 2015), and browser support is universal (97%). Configuration requires minimal changes (just TLS with warp-tls), and performance matches nginx despite being Haskell code. The `http2` library's 10+ years and 70+ releases demonstrate production readiness.

**Deploy HTTP/3 through reverse proxies for mobile-heavy or global audiences.** The protocol delivers significant improvements on problematic networks (25-50%+), particularly valuable for developing markets and mobile users. Nginx or Caddy provide mature implementations while Haskell applications continue using proven Warp interfaces. Direct Haskell HTTP/3 via warp-quic should wait until version 1.0+ for production use, though experimentation is encouraged for learning and feedback.

**Avoid server push entirely**, as it's deprecated and removed from major browsers. Use preload hints (`<link rel="preload">`) or HTTP 103 Early Hints instead. Testing server push capabilities in the `http2` library wastes development time on abandoned technology.

**Prioritize testing across diverse network conditions.** HTTP/2 and HTTP/3 benefits vary dramatically by network quality, with the largest gains on the slowest connections. Test on cellular networks (high latency, packet loss), from international locations (high RTT), and through enterprise networks (potential UDP blocking) to ensure fallback mechanisms work correctly.

**Monitor protocol distribution and fallback rates.** Unexpected fallback patterns indicate network issues, client compatibility problems, or configuration errors. Track CPU usage with HTTP/3, as QUIC's user-space implementation requires more processing than kernel TCP. Budget for this overhead when scaling.

The Haskell HTTP implementation ecosystem provides production-ready building blocks for modern web applications, with HTTP/2 support matching industry leaders and HTTP/3 capabilities emerging through active development. The unified architecture across `http2`, `quic`, and `http3` libraries ensures smooth adoption paths while maintaining the type safety and composability that make Haskell valuable for production systems.
