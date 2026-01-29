# Building a Production-Grade Haskell Reverse Proxy for WebSocket and HTTP Streaming

The root cause of nginx's WebSocket/streaming conflict lies in **mutually exclusive Connection header requirements** combined with fundamentally different connection state semantics. Modern proxies like HAProxy, Caddy, and Envoy avoid this through unified state machines that treat protocol upgrades as first-class citizens. A Haskell implementation using WAI's `responseRaw` with the `splice` package for zero-copy forwarding can achieve superior architecture without these conflicts.

---

## The nginx conflict stems from header and buffer incompatibilities

The nginx WebSocket/SSE conflict is **architectural, not a bug**. WebSocket requires `Connection: upgrade` to signal protocol switch, while SSE requires `Connection: ""` (empty) for persistent HTTP streaming. When using nginx's common `map` block for WebSocket handling, non-WebSocket requests (including SSE) receive `Connection: close`, which terminates the persistent connection needed for streaming.

The secondary conflict involves buffering semantics. SSE requires `proxy_buffering off` to pass each event immediately as it arrives. WebSocket operates in a special tunnel mode that bypasses normal response buffering entirely, using exactly two memory buffers after the 101 handshake. While `proxy_buffering off` doesn't directly break WebSocket, these configurations target fundamentally different connection state models.

nginx strips hop-by-hop headers (`Upgrade`, `Connection`) by default, requiring explicit re-addition for WebSocket. This manual header passthrough conflicts with SSE's empty Connection header requirement. The documentation confirms: "Hop-by-hop headers including 'Upgrade' and 'Connection' are not passed from a client to proxied server" by default.

Timeout semantics compound the problem. nginx's `proxy_read_timeout` applies uniformly to all traffic, including upgraded WebSockets. Since nginx treats WebSocket as an opaque TCP tunnel after handshake, it cannot parse WebSocket frames—meaning **ping/pong frames don't reset the timer**. Production deployments often set year-long timeouts (`31536000s`) as workaround, risking resource leaks from silent connection failures.

---

## Modern proxies solve this through unified connection state machines

HAProxy elegantly handles this through a **two-phase connection model**. During the HTTP setup phase, it works in Layer 7 mode processing requests normally. Upon detecting successful upgrade (HTTP 101), HAProxy automatically switches to tunnel mode where no data is analyzed—WebSocket frames pass through as raw TCP. The key innovation is `timeout tunnel`, a separate timeout that takes precedence after upgrade, allowing short HTTP timeouts (**25s**) alongside long WebSocket timeouts (**3600s**).

Caddy takes the simplest approach: WebSocket proxying requires **zero configuration** in version 2. Caddy performs HTTP upgrade requests automatically, transitions the connection to a bidirectional tunnel, and maintains a registry for graceful shutdown. For streaming, Caddy uses intelligent automatic flush detection—when it sees `Content-Type: text/event-stream` or unknown `Content-Length`, it flushes immediately without buffering.

Envoy provides the most explicit configuration through `upgrade_configs` that explicitly enable protocol upgrades per-route or globally. After upgrade, Envoy treats WebSocket connections as plain TCP connections, independent of wire format. Slack successfully migrated millions of concurrent WebSockets from HAProxy to Envoy, citing hot restart without dropping connections and dynamic endpoint updates without configuration reload.

The common pattern across all successful implementations: **detect upgrade headers → validate 101 response → transition to tunnel mode → apply separate timeout domain**. Buffering filters are automatically excluded from upgraded connections—Envoy explicitly documents that "buffering is generally not compatible with upgrades."

---

## Haskell's WAI ecosystem supports transparent proxy architecture

For a Haskell reverse proxy, the recommended approach uses WAI's `responseRaw` combined with raw byte forwarding rather than full WebSocket frame parsing. The `http-reverse-proxy` package demonstrates this pattern: after detecting WebSocket upgrade via `isWebSocketsReq`, it creates bidirectional conduit streams between client and backend sockets.

```haskell
handleWebSocketProxy :: Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived
handleWebSocketProxy req respond = respond $
  responseRaw (rawProxy targetHost targetPort) backupResponse
```

The `websockets` library (version **0.13.0.0**) is production-quality and actively maintained since 2011, integrating with WAI via `wai-websockets`. It exposes multiple abstraction levels: high-level message-oriented APIs, mid-level `Message` types including control frames, and low-level `Stream` module for custom connection sources. However, for a transparent proxy, full frame parsing introduces unnecessary overhead.

Warp does **not** have built-in WebSocket handling—it relies on external libraries. The key mechanism is `responseRaw`, introduced specifically to enable reverse proxying WebSockets. Michael Snoyman noted: "Now with responseRaw support, all users of http-reverse-proxy automatically get WebSockets support."

Memory considerations matter for high-connection scenarios. The `websockets` library's per-connection overhead comes from GHC runtime stack space, per-message buffering (configurable via `SizeLimit`), and compression state (~64KB with defaults). ByteString uses pinned memory that cannot be moved by GC, potentially causing heap fragmentation with many small strings. For stored metadata, prefer `ShortByteString` (unpinned memory).

---

## Zero-copy forwarding matches production proxy behavior

Production proxies universally use **opaque/tunnel-mode forwarding** for WebSocket traffic after HTTP upgrade. HAProxy documentation states: "If everything goes well, the websocket is established, then HAProxy fails over to tunnel mode, no data is analyzed anymore." Envoy similarly "does not interpret the websocket frames."

The Haskell `splice` package provides production-ready socket-to-socket data transfer. On GNU/Linux, it uses the zero-copy `splice()` system call; on other platforms, it falls back to a portable implementation with single memory buffer:

```haskell
-- Bidirectional proxy loop
void . forkIO . try_ $ splice 1024 (clientSocket, _) (backendSocket, _)
void . forkIO . try_ $ splice 1024 (backendSocket, _) (clientSocket, _)
```

Protocol requirements that force frame parsing include: client-to-server frame masking validation, per-message compression (permessage-deflate extension), frame validation for security, and control frame handling at proxy level. However, for transparent proxying, these requirements don't apply—masking happens at endpoints, and control frames pass through unchanged.

A critical performance insight from kernel developers: `splice()` can actually be **slower** than naive read/write for small transfers due to abstraction overhead. Cloudflare's analysis shows that splice "copies data by assigning physical memory page pointers" rather than byte copying, but the syscall overhead matters. Recommended chunk size is **64KB** (matching kernel pipe size) for optimal splice performance.

| Strategy | CPU Usage | Memory | Visibility | Production Use |
|----------|-----------|--------|------------|----------------|
| Zero-copy (opaque) | Minimal | Buffer only | Connection-level | HAProxy, Envoy, Traefik |
| Parsed frames | Higher | Buffer + structures | Full messages | Security proxies |

---

## Ping/pong handling should be transparent with proxy-initiated health checks

RFC 6455 permits intermediaries to "coalesce or split" fragmented messages, but does **not specify** how proxies should handle ping/pong frames. The protocol expects pings to come from actual endpoints for true end-to-end liveness verification.

**Transparent forwarding** preserves end-to-end semantics, provides accurate RTT measurements, and requires no WebSocket parsing after handshake. This is what nginx and HAProxy use in tunnel mode. The downside: proxy cannot independently detect if backend dies silently.

**Proxy-level handling** (intercepting pings, responding with pongs) breaks end-to-end semantics—the server thinks a connection is alive when the client may be dead. Traefik received criticism for this behavior (GitHub issue #3683): "Traefik will answer all Ping messages and drop all Pong messages instead of forwarding them."

The **recommended hybrid approach**: forward all ping/pong frames transparently while implementing proxy-level connection monitoring. Track last activity timestamp per connection; after configurable idle period, proxy sends its own independent pings to both sides; terminate connections that don't respond within timeout; reset activity timer on ANY frame (data or control).

```
Per-connection state:
  last_activity: timestamp
  pong_expected: bool

Periodic check (every 10s):
  if pong_expected and (now - ping_sent_at) > pong_timeout:
    terminate_connection("pong timeout")
  elif (now - last_activity) > idle_threshold:
    send_ping(); pong_expected = true
```

---

## Timeout architecture requires protocol-aware separation

The fundamental problem: different protocols have vastly different lifetime expectations. HTTP requests complete in **30-300 seconds**. WebSocket connections may live for **hours to days**, possibly legitimately idle. SSE/streaming connections are long-lived but unidirectional.

nginx's timeout problem stems from `proxy_read_timeout` applying uniformly to all traffic. Combined with WebSocket frame opacity in tunnel mode, ping frames cannot reset the timer. Common workaround of year-long timeouts creates resource leak risk—"you won't detect silent backend netsplits."

HAProxy's model provides the blueprint for proper timeout architecture:

```
defaults
  timeout client    25s     # HTTP inactivity
  timeout server    25s     # HTTP inactivity
  timeout connect   5s      # TCP establishment
  timeout tunnel    3600s   # WebSocket/upgraded connections
```

The key insight: `timeout tunnel` automatically applies after successful protocol upgrade, allowing short HTTP timeouts but long WebSocket timeouts without configuration conflicts.

**Recommended timeout architecture for Haskell proxy:**

- **HTTP idle timeout**: 60 seconds
- **WebSocket tunnel timeout**: 3600 seconds (1 hour)
- **Proxy ping interval**: 30 seconds (must be shorter than tunnel timeout)
- **Pong response timeout**: 10 seconds
- **SSE/streaming timeout**: 3600 seconds
- **Per-route overrides**: Essential for diverse application requirements

Auto-detect connection type via `Connection: Upgrade` + `Upgrade: websocket` headers, response code 101, or `Content-Type: text/event-stream` for SSE.

---

## Architectural design principles for the Haskell proxy

The connection state machine should explicitly model different phases:

```haskell
data ConnectionState
    = HttpRequest          -- Initial HTTP parsing
    | HttpResponse         -- Response from upstream
    | ProtocolUpgrade      -- Detected upgrade, awaiting 101
    | TunnelMode           -- Bidirectional byte stream (WebSocket)
    | StreamingResponse    -- Chunked/SSE, flush immediately

transitionState :: ConnectionState -> Event -> ConnectionState
```

**Buffer management strategy:**
1. **Default**: Small buffers with periodic flushing for wire efficiency
2. **Streaming detection**: Zero-copy pass-through when `text/event-stream` detected
3. **Upgrade connections**: No buffering, direct pipe via `splice`
4. **Backpressure**: Watermark-based flow control (Envoy model)

**Key implementation decisions to avoid nginx's problems:**

- **Preserve Upgrade headers**: Don't strip hop-by-hop headers for reverse proxy use case
- **Detect Content-Type early**: Check for `text/event-stream` before buffering decisions
- **Separate timeout pools**: Long-lived connections get different timeout handling automatically
- **Connection registry**: Track upgraded connections for graceful shutdown
- **WebSocket frame awareness**: Even in tunnel mode, optionally parse control frames to reset idle timer and enable proxy-level health checks

**Recommended Haskell stack:**
- `wai` + `warp`: HTTP server foundation
- `streaming-commons`: TCP client connections
- `splice`: Zero-copy socket forwarding on Linux
- `async`: Concurrent bidirectional copy with `race_`
- `websockets` + `wai-websockets`: Only if frame-level access needed

**Architecture flow:**
```
Listener → HTTP Parser → Route Match →
  ├─ Regular HTTP → Buffer Pool → Upstream → Response Buffer → Client
  ├─ WebSocket → Upgrade Handler → Bidirectional Tunnel (splice)
  └─ SSE/Stream → Detect Header → Immediate Flush → Client
```

The fundamental architectural advantage over nginx: a single, unified routing path that auto-detects protocol type and transitions connection state appropriately, rather than requiring separate location blocks with conflicting header/buffering configurations. By treating streaming and WebSocket as natural variations of connection state rather than special cases requiring manual configuration, the Haskell proxy can achieve the elegant behavior of modern proxies like Caddy while maintaining the performance characteristics of HAProxy's tunnel mode.
