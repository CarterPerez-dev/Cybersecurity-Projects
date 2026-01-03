# WebSocket Implementation - Research & Prep (Milestone 1.5)

**Created:** 2025-11-16
**Status:** Planning Phase

---

## 🎯 **The REAL Goal**

Not just "make WebSockets work" - that's easy.
**Make WebSockets BETTER than nginx** and **solve the streaming/WebSocket conflict** that nginx has.

### **The Problem We're Solving** (From Real Experience)

> "streaming doesn't even work for me, and I remember hearing a while ago I have no clue if true but the thing to allow websockets to work conflict with what makes streaming work in nginx so I can't have both working"

**THIS is our target:** Make WebSockets + Streaming work SIMULTANEOUSLY without conflicts.

Nginx config issues:
- `proxy_buffering off` needed for streaming (Ollama AI)
- `proxy_http_version 1.1` + `Upgrade` + `Connection "upgrade"` needed for WebSockets
- Timeouts configured differently (`proxy_read_timeout 86400` for WebSockets vs `300s` for streaming)
- They conflict in nginx - can't have both perfect

**Our advantage:** We're building from scratch in Haskell - we can do BOTH right by design!

---

## 🧠 **Key Questions to Research**

### 1. **Technical Questions**
- How does WAI/Warp handle WebSocket upgrades natively?
- Does Haskell's `websockets` library play nice with Warp?
- How do we detect WebSocket handshake vs regular HTTP?
- Can we proxy WebSocket frames without parsing them? (performance)
- How do we handle bidirectional streaming efficiently? (use STM channels? conduits?)

### 2. **The Conflict Question** ⚠️
- WHY do streaming and WebSockets conflict in nginx?
- Is it buffering? Connection reuse? Timeout handling?
- How do we architect to avoid this entirely?

### 3. **Performance Questions**
- What's the overhead of proxying WebSocket frames?
- Can we do zero-copy WebSocket proxying?
- How do we handle thousands of concurrent WebSocket connections?
- Memory usage per connection?

### 4. **Protocol Questions**
- WebSocket handshake: do we validate or just proxy it?
- Do we need to parse WebSocket frames or pass through opaque?
- How do we handle WebSocket extensions (compression, etc.)?
- ping/pong frame handling - proxy or handle ourselves?

---

## 📚 **Research Needed**

### **Existing Research Docs**
We have:
- ✅ `http2-http3.md` - might have streaming info
- ✅ `performance-optimization.md` - zero-copy, memory efficiency
- ✅ `tls-ssl.md` - secure WebSockets (wss://)

Need to READ for relevant info.

### **New Research Required**

#### **1. Modern WebSocket Best Practices (2024/2025)**
Sources to search:
- RFC 6455 (WebSocket protocol) - official spec
- Haskell `websockets` library docs - latest version
- Warp WebSocket examples - production patterns
- Stack Overflow - "nginx websocket streaming conflict" - find the root cause!
- Modern WebSocket proxying techniques - what's changed since 2020?

#### **2. Haskell-Specific Patterns**
- How does `websockets` library integrate with WAI?
- Conduit vs Pipes vs Streaming for bidirectional data?
- STM patterns for WebSocket message routing?
- Resource cleanup on connection drop?

#### **3. Performance Benchmarks**
- What's nginx WebSocket performance? (baseline)
- What's Warp native WebSocket performance?
- Overhead of proxying vs direct serving?
- Can we beat nginx?

#### **4. Real-World Problems**
Search for:
- "nginx websocket not working"
- "nginx streaming chunked transfer"
- "websocket proxy buffering issues"
- "socket.io nginx configuration problems"

Learn from what DOESN'T work!

---

## 🏗️ **High-Level Implementation Plan** (Tentative)

### **Phase 1: Detection & Handshake**
**Goal:** Detect WebSocket upgrade request, proxy handshake

```
Request comes in → Check headers (Upgrade: websocket) →
  If YES: WebSocket path
  If NO: Normal HTTP path (existing code)
```

**Key:** Don't break existing HTTP proxying!

### **Phase 2: Connection Upgrade**
**Goal:** Establish proxy connection to backend WebSocket

```
Client ←→ Proxy ←→ Backend
   WebSocket    WebSocket
```

**Challenge:** Maintain two WebSocket connections, proxy frames bidirectionally

### **Phase 3: Bidirectional Streaming**
**Goal:** Stream frames in BOTH directions simultaneously

```haskell
-- Conceptual:
forkIO $ forever $ do
  clientFrame <- receiveFromClient
  sendToBackend clientFrame

forkIO $ forever $ do
  backendFrame <- receiveFromBackend
  sendToClient backendFrame
```

**Challenge:** Handle connection drops, timeouts, proper cleanup

### **Phase 4: Integration with Streaming**
**Goal:** Ensure WebSockets + chunked transfer streaming coexist

**Test Case:**
- WebSocket on `/api/socket.io/`
- Chunked streaming on `/api/ollama/stream`
- BOTH working simultaneously without conflicts!

---

## ❓ **Open Questions & Decisions**

### **1. Library Choice**
**Options:**
- A) Use `websockets` library (mature, battle-tested)
- B) Use Warp's native WebSocket support
- C) Roll our own (probably stupid)

**Need to research:** Which integrates better with our existing WAI app?

### **2. Frame Handling**
**Options:**
- A) Parse WebSocket frames (inspect, modify, validate)
- B) Proxy frames opaquely (zero-copy, faster, less control)

**Trade-off:** Performance vs observability/security

### **3. Connection State**
**How to track WebSocket connections?**
- Add to load balancer stats?
- Separate WebSocket connection pool?
- Integrate with health checking?

### **4. Timeout Strategy**
**Nginx problem:** Different timeouts for HTTP vs WebSocket vs Streaming

**Our approach:**
- Configurable per-route?
- Detect connection type and auto-adjust?
- Global defaults with overrides?

---

## 🎯 **Success Criteria**

**Minimum (Just Working):**
- ✅ Detects WebSocket handshake
- ✅ Proxies upgrade to backend
- ✅ Bidirectional frame proxying
- ✅ Handles connection drops

**Good (Better than Basic):**
- ✅ Zero-copy frame proxying (performance)
- ✅ Works with TLS (wss://)
- ✅ Integrates with load balancing
- ✅ Health checks don't break WebSockets

**Excellent (Better than Nginx):**
- ✅ **WebSockets + Streaming work SIMULTANEOUSLY without conflicts**
- ✅ Auto-detection (no special config needed for WebSockets)
- ✅ Better error messages than nginx
- ✅ Observable (metrics on WebSocket connections)
- ✅ Faster than nginx WebSocket proxying

---

## 📋 **Next Steps**

1. **Read existing research docs** (http2-http3.md, performance-optimization.md)
2. **Deep dive into websockets library** - read source if needed
3. **Find nginx conflict root cause** - search Stack Overflow, GitHub issues
4. **Study WAI WebSocket examples** - how does Warp do it natively?
5. **Benchmark nginx WebSocket performance** - set a target to beat
6. **Design the architecture** - how it integrates with existing Proxy.hs
7. **Write research doc** - `websockets-implementation.md` with full details

**Then:** Start coding with confidence, knowing we have a solid plan!

---

## 💡 **Insights to Remember**

- WebSockets are just HTTP upgrades - leverage existing HTTP proxying code
- Bidirectional = two concurrent loops, not sequential
- Connection cleanup is critical - use `bracket` pattern
- Performance matters - socket.io can have 1000s of connections
- The nginx conflict is REAL - don't repeat their mistakes

**Philosophy:** Research first, code smart, build something genuinely better.
