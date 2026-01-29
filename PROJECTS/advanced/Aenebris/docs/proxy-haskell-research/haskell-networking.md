# Haskell Networking with Warp: Technical Deep Dive

This comprehensive research document covers Warp web server architecture, performance, and advanced networking patterns including WebSocket handling, HTTP proxying, and streaming responses.

## Performance and Architecture

### How Warp achieves exceptional performance

Warp delivers **performance comparable to nginx** while maintaining clean, functional code under 1,300 source lines. This achievement stems from systematic optimizations across every layer of the request-response cycle.

**Lightweight thread architecture** forms Warp's foundation. GHC's green threads enable a "one thread per connection" model without traditional threading overhead. Each connection spawns a dedicated user thread that handles the complete request-response cycle. With 100,000+ concurrent threads running smoothly on modern hardware, this approach combines the programming clarity of synchronous code with event-driven performance.

The I/O manager evolved significantly across GHC versions. Early implementations used a single I/O manager thread handling all events via epoll or kqueue. GHC 7.8+ introduced **parallel I/O managers** with per-core event registration tables. Each CPU core gets its own epoll instance and I/O manager thread, eliminating contention while GHC's work-stealing scheduler distributes user threads efficiently across cores.

**The "yield hack"** represents a brilliant scheduler optimization. After sending a response, the thread calls `yield` to move itself to the end of the run queue. This allows other threads to execute while the next request arrives, so the subsequent `recv()` call typically succeeds immediately rather than returning EAGAIN and invoking the I/O manager. This simple technique dramatically reduces I/O manager overhead on small core counts.

### HTTP parsing optimizations

Warp's hand-rolled HTTP parser achieves **5x better performance** than general parser libraries like Parsec or Attoparsec. The key is **ByteString splicing** - a zero-copy technique that creates multiple ByteString views into a single 4KB buffer. The parser reads 4096 bytes from the socket, then uses pointer arithmetic to slice the buffer into request line and headers without copying memory.

Each ByteString is just three fields: a pointer to the buffer, an offset, and a length. Scanning for newlines uses C-level `memchr`, creating slices with different offsets all sharing the same underlying memory. Path parsing uses specialized functions like a custom `toLower` for 8-bit characters that's 5x faster than the Unicode version.

### Buffer management strategy

Buffer management exemplifies Warp's attention to low-level details. GHC's memory allocator uses a global lock for "large" objects (over 409 bytes on 64-bit systems). The original approach allocated a new pinned ByteString via `mallocByteString` for each recv call, potentially acquiring the global lock twice per request.

The optimized approach allocates a **single 4KB buffer per connection** using `malloc()`, which uses arena-based allocation without global locks. The buffer persists for the connection lifetime and serves double duty for both receiving and sending. After receiving data, a ByteString is allocated and the data copied with memcpy - just one allocation using the fast malloc arena. For responses, the same buffer holds composed headers before sending.

### System call optimizations

**accept4()** reduces connection establishment from 3 syscalls to 1. Instead of separate `accept()`, `fcntl()` to get flags, and `fcntl()` to set non-blocking, the Linux-specific `accept4()` accepts and sets non-blocking atomically.

**sendfile() with MSG_MORE** provides zero-copy file serving. The naive approach sent headers via `writev()` and body via `sendfile()` in separate TCP packets. Using `send()` with the MSG_MORE flag for headers tells the kernel more data is coming, so it buffers the header. The subsequent `sendfile()` sends header and body together in one packet. This optimization yields **100x throughput improvement** for sequential requests.

**File descriptor caching** eliminates repeated `open()/close()` syscalls for popular files. An LRU cache using a red-black tree multimap stores file descriptors with timeout-based cleanup. The same timeout manager used for connections handles cache pruning. File metadata (size, modification time) is cached alongside descriptors.

### Response composition

Header composition switched from Builder abstractions to **direct memcpy**. While Builder's rope-like structure offers O(1) append and O(N) packing, direct memcpy after pre-calculating total header size proves faster. Specialized optimizations include custom GMT date formatting with per-second caching, eliminating lookup calls for common headers, and 8-bit-only case-insensitive comparison.

Response types map to different sending strategies. **ResponseFile** uses sendfile() for zero-copy body transfer. **ResponseBuilder** fills the reused buffer incrementally with blaze-builder for efficient construction. **ResponseSource** uses conduit for streaming with deterministic resource cleanup.

### Timeout management and Slowloris protection

A single **timeout manager thread** handles all connection timeouts rather than spawning a thread per timeout. Each connection has an IORef pointing to its status (Active/Inactive). The timeout manager iterates the status list, toggling Active to Inactive and killing connections that remain Inactive.

The implementation uses **lock-free atomicModifyIORef** (CAS-based) instead of MVar locks for better concurrency. A safe swap-and-merge algorithm atomically swaps the list with empty, processes statuses, then merges back new connections added during processing. Lazy evaluation makes the merge O(1) while actual merging happens later as O(N).

Protection against Slowloris attacks works by tickling (resetting) timeouts when significant data is received - either when all request headers are read or at least 2048 bytes of request body arrive. Connections with no activity within the timeout period (default 30 seconds) are terminated.

### HTTP/2 support

Warp 3.0+ includes full HTTP/2 support with **performance matching HTTP/1.1**. The implementation handles dynamic priority changes, efficient request queuing, and sender loop continuation. The same file serving logic and buffer management applies to both protocols. Frame handling uses 16,384-byte max payload (2^14), matching TLS record size. Server push is supported via Settings with logging hooks for push events.

### Benchmarking results

On a 12-core Ubuntu bare-metal machine serving nginx's index.html (151 bytes) with 1000 connections making 100 requests each over keep-alive connections, **Mighty (built on Warp) delivers throughput comparable to nginx**. With multiple workers, Mighty scales better through prefork while nginx performance plateaus at 5+ workers. Profiling shows I/O dominates CPU time as expected, with parser overhead eliminated from the hot path.

## WAI Specification

### Core design

WAI (Web Application Interface) provides a **common protocol between web servers and web applications**, abstracting server implementation details so applications remain portable. The design emphasizes performance through streaming interfaces paired with ByteString's Builder type, removes variables that aren't universal to all servers, and uses continuation-passing style since WAI 3.0 for proper resource management.

### Application type

```haskell
type Application = Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived
```

The Application type uses **continuation-passing style** to ensure safe resource handling. The second parameter is a "send response" function that must be called exactly once:

```haskell
app :: Application
app req respond = bracket_
    (putStrLn "Allocating scarce resource")
    (putStrLn "Cleaning up")
    (respond $ responseLBS status200 [] "Hello World")
```

This CPS approach guarantees resources are properly managed even when exceptions occur.

### Middleware type

```haskell
type Middleware = Application -> Application
```

Middleware wraps applications to add functionality. Key combinators include:

```haskell
-- Conditionally apply middleware
ifRequest :: (Request -> Bool) -> Middleware -> Middleware

-- Modify responses
modifyResponse :: (Response -> Response) -> Middleware
```

### Request structure

The Request datatype contains all information about an incoming HTTP request:

**Key fields:**
- `requestMethod :: Method` - HTTP method (GET, POST, etc.)
- `httpVersion :: HttpVersion` - HTTP version
- `rawPathInfo :: ByteString` - Raw path from URL
- `rawQueryString :: ByteString` - Query string including leading '?'
- `requestHeaders :: RequestHeaders` - Header key-value pairs
- `isSecure :: Bool` - SSL/TLS status
- `remoteHost :: SockAddr` - Client host information
- `pathInfo :: [Text]` - Path split into segments
- `queryString :: Query` - Parsed query parameters
- `getRequestBodyChunk :: IO ByteString` - Read next body chunk
- `vault :: Vault` - Arbitrary data shared between middleware/app
- `requestBodyLength :: RequestBodyLength` - Known length or chunked

**Streaming request bodies** process data incrementally without loading everything into memory:

```haskell
-- Read request body chunk by chunk
processBody :: Request -> IO ()
processBody req = do
    chunk <- getRequestBodyChunk req
    unless (BS.null chunk) $ do
        processChunk chunk
        processBody req
```

### Response types

WAI provides multiple constructors optimized for different scenarios:

```haskell
-- Response from a file (efficient for static content)
responseFile :: Status -> ResponseHeaders -> FilePath -> Maybe FilePart -> Response

-- Response from a Builder (for constructed content)
responseBuilder :: Status -> ResponseHeaders -> Builder -> Response

-- Response from lazy ByteString
responseLBS :: Status -> ResponseHeaders -> ByteString -> Response

-- Streaming response (for large/dynamic content)
responseStream :: Status -> ResponseHeaders -> StreamingBody -> Response

-- Raw response (for WebSockets upgrade, etc.)
responseRaw :: (IO ByteString -> (ByteString -> IO ()) -> IO ()) -> Response -> Response
```

**StreamingBody type:**
```haskell
type StreamingBody = (Builder -> IO ()) -> IO () -> IO ()
```

The first function sends chunks, the second flushes to the client.

## HTTP Proxying with Warp

### Using http-reverse-proxy

The easiest approach uses the `http-reverse-proxy` package:

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Network.HTTP.ReverseProxy
import Network.HTTP.Client.TLS
import Network.Wai
import Network.Wai.Handler.Warp (run)

main :: IO ()
main = do
    manager <- newTlsManager
    let app = waiProxyToSettings
                (\request -> return $ WPRProxyDest $ ProxyDest "example.com" 80)
                defaultWaiProxySettings
                manager
    run 3000 app
```

**Advanced example with request modification:**

```haskell
bingExample :: IO Application
bingExample = do
    manager <- newTlsManager
    pure $ waiProxyToSettings
        (\request -> return $ WPRModifiedRequestSecure
            (request { requestHeaders = [("Host", "www.bing.com")] })
            (ProxyDest "www.bing.com" 443))
        defaultWaiProxySettings {wpsLogRequest = print}
        manager
```

### WaiProxyResponse type

```haskell
data WaiProxyResponse
    = WPRResponse WAI.Response           -- Return custom response
    | WPRProxyDest ProxyDest             -- Forward to destination
    | WPRModifiedRequest WAI.Request ProxyDest  -- Modify then forward
    | WPRApplication WAI.Application     -- Handle with application
```

### Building a custom HTTP proxy

For more control, build using http-conduit directly:

```haskell
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Wai
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import qualified Data.ByteString as BS

-- Custom proxy application
proxyApp :: Manager -> Application
proxyApp manager request respond = do
    -- Build the proxied request
    let targetHost = "httpbin.org"
        targetPort = 80
        proxiedReq = defaultRequest
            { method = requestMethod request
            , host = targetHost
            , port = targetPort
            , path = rawPathInfo request
            , queryString = rawQueryString request
            , requestHeaders = fixHeaders (requestHeaders request)
            , requestBody = case requestBodyLength request of
                KnownLength len -> RequestBodyStreamChunked $ \give ->
                    let loop = do
                            chunk <- getRequestBodyChunk request
                            if BS.null chunk
                                then return ()
                                else give chunk >> loop
                    in loop
                ChunkedBody -> RequestBodyStreamChunked $ \give ->
                    let loop = do
                            chunk <- getRequestBodyChunk request
                            if BS.null chunk
                                then return ()
                                else give chunk >> loop
                    in loop
            }

    -- Make the request and forward response
    httpLbs proxiedReq manager >>= \response ->
        respond $ responseLBS
            (responseStatus response)
            (fixResponseHeaders $ responseHeaders response)
            (responseBody response)

-- Fix headers (remove hop-by-hop headers)
fixHeaders :: RequestHeaders -> RequestHeaders
fixHeaders = filter $ \(name, _) -> name `notElem` hopByHopHeaders
  where
    hopByHopHeaders =
        [ "connection", "keep-alive", "proxy-authenticate"
        , "proxy-authorization", "te", "trailers"
        , "transfer-encoding", "upgrade"
        ]

fixResponseHeaders :: ResponseHeaders -> ResponseHeaders
fixResponseHeaders = filter $ \(name, _) -> name `notElem` hopByHopHeaders
  where
    hopByHopHeaders =
        [ "connection", "keep-alive", "proxy-authenticate"
        , "proxy-authorization", "te", "trailers"
        , "transfer-encoding", "upgrade"
        ]

main :: IO ()
main = do
    putStrLn "Starting HTTP proxy on port 8080"
    manager <- newManager tlsManagerSettings
    run 8080 (proxyApp manager)
```

### Advanced proxy features

**Handling headers:**

```haskell
-- Add X-Forwarded-For header
addForwardedFor :: Request -> RequestHeaders -> RequestHeaders
addForwardedFor req headers =
    let clientIP = show (remoteHost req)
        existing = lookup "X-Forwarded-For" headers
        newValue = case existing of
            Nothing -> BS.pack clientIP
            Just old -> old <> ", " <> BS.pack clientIP
    in ("X-Forwarded-For", newValue) : filter ((/= "X-Forwarded-For") . fst) headers

-- Set Host header for target
setHostHeader :: ByteString -> RequestHeaders -> RequestHeaders
setHostHeader targetHost headers =
    ("Host", targetHost) : filter ((/= "Host") . fst) headers
```

**WebSocket upgrade support** is automatic in http-reverse-proxy:

```haskell
waiProxyToSettings
    getDest
    defaultWaiProxySettings
        { wpsUpgradeToRaw = \req ->
            lookup "upgrade" (requestHeaders req) == Just "websocket"
        }
    manager
```

### Production considerations

**Connection pooling** - Share Manager instances:
```haskell
main = do
    manager <- newManager tlsManagerSettings  -- Create once
    run 8080 (proxyApp manager)
```

**Logging:**
```haskell
import Network.Wai.Middleware.RequestLogger

main = do
    manager <- newManager tlsManagerSettings
    run 8080 $ logStdoutDev $ proxyApp manager
```

**Error handling:**
```haskell
customOnExc :: SomeException -> WAI.Application
customOnExc exc _req respond = do
    putStrLn $ "Proxy error: " ++ show exc
    respond $ responseLBS
        status502
        [("Content-Type", "text/plain")]
        ("Proxy Error: " <> LBS.pack (show exc))
```

## Streaming Responses

### How streaming works in WAI/Warp

WAI defines streaming through the StreamingBody type which provides two callbacks - one to write data chunks and one to flush buffered data immediately. This approach **does not buffer the entire response in memory**.

```haskell
type StreamingBody = (Builder -> IO ()) -> IO () -> IO ()

responseStream :: Status -> ResponseHeaders -> StreamingBody -> Response
```

**Key features:**
- Automatic chunked transfer encoding in HTTP/1.1
- Backpressure through callback blocking
- Resource safety through CPS
- Constant memory usage

### Basic streaming example

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Network.Wai
import Network.Wai.Handler.Warp
import Network.HTTP.Types
import Data.ByteString.Builder (byteString)

app :: Application
app _req respond = respond $
  responseStream status200 [("Content-Type", "text/plain")] $ \write flush -> do
    write $ byteString "Hello\n"
    flush
    write $ byteString "World\n"

main :: IO ()
main = run 3000 app
```

### Streaming large files

```haskell
import qualified Data.ByteString as B
import System.IO
import Data.Function (fix)
import Control.Monad (unless)

streamFileApp :: Application
streamFileApp _req respond =
  withBinaryFile "largefile.txt" ReadMode $ \h ->
    respond $ responseStream status200 [("Content-Type", "text/plain")] $
      \chunk _flush ->
        fix $ \loop -> do
          bs <- B.hGetSome h 4096  -- Only 4KB in memory at once
          unless (B.null bs) $ do
            chunk $ byteString bs
            loop
```

**Note:** For single files, `responseFile` is preferred as it uses sendfile() for zero-copy transfer. Streaming shines when concatenating multiple sources or generating content dynamically.

### Server-Sent Events (SSE)

SSE enables real-time server-to-client updates over HTTP:

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Control.Concurrent (threadDelay)
import Control.Monad (forM_)
import Data.Monoid ((<>))
import qualified Data.ByteString.Char8 as C8

sseApp :: Application
sseApp _req sendResponse = sendResponse $
  responseStream status200
    [("Content-Type", "text/event-stream"),
     ("Cache-Control", "no-cache"),
     ("Connection", "keep-alive")]
    myStream

myStream :: (Builder -> IO ()) -> IO () -> IO ()
myStream send flush = do
  send $ byteString "data: Starting streaming response.\n\n"
  flush

  forM_ [1..50 :: Int] $ \i -> do
    threadDelay 1000000  -- 1 second
    send $ byteString "data: Message " <> byteString (C8.pack $ show i) <> byteString "\n\n"
    flush
```

**SSE format:** Each event uses `data: <message>\n\n` with optional fields like `event:`, `id:`, and `retry:`.

## Conduit Integration

### Conduit fundamentals

Conduit provides **streaming data processing** with deterministic resource handling. The three core abstractions are:

```haskell
type Source m o = ConduitT () o m ()         -- Produces values
type Sink i m r = ConduitT i Void m r        -- Consumes values
type Conduit i m o = ConduitT i o m ()       -- Transforms values

-- Operators
(.|) :: Monad m => ConduitM a b m () -> ConduitM b c m r -> ConduitM a c m r  -- fusion
runConduit :: Monad m => ConduitT () Void m r -> m r  -- execution
```

**Key properties:**
- Constant memory usage for arbitrarily large data
- Deterministic resource cleanup (no lazy I/O pitfalls)
- Composability for building complex pipelines
- Automatic backpressure through await/yield

### Simple conduit example

```haskell
import Conduit

main = do
  -- Pure operations
  result <- runConduit $ yieldMany [1..10] .| sumC
  print result  -- 55

  -- File operations
  runConduitRes $
    sourceFile "input.txt" .|
    sinkFile "output.txt"
```

### Conduit file streaming in Warp

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Data.Conduit
import qualified Data.Conduit.Binary as CB
import Control.Monad.Trans.Resource

conduitFileApp :: Application
conduitFileApp _req respond =
  respond $ responseStream status200 [("Content-Type", "text/plain")] $
    \write flush -> runResourceT $ do
      CB.sourceFile "largefile.txt" $$ CB.mapM_ $ \chunk -> liftIO $ do
        write (byteString chunk)
        flush
```

### Streaming from database

```haskell
import Database.Persist
import Data.Conduit
import qualified Data.Conduit.List as CL

streamFromDB :: Handler ()
streamFromDB = do
  -- selectSource returns a conduit Source
  selectSource [] []
    $$ CL.mapM_ $ \(Entity _ record) ->
         liftIO $ processRecord record
```

## Comparing Streaming Libraries

### Feature comparison

| Feature | Conduit | Pipes | Streaming |
|---------|---------|-------|-----------|
| **API Simplicity** | Moderate | More complex | Simple |
| **Performance** | Excellent | Excellent | Good |
| **Type Safety** | Strong | Very strong | Strong |
| **Resource Safety** | Built-in (ResourceT) | Manual (SafeT) | Manual |
| **Ecosystem** | Large (Yesod/Warp) | Moderate | Small |
| **Learning Curve** | Moderate | Steep | Gentle |
| **HTTP Integration** | Native (http-conduit) | Good (pipes-http) | Limited |

### When to use each

**Conduit** - Best choice for Warp applications:
- Tight integration with Yesod/Warp ecosystem
- Excellent resource management via ResourceT
- Large ecosystem (conduit-extra, http-conduit)
- HTTP streaming is first-class

```haskell
-- Conduit example
import Data.Conduit
import qualified Data.Conduit.List as CL

sumConduit :: IO Int
sumConduit = runConduit $
  yieldMany [1..10] .|
  CL.fold (+) 0
```

**Pipes** - For mathematically principled streaming:
- Follows category laws
- More flexible composition
- Better for complex pipelines
- Steeper learning curve

```haskell
-- Pipes example
import Pipes
import qualified Pipes.Prelude as P

sumPipes :: IO Int
sumPipes = P.fold (+) 0 id $ each [1..10]
```

**Streaming** - For straightforward use cases:
- Simplest API (closest to lists)
- Good for basic streaming
- Smaller ecosystem

```haskell
-- Streaming example
import Streaming
import qualified Streaming.Prelude as S

sumStreaming :: IO Int
sumStreaming = S.fold_ (+) 0 id $ S.each [1..10]
```

### Memory management and backpressure

**Key principles for constant memory:**
1. Never buffer entire response
2. Use appropriate chunk sizes (4-8KB disk, 16-64KB network)
3. Flush strategically (balance latency vs throughput)
4. Use bracket or ResourceT for cleanup

**Backpressure is automatic** - the write callback in StreamingBody blocks when the client's TCP buffer is full, naturally slowing down the producer. No manual intervention needed.

### Working examples

**Streaming CSV generation:**

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Control.Monad (forM_)
import qualified Data.ByteString.Char8 as C8

generateCSV :: (Builder -> IO ()) -> IO () -> IO ()
generateCSV write flush = do
  -- Header
  write $ byteString "id,name,value\n"
  flush

  -- Generate 1 million rows without buffering
  forM_ [1..1000000] $ \i -> do
    let row = byteString $ C8.pack $
          show i ++ ",Item" ++ show i ++ "," ++ show (i * 100) ++ "\n"
    write row
    when (i `mod` 1000 == 0) flush

csvApp :: Application
csvApp _req respond = respond $
  responseStream status200
    [("Content-Type", "text/csv"),
     ("Content-Disposition", "attachment; filename=data.csv")]
    generateCSV
```

**Progress updates during long operation:**

```haskell
processWithProgress :: (Builder -> IO ()) -> IO () -> IO ()
processWithProgress write flush = do
  let total = 100

  forM_ [1..total] $ \i -> do
    threadDelay 100000  -- Simulate work

    let progress = byteString $
          "data: {\"progress\": " <>
          byteString (C8.pack $ show i) <>
          ", \"total\": " <>
          byteString (C8.pack $ show total) <>
          "}\n\n"
    write progress
    flush

  write $ byteString "data: {\"status\": \"complete\"}\n\n"
  flush
```

## WebSocket Handling

### WebSocket integration architecture

Warp integrates with WebSockets through the **wai-websockets bridge package**, connecting WAI with the websockets library. This allows handling both regular HTTP and WebSocket upgrades seamlessly on the same port.

**Key components:**
- **websockets library**: Core WebSocket protocol (RFC 6455)
- **wai-websockets**: Bridge between WAI and websockets
- **Network.Wai.Handler.WebSockets**: Integration module

**Main integration function:**
```haskell
websocketsOr :: ConnectionOptions -> ServerApp -> Application -> Application
```

Where:
- `ConnectionOptions`: WebSocket configuration
- `ServerApp`: WebSocket handler (type: `PendingConnection -> IO ()`)
- `Application`: Fallback WAI application for non-WebSocket requests

### Basic WebSocket server

```haskell
{-# LANGUAGE OverloadedStrings #-}

import qualified Network.WebSockets as WS
import qualified Network.Wai as Wai
import qualified Network.Wai.Handler.Warp as Warp
import qualified Network.Wai.Handler.WebSockets as WaiWS
import Control.Monad (forever)
import qualified Data.Text as T

main :: IO ()
main = do
    putStrLn "WebSocket server running on http://localhost:9160"
    Warp.runSettings
        (Warp.setPort 9160 Warp.defaultSettings)
        $ WaiWS.websocketsOr WS.defaultConnectionOptions wsApp httpApp

-- WebSocket application
wsApp :: WS.ServerApp
wsApp pending = do
    conn <- WS.acceptRequest pending
    WS.withPingThread conn 30 (return ()) $ do
        msg <- WS.receiveData conn
        WS.sendTextData conn ("Echo: " <> msg :: T.Text)

-- Fallback HTTP application
httpApp :: Wai.Application
httpApp _ respond = respond $ Wai.responseLBS
    status200
    [("Content-Type", "text/plain")]
    "WebSocket server"
```

### Multi-user chat server

```haskell
{-# LANGUAGE OverloadedStrings #-}

import qualified Network.WebSockets as WS
import Control.Concurrent (MVar, newMVar, modifyMVar_, modifyMVar, readMVar)
import Control.Exception (finally)
import Control.Monad (forM_, forever)
import qualified Data.Text as T

type Client = (T.Text, WS.Connection)
type ServerState = [Client]

broadcast :: T.Text -> ServerState -> IO ()
broadcast message clients = do
    T.putStrLn message
    forM_ clients $ \(_, conn) -> WS.sendTextData conn message

application :: MVar ServerState -> WS.ServerApp
application state pending = do
    conn <- WS.acceptRequest pending
    WS.withPingThread conn 30 (return ()) $ do
        msg <- WS.receiveData conn
        clients <- readMVar state
        case msg of
            _ | not (prefix `T.isPrefixOf` msg) ->
                WS.sendTextData conn ("Wrong announcement" :: T.Text)
              | otherwise -> flip finally disconnect $ do
                  modifyMVar_ state $ \s -> do
                      let s' = client : s
                      WS.sendTextData conn $
                          "Welcome! Users: " <> T.intercalate ", " (map fst s)
                      broadcast (fst client <> " joined") s'
                      return s'
                  talk conn state client
          where
            prefix = "Hi! I am "
            client = (T.drop (T.length prefix) msg, conn)
            disconnect = do
                s <- modifyMVar state $ \s ->
                    let s' = filter ((/= fst client) . fst) s
                    in return (s', s')
                broadcast (fst client <> " disconnected") s

talk :: WS.Connection -> MVar ServerState -> Client -> IO ()
talk conn state (user, _) = forever $ do
    msg <- WS.receiveData conn
    readMVar state >>= broadcast (user <> ": " <> msg)
```

### Key WebSocket functions

**Connection management:**
- `acceptRequest :: PendingConnection -> IO Connection`
- `rejectRequest :: PendingConnection -> ByteString -> IO ()`
- `withPingThread :: Connection -> Int -> IO () -> IO () -> IO ()`

**Sending data:**
- `sendTextData :: WebSocketsData a => Connection -> a -> IO ()`
- `sendBinaryData :: WebSocketsData a => Connection -> a -> IO ()`

**Receiving data:**
- `receiveData :: WebSocketsData a => Connection -> IO a`
- `receiveDataMessage :: Connection -> IO DataMessage`

## TLS Termination

### warp-tls configuration

The `warp-tls` package provides TLS support using the pure Haskell `tls` library, supporting TLS 1.0-1.3, HTTP/2 via ALPN, client certificates, and SNI for multiple certificates.

**Basic setup:**

```haskell
{-# LANGUAGE OverloadedStrings #-}

import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS

main :: IO ()
main = do
    let tlsOpts = tlsSettings "cert.pem" "key.pem"
        warpOpts = setPort 443 defaultSettings
    runTLS tlsOpts warpOpts app

app :: Application
app _ respond = respond $ responseLBS
    status200
    [("Content-Type", "text/plain")]
    "Hello, HTTPS!"
```

### Advanced TLS configuration

```haskell
import Network.TLS
import Network.TLS.Extra.Cipher (ciphersuite_strong)

advancedTLS :: IO ()
advancedTLS = do
    let tlsOpts = (tlsSettings "cert.pem" "key.pem")
            { tlsAllowedVersions = [TLS13, TLS12]  -- Only TLS 1.2/1.3
            , tlsCiphers = ciphersuite_strong       -- Strong ciphers only
            , tlsWantClientCert = False
            , tlsServerHooks = defaultServerHooks
                { onClientCertificate = validateClientCert
                }
            , tlsSessionManagerConfig = Just defaultConfig
                { configTicketLifetime = 3600  -- 1 hour
                }
            , onInsecure = DenyInsecure "This server requires HTTPS"
            }

        warpOpts = setPort 443 $ setHost "0.0.0.0" $ defaultSettings

    runTLS tlsOpts warpOpts app

validateClientCert :: CertificateChain -> IO CertificateUsage
validateClientCert _ = return CertificateUsageAccept
```

### TLS with WebSockets

```haskell
{-# LANGUAGE OverloadedStrings #-}

import qualified Network.WebSockets as WS
import Network.Wai.Handler.WarpTLS
import Network.Wai.Handler.WebSockets

secureTLS :: IO ()
secureTLS = do
    let tlsOpts = tlsSettings "cert.pem" "key.pem"
        warpOpts = setPort 443 defaultSettings
        wsApp = websocketsOr WS.defaultConnectionOptions wsHandler httpApp

    runTLS tlsOpts warpOpts wsApp

wsHandler :: WS.ServerApp
wsHandler pending = do
    conn <- WS.acceptRequest pending
    WS.withPingThread conn 30 (return ()) $ do
        msg <- WS.receiveData conn
        WS.sendTextData conn ("Secure echo: " <> msg)
```

### Dynamic certificate selection with SNI

```haskell
import Data.IORef

dynamicCerts :: IO ()
dynamicCerts = do
    let tlsOpts = tlsSettingsSni $ \mbHostname -> do
            case mbHostname of
                Just "example.com" -> loadCredentials "example.pem" "example-key.pem"
                Just "other.com"   -> loadCredentials "other.pem" "other-key.pem"
                _                  -> loadCredentials "default.pem" "default-key.pem"

    runTLS tlsOpts defaultSettings app

loadCredentials :: FilePath -> FilePath -> IO Credentials
loadCredentials certFile keyFile = do
    result <- credentialLoadX509 certFile keyFile
    case result of
        Right creds -> return $ Credentials [creds]
        Left err    -> error $ "Failed to load credentials: " ++ err
```

## Connection Lifecycle Management

### Connection establishment

**TCP flow:**
1. Client initiates TCP connection
2. Warp accepts on listening socket
3. TLS handshake (if using warp-tls)
4. HTTP request parsing
5. Application handler invocation

**Lifecycle hooks:**

```haskell
let settings = defaultSettings
        { settingsPort = 8080
        , settingsHost = "0.0.0.0"
        , settingsOnOpen = \sockAddr -> do
            putStrLn $ "Connection opened from: " ++ show sockAddr
            return True  -- Accept connection
        , settingsOnClose = \sockAddr -> do
            putStrLn $ "Connection closed from: " ++ show sockAddr
        }
```

### Timeout management

Warp implements sophisticated timeout handling for Slowloris protection:

```haskell
let settings = defaultSettings
        { settingsTimeout = 30  -- 30 seconds
        , settingsSlowlorisSize = 2048  -- Bytes before timeout tickle
        }
```

**Timeout rules:**
- Timeout created when connection opens
- Reset when all request headers read
- Reset when at least 2048 bytes of body read
- Reset when response data sent
- Connection terminated if no activity within timeout period

### Graceful shutdown

```haskell
import Control.Concurrent
import System.Posix.Signals

gracefulShutdown :: IO ()
gracefulShutdown = do
    let settings = setInstallShutdownHandler shutdownHandler
                 $ setGracefulShutdownTimeout (Just 30)  -- 30 seconds max
                 $ setPort 8080 defaultSettings

    runSettings settings app
  where
    shutdownHandler closeSocket = do
        installHandler sigTERM (Catch $ do
            putStrLn "Received TERM signal, shutting down gracefully..."
            closeSocket  -- Stop accepting new connections
            ) Nothing
        installHandler sigINT (Catch $ do
            putStrLn "Received INT signal, shutting down gracefully..."
            closeSocket
            ) Nothing
```

**Graceful shutdown behavior:**
- Server stops accepting new connections
- Existing connections continue to completion
- Optional timeout forces termination of long-running requests
- Clean resource cleanup

### Production settings

```haskell
{-# LANGUAGE OverloadedStrings #-}

productionSettings :: Settings
productionSettings =
    setPort 443
    $ setHost "*"
    $ setOnOpen onOpen
    $ setOnClose onClose
    $ setOnException onException
    $ setTimeout 60
    $ setSlowlorisSize 2048
    $ setHTTP2Enabled True
    $ setGracefulShutdownTimeout (Just 30)
    $ setMaximumBodyFlush (Just 8192)
    $ setServerName "MyApp/1.0"
    $ setInstallShutdownHandler shutdownHandler
    $ defaultSettings
  where
    onOpen sockAddr = do
        putStrLn $ "Connection: " ++ show sockAddr
        return True

    onClose sockAddr =
        putStrLn $ "Closed: " ++ show sockAddr

    onException _ e =
        putStrLn $ "Exception: " ++ show e

    shutdownHandler closeSocket = do
        _ <- installHandler sigTERM (Catch closeSocket) Nothing
        _ <- installHandler sigINT (Catch closeSocket) Nothing
        return ()
```

## Handling WebSocket and Streaming Simultaneously

### The core challenge

The challenge of handling WebSocket and HTTP streaming simultaneously stems from **protocol mismatch** - HTTP proxies were designed for document transfer (request-response), not persistent connections.

**Key technical challenges:**

**1. Proxy buffering problem** - nginx and reverse proxies buffer responses by default, optimized for traditional HTTP. When streaming, data may sit in buffers until they fill, causing 25+ second delays in real-time applications.

**2. Connection upgrade handling** - The `Upgrade` header is hop-by-hop, not end-to-end. Regular HTTP proxies don't automatically forward `Upgrade: websocket`. Each hop needs explicit upgrade handling, and the proxy must switch from HTTP processing to establishing a tunnel.

**3. Timeout issues** - HTTP proxies timeout idle connections (default 60s in nginx). WebSocket connections and streaming responses appear "idle" to proxies designed for short-lived HTTP, causing premature disconnection.

**4. Multiplexing limitations** - HTTP/1.1 has no native multiplexing. WebSocket requires a dedicated TCP connection, using one of the browser's limited connection slots (6-8 per domain). WebSocket and streaming HTTP compete for these slots.

### Protocol differences

| Aspect | HTTP Streaming | WebSocket |
|--------|----------------|-----------|
| **Direction** | Unidirectional (server→client) | Bidirectional (full-duplex) |
| **Protocol** | HTTP (chunked encoding) | Dedicated protocol (RFC 6455) |
| **Overhead** | ~8KB headers per request | ~2 bytes per frame |
| **Framing** | Chunked encoding | Built-in message framing |
| **State** | Stateless | Stateful (requires sticky sessions) |
| **Buffering** | Proxies may buffer unpredictably | Binary framing prevents disk buffering |

### Warp's native handling

Warp provides **native support for both protocols** on the same server/port through its filter-based architecture:

**Single port handling:**
```haskell
{-# LANGUAGE OverloadedStrings #-}

import qualified Network.WebSockets as WS
import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WebSockets

main :: IO ()
main = do
    let port = 8000
        wsApp = websocketsOr WS.defaultConnectionOptions websocketHandler httpHandler
    putStrLn $ "Server running on port " ++ show port
    run port wsApp

-- WebSocket handler
websocketHandler :: WS.ServerApp
websocketHandler pending = do
    conn <- WS.acceptRequest pending
    WS.withPingThread conn 30 (return ()) $ forever $ do
        msg <- WS.receiveData conn
        WS.sendTextData conn ("Echo: " <> msg)

-- HTTP handler (including streaming)
httpHandler :: Application
httpHandler req respond =
    case pathInfo req of
        ["stream"] -> respond $ streamingResponse
        ["ws"]     -> respond $ responseLBS status404 [] "Use WebSocket protocol"
        _          -> respond $ responseLBS status200 [] "Hello HTTP"

streamingResponse :: Response
streamingResponse = responseStream
    status200
    [("Content-Type", "text/event-stream")]
    $ \write flush -> forever $ do
        threadDelay 1000000
        write $ byteString "data: tick\n\n"
        flush
```

**Architecture benefits:**
- Path-based routing on same port
- HTTP routes handle streaming via `responseStream`
- WebSocket routes handled by `websocketsOr`
- No proxy buffering issues (Warp is origin server)
- Async-first architecture handles thousands of concurrent connections efficiently

### Architectural solutions

**Solution 1: Path-based routing with nginx**

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}

server {
    listen 80;
    server_name example.com;

    # WebSocket endpoint
    location /ws/ {
        proxy_pass http://localhost:8001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;

        # Critical: disable buffering
        proxy_buffering off;

        # Increase timeouts
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # HTTP streaming endpoint (SSE)
    location /stream/ {
        proxy_pass http://localhost:8002;
        proxy_http_version 1.1;

        # Critical: disable buffering for streaming
        proxy_buffering off;
        proxy_cache off;

        # Keep connection alive
        proxy_set_header Connection '';
        proxy_set_header Cache-Control 'no-cache';
    }

    # Regular HTTP
    location / {
        proxy_pass http://localhost:8080;
        proxy_buffering on;  # Can enable here
    }
}
```

**Critical settings:**
- `proxy_buffering off` - **Essential** for both WebSocket and streaming
- `proxy_read_timeout` - Prevent idle connection timeouts
- `proxy_http_version 1.1` - Required for connection upgrade
- `Connection $connection_upgrade` - Dynamic header based on upgrade request

**Solution 2: Separate ports**

Run different services on different ports, route via nginx:
- HTTP: `:8080`
- WebSocket: `:8081`
- Streaming: `:8082`

Advantages: Clear separation, independent optimization, easier scaling
Disadvantages: More complex deployment, clients need multiple endpoints

**Solution 3: Single Warp application** (recommended)

Benefits:
- Same domain and port for all protocols
- Simplified deployment
- No nginx required (Warp runs directly)
- Native protocol handling

When to add nginx:
- SSL/TLS termination
- Load balancing across instances
- Static file serving
- Rate limiting

### Production architecture patterns

**Pattern: Microservices with specialized services**

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
┌──────▼──────────────────┐
│   Nginx/ALB             │
│  (Path-based routing)   │
└──┬──────────┬──────────┬┘
   │          │          │
┌──▼────┐  ┌─▼────────┐ ┌▼──────┐
│ HTTP  │  │WebSocket │ │Stream │
│Service│  │ Service  │ │Service│
│:8080  │  │  :8081   │ │ :8082 │
└───────┘  └────┬─────┘ └───────┘
                │
          ┌─────▼──────┐
          │   Redis    │
          │(State sync)│
          └────────────┘
```

**Pattern: Single Warp server**

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
┌──────▼──────────┐
│   Nginx (TLS)   │
│ (Optional proxy)│
└──────┬──────────┘
       │
┌──────▼──────────────┐
│   Warp Server       │
│  ┌──────────────┐   │
│  │ HTTP Routes  │   │
│  ├──────────────┤   │
│  │ WS Routes    │   │
│  ├──────────────┤   │
│  │Stream Routes │   │
│  └──────────────┘   │
└─────────────────────┘
```

### Best practices

**1. Disable proxy buffering:**
```nginx
location /ws/ {
    proxy_buffering off;
    proxy_cache off;
}
```

**2. Set appropriate timeouts:**
```nginx
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
```

**3. Always use TLS/SSL:**
- WSS (WebSocket Secure) and HTTPS
- Prevents proxy interference
- Required for security

**4. Implement heartbeats:**
```haskell
-- In WebSocket handler
WS.withPingThread conn 30 (return ()) $ do
    -- Your WebSocket logic
```

**5. State management for scaling:**
```haskell
-- Use Redis for distributed state
import Database.Redis

broadcastToAll :: Connection -> ByteString -> IO ()
broadcastToAll redis msg = do
    runRedis redis $ publish "channel" msg
    return ()
```

### Limitations and caveats

**WebSocket limitations:**
- Head-of-line blocking (large messages block subsequent ones)
- Corporate firewalls may block WebSocket (use WSS on port 443)
- Stateful connections complicate horizontal scaling
- No automatic reconnection (must implement in application)

**HTTP streaming limitations:**
- Unidirectional (server→client only)
- Intermediary proxies may buffer despite configuration
- Browser connection limits (6-8 per domain in HTTP/1.1)

**Warp-specific considerations:**
- Each WebSocket requires memory for buffers
- No built-in fallback to long-polling (unlike Socket.IO)
- Proper nginx configuration required when used as backend

### Alternative: Server-Sent Events

For unidirectional streaming, SSE offers advantages:

```haskell
sseHandler :: Application
sseHandler _req respond = respond $
    responseStream status200
        [("Content-Type", "text/event-stream"),
         ("Cache-Control", "no-cache")]
        $ \write flush -> forever $ do
            threadDelay 1000000
            write $ byteString "data: update\n\n"
            flush
```

**SSE advantages:**
- Automatic reconnection
- Event ID tracking
- Works over standard HTTP
- Better proxy compatibility

**SSE disadvantages:**
- Unidirectional only
- Text-only (UTF-8)
- Less efficient than WebSocket for bidirectional communication

## Annotated Source Code Analysis

### Key architectural decisions

**1. Buffer reuse architecture**

Located in `Network.Wai.Handler.Warp.Run`:

```haskell
-- Allocate 4KB buffer once per connection
buffer <- mallocBytes bufSize

-- Reuse for receive
bytes <- recv socket buffer bufSize

-- Reuse for send
composeHeader buffer headerSize
send socket buffer headerSize
```

**Design decision:** Single buffer per connection eliminates repeated allocations and global lock contention. The 4KB size stays under GHC's "large object" threshold (409 bytes on 64-bit) for subsequent allocations.

**2. Timeout manager implementation**

Located in `Network.Wai.Handler.Warp.Timeout`:

```haskell
-- Lock-free status updates
atomicModifyIORef statusRef $ \old -> (Active, old)

-- Safe swap-and-merge in timeout thread
xs <- atomicModifyIORef ref (\ys -> ([], ys))
xs' <- pruneInactive xs
atomicModifyIORef ref (\ys -> (merge xs' ys, ()))
```

**Design decision:** Using CAS-based `atomicModifyIORef` instead of `MVar` avoids lock contention. The swap-and-merge pattern ensures new connections added during processing aren't lost.

**3. HTTP/1.1 parser**

Located in `Network.Wai.Handler.Warp.Request`:

```haskell
-- Zero-copy ByteString slicing
parseRequestLine :: ByteString -> Either String (Method, ByteString, HttpVersion)
parseRequestLine bs = do
    let (method, rest1) = breakSpace bs
        (path, rest2) = breakSpace rest1
        version = rest2
    -- All share same buffer, just different offsets
```

**Design decision:** Hand-rolled parser using pointer arithmetic achieves 5x speedup over parser combinators by avoiding unnecessary allocations and leveraging C-level `memchr` for scanning.

**4. ResponseFile optimization**

Located in `Network.Wai.Handler.Warp.SendFile`:

```haskell
-- Use sendfile syscall for zero-copy
send header MSG_MORE  -- Tell kernel more data coming
sendfile fd offset count  -- Kernel sends header + body together
```

**Design decision:** The MSG_MORE flag prevents sending header and body in separate TCP packets, achieving 100x throughput improvement for sequential requests by reducing packet overhead.

### Performance-critical code paths

**Connection handling loop** (`Network.Wai.Handler.Warp.Run`):

```haskell
serveConnection conn settings app = do
    -- recv() -> parse -> app -> compose -> send()
    -- The yield hack after send():
    yield  -- Push thread to end of run queue
    -- Next recv() likely succeeds immediately
```

This simple `yield` call is responsible for major throughput improvements by reducing I/O manager invocations.

**File descriptor cache** (`Network.Wai.Handler.Warp.FdCache`):

Uses red-black tree multimap for O(log N) lookups with timeout-based pruning. The cache stores both file descriptors and stat results, eliminating repeated syscalls for popular files.

### HTTP/2 implementation

Located in `Network.Wai.Handler.Warp.HTTP2`:

The HTTP/2 implementation reuses the same buffer management and file serving logic as HTTP/1.1, with frame handling using 16,384-byte chunks (matching TLS record size). Dynamic priority changes and sender loop continuation ensure performance parity with HTTP/1.1.

## Conclusion

Warp demonstrates that functional programming achieves exceptional systems programming performance through careful optimization. Key insights include GHC's user threads providing thread-per-connection clarity with event-driven efficiency, immutability enabling fearless concurrency, type safety preventing entire bug classes, and high-level abstractions compiling to efficient code.

The ecosystem around Warp (WAI, conduit, websockets, warp-tls) provides production-ready tools for building high-performance web applications. The ability to handle regular HTTP, streaming responses, and WebSocket connections on the same port with consistent performance makes Warp an excellent choice for modern web services.

For production deployments, the key considerations are proper nginx configuration when used as a reverse proxy (particularly `proxy_buffering off` for streaming and WebSocket), appropriate timeout settings, TLS configuration with modern protocols and ciphers, graceful shutdown handling, and state management for horizontal scaling of WebSocket applications.

The combination of Warp's efficiency (comparable to nginx), Haskell's type safety, and the clean abstractions provided by the surrounding ecosystem creates a compelling platform for building reliable, high-performance web services.
