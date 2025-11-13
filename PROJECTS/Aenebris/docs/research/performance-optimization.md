# Zero-copy proxying unlocks gigabit+ throughput in Haskell

Building a high-performance proxy in Haskell requires understanding zero-copy techniques, compiler optimizations, and profiling methodologies. Zero-copy operations using splice() and sendfile() eliminate CPU copies between kernel buffers, reducing latency by 20-40% and enabling proxy servers to forward 60+ Gbps on modest hardware. Combined with GHC's advanced optimization capabilities and proper benchmarking, Haskell can achieve performance comparable to nginx while maintaining type safety and maintainability. The key insight: HAProxy demonstrates 1 Gbps forwarding on a 3-watt device using splice(), while Warp reaches 50,000 requests/second matching nginx performance through careful optimization of ByteString usage, zero-copy file serving, and GC tuning.

This report provides implementation-ready guidance for building production-grade proxies in Haskell, covering syscall-level optimizations through Haskell's Foreign Function Interface, compiler flag tuning for maximum performance, and comprehensive profiling workflows to identify bottlenecks. The techniques here enable developers to leverage Linux kernel optimizations while working in a high-level functional language.

## Zero-copy fundamentals eliminate redundant data movement

Traditional I/O operations copy data four times: disk to kernel buffer, kernel to user space, user space to socket buffer, and socket buffer to network. Each copy consumes CPU cycles and memory bandwidth. Zero-copy techniques reduce this to two DMA transfers with zero CPU copies, keeping data in kernel space throughout the transfer.

**splice() enables socket-to-socket forwarding**. This syscall moves data between file descriptors using kernel pipe buffers without user-space copies. For proxy servers forwarding between client and backend sockets, splice() is essential. The syscall signature requires one descriptor to be a pipe, creating a two-step process: splice data from source socket to pipe, then from pipe to destination socket. Kernel implementation uses reference-counted page pointers rather than copying bytes—only metadata changes, not actual data.

Performance characteristics show dramatic improvements. At 10 Gbps with 16KB buffers, copy overhead represents only 6.25% of processing time on modern Xeon processors achieving 20 GB/s memory bandwidth. However, eliminating this overhead alongside reduced context switches (from 4 to 2) and minimal cache pollution enables **HAProxy to achieve 60 Gbps forwarding on 4-core machines**. The key limitation: at least one file descriptor must be a pipe, and NIC must support scatter-gather DMA for optimal performance.

**sendfile() optimizes file-to-socket transfers**. Designed for serving static files, sendfile() transfers data directly from file to socket without user-space intervention. Modern Linux implementations (5.12+) actually implement sendfile() as a wrapper around splice() internally. The API is simpler than splice(), requiring no intermediate pipe, making it ideal for serving cached content or static files in reverse proxy scenarios.

Performance benchmarks reveal significant gains. Netflix achieved 6.7x throughput improvement (6 Gbps to 40 Gbps) on FreeBSD using sendfile() optimizations. Java zero-copy implementations showed 26% faster file copies with 56% less CPU time and 65% fewer cache misses compared to traditional I/O. For production proxy workloads, Google's MSG_ZEROCOPY research demonstrated 5-8% improvements in real deployments, though simple benchmarks showed 39% gains—the difference attributable to zero-copy setup costs for smaller transfers.

**When zero-copy provides maximum benefit**: Large file transfers (>10KB), high-frequency forwarding operations, memory bandwidth-constrained systems, and static content serving all benefit substantially. Conversely, small messages (<4KB), SSL/TLS connections requiring user-space processing, and dynamic content generation see limited or no benefit from zero-copy techniques.

## Haskell FFI bridges to zero-copy syscalls

Haskell's Foreign Function Interface enables direct access to Linux syscalls while maintaining type safety. The key challenge lies in marshalling between Haskell's high-level types and C's low-level representations, particularly for file descriptors, buffers, and error handling.

**Basic FFI patterns establish syscall bindings**. Foreign imports declare C function signatures with appropriate type mappings: `CInt` for integers, `CSsize` for signed size types, `Ptr a` for pointers. The `unsafe` keyword speeds calls that cannot callback to Haskell, while `safe` allows blocking operations without freezing other Haskell threads. For zero-copy syscalls, unsafe imports suffice as they're simple kernel calls.

```haskell
{-# LANGUAGE ForeignFunctionInterface #-}
import Foreign.C.Types
import System.Posix.Types (Fd(..))

foreign import ccall unsafe "splice"
  c_splice :: CInt -> Ptr CLong -> CInt -> Ptr CLong 
           -> CSize -> CUInt -> IO CSsize

splice :: Fd -> Fd -> Int -> [SpliceFlag] -> IO Int
splice (Fd fdIn) (Fd fdOut) len flags = do
  let cflags = foldr (.|.) 0 [f | SpliceFlag f <- flags]
  result <- c_splice fdIn nullPtr fdOut nullPtr 
                     (fromIntegral len) cflags
  if result == -1
    then throwErrno "splice"
    else return (fromIntegral result)
```

**Existing libraries provide production-ready implementations**. The `splice` package offers cross-platform zero-copy transfers, automatically using Linux splice() on GNU/Linux and falling back to portable Haskell implementations elsewhere. Its API handles bidirectional forwarding for proxy scenarios:

```haskell
import Network.Socket.Splice
import Control.Concurrent (forkIO)

-- Bidirectional zero-copy proxy
forkIO $ splice 4096 (clientSocket, Nothing) (backendSocket, Nothing)
forkIO $ splice 4096 (backendSocket, Nothing) (clientSocket, Nothing)
```

The `simple-sendfile` package powers Warp's high-performance static file serving. Used internally by Warp for ResponseFile handlers, it automatically selects optimal implementations: Linux sendfile(), FreeBSD/macOS native sendfile(), Windows TransmitFile(), or portable fallback. The API supports sending with headers in a single operation using the MSG_MORE flag:

```haskell
import Network.Sendfile

sendfileWithHeader :: Socket -> FilePath -> FileRange 
                   -> IO () -> [ByteString] -> IO ()
-- Sends headers and file data efficiently
sendfileWithHeader sock path (PartOfFile offset len) 
                   tickle headers
```

**WAI/Warp integration demonstrates production patterns**. Warp's `ResponseFile` constructor triggers zero-copy serving automatically. When serving static files, Warp uses sendfile() with header coalescing—sending HTTP headers via send() with MSG_MORE flag, then immediately calling sendfile() for the body. This optimization proved 100x faster for sequential requests by ensuring headers and body transmit in a single TCP packet.

Warp also implements file descriptor caching, controlled by `settingsFdCacheDuration`. Setting this to 10-30 seconds for static content eliminates repeated open() syscalls, though it requires caution in development environments where files change frequently. The default zero seconds prioritizes correctness over performance.

**Error handling requires careful EINTR and EAGAIN management**. Network syscalls can return EINTR (interrupted) or EAGAIN (would block) errors that require retry logic:

```haskell
spliceWithRetry :: Fd -> Fd -> Int -> IO ()
spliceWithRetry fdIn fdOut chunkSize = loop
  where
    loop = do
      result <- try $ splice fdIn fdOut chunkSize 
                      [spliceNonBlock, spliceMore]
      case result of
        Right 0 -> return ()  -- EOF
        Right n | n < chunkSize -> do
          threadWaitRead fdIn
          threadWaitWrite fdOut
          loop
        Right _ -> loop
        Left e | ioeGetErrorType e == eAGAIN -> do
          threadWaitWrite fdOut
          loop
        Left e -> throwIO e
```

Integration with GHC's I/O manager via `threadWaitRead` and `threadWaitWrite` enables non-blocking operation without busy-waiting, crucial for handling thousands of concurrent connections efficiently.

## ByteString optimization reduces allocation pressure

Haskell's ByteString types provide efficient binary data handling essential for network protocols. Understanding internal representations and choosing appropriate variants dramatically impacts proxy performance.

**Strict ByteString uses contiguous memory with minimal overhead**. Internally represented as a ForeignPtr with offset and length, strict ByteStrings enable zero-copy slicing—multiple ByteStrings can reference the same underlying buffer with different offsets. This **splicing capability eliminates copying during HTTP header parsing**: parsing "GET /path HTTP/1.1" can produce three ByteStrings (method, path, version) by adjusting offsets without copying bytes.

Memory overhead measures approximately 48 bytes per ByteString (ForeignPtr metadata), but the actual byte data contains no pointers, meaning GC doesn't scan it—only the metadata structures. For large allocations (>409 bytes on 64-bit), ByteStrings use pinned memory requiring a global lock, potentially causing contention on systems with 16+ cores. However, pinned memory prevents GC from moving data, enabling safe FFI calls to C functions expecting stable pointers.

**Lazy ByteString implements streaming via chunk lists**. Represented as a lazy list of strict ByteString chunks (default 32KB each), lazy ByteStrings handle arbitrarily large data without loading everything into memory. The chunk list spine adds some GC overhead, but allows processing gigabyte files with constant memory usage. Critical insight from Warp's implementation: "Lazy ByteStrings manipulate large or unbounded streams without requiring the entire sequence resident in memory."

Conversion costs between variants matter significantly. `toStrict` forces entire lazy ByteString evaluation then copies all data (O(n) time and space). Conversely, `fromStrict` merely wraps a strict ByteString in a single-chunk lazy ByteString (O(1)). The Hackage documentation warns: **"Avoid converting back and forth between strict and lazy bytestrings"** as repeated conversions waste CPU and memory.

**Builder patterns enable efficient construction**. The ByteString.Builder monoid supports O(1) concatenation, assembling responses from multiple parts without intermediate allocations:

```haskell
import Data.ByteString.Builder

buildHttpResponse :: Int -> [(ByteString, ByteString)] 
                  -> LazyByteString -> LazyByteString
buildHttpResponse status headers body = toLazyByteString builder
  where
    builder = statusLine <> headerLines 
           <> byteString "\r\n" <> lazyByteString body
    statusLine = byteString "HTTP/1.1 " <> intDec status 
              <> byteString " OK\r\n"
    headerLines = mconcat 
      [ byteString k <> byteString ": " <> byteString v <> byteString "\r\n"
      | (k, v) <- headers ]
```

Warp discovered Builder too slow for hot paths like HTTP header composition, implementing custom memcpy()-based composers instead. For application-level code, Builder provides excellent performance while maintaining readability.

**Connection pooling prevents resource exhaustion**. The `resource-pool` library manages reusable connections efficiently. Key configuration parameters include stripe count (independent sub-pools reducing lock contention), resources per stripe (total capacity), and idle timeout (automatic cleanup).

```haskell
import Data.Pool

createBackendPool :: HostName -> PortNumber -> IO (Pool Socket)
createBackendPool host port = do
  capabilities <- getNumCapabilities
  newPool $ 
    defaultPoolConfig
      (connectBackend host port)  -- Create function
      close                        -- Destroy function
      30.0                         -- 30 sec idle timeout
      (10 * capabilities)          -- 10 connections per core
    & setNumStripes (Just capabilities)
```

Stripe count should match capabilities for optimal load distribution. The `withResource` function ensures exception-safe usage: if the action throws any exception, the resource gets destroyed rather than returned to the pool, preventing poisoned connections from circulating. For applications where backend connections may die unexpectedly, implement health checking before use.

Network I/O integration with ByteString achieves maximum efficiency using the `Network.Socket.ByteString` module. The `sendAll` function ensures complete transmission, looping until all bytes transmit. The `sendMany` function implements vectored I/O (scatter-gather), transmitting multiple ByteStrings in a single syscall—critical for sending HTTP headers and body efficiently.

## GHC compiler flags unlock native performance

Glasgow Haskell Compiler offers extensive optimization controls affecting runtime performance by orders of magnitude. Understanding flag interactions and profiling-driven tuning separates adequate from exceptional performance.

**Optimization levels provide base performance tiers**. The `-O` flag enables safe optimizations balancing compile time with runtime performance, typically achieving 5% better performance than the native code generator baseline. The `-O2` flag applies aggressive optimizations including spec-constr (recursive function specialization based on argument shapes) and liberate-case (unrolling recursive functions once in their RHS). While `-O2` significantly increases compile time, recent GHC versions show diminishing returns—it rarely produces substantially better code than `-O` for most programs.

Specific optimizations merit individual attention. **Strictness analysis** (`-fstrictness`, enabled by default with `-O`) determines which function arguments are strict, enabling call-by-value and unboxing. The worker/wrapper transformation (`-fworker-wrapper`) exploits this information by creating specialized worker functions with unboxed arguments. These optimizations fundamentally change evaluation strategy, eliminating thunk allocation in hot paths.

**Common subexpression elimination** (`-fcse`) eliminates redundant computations but can interfere with streaming libraries. The key issue: **full laziness** (`-ffull-laziness`) floats let-bindings outside lambdas to reduce repeated computation, but increases memory residency through additional sharing. For streaming applications using conduit or pipes, `-fno-full-laziness` may prevent space leaks caused by over-sharing.

Inlining controls determine function call overhead. The `-funfolding-use-threshold` flag (default 80) governs when functions inline at call sites—the "most useful knob" for controlling inlining according to GHC developers. Lower values reduce code size at performance cost, higher values increase inlining aggressiveness. Cross-module optimization requires `-fcross-module-specialise`, allowing INLINABLE functions to specialize across module boundaries.

**LLVM backend trades compilation speed for runtime performance**. Activated with `-fllvm`, it leverages LLVM's advanced optimization passes including partial redundancy elimination, sophisticated loop optimizations, and superior register allocation. Numeric-intensive code sees 10-30% improvements, with some cases showing 2x speedups. The `lens` library compiles 22% faster wall-clock time with proper parallelization using LLVM. However, LLVM requires external installation and roughly doubles compilation time compared to GHC's native code generator.

**Manual pragmas direct compiler optimization**. The INLINE pragma aggressively inlines functions by making their "cost" effectively zero, critical for functions that enable downstream optimizations through inlining. However, overuse causes code bloat. The INLINABLE pragma exports function unfoldings for cross-module optimization without forcing inlining—ideal for polymorphic library functions enabling specialization at call sites:

```haskell
{-# INLINABLE genericSort #-}
genericSort :: Ord a => [a] -> [a]
genericSort = ...  -- Will specialize for each type

{-# SPECIALIZE genericSort :: [Int] -> [Int] #-}
-- Explicitly requests specialized version
```

Runtime system tuning complements compile-time optimization. **Parallel GC configuration** balances throughput and latency. The `-N` flag sets capability count (typically number of cores), while `-qg1` restricts parallel GC to old generation only, improving cache locality for young generation collections. For parallel programs, consider `-qb` (disable load balancing) to reduce GC overhead.

Allocation area sizing (`-A`) critically impacts GC frequency. Default 4MB works well for sequential programs, but parallel applications benefit from 64MB or larger. The `-n` flag divides allocation area into chunks, enabling better parallel utilization: `-A64m -n4m` creates 16 chunks allowing cores allocating faster to grab more allocation area. This configuration particularly benefits programs with 8+ cores and high allocation rates.

Heap size management via `-H` (suggested heap) and `-M` (maximum heap) prevents memory exhaustion while allowing GC to optimize collection timing. Setting `-H2G` hints at expected heap size, allowing GC to size generations appropriately. Setting `-M4G` caps maximum heap, throwing exceptions when exceeded—essential for production servers preventing OOM kills.

**Production build configuration combines multiple techniques**:

```bash
# CPU-intensive application
ghc -O2 -fllvm -threaded -rtsopts -with-rtsopts=-N Main.hs

# Runtime execution
./Main +RTS -N -A64m -n8m -qg1 -H2G -M4G -RTS
```

For development, disable optimization (`-O0`) for fastest compilation, using `-O` or `-O2` only for performance testing. The cabal.project file provides package-level control:

```
optimization: 2  -- Use -O2 for local packages

package myproxy
  ghc-options: -threaded -rtsopts -with-rtsopts=-N
```

Never use `ghc-options: -O2` in .cabal files—use the `optimization` field instead to properly integrate with Cabal's build system.

## Benchmarking methodology validates optimization impact

Accurate performance measurement requires understanding tool capabilities, avoiding common pitfalls, and statistical rigor. Different tools serve different purposes: criterion for micro-benchmarks, wrk for HTTP/1.1 load testing, h2load for HTTP/2.

**wrk excels at HTTP/1.1 load generation**. Its multi-threaded architecture generates high request rates, with LuaJIT scripting enabling complex request patterns. Basic usage requires thread count (`-t`), connection count (`-c`), and duration (`-d`):

```bash
wrk -t4 -c100 -d60s --latency http://localhost:8080/api/endpoint
```

Thread count should typically match CPU cores on the load generator machine. Connection count should exceed thread count significantly—common ratios range from 10:1 to 100:1 depending on expected production concurrency. Duration minimum should be 30 seconds, with 60+ seconds preferred for stable statistics accounting for JIT warmup and cache effects.

Lua scripting enables realistic traffic patterns. The `request()` function executes per-request, enabling dynamic request generation:

```lua
names = {"Alice", "Bob", "Charlie"}
request = function()
  headers = {}
  headers["Content-Type"] = "application/json"
  body = '{"name": "' .. names[math.random(#names)] .. '"}'
  return wrk.format("POST", "/api/users", headers, body)
end
```

Interpreting results requires understanding latency distribution. The `--latency` flag provides percentile breakdown:

```
Latency Distribution
   50%  635.91us
   75%  712.34us  
   90%  1.04ms
   99%  2.87ms
```

The 50th percentile (median) represents typical performance, while 99th percentile reveals tail latency crucial for user experience. **Standard deviation percentage above 90% indicates consistent performance**—lower values suggest high variance requiring investigation.

**h2load specializes in HTTP/2 testing**. Unlike wrk, h2load supports HTTP/2 multiplexing via the `-m` flag (max concurrent streams per client). This tests server HTTP/2 implementation efficiency:

```bash
h2load -n100000 -c100 -m100 https://localhost:8443
```

With 100 clients each maintaining 100 concurrent streams, the server handles 10,000 concurrent requests—testing multiplexing and priority handling. The output reports header compression statistics showing HPACK efficiency, typically 90%+ compression for repeated headers. Comparing HTTP/1.1 vs HTTP/2 requires running h2load with `--h1` flag:

```bash
h2load -n50000 -c100 -m1 --h1 http://localhost:8080   # HTTP/1.1
h2load -n50000 -c100 -m100 https://localhost:8443      # HTTP/2
```

**criterion provides statistically rigorous micro-benchmarking**. Designed for Haskell-specific challenges like lazy evaluation, criterion runs benchmarks multiple times, applies linear regression to filter noise, and reports confidence intervals:

```haskell
import Criterion.Main

main = defaultMain
  [ bgroup "parsing"
    [ bench "parseHeaders" $ nf parseHeaders sampleInput
    , bench "parseBody"    $ nf parseBody sampleBody
    ]
  ]
```

The critical distinction: `nf` (normal form) versus `whnf` (weak head normal form). For strict data like `Int` or `Bool`, `whnf` suffices. For structures like lists or ByteStrings where you want to ensure full evaluation, **use `nf` to avoid measuring only thunk creation**:

```haskell
-- WRONG: Only evaluates list constructor
bench "sum" $ whnf sum [1..1000000]

-- RIGHT: Forces complete evaluation
bench "sum" $ nf sum [1..1000000]
```

Environment setup prevents measurement artifacts from file I/O or initialization:

```haskell
main = defaultMain
  [ env setupEnv $ \testData ->
      bgroup "processing"
        [ bench "process" $ nf processData testData ]
  ]
  where setupEnv = BS.readFile "input.dat"
```

**System preparation ensures reproducible results**. CPU frequency scaling causes variance—set CPU governor to performance mode:

```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

Background processes introduce noise. Stop unnecessary services before benchmarking. For network benchmarks, **use separate machines for load generator and server**—localhost testing eliminates network stack traversal, producing unrealistic results.

Warmup periods matter significantly. First runs encounter cold caches (CPU, disk), uninitialized JIT state, and fresh memory allocation. h2load provides explicit warmup via `--warm-up-time=5`, running 5 seconds before starting measurement. For wrk, run a short test first, then the main benchmark.

Statistical rigor requires multiple runs. Run each benchmark 3-5 times, report median performance. Criterion handles this automatically, but for wrk/h2load, script multiple executions:

```bash
for i in {1..5}; do
  wrk -t4 -c100 -d60s http://localhost:8080 >> results-run-$i.txt
done
```

## Profiling reveals hidden performance bottlenecks

Systematic profiling identifies actual bottlenecks rather than assumed hotspots. GHC's profiling infrastructure spans CPU time, memory allocation, garbage collection, and heap composition.

**Cost-center profiling measures time and allocation**. Compiling with `-prof -fprof-late` instruments code with cost centers while minimizing optimization interference. The `fprof-late` flag inserts cost centers after optimization passes, reducing profiling overhead compared to traditional `-fprof-auto`:

```bash
ghc -O2 -prof -fprof-late -rtsopts MyProgram.hs
./MyProgram +RTS -p -RTS
```

The resulting `.prof` file shows time and allocation percentages:

```
COST CENTRE          %time  %alloc
parseRequest          23.4    18.2
routeMatching         12.7     8.1
buildResponse         34.8    42.3
```

Interpreting these results: `buildResponse` consumes most time (34.8%) and allocations (42.3%), making it the primary optimization target. The `entries` column reveals invocation count—high entry count with low per-call cost may indicate inappropriate inlining.

**Flame graphs visualize profiling data** effectively. The `ghc-prof-flamegraph` tool converts `.prof` files to interactive SVG visualizations showing call stacks hierarchically:

```bash
ghc-prof-flamegraph MyProgram.prof
# Generates MyProgram.svg

ghc-prof-flamegraph --alloc MyProgram.prof  # Allocation flamegraph
```

Flame graph width represents time/allocation percentage, height shows call stack depth. Wide flat sections indicate optimization opportunities. Clicking sections zooms into subtrees for detailed analysis.

**Heap profiling diagnoses memory issues**. Different profiling modes reveal distinct information. The `-hc` flag profiles by cost center (who allocated), `-hy` by type (what was allocated), `-hd` by constructor (specific data constructors), and `-hr` by retainer (what keeps objects alive):

```bash
ghc -O2 -prof -fprof-auto -rtsopts -eventlog MyProgram.hs
./MyProgram +RTS -hy -l -i0.1 -RTS
eventlog2html MyProgram.eventlog
```

The `-i0.1` flag samples every 0.1 seconds for detailed temporal resolution. Generated HTML provides interactive charts showing memory composition over time. Rising memory suggests space leaks—**look for THUNK accumulation indicating lazy evaluation building unevaluated expressions**.

**Info table profiling eliminates profiling overhead**. This newer technique requires no `-prof` compilation, instead using debug information from `-finfo-table-map`:

```bash
ghc -O2 -finfo-table-map -fdistinct-constructor-tables -eventlog MyProgram.hs
./MyProgram +RTS -hi -l -RTS
eventlog2html MyProgram.eventlog
```

This approach provides heap profiles without profiling's 20-100% runtime overhead. The detailed HTML report includes exact source locations for allocations, crucial for identifying leak sources. Constructor tables enable pinpointing which module and line created specific heap objects.

**Garbage collection statistics reveal GC pressure**. The `-s` flag outputs summary statistics after execution:

```
MUT time      0.63s   (  0.64s elapsed)
GC time      19.60s   ( 19.62s elapsed)
Total time   20.23s   ( 20.26s elapsed)
Productivity   3.1%
```

Productivity below 80% indicates excessive GC overhead. The detailed breakdown shows:

```
Gen 0:  3222 collections, parallel
Gen 1:    10 collections, parallel
Alloc rate: 1,823 bytes per MUT second
```

High Gen 0 collections with large allocation rate suggests **increasing `-A` (allocation area)**. Frequent Gen 1 collections indicate insufficient heap size—try larger `-H` or `-M` values. High "bytes copied during GC" suggests living data exceeds allocation area, requiring larger nursery.

**EventLog and ThreadScope visualize parallel execution**. For threaded programs, eventlog captures detailed execution traces:

```bash
ghc -O2 -threaded -eventlog -rtsopts MyProgram.hs
./MyProgram +RTS -N4 -ls -RTS
threadscope MyProgram.eventlog
```

ThreadScope displays CPU activity across cores, spark creation/conversion (for parallel strategies), GC activity, and thread migration. Effective parallel programs show sustained CPU activity across all cores with minimal GC pauses. Gaps indicate load imbalance or excessive synchronization.

**Profiling workflow progresses systematically**:

1. **Baseline measurement** with `-O2 +RTS -s` establishes initial performance
2. **Time profiling** with `-prof -fprof-late +RTS -p` identifies CPU hotspots  
3. **Memory profiling** with `-hd -l` and eventlog2html reveals allocation patterns
4. **Detailed investigation** using info table profiling for exact source locations
5. **Iterative optimization** applying fixes and re-profiling to verify improvements

Common patterns emerge from profiling. **Space leaks from lazy accumulation** manifest as rising THUNK count in heap profiles. Fix with strict foldl' and bang patterns. **CAF retention** appears as constant memory baseline—convert top-level values to functions accepting unit argument. **List fusion failures** show intermediate list allocation—switch to Vector with fusion or streaming libraries.

## Optimization checklist ensures systematic improvement

Successful optimization follows priority order: algorithms trump micro-optimizations, measure before optimizing, and validate improvements with profiling.

**Algorithmic improvements provide largest gains**. Changing from O(n²) to O(n log n) complexity dwarfs low-level optimizations. Before tuning GHC flags or adding strictness, evaluate data structures and algorithms. Replace lists with vectors for random access, Map with HashMap for integer keys, and sort algorithms with appropriate complexity for data characteristics.

**Compilation optimization checklist**:
- [ ] Use `-O` or `-O2` for production builds
- [ ] Add `-fllvm` for numeric-intensive code after benchmarking
- [ ] Enable `-threaded` for concurrent programs  
- [ ] Include `-rtsopts` to allow runtime tuning
- [ ] Set `-with-rtsopts=-N` for automatic parallelism
- [ ] Use `optimization: 2` in cabal.project, not `ghc-options`

**Code-level optimization checklist**:
- [ ] Add `INLINABLE` to polymorphic library exports
- [ ] Add `SPECIALIZE` pragmas for frequently-used type instances
- [ ] Use strict evaluation on hot path arguments (bang patterns)
- [ ] Mark strict record fields with `!` or use `UNPACK` for small fields
- [ ] Replace `foldl` with `foldl'` for strict accumulation
- [ ] Use `ByteString` throughout, avoiding `String` in I/O paths
- [ ] Prefer `Builder` for constructing `ByteString` responses

**Runtime tuning checklist**:
- [ ] Set `-N` to number of CPU cores for parallel programs
- [ ] Tune `-A` based on allocation rate (start with 64MB for parallel)
- [ ] Use `-n` for chunk allocation on 8+ core systems
- [ ] Set `-H` to hint expected heap size
- [ ] Set `-M` to cap maximum memory usage
- [ ] Monitor GC with `+RTS -s` to verify tuning effectiveness

**Zero-copy implementation checklist**:
- [ ] Use `splice` package for socket-to-socket forwarding
- [ ] Use `simple-sendfile` or Warp's `ResponseFile` for static content
- [ ] Implement connection pooling with `resource-pool` (stripes = cores)
- [ ] Configure appropriate idle timeouts (10-30 seconds)
- [ ] Add health checking for long-lived backend connections
- [ ] Use `sendAll` to ensure complete transmission
- [ ] Enable `NoDelay` socket option to disable Nagle algorithm

**Benchmarking validation checklist**:
- [ ] Set CPU governor to performance mode
- [ ] Stop unnecessary background services
- [ ] Use separate machines for load generator and server
- [ ] Include 5-10 second warmup period
- [ ] Run benchmarks for 60+ seconds duration
- [ ] Execute 3-5 runs and report median
- [ ] Document hardware, software versions, and configuration
- [ ] Store benchmark results in version control

**Profiling workflow checklist**:
- [ ] Establish baseline with `+RTS -s` statistics
- [ ] Profile time with `-prof -fprof-late +RTS -p`
- [ ] Generate flamegraphs for visual analysis
- [ ] Profile memory with `-hd -l` and eventlog2html
- [ ] Use info table profiling for exact source locations
- [ ] Verify productivity \u003e 80% (not GC-bound)
- [ ] Check allocation rate and GC frequency
- [ ] Re-profile after each optimization to confirm improvement

**Common pitfalls to avoid**:
- Don't optimize without profiling data
- Don't use `ghc-options: -O2` in .cabal files
- Don't over-inline (causes code bloat)
- Don't use `whnf` when `nf` is needed in criterion
- Don't benchmark on localhost (unrealistic network stack)
- Don't forget warmup periods
- Don't assume more `-A` is always better
- Don't apply `-funbox-strict-fields` globally without testing

## Zero-copy implementation guide provides practical patterns

Implementing zero-copy proxying in Haskell combines FFI syscall bindings, existing library usage, and careful error handling. This section provides production-ready code patterns.

**Complete proxy server with connection pooling**:

```haskell
{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Socket hiding (recv, send)
import Network.Socket.ByteString
import Network.Socket.Splice
import Data.Pool
import Control.Concurrent
import Control.Monad
import Control.Exception
import System.IO

data ProxyConfig = ProxyConfig
  { listenPort :: PortNumber
  , targetHost :: HostName  
  , targetPort :: PortNumber
  , poolStripes :: Int
  , poolPerStripe :: Int
  , poolIdleTime :: Double
  }

-- Create backend connection pool
createBackendPool :: ProxyConfig -> IO (Pool Socket)
createBackendPool config = 
  newPool $ 
    defaultPoolConfig
      (connectBackend (targetHost config) (targetPort config))
      close
      (poolIdleTime config)
      (poolPerStripe config)
    & setNumStripes (Just $ poolStripes config)

connectBackend :: HostName -> PortNumber -> IO Socket
connectBackend host port = do
  addr:_ <- getAddrInfo 
    (Just defaultHints { addrSocketType = Stream })
    (Just host) (Just $ show port)
  sock <- socket (addrFamily addr) Stream defaultProtocol
  setSocketOption sock NoDelay 1
  setSocketOption sock ReuseAddr 1
  connect sock (addrAddress addr)
  return sock

-- Main proxy server
runProxy :: ProxyConfig -> IO ()
runProxy config = do
  pool <- createBackendPool config
  addr:_ <- getAddrInfo
    (Just defaultHints 
      { addrSocketType = Stream
      , addrFlags = [AI_PASSIVE] })
    Nothing (Just $ show $ listenPort config)
    
  sock <- socket (addrFamily addr) Stream defaultProtocol
  setSocketOption sock ReuseAddr 1
  bind sock (addrAddress addr)
  listen sock 128
  
  putStrLn $ "Proxy listening on port " ++ show (listenPort config)
  
  forever $ do
    (client, clientAddr) <- accept sock
    forkIO $ handleClient pool client
      `finally` gracefulClose client 5000

-- Handle individual connection with zero-copy
handleClient :: Pool Socket -> Socket -> IO ()
handleClient pool client = do
  done <- newEmptyMVar
  
  withResource pool $ \backend -> do
    -- Bidirectional zero-copy forwarding
    let chunkSize = 65536  -- 64KB chunks
    
    forkIO $ do
      result <- try $ splice chunkSize (client, Nothing) 
                                      (backend, Nothing)
      case result of
        Left (e :: SomeException) -> 
          putStrLn $ "Client->Backend error: " ++ show e
        Right _ -> return ()
      putMVar done ()
    
    result <- try $ splice chunkSize (backend, Nothing)
                                    (client, Nothing)
    case result of
      Left (e :: SomeException) ->
        putStrLn $ "Backend->Client error: " ++ show e
      Right _ -> return ()
    
    takeMVar done

main :: IO ()
main = do
  capabilities <- getNumCapabilities
  let config = ProxyConfig
        { listenPort = 8080
        , targetHost = "backend.example.com"
        , targetPort = 8080
        , poolStripes = capabilities
        , poolPerStripe = 10
        , poolIdleTime = 30.0
        }
  runProxy config
```

**Efficient HTTP response builder**:

```haskell
{-# LANGUAGE OverloadedStrings #-}
import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BL

buildHttpResponse :: Int -> [(ByteString, ByteString)] 
                  -> BL.ByteString -> BL.ByteString
buildHttpResponse status headers body = toLazyByteString $
  mconcat
    [ byteString "HTTP/1.1 "
    , intDec status
    , byteString " "
    , statusText status
    , byteString "\r\n"
    , mconcat [ byteString k <> byteString ": " 
             <> byteString v <> byteString "\r\n"
              | (k, v) <- headers ]
    , byteString "\r\n"
    , lazyByteString body
    ]
  where
    statusText 200 = byteString "OK"
    statusText 404 = byteString "Not Found"  
    statusText 500 = byteString "Internal Server Error"
    statusText _   = byteString "Unknown"
```

**Zero-copy HTTP header parser**:

```haskell
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.Word

-- Parse request line without copying
parseRequestLine :: ByteString -> Maybe (ByteString, ByteString, ByteString)
parseRequestLine bs = do
  let (method, rest1) = BS.break (== space) bs
  guard (not $ BS.null rest1)
  
  let rest2 = BS.drop 1 rest1
      (path, rest3) = BS.break (== space) rest2
  guard (not $ BS.null rest3)
  
  let rest4 = BS.drop 1 rest3
      (version, _) = BS.break (== cr) rest4
      
  return (method, path, version)
  where
    space = 32; cr = 13

-- Parse headers using splicing
parseHeaders :: ByteString -> [(ByteString, ByteString)]
parseHeaders = go . BC.lines
  where
    go [] = []
    go (line:rest)
      | BS.null line = []
      | otherwise = 
          case BC.break (== ':') line of
            (key, value) 
              | BS.null value -> go rest
              | otherwise -> 
                  let val = BS.dropWhile (== 32) (BS.drop 1 value)
                  in (key, val) : go rest
```

**Cabal configuration for production**:

```cabal
-- myproxy.cabal
name:          myproxy
version:       0.1.0.0
build-type:    Simple
cabal-version: 2.0

executable myproxy
  main-is:          Main.hs
  build-depends:    base >= 4.14 && < 5
                  , network >= 3.1
                  , bytestring >= 0.11
                  , resource-pool >= 0.3
                  , splice >= 0.4
  ghc-options:      -O2 -threaded -rtsopts -with-rtsopts=-N
  default-language: Haskell2010

-- For profiling builds
-- cabal build --enable-profiling --ghc-options="-fprof-late"
```

**Deployment script with optimal RTS settings**:

```bash
#!/bin/bash
# deploy.sh

# Build optimized binary
cabal build --enable-optimization=2

# Set CPU governor
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Run with optimized RTS settings
./myproxy +RTS \
  -N         `# Use all cores` \
  -A64m      `# 64MB allocation area` \
  -n4m       `# 4MB chunks` \
  -qg1       `# Parallel GC for old gen only` \
  -H2G       `# Hint 2GB heap` \
  -M4G       `# Cap at 4GB` \
  -I0        `# Disable idle GC` \
  -T         `# Collect statistics` \
  -RTS
```

This implementation guide provides production-ready patterns combining zero-copy techniques, efficient ByteString usage, connection pooling, and optimal compiler/runtime configuration for building high-performance proxies in Haskell.
