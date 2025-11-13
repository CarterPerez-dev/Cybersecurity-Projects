# Rate Limiting Algorithms and Distributed Systems for API Security

Modern API security demands sophisticated rate limiting to prevent abuse, ensure fair resource allocation, and maintain system stability under attack. Production systems at Cloudflare process 46 million requests per second with sub-100 microsecond detection latency, while Stripe's Redis-based implementation handles millions of requests monthly. The sliding window counter algorithm has emerged as the industry standard, achieving 94% accuracy with O(1) complexity and 16MB memory footprint per million users—a balance proven at billion-request scale.

This comprehensive technical guide covers algorithm selection, distributed implementation patterns, adaptive and ML-based approaches, and production-ready code examples from systems handling global-scale traffic. The research synthesizes implementations from GitHub, AWS, Stripe, Cloudflare, and academic foundations, providing decision frameworks for selecting algorithms, Redis schemas with atomic Lua scripts, and security patterns for defending against sophisticated attacks.

## Core algorithm comparison reveals critical tradeoffs

Rate limiting algorithms differ fundamentally in their approach to traffic management, with each optimized for specific use cases. The sliding window counter represents the convergence point of accuracy and performance that has driven its adoption across high-traffic production systems.

**Token bucket** dominates where burst capacity is essential. AWS API Gateway and Stripe both implement this approach, allowing clients to accumulate tokens at a fixed refill rate while permitting instant bursts up to bucket capacity. A bucket configured with 100 token capacity and 10 tokens/second refill rate allows an immediate burst of 100 requests followed by sustained throughput of 10 requests/second. The algorithm requires only 20 bytes per user (storing token count and last refill timestamp), achieving 500 nanosecond latency with 94% accuracy. Implementation involves simple arithmetic: elapsed time multiplied by refill rate determines new tokens, with consumption checked against available balance. The primary weakness emerges at boundaries where clients can game the system by timing requests to burst periods, and greedy clients may monopolize resources by constantly draining tokens.

**Leaky bucket** enforces perfectly smooth output rates, making it ideal for protecting backend systems requiring constant load. NGINX implements this as its default algorithm, processing requests from a FIFO queue at fixed intervals. Unlike token bucket's variable output, leaky bucket guarantees predictable backend load—critical for VoIP systems, real-time streaming, and network traffic shaping. The algorithm maintains a queue of pending requests that "leak" at constant rate, introducing ~5 microsecond latency with greater than 99% accuracy. Memory consumption scales with queue size at approximately 800MB per million users with 100-request capacity, significantly higher than alternatives. The fatal flaw is inability to handle legitimate bursts: a mobile app syncing after extended offline period faces request starvation despite low average rate. Shopify's GraphQL API implements a sophisticated points-based variant where query complexity determines "marble" cost, with buckets leaking at 50-500 points/second depending on subscription tier.

**Sliding window log** achieves the highest accuracy of any algorithm at 99.997% based on Cloudflare's analysis of 400 million requests, with zero false positives and only 3 false negatives (all under 15% above threshold). The algorithm maintains a sorted set of every request timestamp, removing expired entries and counting remaining requests on each check. This perfect accuracy comes at severe cost: O(n) time complexity for processing, 800MB to 8GB memory per million users depending on traffic volume, and 50 microsecond latency. Implementation requires careful memory management with aggressive cleanup to prevent unbounded growth. The algorithm suits low-volume APIs where precision matters more than scalability, or regulatory environments requiring perfect audit trails.

**Sliding window counter** has emerged as the recommended algorithm for production systems, used by Cloudflare to handle billions of requests daily. This hybrid approach maintains counters for current and previous time windows, calculating a weighted estimate: `count = prev_count × (1 - elapsed%) + current_count`. With only 16 bytes per user, O(1) complexity, and 1 microsecond latency, the algorithm achieves 94% accuracy—a 6% average variance acceptable for nearly all use cases. The boundary approximation creates edge cases: a client making 94 requests at 00:00:59 and 94 at 00:01:01 might pass when the true sliding window would reject. However, this 6% error rate represents an optimal engineering tradeoff: sliding window log's 99.997% accuracy costs 50x more memory and 50x higher latency for marginal improvement.

**Fixed window** serves only non-critical scenarios due to catastrophic burst problems. Time divided into fixed intervals with counters resetting at boundaries creates the infamous "double rate" vulnerability: 10 requests at 00:00:59 plus 10 at 00:01:01 yields 20 requests in 2 seconds despite a 10/minute limit. The algorithm offers 100 nanosecond latency and 12MB per million users, but 50-200% accuracy variance disqualifies it for production APIs. Use cases are limited to internal development, prototyping, or highly tolerant systems where boundary bursts pose no risk.

### Algorithm selection matrix

| Algorithm | Time | Space/User | Latency | Accuracy | Memory (1M users) | Burst Support | Best Use Case |
|-----------|------|------------|---------|----------|-------------------|---------------|---------------|
| **Fixed Window** | O(1) | 12B | 100ns | 50-200% | 12 MB | Poor | Development only |
| **Token Bucket** | O(1) | 20B | 500ns | ~94% | 20 MB | Excellent | APIs with variable traffic |
| **Sliding Window Counter** | O(1) | 16B | 1μs | ~94% | 16 MB | Good | **Recommended for production** |
| **Sliding Window Log** | O(n) | 800-8000B | 50μs | 99.997% | 800MB-8GB | Good | High-precision/low-volume |
| **Leaky Bucket** | O(1) | 800B | 5μs | >99% | 800 MB | None | Constant rate required |

The decision framework is straightforward: **choose sliding window counter for 95% of production systems**. Its performance characteristics match modern distributed architectures while accuracy suffices for security and fairness. Select token bucket when burst handling is critical and you're following industry standards (AWS, Stripe patterns). Choose leaky bucket only when backend systems absolutely require constant rate input (NGINX integration, legacy systems). Reserve sliding window log for regulatory compliance, high-security environments, or low-traffic APIs where memory cost is irrelevant.

## Distributed rate limiting demands atomic operations

Rate limiting in distributed systems introduces race conditions, consistency challenges, and synchronization overhead that can undermine algorithm guarantees. Redis-based implementations with atomic Lua scripts solve these problems while maintaining sub-millisecond latency at scale.

**Redis sorted sets** provide the foundation for sliding window log implementation. The atomic Lua script handles three operations in a single round-trip: remove expired timestamps with `ZREMRANGEBYSCORE`, count remaining entries with `ZCARD`, and conditionally add new timestamp with `ZADD`. The key design pattern uses the timestamp as both member and score, enabling efficient range queries. TTL set via `EXPIRE` prevents memory leaks from abandoned keys. This pattern scales to millions of users with proper key naming: `rate_limit:{user_id}:{endpoint}` enables per-user, per-endpoint limits with independent quotas.

```lua
-- sliding_window.lua
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local current_time = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, '-inf', current_time - window)
local count = redis.call('ZCARD', key)

if count < limit then
    redis.call('ZADD', key, current_time, current_time)
    redis.call('EXPIRE', key, window)
    return {1, limit - count - 1}
else
    return {0, 0}
end
```

**Token bucket in Redis** uses hash structures to store mutable state atomically. The hash contains `tokens` (float) and `last_refill` (timestamp) fields updated together. The refill algorithm calculates elapsed time since last refill, computes new tokens as `min(capacity, current + elapsed × rate)`, and conditionally decrements if sufficient tokens exist. The pattern avoids race conditions by performing all calculations within the Lua script's atomic context. TTL set to 3600 seconds (one hour) auto-expires inactive users while allowing legitimate users to maintain state across requests.

```lua
-- token_bucket.lua
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local current_time = tonumber(ARGV[3])
local requested = tonumber(ARGV[4]) or 1

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1]) or capacity
local last_refill = tonumber(bucket[2]) or current_time

local elapsed = current_time - last_refill
tokens = math.min(capacity, tokens + elapsed * refill_rate)

if tokens >= requested then
    tokens = tokens - requested
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', current_time)
    redis.call('EXPIRE', key, 3600)
    return {1, math.floor(tokens)}
else
    return {0, math.floor(tokens)}
end
```

**Sliding window counter** achieves optimal performance by storing only two integer counters rather than full request logs. The implementation requires two keys: `{user}:{current_minute}` and `{user}:{previous_minute}`. The weighted calculation `previous_count × (1 - elapsed_percent) + current_count` approximates the true sliding window. The critical insight: this approximation delivers 94% accuracy while consuming 94% less memory than sorted sets. Production deployments should handle key rotation carefully, potentially storing both keys in a hash structure to ensure atomic updates across window boundaries.

**Consistent hashing** distributes rate limit state across Redis cluster nodes while minimizing key redistribution during scaling. Cloudflare's implementation uses Twemproxy with consistent hashing to shard rate limit data across memcache clusters. When adding nodes, only K/n keys redistribute (K = total keys, n = nodes), preserving most rate limit counters. This pattern enables horizontal scaling without reset-all disruption. The tradeoff: distributed counts become "never completely accurate" as AWS documentation states—network latency between nodes introduces timing windows where concurrent requests may both succeed despite exceeding limits. Production systems accept this 1-3% variance as cost of distribution.

**High availability patterns** prevent rate limiter failures from cascading. Redis Sentinel provides automatic failover with 3-5 sentinel nodes monitoring master health. Upon master failure, sentinels promote a replica within seconds, with applications reconnecting automatically via sentinel-aware clients. Redis Cluster offers alternative architecture with hash slots sharded across nodes, providing both HA and horizontal scaling. The critical decision: **fail open or fail closed** during Redis outage. Stripe fails open (allows requests) to prioritize availability; financial systems often fail closed (deny requests) for security. Implementing circuit breakers wraps Redis calls, tracking failure rates and automatically entering degraded mode when thresholds exceed limits.

```javascript
async function checkRateLimit(userId) {
  try {
    return await redis.eval(luaScript, [key], [limit, window, Date.now()]);
  } catch (error) {
    logger.warn('Rate limiter degraded', { error, userId });
    metrics.increment('rate_limiter.errors');
    return { allowed: true, degraded: true }; // Fail open
  }
}
```

**Schema design best practices** center on key naming conventions that enable efficient queries and avoid collisions. The pattern `{prefix}:{identifier}:{scope}:{timestamp}` provides hierarchy: `rate_limit:api:user:12345:endpoint:/api/data:window:1672531200`. This structure supports querying by user, endpoint, or time window. TTL strategies should align with window duration: set expiry to 2× window duration to prevent premature deletion during edge cases. For token bucket, longer TTL (1 hour) maintains state for intermittent users while auto-expiring inactive accounts. Memory optimization: use Redis hashes for small objects (under 100 fields) as they consume less memory than separate keys due to ziplist encoding.

**Alternative distributed stores** offer different tradeoffs. Memcached provides simpler protocol with potentially lower latency but lacks Lua scripting, forcing less efficient read-modify-write patterns. Hazelcast offers in-process data grids eliminating network latency entirely, ideal for rate limiting within microservices. Etcd suits systems already using it for configuration, though write throughput lags Redis. The verdict: **Redis dominates production rate limiting** due to Lua atomicity, proven scale (Cloudflare, Stripe, GitHub), and operational maturity. Consider alternatives only when architectural constraints prevent Redis adoption.

## Adaptive rate limiting responds to real-time conditions

Static rate limits fail when traffic patterns vary or system capacity fluctuates. Adaptive algorithms adjust limits dynamically based on server health metrics, user reputation, and traffic analysis, achieving optimal throughput while preventing overload.

**Netflix's adaptive concurrency limits** apply TCP congestion control principles to API rate limiting. The algorithm calculates `gradient = RTT_no_load / RTT_actual`, where gradient of 1 indicates no queuing delay, while values less than 1 signal congestion. The formula `newLimit = currentLimit × gradient + sqrt(currentLimit)` adjusts concurrency dynamically, with square root queue size enabling fast growth at low limits while providing stability at scale. Production results show convergence within seconds to optimal concurrency, near 100% retry success rate, and elimination of manual tuning. The approach prevents cascading failures by automatically backing off when backend latency increases, then gradually restoring capacity as performance recovers.

**AIMD (Additive Increase, Multiplicative Decrease)** provides simpler alternative inspired by TCP congestion algorithms. During normal operation, gradually increase rate limits (e.g., +10 requests/minute every 5 minutes). Upon detecting congestion—CPU above 80%, error rate exceeding 5%, or P99 latency doubling—multiplicatively decrease limits by 50%. This asymmetric approach provides stability: slow increases prevent oscillation while rapid decreases protect against overload. Implementation tracks moving averages of key metrics with circuit breaker pattern triggering limit adjustments.

**Server load monitoring** drives adjustments based on real-time capacity. CPU utilization above 80% triggers linear reduction of rate limits: `adjusted_limit = base_limit × (1 - cpu_load)`. Memory pressure follows similar pattern with heap usage monitoring. Response latency provides early warning: P99 latency exceeding baseline by 2× suggests saturation before resource metrics spike. Queue depth offers immediate signal: pending request count above threshold indicates insufficient capacity. Bitbucket Data Center combines physical memory evaluation (at startup) with CPU load monitoring (periodic) to dynamically allocate operation tickets, with formula `safe_bound = (total_RAM - JVM_heap - overhead) / avg_operation_memory` determining memory-constrained limits.

**User reputation scoring** enables trust-based differentiation. IP reputation combines multiple signals: threat score (0-100 probability of malicious intent based on historical attacks), VPN/proxy detection (likelihood of anonymization), blocklist presence (checking 100+ databases), and behavioral patterns (request rate consistency, navigation flow, session characteristics). High-reputation users receive elevated limits while suspicious actors face restrictions. GitHub demonstrates tiered approach: unauthenticated requests limited to 60/hour, authenticated to 5,000/hour, enterprise to 15,000/hour. Stripe adjusts limits per customer tier with automatic promotion as usage grows, balancing security and user experience.

**Cloudflare's volumetric abuse detection** uses unsupervised learning to establish per-endpoint baselines automatically. The system analyzes P99, P90, and P50 request rate distributions over time, identifying anomalies that indicate attacks rather than legitimate traffic surges. Per-session limits (via authorization tokens rather than IP addresses) minimize false positives from CGNAT shared IPs. The approach adapts to traffic changes automatically—distinguishing viral marketing campaigns from DDoS attacks by analyzing request patterns across endpoints. Integration with WAF machine learning scores, bot management scores, and TLS fingerprinting provides multi-dimensional threat assessment.

**Automatic scaling strategies** adjust both rate limits and infrastructure capacity. Kubernetes-based deployments monitor cluster metrics (CPU, memory per pod) via Prometheus at 10-second intervals, feeding decisions to adaptive policy engines. When average CPU exceeds 70%, the system both reduces per-user rate limits by 20% and triggers horizontal pod autoscaling. This dual response—reducing demand while increasing supply—prevents cascading failures during traffic spikes. AWS Shield Advanced employs 24-hour to 30-day baseline learning periods, automatically creating WAF rules when traffic exceeds learned patterns, with mitigation rules deployed in count or block mode based on confidence levels.

## Machine learning detects sophisticated attacks

Traditional rate limiting fails against coordinated distributed attacks, low-and-slow techniques, and adversarial evasion. Machine learning models trained on billions of requests identify attack patterns invisible to rule-based systems, achieving detection rates above 99% while maintaining sub-millisecond inference latency.

**Cloudflare's production ML pipeline** processes 46+ million HTTP requests per second in real-time, using CatBoost gradient boosting models with sub-50 microsecond inference per model. The architecture runs multiple models in shadow mode (logging only) with one active model influencing firewall decisions, enabling safe validation before promotion. Training data comes from trillions of requests across 26+ million internet properties, with high-confidence labels generated by heuristics engine (classifying ~15% of traffic) and customer-reported incidents. CatBoost was selected for native categorical feature support, reduced overfitting through novel gradient boosting scheme, and fast inference via C and Rust APIs. The bot score output ranges 0-100 (0=bot, 100=human), integrating with firewall rules for action decisions (allow, challenge, block).

**Feature engineering** determines model effectiveness. Network-level features include IP geolocation, ASN (Autonomous System Number), reputation scores, and JA3 TLS fingerprints capturing client SSL/TLS implementation. Header analysis examines User-Agent parsing and validation, Accept-Language patterns, header order and capitalization, and presence of custom headers. Inter-request features from Cloudflare's Gagarin platform track request rate over time windows, session duration and consistency, navigation patterns with referrer chains, and time-between-requests distributions. Behavioral features capture mouse movements, click patterns, keystroke dynamics, and maximum sustained click rate via sliding window analysis. Research on Twitter bot detection identified 49 profile features spanning message-based metrics (URL count, retweet frequency), part-of-speech patterns, special character usage, word frequency distributions, and sentiment analysis.

**Akamai's Behavioral DDoS Engine** combines multiple AI components into integrated defense. The baseline generator processes clean data over 2-week periods to create traffic profiles. The detection engine maintains multidimensional traffic views leveraging baseline intelligence. The mitigation engine identifies attackers using dimension combinations (IP + User-Agent + geolocation). Platform DDoS Intelligence provides threat signals from historical attack data. The baseline validator employs AI-based tuning, evaluating hundreds of attacks monthly to reduce false positives. Protection levels adjust sensitivity: strict mode responds rapidly to slight anomalies (high-security environments), moderate balances protection versus false positives (recommended), while conservative tolerates substantial deviations. Production case studies show 99.95% detection rate across 1.4 billion requests from 7,000+ IPs and 99.50% detection across 185 million requests from 5,000+ IPs.

**Anomaly detection algorithms** identify novel attack patterns without labeled training data. Isolation Forest effectively detects outliers in high-dimensional feature spaces by measuring how quickly observations can be isolated via random partitioning. K-Nearest Neighbors Conformal Anomaly Detection uses Mahalanobis distance and non-conformity measures (sum of distances to k-nearest neighbors) for contextual anomaly detection. Relative entropy (Kullback-Leibler divergence) compares current request distributions to baseline distributions via hypothesis testing. Deep learning approaches include LSTM recurrent neural networks for temporal pattern recognition in request sequences and autoencoders learning normal traffic patterns in unsupervised fashion, with reconstruction error indicating anomalies.

**Real-time versus batch prediction** presents fundamental architectural tradeoff. Real-time inference generates predictions on-demand at request time with sub-millisecond to low-millisecond latency requirements. Cloudflare's edge deployment runs models on every edge server with <100 microsecond overhead, using CatBoost via LuaJIT FFI with no network calls. The approach handles single observation processing with continuous availability at millions of requests/second throughput. Batch prediction processes large datasets offline on scheduled intervals (hourly, daily, weekly), enabling complex model architectures and extensive feature computation via big data frameworks (Spark, Hadoop) with cost-optimized compute. Use cases include historical traffic analysis, model retraining data generation, and reputation score updates. The hybrid approach: real-time inference for immediate blocking decisions, batch processing for reputation updates and model retraining.

**Integration with traditional rate limiting** creates layered defense. Layer 1 employs traditional algorithms (token bucket, leaky bucket) providing fast, deterministic response in <1ms. Layer 2 adds heuristics engine with simple rule-based detection executing in ~20 microseconds, classifying ~15% of traffic. Layer 3 incorporates ML models with multi-feature analysis and ~50 microsecond inference handling sophisticated attacks. Layer 4 applies behavioral analysis with unsupervised anomaly detection and long-term pattern recognition. Layer 5 reserves human verification (CAPTCHA, JavaScript challenge) as fallback for uncertain cases. Score combination methods include weighted ensemble (`FinalScore = w1×Heuristic + w2×ML + w3×Behavior`), decision trees with confidence-based routing, and uncertainty thresholds triggering additional verification.

**AWS Shield Advanced demonstrates production integration** with automatic ML-based mitigation. The system monitors traffic baselines over 24 hours to 30 days, detecting deviations using ML models combined with heuristics. Upon detection, Shield automatically creates WAF rules deployed in Shield-managed rule group (consuming 150 WCU capacity), with customers choosing count or block mode. Rules automatically remove when attacks subside, providing adaptive defense without manual intervention. Integration with CloudWatch enables alerting and 24/7 DRT (DDoS Response Team) support for Enterprise customers.

## Proof-of-work and advanced strategies add defense layers

Rate limiting alone cannot stop determined attackers with distributed resources. Proof-of-work challenges, geographic filtering, hierarchical limits, and context-aware strategies create defense-in-depth against sophisticated threats.

**Cloudflare Turnstile** represents modern CAPTCHA alternative, running non-interactive JavaScript challenges including proof-of-work, proof-of-space, Web API probing, and browser quirk detection. Three widget modes provide flexibility: managed mode (adaptive checkbox), non-interactive (visible but no interaction), and invisible (completely hidden). Tokens expire after 300 seconds with single-use only validation, requiring server-side verification via Siteverify API. Implementation requires simple HTML div with sitekey and included JavaScript. Security considerations demand never exposing secret keys client-side, rotating keys regularly, restricting hostnames to controlled domains, and monitoring via Turnstile Analytics. Production use cases include login form protection, API endpoint protection via WAF integration, and form submission validation.

**Computational puzzles** create asymmetric costs: hard to solve but easy to verify. Hash-based puzzles require finding nonce such that `sha256(challenge + nonce)` has N leading zeros, with difficulty adjusted by required zero count. Client-side implementation solves transparently without user awareness, while server validates solution in microseconds. Performance metrics show 85% false positive reduction versus CAPTCHA-only, 95% completion rates (versus 70% for visual challenges), and 80% reduction in successful bot attacks. The approach suits account registration (medium difficulty), login verification (low difficulty), and anti-scraping measures (variable difficulty), with difficulty dynamically adjusted based on threat level.

**Geographic-based rate limiting** applies region-specific limits optimizing for threat landscape and resource costs. MaxMind GeoIP databases provide 99% country accuracy, 75% city accuracy via IP-based geographic determination. Tiered regional limits example: US-OR (Oregon) receives 1000 requests/minute as high-trust region, rest of US gets 500 requests/minute, while default regions limited to 100 requests/minute. AWS WAF geo match implementation supports country codes with per-region rate limits. Use cases include fighting spam from specific regions, prioritizing resources for key markets, compliance with regional regulations, and cost optimization. Critical security consideration: **never rely solely on geography** as VPNs easily spoof location. Layer geographic limits with IP reputation, behavioral analysis, and proof-of-work challenges.

**Hierarchical rate limiting** implements multiple cascading layers preventing resource starvation. Four-layer architecture: Layer 1 global infrastructure limits (100,000 requests/second across entire infrastructure prevents system overload), Layer 2 category/service limits (authentication 10,000/minute, data API 50,000/minute separates traffic classes), Layer 3 user/client limits (1,000 requests/hour per user ensures fairness), Layer 4 endpoint-specific limits (POST /expensive 10/minute protects costly operations). Redis implementation checks all layers hierarchically, incrementing all counters only when all checks pass, providing atomic multi-level enforcement. Slack's notification system demonstrates pattern: global limit 100 notifications/30 minutes, with category limits for errors (10), warnings (10), info (10) that sum above global limit, demonstrating how global acts as final constraint.

**HTTP method-specific rate limiting** recognizes different resource impacts by method. GET requests typically allow 100-1000/minute as read-only and less expensive. POST requests restricted to 10-50/minute for resource creation with higher cost. PUT/PATCH receives 20-100/minute for updates with moderate cost. DELETE most restrictive at 5-20/minute given security sensitivity. NGINX implementation maps request methods to different limit zones, applying write operation limits (10/minute) to POST/PUT/DELETE while read operations (100/minute) apply to GET. Login endpoints warrant special treatment: `POST /api/login` limited to 5 attempts/minute per IP and 10 attempts/minute per username, with exceeded limits triggering security alerts and incrementing threat scores.

**Burst handling techniques** separate algorithms' core differentiator. Token bucket allows bursts up to bucket capacity: 100 token capacity with 10 tokens/second refill permits 100 request instant burst followed by sustained 10/second. Configuration flexibility: capacity determines maximum burst size, refill rate sets sustained throughput, tokens per request enables weighted costs. Leaky bucket smooths bursts into constant output rate, processing requests from queue at fixed intervals. The bucket accepts bursts into queue (up to capacity), but backend receives perfectly steady stream. Comparison reveals token bucket best for bursty traffic and variable traffic patterns, while leaky bucket optimal when backend requires constant rate (VoIP, streaming, real-time systems). Combined approach uses local token bucket (capacity 100, refill 50/second) absorbing local bursts with global leaky bucket (capacity 1000, leak 100/second) smoothing global traffic.

**Time-based adjustments** adapt to known traffic patterns. Peak hours handling (8am-5pm business hours) allows higher limits (100 requests/minute) during expected high traffic, with off-peak hours (6pm-7am) reduced limits (50 requests/minute). Adaptive strategies monitor server load, reducing limits when CPU exceeds 80% regardless of time. Maintenance windows employ severe restrictions (10 requests/minute) with whitelist for admin IPs and monitoring systems during scheduled downtime. Critical implementation detail: **prevent thundering herd at window boundaries** by adding jitter to retry timing (±20% randomization) so clients don't all retry simultaneously at exact boundary.

**Strategy selection** depends on traffic characteristics and security requirements. Per-IP rate limiting suits anonymous traffic, DDoS prevention, and brute force mitigation as first defense layer, but fails against shared IPs (NAT, proxies) and VPN bypass. Per-user limiting enables precise control for authenticated users, supports subscription tiers, and provides better UX, requiring authentication mechanism. Per-endpoint limiting protects resource-intensive operations with different costs: POST /login limited to 5/minute, GET /health unlimited, POST /api/data 100/hour. **Recommended approach combines all three**: global infrastructure limit (10,000/minute), per-IP limit (100/minute), per-user tier limits (1,000/hour free, 10,000/hour premium), and per-endpoint limits for sensitive operations.

## Real-world implementations provide production patterns

Major platforms have converged on proven patterns through years of evolution handling billions of requests. Their implementations reveal practical tradeoffs between theoretical purity and operational reality.

**GitHub API** implements token bucket with sophisticated point-based secondary limits. Primary limits: unauthenticated 60/hour per IP, authenticated 5,000/hour, Enterprise Cloud 15,000/hour for GitHub Apps. Secondary limits prevent abuse: max 100 concurrent requests, 900 points/minute for REST (2,000 for GraphQL), 90 seconds CPU time per 60 seconds real time, 80 content-creating requests/minute. Point costs vary by operation: GET/HEAD/OPTIONS cost 1 point, POST/PATCH/PUT/DELETE cost 5 points, GraphQL mutations 5 points. Headers returned include `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-used`, `x-ratelimit-reset` (Unix epoch), and `x-ratelimit-resource`. Error responses use 403 or 429 status with `x-ratelimit-remaining` at 0. Best practices include conditional requests (ETags, If-None-Match), response caching, and GraphQL to reduce calls.

**Stripe API** employs Redis-based token bucket with four limiter types: request rate limiter (100/second live mode, 25/second sandbox), concurrent request limiter, fleet usage load shedder (critical vs non-critical requests), and worker utilization load shedder. Resource-specific limits include 1,000 PaymentIntent updates/hour per intent, Files API 20 read + 20 write/second, Search API 20 read/second, meter events 1,000 calls/second. The `Stripe-Rate-Limited-Reason` header indicates which limit triggered (global-concurrency, global-rate, endpoint-concurrency, endpoint-rate, resource-specific). Engineering blog reveals Redis provides low-latency distributed state, with exponential backoff recommended (randomization prevents thundering herd), and client-side token bucket for sophisticated applications. The system "constantly triggered," rejecting millions of test mode requests monthly, demonstrating production hardening.

**AWS API Gateway** uses token bucket with multi-level throttling: account-level default 10,000 requests/second per region with 5,000 burst capacity (lower regions 2,500 RPS with 1,250 burst). Throttling order: per-client → per-method → per-stage → account-level → regional. Usage plans enable custom limits per API key/client. Status code 429 returned with no specific rate limit headers by default, relying on CloudWatch metrics for monitoring. Documentation acknowledges distributed architecture means rate limiting "never completely accurate," with brief request acceptance after quota reached acceptable. Token bucket refills at rate limit with capacity equal to burst limit, allowing burst traffic followed by sustained throughput.

**Cloudflare Advanced Rate Limiting** supports counting by IP address, country, ASN, headers (custom, User-Agent), cookies, query parameters, session IDs, JA3 fingerprints (TLS client fingerprinting), bot scores, and request/response body fields. Dynamic fields include WAF machine learning scores, bot management scores, response status codes, and JSON body values (GraphQL operations). Use cases: count by session ID for authenticated APIs, track suspicious login patterns (failed 401/403 responses), rate limit GraphQL mutations via body inspection, separate counting from mitigation expressions. Integration with Bot Management provides scores consumed by firewall rules: `if (cf.bot_management.score < 30 and http.request.uri.path eq "/login") { action: challenge }`. Actions available include log, bypass, allow, challenge (CAPTCHA), JS challenge (browser validation), and block.

**Shopify API** implements leaky bucket with calculated query cost for GraphQL. REST Admin API limits: standard plan 40 requests bucket with 2/second leak, Shopify Plus 400 requests bucket with 20/second leak, private apps can request up to 200/second. GraphQL points system: scalar field 0 points, object field 1 point, connection (first N) costs N points, mutation 10 points default. Standard plan 50 points/second, Advanced 100 points/second, Plus up to 500 points/second, with 1,000 point bucket capacity. Header `X-Shopify-Shop-Api-Call-Limit` shows "current/max" (e.g., "32/40"). The leaky bucket metaphor: bucket holds "marbles" (requests) that leak at constant rate, with each REST request 1 marble and GraphQL requests variable marbles based on complexity.

**Performance benchmarks** reveal production characteristics. Stripe's Redis-based system handles millions of requests monthly with sub-millisecond latency. Cloudflare's distributed rate limiting across global edge network uses Twemproxy cluster with consistent hashing, processing 46+ million requests/second. AWS acknowledges variance between configured and actual limits depending on request volume, backend latency, and distributed gateway architecture. Algorithm throughput comparison: Fixed Window highest (minimal overhead), Token Bucket very high, Sliding Window Counter high, Leaky Bucket medium-high, Sliding Window Log medium. Accuracy ranking: Sliding Window Log 99.997%, Leaky Bucket >99%, Sliding Window Counter ~94%, Token Bucket ~94%, Fixed Window lowest (boundary issues). Memory efficiency: Fixed Window/Token Bucket/Sliding Window Counter all O(1) at 12-20MB per million users, Leaky Bucket O(n) at 800MB, Sliding Window Log O(n) at 800MB-8GB.

## Implementation requires standardized headers and error handling

Production rate limiters must communicate limits, remaining quota, and reset timing to clients reliably. IETF standardization efforts and RFC specifications provide battle-tested patterns.

**IETF draft-ietf-httpapi-ratelimit-headers-10** defines modern standard replacing legacy X-RateLimit headers. `RateLimit-Policy` header advertises quota policies: `"default";q=100;w=60` (100 requests per 60 second window). Parameters include `q` (REQUIRED quota limit), `w` (OPTIONAL window seconds), `qu` (OPTIONAL quota unit like "requests", "content-bytes", "concurrent-requests"), and `pk` (OPTIONAL partition key for multi-tenant). Multiple policies can coexist: `"burst";q=100;w=60,"daily";q=1000;w=86400`. The `RateLimit` header indicates current service limits: `"default";r=50;t=30` (50 remaining with 30 seconds until reset). Parameters: `r` (REQUIRED remaining quota), `t` (OPTIONAL delta-seconds until reset). Critical design: **use delta-seconds not timestamps** to avoid clock synchronization issues, prevent clock skew problems, and eliminate thundering herd when all clients reset simultaneously.

**Legacy headers** remain common during transition period. Standard pattern: `X-RateLimit-Limit: 100` (maximum allowed), `X-RateLimit-Remaining: 50` (quota remaining), `X-RateLimit-Reset: 60` (seconds until reset), `Retry-After: 60` (when rate limited). Legacy headers should be maintained alongside IETF standard headers during migration period, with documentation clarifying which to prefer.

**HTTP 429 Too Many Requests** provides standardized error response. RFC 9457 Problem Details format:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/problem+json
Retry-After: 60
RateLimit: "default";r=0;t=60

{
  "type": "https://iana.org/assignments/http-problem-types#quota-exceeded",
  "title": "Too Many Requests",
  "detail": "You have exceeded the maximum number of requests",
  "instance": "/api/users/123",
  "violated-policies": ["default"],
  "trace": {
    "requestId": "uuid-here"
  }
}
```

**HTTP 503 Service Unavailable** signals temporary capacity reduction distinct from quota exhaustion. Use when system is degraded but client hasn't exceeded personal quota: `Retry-After: 120` with problem details type `temporary-reduced-capacity`. This distinction enables clients to understand whether they should back off permanently (429) or retry after system recovery (503).

**Exponential backoff with jitter** prevents thundering herd. Client implementation should parse `Retry-After` header, falling back to exponential calculation: initial delay 1-2 seconds, doubling on each retry, max 3-5 attempts. Jitter critical: add ±20% randomization to delay so clients don't synchronize retries. Production implementation:

```javascript
async function fetchWithRetry(url, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const res = await fetch(url);
    
    if (res.status === 429) {
      const retryAfter = res.headers.get('retry-after');
      const delay = parseInt(retryAfter) * 1000 || (1000 * Math.pow(2, attempt));
      const jitter = delay * 0.2 * (Math.random() - 0.5);
      
      await sleep(delay + jitter);
      continue;
    }
    
    return res;
  }
  throw new Error('Max retries exceeded');
}
```

**Data structure design** determines algorithm performance. Fixed window uses simple counter with TTL: `rate_limit:{user_id}:{window_id}` storing integer count with O(1) time and space. Sliding window log employs Redis sorted set: `rate_limit:{user_id}` with timestamps as both members and scores, O(N) space, O(log N) operations. Sliding window counter stores two counters `{user}:{current_minute}` and `{user}:{previous_minute}` with weighted formula. Token bucket uses hash with fields `{tokens: float, last_refill: timestamp}`. Key design principle: all TTL must be set to prevent memory leaks, typically 2× window duration to handle edge cases, with token bucket using longer TTL (3600 seconds) for intermittent users.

**Testing strategies** validate implementation correctness. Unit testing covers basic limit enforcement (verify N requests allowed, N+1 rejected), window reset (confirm new requests allowed after expiry), and atomicity under concurrency (verify exactly N allowed from 2N concurrent requests). Load testing uses k6 or JMeter: 100 virtual users, 30 second duration, thresholds ensuring 429 rate below 10%, validation that rate limit headers present. Production testing should verify: Lua scripts atomic across operations, TTL set on all keys, server-side time used exclusively, headers RFC-compliant, 429/503 status codes appropriate, exponential backoff with jitter, monitoring tracks health metrics, failover tested with Redis Sentinel, degradation plan for outages.

**Edge cases** require careful handling. Clock skew solved by server-side monotonic time only—never trust client timestamps. Bounded tolerance can sanitize suspicious timestamps: `if (abs(client_time - server_time) > max_skew) return server_time`. Race conditions prevented by atomic Lua scripts executing all operations in single transaction. Distributed locks (Redlock) provide alternative but add latency. Failover scenarios handled via Redis Sentinel with 3-5 sentinel nodes monitoring master health, applications reconnecting automatically. Graceful degradation decides fail-open (allow requests, prioritize availability) versus fail-closed (deny requests, prioritize security). Network partitions use max-wins conflict resolution: `resolved = max(countA, countB)` taking most restrictive count after heal. Thundering herd prevented by jitter in retry timing: ±20% randomization in Retry-After. Memory leaks avoided by aggressive cleanup: `ZREMRANGEBYSCORE` removes old entries plus `EXPIRE` for auto-deletion.

**Production deployment checklist** ensures operational readiness: atomicity via Lua scripts for all operations, TTL set on all Redis keys, time source server-side monotonic only, headers return RFC-compliant RateLimit format, status codes use 429/503 appropriately, retry logic implements exponential backoff plus jitter, monitoring tracks limiter health metrics, load testing under expected peak load, failover via Redis Sentinel or Cluster mode, documentation provides clear rate limit policies, degradation plan handles graceful failure, logging captures violations for security analysis. Performance benchmarks on AWS ElastiCache r6g.large: Fixed Window ~50,000 ops/sec, Sliding Window Log ~10,000 ops/sec, Sliding Window Counter ~40,000 ops/sec, Token Bucket ~35,000 ops/sec.

## Security considerations must address sophisticated attacks

Rate limiting serves as critical security control, but attackers continuously evolve evasion techniques. Defense-in-depth architectures, proper monitoring, and attack-specific mitigations protect against sophisticated threats.

**DDoS protection** requires multi-layer defense. Layer 3/4 network rate limiting at CDN edge blocks volumetric floods before reaching application infrastructure. Layer 7 application rate limiting inspects HTTP requests, blocking application-layer attacks (Slowloris, HTTP floods). Distributed global rate limiting with shared state across edge nodes prevents circumvention via geographic distribution. Strict limits on expensive endpoints protect resource-intensive operations: database queries, external API calls, complex computations warrant 10-100× lower limits than read operations.

**Brute force protection** demands endpoint-specific strategies. Login protection implements multiple limit layers: 5 attempts per 5 minutes per IP, 10 attempts per hour per username, 10,000 attempts per hour globally. Actions escalate: return 429 after limit, exponential backoff on repeated failures, CAPTCHA after 3 failures, account lock after 10 failures, security team alert on patterns. Credential stuffing detection tracks failed login attempts over 1 hour window: threshold of >100 401 responses from single IP or >50 403 responses triggers rate limit reduction (1 request/minute), CAPTCHA requirement, and security review.

**API scraping prevention** detects automated data collection. Indicators include high volume (>1000 requests/minute), high 404 rate (>50% of requests suggesting enumeration), suspicious or missing User-Agent headers, and sequential resource ID access patterns. Actions reduce limit to 10 requests/minute, require authentication, or challenge with proof-of-work (difficulty 5). More sophisticated scrapers warrant behavioral analysis: mouse movement patterns, JavaScript execution validation, and browser fingerprint consistency checks.

**Defense in depth** layers multiple security controls. Layer 1 CDN rate limiting provides first defense at edge. Layer 2 API Gateway rate limiting adds second checkpoint. Layer 3 application rate limiting enforces business logic limits. Layer 4 database connection limits prevent resource exhaustion. Layer 5 circuit breakers detect cascade failures and fail gracefully. Each layer defends against different attack vectors with different granularity.

**Monitoring and alerting** detect attacks in progress. Metrics to track: rate limit hits (requests denied), 429 response count, requests per second (detect spikes), average burst size. Alerts trigger on: spike in 429s (>1000/minute suggests attack), single user abuse (>90% of limit repeatedly), distributed attack (>100 IPs simultaneously hitting limits). Log violations for security analysis: timestamp, user identifier, endpoint, limit exceeded, IP address, User-Agent, and any additional context. Integration with SIEM systems enables correlation with other security events.

**Key protection** prevents limit bypass via compromised credentials. Never expose secrets client-side—API keys, tokens, or credentials must remain server-side only. Rotate API keys regularly (quarterly or after suspected compromise). Use different keys per environment (development, staging, production). Implement key revocation capability with immediate effect. Monitor for compromised keys via anomaly detection: sudden usage spike, requests from unusual geographies, or access pattern changes suggest compromise.

**IP spoofing prevention** validates request origin. Trust X-Forwarded-For only from trusted proxies (Cloudflare IPs, internal load balancers), falling back to direct connection IP for untrusted sources. Validation logic: `if (source_ip in trusted_proxies) use_x_forwarded_for else use_source_ip`. Attackers cannot spoof source IP in TCP connections (requires completing handshake), but HTTP headers easily forged. Additional validation: check for multiple X-Forwarded-For values (chain of proxies), validate IP format, and compare against geolocation data for consistency.

**Hierarchical rate limiting** prevents resource starvation. Global infrastructure limit (100,000/second) protects total capacity. Category limits (authentication 10,000/minute, data API 50,000/minute) prevent single category monopolizing resources. Per-user limits (1,000/hour) ensure fairness. Per-endpoint limits protect expensive operations. All layers checked hierarchically with atomic counter increments ensuring consistency. Slack's approach: global 100 notifications/30 minutes with category sublimits (errors 10, warnings 10, info 10) that sum above global, demonstrating global as final constraint.

**Common pitfalls** undermine security if not avoided. Non-atomic read-modify-write creates race conditions: `const count = await redis.get(key); if (count < limit) await redis.set(key, count + 1)` allows concurrent requests both succeeding. Solution: atomic Lua scripts. Missing TTL causes memory leaks: `await redis.incr(key)` lives forever. Solution: `redis.multi().incr(key).expire(key, 60).exec()`. Trusting client time enables manipulation: `const time = req.body.timestamp` attacker-controlled. Solution: `const time = Date.now()` server authority. No error handling causes cascading failures. Solution: try-catch with fail-closed default and comprehensive logging.

The security landscape continuously evolves. **Adaptive, ML-based rate limiting with defense-in-depth** provides robust protection against current threats while remaining flexible enough to address emerging attack patterns. Regular security audits, penetration testing, and incident response planning ensure rate limiting effectiveness over time.
