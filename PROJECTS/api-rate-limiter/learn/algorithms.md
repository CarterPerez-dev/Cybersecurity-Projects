# How the Rate Limiting Algorithms Actually Work

This package ships three algorithms. Most people just pick one without understanding what they actually do differently. Here is what is happening under the hood.

## The Short Version

| Algorithm | Good at | Bad at |
|-----------|---------|--------|
| Sliding Window | Accuracy, memory efficiency | Nothing really |
| Token Bucket | Handling bursts gracefully | Can feel unpredictable |
| Fixed Window | Simplicity, speed | Boundary bursts (see below) |

Sliding window is the default because Cloudflare tested it across 400 million requests and measured 99.997% accuracy. That is not marketing, that is just what the math works out to.

## Fixed Window (and why it has a problem)

Fixed window is the simplest approach. Divide time into chunks (say, 1 minute windows), count requests in each chunk, block when the count hits the limit.

```
Window 1 (0:00-0:59)    Window 2 (1:00-1:59)
[--------------------]  [--------------------]
      87 requests              12 requests
```

The problem nobody thinks about: what happens at the boundary?

Say you have a 100 requests/minute limit. A client sends 100 requests at 0:59 (allowed, counter is 100). Then at 1:00, the window resets and they send another 100 requests (allowed, new window). That is 200 requests in 2 seconds. The limit is supposed to be 100/minute but they got 200.

This is called the boundary burst problem. It is not theoretical. Attackers know about it.

```
0:00           0:59  1:00           1:59
[---------------||--][--||---------------]
                100     100
                   ^
                   200 requests in 2 seconds
```

Fixed window is still useful when you need maximum speed and can tolerate this edge case. But for most APIs, you want something better.

## Sliding Window Counter (the default)

This fixes the boundary problem by looking at two windows and doing weighted interpolation.

The idea: instead of hard window boundaries, calculate a weighted average based on how far into the current window you are.

```python
elapsed_ratio = (current_time % window_size) / window_size
weighted_count = (previous_window_count * (1 - elapsed_ratio)) + current_window_count
```

Say you are 40% into the current minute. You take 60% of the previous window count plus 100% of the current window count. This creates a "sliding" effect where the window smoothly moves forward rather than jumping.

```
Previous window    Current window
[-------50-------] [---20---.........]
                        ^
                        40% elapsed

weighted = (50 * 0.6) + 20 = 30 + 20 = 50
```

Memory cost is just two integers per client (previous count, current count). The 99.997% accuracy comes from the fact that you are approximating a true sliding window with minimal storage.

The tradeoff is about 6% average error compared to a perfect sliding window log. In practice nobody notices.

## Token Bucket (for bursty traffic)

Token bucket thinks about rate limiting differently. Instead of counting requests, you have a bucket that fills with tokens over time. Each request takes a token. No tokens, no request.

```
Bucket capacity: 10 tokens
Refill rate: 1 token/second

[OOOOOOOOOO]  <- full bucket (10 tokens)

5 requests come in at once:
[OOOOO-----]  <- 5 tokens left

Wait 3 seconds:
[OOOOOOOO--]  <- refilled to 8 tokens
```

The key difference from sliding window: burst tolerance.

With sliding window at 60 requests/minute, a client can only ever make 60 requests in any 60 second period. Steady, predictable.

With token bucket at 60 tokens/minute capacity and 1 token/second refill, a client can burn all 60 tokens instantly if they saved up, then wait for refills. Bursty, but still respects the average rate.

The math:
```python
tokens = min(capacity, tokens + (elapsed_time * refill_rate))
if tokens >= 1:
    tokens -= 1
    return allowed
return denied
```

When to use it: APIs where legitimate clients have bursty patterns. Mobile apps that sync on open. Batch processing endpoints. Anything where "60 per minute average" makes more sense than "never more than 60 in any minute."

## How We Store This Stuff

All three algorithms need to track state per client. The storage layer handles this.

For sliding window, we store:
```
key: "rl:v1:user:GET:/api/data:abc123:60"
value: {count: 47, window_start: 1703894400}
```

For token bucket:
```
key: "rl:v1:user:GET:/api/data:abc123:bucket"
value: {tokens: 8.5, last_update: 1703894567.123}
```

Memory storage uses Python dicts with LRU eviction when you hit max keys. Redis storage uses Lua scripts to make the read-modify-write atomic (more on why in the architecture doc).

## Picking an Algorithm

Most of the time: sliding window. It is accurate, memory efficient, and has no weird edge cases.

Use token bucket when:
- Your clients legitimately need burst capacity
- "Average rate" matters more than "instantaneous rate"
- You are rate limiting something like file uploads or batch operations

Use fixed window when:
- You need maximum performance and minimal complexity
- The boundary burst is acceptable for your use case
- You are doing something like daily API quotas where minute-level precision does not matter

## The Math Behind Sliding Window Accuracy

If you are curious why the 6% error claim holds up:

The worst case is when all requests from the previous window happened at the very end, and all requests from the current window happened at the very beginning. The weighted formula slightly miscounts in this scenario.

But in practice, requests are distributed somewhat evenly (especially under attack, which is when accuracy matters most). Real world testing shows the error averages around 0.003% under normal load. The 6% figure is the theoretical worst case with adversarial timing.

For rate limiting, this is more than good enough. You are not doing financial accounting here. Being off by one or two requests out of a hundred is fine.
