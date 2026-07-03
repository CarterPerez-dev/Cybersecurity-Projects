// ©AngelaMos | 2026
// ratelimit.zig

const std = @import("std");

const NS_PER_SEC: u64 = 1_000_000_000;
const max_gap_ns: f64 = 3.6e12;

pub const Jitter = struct {
    prng: std.Random.DefaultPrng,
    mean_ns: f64,

    pub fn init(seed: u64, mean_ns: u64) Jitter {
        return .{ .prng = std.Random.DefaultPrng.init(seed), .mean_ns = @floatFromInt(mean_ns) };
    }

    pub fn nextGapNs(self: *Jitter) u64 {
        const u = self.prng.random().float(f64);
        const safe_u = if (u <= 0.0) std.math.floatMin(f64) else u;
        const gap = -@log(safe_u) * self.mean_ns;
        return @intFromFloat(std.math.clamp(gap, 0.0, max_gap_ns));
    }
};

pub const TokenBucket = struct {
    step_ns: u64,
    cap_ns: u64,
    bank_ns: u64,
    last_ns: u64,
    jitter: ?Jitter = null,

    pub fn init(rate_pps: u64, capacity: u64) TokenBucket {
        const step = if (rate_pps == 0) NS_PER_SEC else NS_PER_SEC / rate_pps;
        const safe_step = if (step == 0) 1 else step;
        return .{
            .step_ns = safe_step,
            .cap_ns = safe_step * capacity,
            .bank_ns = 0,
            .last_ns = 0,
        };
    }

    pub fn withJitter(self: TokenBucket, seed: u64) TokenBucket {
        var b = self;
        b.jitter = Jitter.init(seed, self.step_ns);
        return b;
    }

    pub fn prime(self: *TokenBucket, now_ns: u64) void {
        self.last_ns = now_ns;
    }

    pub fn refund(self: *TokenBucket, tokens: u64) void {
        self.bank_ns = @min(self.bank_ns +| tokens *| self.step_ns, self.cap_ns);
    }

    pub fn takeBatch(self: *TokenBucket, now_ns: u64, want: u64) u64 {
        if (now_ns > self.last_ns) {
            const elapsed = now_ns - self.last_ns;
            self.bank_ns = @min(self.bank_ns +| elapsed, self.cap_ns);
        }
        self.last_ns = now_ns;
        const available = self.bank_ns / self.step_ns;
        const granted = @min(want, available);
        self.bank_ns -= granted * self.step_ns;
        return granted;
    }
};

test "bucket starts empty and grants one token per step_ns" {
    var tb = TokenBucket.init(1000, 10);
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(0, 5));
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(1_000_000, 5));
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(1_500_000, 5));
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(2_000_000, 5));
}

test "burst is capped at capacity" {
    var tb = TokenBucket.init(1000, 10);
    try std.testing.expectEqual(@as(u64, 10), tb.takeBatch(1_000_000_000, 1000));
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(1_000_000_000, 1000));
}

test "takeBatch grants only up to want" {
    var tb = TokenBucket.init(1_000_000, 100);
    try std.testing.expectEqual(@as(u64, 50), tb.takeBatch(100_000, 50));
    try std.testing.expectEqual(@as(u64, 50), tb.takeBatch(100_000, 50));
}

test "non-monotonic now does not over-credit" {
    var tb = TokenBucket.init(1000, 10);
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(1_000_000, 5));
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(500_000, 5));
}

test "zero rate degrades to one-token-per-second, never divides by zero" {
    var tb = TokenBucket.init(0, 4);
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(NS_PER_SEC, 10));
    try std.testing.expectEqual(@as(u64, 4), tb.takeBatch(NS_PER_SEC * 10, 10));
}

test "cold prime starts the bank empty so a low-rate scan does not front-load a burst" {
    var tb = TokenBucket.init(1000, 64);
    tb.prime(5_000_000_000);
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(5_000_000_000, 100));
    try std.testing.expectEqual(@as(u64, 1), tb.takeBatch(5_001_000_000, 100));
}

test "refund returns unused tokens to the bank, clamped at capacity" {
    var tb = TokenBucket.init(1000, 10);
    try std.testing.expectEqual(@as(u64, 10), tb.takeBatch(1_000_000_000, 10));
    try std.testing.expectEqual(@as(u64, 0), tb.takeBatch(1_000_000_000, 10));
    tb.refund(4);
    try std.testing.expectEqual(@as(u64, 4), tb.takeBatch(1_000_000_000, 10));
    tb.refund(1000);
    try std.testing.expectEqual(@as(u64, 10), tb.takeBatch(1_000_000_000, 100));
}

test "withJitter attaches a Poisson pacer keyed to the configured step" {
    const tb = TokenBucket.init(1000, 1000).withJitter(0xABCDEF);
    try std.testing.expect(tb.jitter != null);
    try std.testing.expectEqual(@as(f64, 1_000_000.0), tb.jitter.?.mean_ns);
}

test "Poisson gaps average to the mean and are not constant" {
    var jit = Jitter.init(0x5EED_1234, 1_000_000);
    const n: usize = 40_000;
    var total: u128 = 0;
    const first: u64 = jit.nextGapNs();
    var saw_different = false;
    total += first;
    var i: usize = 1;
    while (i < n) : (i += 1) {
        const g = jit.nextGapNs();
        total += g;
        if (g != first) saw_different = true;
    }
    const mean = @as(f64, @floatFromInt(@as(u64, @intCast(total / n))));
    try std.testing.expect(saw_different);
    try std.testing.expect(mean > 900_000.0 and mean < 1_100_000.0);
}

test "Poisson gap survives the u=0 edge without dividing into infinity" {
    var jit = Jitter.init(1, 500);
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const g = jit.nextGapNs();
        try std.testing.expect(g <= @as(u64, @intFromFloat(max_gap_ns)));
    }
}
