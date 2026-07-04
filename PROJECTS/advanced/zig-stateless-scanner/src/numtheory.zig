// ©AngelaMos | 2026
// numtheory.zig

const std = @import("std");

pub fn mulMod(a: u64, b: u64, m: u64) u64 {
    return @intCast((@as(u128, a) * @as(u128, b)) % m);
}

pub fn modExp(base: u64, exp: u64, modulus: u64) u64 {
    if (modulus == 1) return 0;
    var result: u64 = 1;
    var b: u64 = base % modulus;
    var e: u64 = exp;
    while (e > 0) {
        if (e & 1 == 1) result = mulMod(result, b, modulus);
        b = mulMod(b, b, modulus);
        e >>= 1;
    }
    return result;
}

pub fn isPrime(n: u64) bool {
    if (n < 2) return false;
    const small = [_]u64{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
    for (small) |p| {
        if (n == p) return true;
        if (n % p == 0) return false;
    }
    var d: u64 = n - 1;
    var r: u32 = 0;
    while (d & 1 == 0) : (d >>= 1) r += 1;
    for (small) |a| {
        var x = modExp(a, d, n);
        if (x == 1 or x == n - 1) continue;
        var i: u32 = 1;
        var composite = true;
        while (i < r) : (i += 1) {
            x = mulMod(x, x, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

pub fn smallestPrimeAbove(n: u64) u64 {
    var candidate = n + 1;
    if (candidate <= 2) return 2;
    if (candidate & 1 == 0) candidate += 1;
    while (!isPrime(candidate)) : (candidate += 2) {}
    return candidate;
}

pub fn distinctPrimeFactors(value: u64, buf: []u64) []u64 {
    var n = value;
    var count: usize = 0;
    var f: u64 = 2;
    while (f * f <= n) {
        if (n % f == 0) {
            buf[count] = f;
            count += 1;
            while (n % f == 0) n /= f;
        }
        f += if (f == 2) 1 else 2;
    }
    if (n > 1) {
        buf[count] = n;
        count += 1;
    }
    return buf[0..count];
}

pub fn isPrimitiveRoot(candidate: u64, prime: u64, prime_factors: []const u64) bool {
    for (prime_factors) |q| {
        if (modExp(candidate, (prime - 1) / q, prime) == 1) return false;
    }
    return true;
}

pub fn findPrimitiveRoot(prime: u64, rand: std.Random) u64 {
    if (prime == 2) return 1;
    var buf: [64]u64 = undefined;
    const factors = distinctPrimeFactors(prime - 1, &buf);
    while (true) {
        const candidate = rand.intRangeAtMost(u64, 2, prime - 1);
        if (isPrimitiveRoot(candidate, prime, factors)) return candidate;
    }
}

test "modExp known values" {
    try std.testing.expectEqual(@as(u64, 1), modExp(3, 4, 5));
    try std.testing.expectEqual(@as(u64, 24), modExp(2, 10, 1000));
    try std.testing.expectEqual(@as(u64, 0), modExp(10, 3, 1000));
    try std.testing.expectEqual(@as(u64, 445), modExp(4, 13, 497));
}

test "isPrime classifies small and large values" {
    const primes = [_]u64{ 2, 3, 5, 7, 11, 13, 65537, 1009, 4294967311, 281474976710677 };
    for (primes) |p| try std.testing.expect(isPrime(p));
    const composites = [_]u64{ 0, 1, 4, 9, 15, 561, 1105, 4294967296, 281474976710676 };
    for (composites) |c| try std.testing.expect(!isPrime(c));
}

test "smallestPrimeAbove" {
    try std.testing.expectEqual(@as(u64, 257), smallestPrimeAbove(256));
    try std.testing.expectEqual(@as(u64, 65537), smallestPrimeAbove(65536));
    try std.testing.expectEqual(@as(u64, 1009), smallestPrimeAbove(1000));
    try std.testing.expectEqual(@as(u64, 4294967311), smallestPrimeAbove(4294967296));
}

test "distinctPrimeFactors" {
    var buf: [16]u64 = undefined;
    try std.testing.expectEqualSlices(u64, &.{2}, distinctPrimeFactors(256, &buf));
    try std.testing.expectEqualSlices(u64, &.{ 2, 3 }, distinctPrimeFactors(12, &buf));
    try std.testing.expectEqualSlices(u64, &.{ 2, 5 }, distinctPrimeFactors(100, &buf));
    try std.testing.expectEqualSlices(u64, &.{ 2, 3, 5 }, distinctPrimeFactors(30, &buf));
}

test "isPrimitiveRoot for p=7 (roots are 3 and 5)" {
    var buf: [16]u64 = undefined;
    const factors = distinctPrimeFactors(7 - 1, &buf);
    try std.testing.expect(isPrimitiveRoot(3, 7, factors));
    try std.testing.expect(isPrimitiveRoot(5, 7, factors));
    try std.testing.expect(!isPrimitiveRoot(2, 7, factors));
    try std.testing.expect(!isPrimitiveRoot(4, 7, factors));
}

test "findPrimitiveRoot returns a generator that walks the whole group" {
    var prng = std.Random.DefaultPrng.init(0xA11CE_2026);
    const rand = prng.random();
    const primes = [_]u64{ 7, 257, 65537, 1009 };
    for (primes) |p| {
        const g = findPrimitiveRoot(p, rand);
        var seen = [_]bool{false} ** 65537;
        var cur: u64 = 1;
        var k: u64 = 0;
        while (k < p - 1) : (k += 1) {
            cur = mulMod(cur, g, p);
            try std.testing.expect(!seen[cur]);
            seen[cur] = true;
        }
        try std.testing.expectEqual(@as(u64, 1), cur);
    }
}
