// ©AngelaMos | 2026
// targets.zig

const std = @import("std");
const numtheory = @import("numtheory");

pub const Range = struct {
    start: u32,
    end: u32,

    pub fn count(self: Range) u64 {
        return @as(u64, self.end - self.start) + 1;
    }
};

const reserved = [_]Range{
    .{ .start = 0x00000000, .end = 0x00ffffff },
    .{ .start = 0x0a000000, .end = 0x0affffff },
    .{ .start = 0x64400000, .end = 0x647fffff },
    .{ .start = 0x7f000000, .end = 0x7fffffff },
    .{ .start = 0xa9fe0000, .end = 0xa9feffff },
    .{ .start = 0xac100000, .end = 0xac1fffff },
    .{ .start = 0xc0000000, .end = 0xc00000ff },
    .{ .start = 0xc0000200, .end = 0xc00002ff },
    .{ .start = 0xc0a80000, .end = 0xc0a8ffff },
    .{ .start = 0xc6120000, .end = 0xc613ffff },
    .{ .start = 0xc6336400, .end = 0xc63364ff },
    .{ .start = 0xcb007100, .end = 0xcb0071ff },
    .{ .start = 0xe0000000, .end = 0xefffffff },
    .{ .start = 0xf0000000, .end = 0xffffffff },
};

pub fn parseCidr(text: []const u8) !Range {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidCidr;
    const addr_text = text[0..slash];
    const prefix = std.fmt.parseInt(u6, text[slash + 1 ..], 10) catch return error.InvalidCidr;
    if (prefix > 32) return error.InvalidCidr;

    var base: u32 = 0;
    var octets: usize = 0;
    var it = std.mem.splitScalar(u8, addr_text, '.');
    while (it.next()) |part| {
        if (octets == 4) return error.InvalidCidr;
        const octet = std.fmt.parseInt(u8, part, 10) catch return error.InvalidCidr;
        base = (base << 8) | octet;
        octets += 1;
    }
    if (octets != 4) return error.InvalidCidr;

    const host_bits: u6 = @intCast(32 - @as(u32, prefix));
    if (host_bits == 32) return .{ .start = 0, .end = 0xffffffff };
    const sh: u5 = @intCast(host_bits);
    const span: u32 = (@as(u32, 1) << sh) - 1;
    const start = base & ~span;
    return .{ .start = start, .end = start | span };
}

pub fn isReserved(ip: u32) bool {
    var lo: usize = 0;
    var hi: usize = reserved.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (ip < reserved[mid].start) {
            hi = mid;
        } else if (ip > reserved[mid].end) {
            lo = mid + 1;
        } else return true;
    }
    return false;
}

fn subtractReserved(allocator: std.mem.Allocator, acc: *std.ArrayList(Range), r: Range) !void {
    var pending: std.ArrayList(Range) = .empty;
    defer pending.deinit(allocator);
    try pending.append(allocator, r);
    for (reserved) |res| {
        var next: std.ArrayList(Range) = .empty;
        errdefer next.deinit(allocator);
        for (pending.items) |cur| {
            if (res.end < cur.start or res.start > cur.end) {
                try next.append(allocator, cur);
                continue;
            }
            if (cur.start < res.start) try next.append(allocator, .{ .start = cur.start, .end = res.start - 1 });
            if (cur.end > res.end) try next.append(allocator, .{ .start = res.end + 1, .end = cur.end });
        }
        pending.deinit(allocator);
        pending = next;
    }
    for (pending.items) |s| try acc.append(allocator, s);
}

pub const IpPicker = struct {
    allocator: std.mem.Allocator,
    ranges: []Range,
    prefix: []u64,
    count: u64,

    pub fn build(allocator: std.mem.Allocator, user: []const Range) !IpPicker {
        var acc: std.ArrayList(Range) = .empty;
        defer acc.deinit(allocator);
        for (user) |r| try subtractReserved(allocator, &acc, r);
        std.mem.sort(Range, acc.items, {}, struct {
            fn lt(_: void, a: Range, b: Range) bool {
                return a.start < b.start;
            }
        }.lt);

        const ranges = try allocator.dupe(Range, acc.items);
        errdefer allocator.free(ranges);
        const prefix = try allocator.alloc(u64, ranges.len + 1);
        var total: u64 = 0;
        for (ranges, 0..) |r, k| {
            prefix[k] = total;
            total += r.count();
        }
        prefix[ranges.len] = total;
        return .{ .allocator = allocator, .ranges = ranges, .prefix = prefix, .count = total };
    }

    pub fn deinit(self: *IpPicker) void {
        self.allocator.free(self.ranges);
        self.allocator.free(self.prefix);
    }

    pub fn at(self: IpPicker, index: u64) u32 {
        std.debug.assert(index < self.count);
        var lo: usize = 0;
        var hi: usize = self.ranges.len;
        while (lo + 1 < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.prefix[mid] <= index) lo = mid else hi = mid;
        }
        const offset: u32 = @intCast(index - self.prefix[lo]);
        return self.ranges[lo].start + offset;
    }
};

pub const Target = struct {
    ip: u32,
    port: u16,
};

pub const Engine = struct {
    picker: IpPicker,
    ports: []u16,
    num_ports: u64,
    total: u64,
    prime: u64,
    generator: u64,
    current: u64,
    steps_left: u64,

    pub fn init(allocator: std.mem.Allocator, cidrs: []const Range, ports: []const u16, seed: u64) !Engine {
        return initShard(allocator, cidrs, ports, seed, 1, 0);
    }

    pub fn initShard(
        allocator: std.mem.Allocator,
        cidrs: []const Range,
        ports: []const u16,
        seed: u64,
        num_shards: u64,
        shard_id: u64,
    ) !Engine {
        var picker = try IpPicker.build(allocator, cidrs);
        errdefer picker.deinit();
        const ports_copy = try allocator.dupe(u16, ports);
        errdefer allocator.free(ports_copy);

        const num_ports: u64 = @intCast(ports.len);
        const total = picker.count * num_ports;
        const prime = numtheory.smallestPrimeAbove(total);
        const order = prime - 1;
        if (num_shards == 0 or shard_id >= num_shards or num_shards > order) return error.InvalidShardCount;

        var prng = std.Random.DefaultPrng.init(seed);
        const rand = prng.random();
        const generator = numtheory.findPrimitiveRoot(prime, rand);
        const start = rand.intRangeAtMost(u64, 1, prime - 1);

        const chunk = order / num_shards;
        const begin = shard_id * chunk;
        const my_steps = if (shard_id == num_shards - 1) order - begin else chunk;
        const offset = numtheory.modExp(generator, begin, prime);
        const current = numtheory.mulMod(start, offset, prime);

        return .{
            .picker = picker,
            .ports = ports_copy,
            .num_ports = num_ports,
            .total = total,
            .prime = prime,
            .generator = generator,
            .current = current,
            .steps_left = my_steps,
        };
    }

    pub fn deinit(self: *Engine) void {
        const allocator = self.picker.allocator;
        self.picker.deinit();
        allocator.free(self.ports);
    }

    pub fn next(self: *Engine) ?Target {
        while (self.steps_left > 0) {
            self.current = numtheory.mulMod(self.current, self.generator, self.prime);
            self.steps_left -= 1;
            const idx = self.current;
            if (idx >= 1 and idx <= self.total) {
                const idx0 = idx - 1;
                const ip_pos = idx0 / self.num_ports;
                const port_pos = idx0 % self.num_ports;
                return .{ .ip = self.picker.at(ip_pos), .port = self.ports[@intCast(port_pos)] };
            }
        }
        return null;
    }
};

test "parseCidr yields the right range and count" {
    const a = try parseCidr("10.0.0.0/24");
    try std.testing.expectEqual(@as(u32, 0x0a000000), a.start);
    try std.testing.expectEqual(@as(u32, 0x0a0000ff), a.end);
    try std.testing.expectEqual(@as(u64, 256), a.count());

    const b = try parseCidr("192.168.1.0/30");
    try std.testing.expectEqual(@as(u64, 4), b.count());

    const h = try parseCidr("8.8.8.8/32");
    try std.testing.expectEqual(@as(u32, 0x08080808), h.start);
    try std.testing.expectEqual(@as(u64, 1), h.count());

    try std.testing.expectError(error.InvalidCidr, parseCidr("999.0.0.0/8"));
    try std.testing.expectError(error.InvalidCidr, parseCidr("10.0.0.0/33"));
}

test "isReserved flags RFC 6890 space, passes public IPs" {
    try std.testing.expect(isReserved((try parseCidr("127.0.0.1/32")).start));
    try std.testing.expect(isReserved((try parseCidr("10.1.2.3/32")).start));
    try std.testing.expect(isReserved((try parseCidr("192.168.1.1/32")).start));
    try std.testing.expect(isReserved((try parseCidr("169.254.5.5/32")).start));
    try std.testing.expect(isReserved((try parseCidr("224.0.0.1/32")).start));
    try std.testing.expect(isReserved((try parseCidr("0.0.0.0/32")).start));
    try std.testing.expect(!isReserved((try parseCidr("8.8.8.8/32")).start));
    try std.testing.expect(!isReserved((try parseCidr("1.1.1.1/32")).start));
}

test "IpPicker maps indices across user CIDRs minus the reserved floor" {
    const cidrs = [_]Range{
        try parseCidr("8.8.8.0/30"),
        try parseCidr("10.0.0.0/24"),
        try parseCidr("1.1.1.0/31"),
    };
    var picker = try IpPicker.build(std.testing.allocator, &cidrs);
    defer picker.deinit();

    try std.testing.expectEqual(@as(u64, 6), picker.count);
    try std.testing.expectEqual(@as(u32, 0x01010100), picker.at(0));
    try std.testing.expectEqual(@as(u32, 0x01010101), picker.at(1));
    try std.testing.expectEqual(@as(u32, 0x08080800), picker.at(2));
    try std.testing.expectEqual(@as(u32, 0x08080803), picker.at(5));
    var i: u64 = 0;
    while (i < picker.count) : (i += 1) try std.testing.expect(!isReserved(picker.at(i)));
}

test "IpPicker over a fully reserved input is empty" {
    const cidrs = [_]Range{try parseCidr("192.168.0.0/16")};
    var picker = try IpPicker.build(std.testing.allocator, &cidrs);
    defer picker.deinit();
    try std.testing.expectEqual(@as(u64, 0), picker.count);
}

test "Engine is a bijection: every IP:port hit exactly once" {
    const cidrs = [_]Range{ try parseCidr("8.8.8.0/28"), try parseCidr("1.2.3.0/30") };
    const ports = [_]u16{ 80, 443, 22 };
    var eng = try Engine.init(std.testing.allocator, &cidrs, &ports, 0xDEADBEEF);
    defer eng.deinit();

    try std.testing.expectEqual(@as(u64, 60), eng.total);
    var seen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer seen.deinit();
    var n: u64 = 0;
    while (eng.next()) |t| {
        try std.testing.expect(!isReserved(t.ip));
        const key = (@as(u64, t.ip) << 16) | t.port;
        try std.testing.expect(!seen.contains(key));
        try seen.put(key, {});
        n += 1;
    }
    try std.testing.expectEqual(@as(u64, 60), n);
    try std.testing.expectEqual(@as(u64, 60), seen.count());
}

test "shards with a shared seed union to the full bijection with no overlap" {
    const cidrs = [_]Range{try parseCidr("8.8.8.0/27")};
    const ports = [_]u16{ 80, 443 };
    const seed: u64 = 0x1234_5678;
    const num_shards: u64 = 4;

    var seen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer seen.deinit();
    var emitted: u64 = 0;
    var s: u64 = 0;
    while (s < num_shards) : (s += 1) {
        var eng = try Engine.initShard(std.testing.allocator, &cidrs, &ports, seed, num_shards, s);
        defer eng.deinit();
        while (eng.next()) |t| {
            const key = (@as(u64, t.ip) << 16) | t.port;
            try std.testing.expect(!seen.contains(key));
            try seen.put(key, {});
            emitted += 1;
        }
    }
    try std.testing.expectEqual(@as(u64, 64), emitted);
    try std.testing.expectEqual(@as(u64, 64), seen.count());
}

test "initShard rejects nonsensical shard counts" {
    const cidrs = [_]Range{try parseCidr("8.8.8.0/30")}; // 4 ips
    const ports = [_]u16{80};                             // total = 4, order = smallestPrimeAbove(4)-1 = 4
    try std.testing.expectError(error.InvalidShardCount, Engine.initShard(std.testing.allocator, &cidrs, &ports, 1, 0, 0));        // num_shards 0
    try std.testing.expectError(error.InvalidShardCount, Engine.initShard(std.testing.allocator, &cidrs, &ports, 1, 100, 0));      // more shards than order
    try std.testing.expectError(error.InvalidShardCount, Engine.initShard(std.testing.allocator, &cidrs, &ports, 1, 2, 5));        // shard_id out of range
}
