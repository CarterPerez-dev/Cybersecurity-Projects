// ©AngelaMos | 2026
// tx.zig

const std = @import("std");
const targets = @import("targets");
const template = @import("template");
const ratelimit = @import("ratelimit");
const cookie = @import("cookie");
const packet = @import("packet");

fn submitFrame(sink: anytype, frame: []const u8) bool {
    if (!sink.submit(frame)) {
        @branchHint(.unlikely);
        sink.kick();
        return sink.submit(frame);
    }
    return true;
}

pub fn run(
    engine: *targets.Engine,
    tmpl: anytype,
    bucket: *ratelimit.TokenBucket,
    sink: anytype,
    clock: anytype,
    max_packets: u64,
    deadline_ns: u64,
) u64 {
    if (bucket.jitter != null) return runJittered(engine, tmpl, bucket, sink, clock, max_packets, deadline_ns);

    bucket.prime(clock.now());
    var sent: u64 = 0;
    var probes: u64 = 0;
    var cursor: usize = 0;
    var frame: [@TypeOf(tmpl.*).max_frame_len]u8 = undefined;
    const vc = tmpl.variantCount();

    var pending: ?targets.Target = engine.next();
    while (pending != null and probes < max_packets) {
        const now_ns = clock.now();
        if (now_ns >= deadline_ns) break;
        const granted = bucket.takeBatch(now_ns, (max_packets - probes) *| vc);
        if (granted == 0) {
            clock.sleepNs(bucket.step_ns);
            continue;
        }
        var used: u64 = 0;
        while (used < granted and probes < max_packets) {
            const t = pending orelse break;
            const len = tmpl.stampVariant(&frame, t.ip, t.port, cursor);
            if (!submitFrame(sink, frame[0..len])) break;
            used += 1;
            sent += 1;
            cursor += 1;
            if (cursor == vc) {
                cursor = 0;
                probes += 1;
                pending = engine.next();
            }
        }
        if (used < granted) bucket.refund(granted - used);
        sink.kick();
    }
    sink.kick();
    return sent;
}

fn runJittered(
    engine: *targets.Engine,
    tmpl: anytype,
    bucket: *ratelimit.TokenBucket,
    sink: anytype,
    clock: anytype,
    max_packets: u64,
    deadline_ns: u64,
) u64 {
    var sent: u64 = 0;
    var probes: u64 = 0;
    var cursor: usize = 0;
    var frame: [@TypeOf(tmpl.*).max_frame_len]u8 = undefined;
    const vc = tmpl.variantCount();

    var pending: ?targets.Target = engine.next();
    while (pending != null and probes < max_packets) {
        if (clock.now() >= deadline_ns) break;
        const t = pending.?;
        const len = tmpl.stampVariant(&frame, t.ip, t.port, cursor);
        if (!submitFrame(sink, frame[0..len])) {
            clock.sleepNs(bucket.step_ns);
            continue;
        }
        sent += 1;
        cursor += 1;
        sink.kick();
        if (cursor < vc) continue;
        cursor = 0;
        probes += 1;
        pending = engine.next();
        if (pending == null) break;
        clock.sleepNs(bucket.jitter.?.nextGapNs() *| vc);
    }
    sink.kick();
    return sent;
}

const FakeClock = struct {
    t: u64 = 0,
    fn now(self: *FakeClock) u64 {
        self.t += 1_000_000_000;
        return self.t;
    }
    fn sleepNs(self: *FakeClock, ns: u64) void {
        self.t += ns;
    }
};

const FakeSink = struct {
    frames: std.ArrayList([54]u8) = .empty,
    kicks: usize = 0,
    allocator: std.mem.Allocator,
    fn submit(self: *FakeSink, frame: []const u8) bool {
        self.frames.append(self.allocator, frame[0..54].*) catch return false;
        return true;
    }
    fn kick(self: *FakeSink) void {
        self.kicks += 1;
    }
};

test "the TX engine drives the M2 bijection through stamp + ratelimit + submit" {
    const test_key = [16]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/30")};
    const ports = [_]u16{ 80, 443 };
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 0xDEADBEEF);
    defer eng.deinit();

    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
    });
    var tb = ratelimit.TokenBucket.init(1000, 64);
    var clock = FakeClock{};
    var sink = FakeSink{ .allocator = std.testing.allocator };
    defer sink.frames.deinit(std.testing.allocator);

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, 1_000_000, std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u64, 8), sent);
    try std.testing.expectEqual(@as(usize, 8), sink.frames.items.len);
    try std.testing.expect(sink.kicks >= 1);

    var seen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer seen.deinit();
    for (sink.frames.items) |*f| {
        try std.testing.expectEqual(@as(u16, 0), packet.checksum(f[14..34]));
        const ip = std.mem.readInt(u32, f[30..34], .big);
        const port = std.mem.readInt(u16, f[36..38], .big);
        try std.testing.expect(!targets.isReserved(ip));
        const key = (@as(u64, ip) << 16) | port;
        try std.testing.expect(!seen.contains(key));
        try seen.put(key, {});
    }
    try std.testing.expectEqual(@as(usize, 8), seen.count());
}

test "max_packets caps the send count below the target total" {
    const test_key = [_]u8{0} ** 16;
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/28")};
    const ports = [_]u16{ 80, 443, 22 };
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 0x1234);
    defer eng.deinit();

    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
    });
    var tb = ratelimit.TokenBucket.init(1000, 64);
    var clock = FakeClock{};
    var sink = FakeSink{ .allocator = std.testing.allocator };
    defer sink.frames.deinit(std.testing.allocator);

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, 5, std.math.maxInt(u64));
    try std.testing.expectEqual(@as(u64, 5), sent);
    try std.testing.expectEqual(@as(usize, 5), sink.frames.items.len);
}

const StuckSink = struct {
    kicks: usize = 0,
    fn submit(_: *StuckSink, _: []const u8) bool {
        return false;
    }
    fn kick(self: *StuckSink) void {
        self.kicks += 1;
    }
};

test "run bails at the deadline when the sink never drains (stall watchdog)" {
    const test_key = [_]u8{0} ** 16;
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/28")};
    const ports = [_]u16{80};
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 0x1234);
    defer eng.deinit();

    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
    });
    var tb = ratelimit.TokenBucket.init(1000, 64);
    var clock = FakeClock{};
    var sink = StuckSink{};

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, 1_000_000, 5_000_000_000);
    try std.testing.expectEqual(@as(u64, 0), sent);
    try std.testing.expect(sink.kicks >= 1);
}

test "decoys emit the real probe plus every spoofed source for each target" {
    const test_key = [_]u8{0} ** 16;
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/30")};
    const ports = [_]u16{80};
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 9);
    defer eng.deinit();
    const total = eng.total;

    const decoys = [_]u32{ 0x01010101, 0x02020202 };
    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .decoys = &decoys,
    });
    var tb = ratelimit.TokenBucket.init(1000, 1000);
    var clock = FakeClock{};
    var sink = FakeSink{ .allocator = std.testing.allocator };
    defer sink.frames.deinit(std.testing.allocator);

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, total, std.math.maxInt(u64));
    try std.testing.expectEqual(total * 3, sent);
    try std.testing.expectEqual(@as(usize, @intCast(total * 3)), sink.frames.items.len);

    var real_count: usize = 0;
    for (sink.frames.items) |*f| {
        if (std.mem.readInt(u32, f[26..30], .big) == 0x0a000001) real_count += 1;
    }
    try std.testing.expectEqual(@as(usize, @intCast(total)), real_count);
}

test "jittered pacing covers every target and advances the clock by the sleeps" {
    const test_key = [_]u8{0} ** 16;
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/29")};
    const ports = [_]u16{80};
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 4);
    defer eng.deinit();
    const total = eng.total;

    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
    });
    var tb = ratelimit.TokenBucket.init(1000, 1000).withJitter(0xC0FFEE);
    var clock = FakeClock{};
    var sink = FakeSink{ .allocator = std.testing.allocator };
    defer sink.frames.deinit(std.testing.allocator);

    const before = clock.t;
    const sent = run(&eng, &tmpl, &tb, &sink, &clock, total, std.math.maxInt(u64));
    try std.testing.expectEqual(total, sent);
    try std.testing.expect(clock.t > before);
}

const SlowClock = struct {
    t: u64 = 0,
    fn now(self: *SlowClock) u64 {
        self.t += 1_000;
        return self.t;
    }
    fn sleepNs(self: *SlowClock, ns: u64) void {
        self.t += ns;
    }
};

const CountSink = struct {
    count: u64 = 0,
    fn submit(self: *CountSink, _: []const u8) bool {
        self.count += 1;
        return true;
    }
    fn kick(_: *CountSink) void {}
};

test "decoy scans keep making progress past the initial token burst (no livelock)" {
    const test_key = [_]u8{0} ** 16;
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.0.0/20")};
    const ports = [_]u16{80};
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 11);
    defer eng.deinit();
    const total = eng.total;

    const decoys = [_]u32{ 0x01010101, 0x02020202 };
    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .decoys = &decoys,
    });
    var tb = ratelimit.TokenBucket.init(1000, 1000);
    var clock = SlowClock{};
    var sink = CountSink{};

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, total, 6_000_000_000);
    try std.testing.expectEqual(sink.count, sent);
    try std.testing.expect(sent > 3000);
}

const BoundedSink = struct {
    frames: std.ArrayList([54]u8) = .empty,
    allocator: std.mem.Allocator,
    held: usize = 0,
    cap: usize,
    fn submit(self: *BoundedSink, frame: []const u8) bool {
        if (self.held >= self.cap) return false;
        self.frames.append(self.allocator, frame[0..54].*) catch return false;
        self.held += 1;
        return true;
    }
    fn kick(self: *BoundedSink) void {
        self.held = 0;
    }
};

test "decoy groups resume across backpressure without re-sending the real probe" {
    const test_key = [_]u8{0} ** 16;
    const cidrs = [_]targets.Range{try targets.parseCidr("8.8.8.0/29")};
    const ports = [_]u16{80};
    var eng = try targets.Engine.init(std.testing.allocator, &cidrs, &ports, 13);
    defer eng.deinit();
    const total = eng.total;

    const decoys = [_]u32{ 0x01010101, 0x02020202 };
    const tmpl = template.SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .decoys = &decoys,
    });
    var tb = ratelimit.TokenBucket.init(1000, 1000);
    var clock = FakeClock{};
    var sink = BoundedSink{ .allocator = std.testing.allocator, .cap = 2 };
    defer sink.frames.deinit(std.testing.allocator);

    const sent = run(&eng, &tmpl, &tb, &sink, &clock, total, std.math.maxInt(u64));
    try std.testing.expectEqual(total * 3, sent);
    try std.testing.expectEqual(@as(usize, @intCast(total * 3)), sink.frames.items.len);

    var real: usize = 0;
    for (sink.frames.items) |*f| {
        if (std.mem.readInt(u32, f[26..30], .big) == 0x0a000001) real += 1;
    }
    try std.testing.expectEqual(@as(usize, @intCast(total)), real);
}
