// ©AngelaMos | 2026
// rx.zig

const std = @import("std");
const classify = @import("classify");
const dedup = @import("dedup");
const cookie = @import("cookie");

pub const Result = classify.Result;
pub const State = classify.State;
pub const TcpClassifier = classify.TcpClassifier;
pub const TcpClassifier6 = classify.TcpClassifier6;
pub const UdpClassifier = classify.UdpClassifier;

const RECV_BUF_LEN: usize = 2048;
const PORT_BITS: u6 = 16;
const NS_PER_MS: u64 = 1_000_000;
const NS_PER_SEC: u64 = 1_000_000_000;

pub fn resultKey(r: Result) u64 {
    return switch (r.addr) {
        .v4 => |ip| (@as(u64, ip) << PORT_BITS) | r.port,
        .v6 => |b| blk: {
            var h = std.hash.Wyhash.init(r.port);
            h.update(&b);
            const k = h.final();
            break :blk if (k == std.math.maxInt(u64)) k -% 1 else k;
        },
    };
}

pub fn run(source: anytype, clf: anytype, dd: *dedup.Dedup, sink: anytype) void {
    var buf: [RECV_BUF_LEN]u8 = undefined;
    while (source.recv(&buf)) |n| {
        if (clf.match(buf[0..n])) |r| {
            if (dd.insert(resultKey(r))) sink.emit(r);
        }
    }
}

pub const QueueSink = struct {
    queue: *std.Io.Queue(Result),
    io: std.Io,

    pub fn emit(self: *QueueSink, r: Result) void {
        self.queue.putOne(self.io, r) catch {};
    }
};

const linux = std.os.linux;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;

pub const OpenError = error{
    NeedCapNetRaw,
    SocketFailed,
    IfIndexFailed,
    BindFailed,
};

const POLL_TICK_MS: i32 = 100;

pub const RecvPlan = union(enum) { stop, poll: i32 };

pub fn planDrain(
    now_ns: u64,
    hard_deadline_ns: u64,
    tx_done: bool,
    drain_anchor_ns: *?u64,
    drain_window_ns: u64,
    tick_ms: i32,
) RecvPlan {
    if (now_ns >= hard_deadline_ns) return .stop;
    if (!tx_done) return .{ .poll = tick_ms };
    if (drain_anchor_ns.* == null) drain_anchor_ns.* = now_ns;
    const deadline = drain_anchor_ns.*.? + drain_window_ns;
    if (now_ns >= deadline) return .stop;
    const remaining_ms: u64 = (deadline - now_ns) / NS_PER_MS;
    const cap: u64 = @intCast(tick_ms);
    const chosen: u64 = @min(remaining_ms + 1, cap);
    return .{ .poll = @intCast(chosen) };
}

pub const Receiver = struct {
    fd: i32,
    tx_done: *std.atomic.Value(bool),
    drain_window_ns: u64,
    hard_cap_ns: u64,
    started: bool = false,
    hard_deadline_ns: u64 = 0,
    drain_anchor_ns: ?u64 = null,

    fn monoNow() u64 {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * NS_PER_SEC + @as(u64, @intCast(ts.nsec));
    }

    pub fn open(ifname: []const u8, proto: u16, tx_done: *std.atomic.Value(bool), drain_window_ns: u64, hard_cap_ns: u64) OpenError!Receiver {
        const rc_sock = linux.socket(
            linux.AF.PACKET,
            linux.SOCK.RAW,
            std.mem.nativeToBig(u16, proto),
        );
        switch (linux.errno(rc_sock)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.NeedCapNetRaw,
            else => return error.SocketFailed,
        }
        const fd: i32 = @intCast(rc_sock);
        errdefer _ = linux.close(fd);

        var ifr = std.mem.zeroes(linux.ifreq);
        if (ifname.len >= ifr.ifrn.name.len) return error.IfIndexFailed;
        @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
        if (linux.errno(linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&ifr))) != .SUCCESS)
            return error.IfIndexFailed;
        const ifindex: i32 = ifr.ifru.ivalue;

        var ignore_outgoing: u32 = 1;
        _ = linux.setsockopt(fd, linux.SOL.PACKET, linux.PACKET.IGNORE_OUTGOING, std.mem.asBytes(&ignore_outgoing), @sizeOf(u32));

        var sll = std.mem.zeroes(linux.sockaddr.ll);
        sll.family = linux.AF.PACKET;
        sll.protocol = std.mem.nativeToBig(u16, proto);
        sll.ifindex = ifindex;
        if (linux.errno(linux.bind(fd, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll))) != .SUCCESS)
            return error.BindFailed;

        return .{ .fd = fd, .tx_done = tx_done, .drain_window_ns = drain_window_ns, .hard_cap_ns = hard_cap_ns };
    }

    pub fn recv(self: *Receiver, buf: []u8) ?usize {
        while (true) {
            const now = monoNow();
            if (!self.started) {
                self.started = true;
                self.hard_deadline_ns = now +| self.hard_cap_ns;
            }
            const done = self.tx_done.load(.acquire);
            const timeout: i32 = switch (planDrain(now, self.hard_deadline_ns, done, &self.drain_anchor_ns, self.drain_window_ns, POLL_TICK_MS)) {
                .stop => return null,
                .poll => |t| t,
            };
            var pfd = [_]linux.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN, .revents = 0 }};
            const pr = linux.poll(&pfd, 1, timeout);
            switch (linux.errno(pr)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return null,
            }
            if (pr == 0) continue;
            const rc = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR, .AGAIN => continue,
                else => return null,
            }
        }
    }

    pub fn close(self: *Receiver) void {
        _ = linux.close(self.fd);
    }
};

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

const our_ip: u32 = 0x0a000001;
const our_port: u16 = 40000;
const target_ip: u32 = 0x08080808;

fn buildReply(buf: *[54]u8, sport: u16, ack: u32, flags: u8) void {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[12..14], 0x0800, .big);
    buf[14] = 0x45;
    buf[14 + 9] = 6;
    std.mem.writeInt(u32, buf[14 + 12 ..][0..4], target_ip, .big);
    std.mem.writeInt(u32, buf[14 + 16 ..][0..4], our_ip, .big);
    std.mem.writeInt(u16, buf[34..36], sport, .big);
    std.mem.writeInt(u16, buf[36..38], our_port, .big);
    std.mem.writeInt(u32, buf[42..46], ack, .big);
    buf[47] = flags;
}

const FakeSource = struct {
    frames: []const []const u8,
    idx: usize = 0,
    fn recv(self: *FakeSource, buf: []u8) ?usize {
        if (self.idx >= self.frames.len) return null;
        const f = self.frames[self.idx];
        self.idx += 1;
        @memcpy(buf[0..f.len], f);
        return f.len;
    }
};

const CollectSink = struct {
    list: *std.ArrayList(Result),
    allocator: std.mem.Allocator,
    fn emit(self: *CollectSink, r: Result) void {
        self.list.append(self.allocator, r) catch {};
    }
};

test "engine classifies, dedups, and emits each found host once" {
    const ck = cookie.Cookie.init(test_key);
    const seq80 = ck.seq(target_ip, 80, our_ip, our_port);
    const seq81 = ck.seq(target_ip, 81, our_ip, our_port);

    var open_a: [54]u8 = undefined;
    var open_b: [54]u8 = undefined;
    var closed_c: [54]u8 = undefined;
    buildReply(&open_a, 80, seq80 +% 1, 0x12);
    buildReply(&open_b, 80, seq80 +% 1, 0x12);
    buildReply(&closed_c, 81, seq81 +% 1, 0x14);
    const frames = [_][]const u8{ &open_a, &open_b, &closed_c };

    var dd = try dedup.Dedup.init(std.testing.allocator, 16);
    defer dd.deinit();
    var list: std.ArrayList(Result) = .empty;
    defer list.deinit(std.testing.allocator);

    var src = FakeSource{ .frames = &frames };
    var sink = CollectSink{ .list = &list, .allocator = std.testing.allocator };
    run(&src, classify.TcpClassifier{ .ck = ck }, &dd, &sink);

    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expectEqual(State.open, list.items[0].state);
    try std.testing.expectEqual(@as(u16, 80), list.items[0].port);
    try std.testing.expectEqual(State.closed, list.items[1].state);
    try std.testing.expectEqual(@as(u16, 81), list.items[1].port);
}

fn drainConsumer(io: std.Io, queue: *std.Io.Queue(Result), out: *std.ArrayList(Result), allocator: std.mem.Allocator) void {
    while (true) {
        const r = queue.getOne(io) catch break;
        out.append(allocator, r) catch {};
    }
}

test "Io.Queue hands the deduped set from a producer to a consumer fiber" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const ck = cookie.Cookie.init(test_key);
    const seq80 = ck.seq(target_ip, 80, our_ip, our_port);
    const seq81 = ck.seq(target_ip, 81, our_ip, our_port);

    var open_a: [54]u8 = undefined;
    var open_b: [54]u8 = undefined;
    var closed_c: [54]u8 = undefined;
    buildReply(&open_a, 80, seq80 +% 1, 0x12);
    buildReply(&open_b, 80, seq80 +% 1, 0x12);
    buildReply(&closed_c, 81, seq81 +% 1, 0x14);
    const frames = [_][]const u8{ &open_a, &open_b, &closed_c };

    var dd = try dedup.Dedup.init(std.testing.allocator, 16);
    defer dd.deinit();
    var out: std.ArrayList(Result) = .empty;
    defer out.deinit(std.testing.allocator);

    var qbuf: [8]Result = undefined;
    var queue = std.Io.Queue(Result).init(&qbuf);

    var consumer = io.async(drainConsumer, .{ io, &queue, &out, std.testing.allocator });

    var src = FakeSource{ .frames = &frames };
    var sink = QueueSink{ .queue = &queue, .io = io };
    run(&src, classify.TcpClassifier{ .ck = ck }, &dd, &sink);
    queue.close(io);
    consumer.await(io);

    try std.testing.expectEqual(@as(usize, 2), out.items.len);
}

const ms: u64 = 1_000_000;

test "planDrain keeps polling while TX is still in flight (no quiet-gap early exit)" {
    var anchor: ?u64 = null;
    const p = planDrain(5 * ms, 100_000 * ms, false, &anchor, 2_000 * ms, POLL_TICK_MS);
    switch (p) {
        .poll => |t| try std.testing.expectEqual(POLL_TICK_MS, t),
        .stop => return error.ShouldNotStopDuringTx,
    }
    try std.testing.expect(anchor == null);
}

test "planDrain anchors the drain window at TX completion, not socket-open" {
    var anchor: ?u64 = null;
    const now: u64 = 30_000 * ms;
    const p = planDrain(now, 100_000 * ms, true, &anchor, 2_000 * ms, POLL_TICK_MS);
    try std.testing.expectEqual(@as(?u64, now), anchor);
    switch (p) {
        .poll => |t| try std.testing.expect(t >= 1 and t <= POLL_TICK_MS),
        .stop => return error.ShouldStillDrain,
    }
}

test "planDrain stops once the post-TX drain window elapses" {
    var anchor: ?u64 = 30_000 * ms;
    const p = planDrain(32_001 * ms, 100_000 * ms, true, &anchor, 2_000 * ms, POLL_TICK_MS);
    try std.testing.expect(std.meta.activeTag(p) == .stop);
}

test "planDrain honors the hard safety cap even if TX never signalled done" {
    var anchor: ?u64 = null;
    const p = planDrain(9_999, 9_999, false, &anchor, 1, POLL_TICK_MS);
    try std.testing.expect(std.meta.activeTag(p) == .stop);
}
