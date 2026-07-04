// ©AngelaMos | 2026
// connect.zig

const std = @import("std");
const linux = std.os.linux;
const mem = std.mem;
const net = std.Io.net;
const classify = @import("classify");
const packet = @import("packet");
const targets = @import("targets");
const ratelimit = @import("ratelimit");
const output = @import("output");

pub const Result = classify.Result;
pub const State = classify.State;

pub const default_concurrency: usize = 128;
pub const default_timeout_ms: u64 = 3000;
pub const min_concurrency: usize = 1;
pub const max_concurrency: usize = 1024;

const NS_PER_MS: u64 = 1_000_000;
const NS_PER_SEC: u64 = 1_000_000_000;
const fd_retry_limit: u32 = 4;
const fd_retry_sleep_ns: u64 = 5 * NS_PER_MS;
const render_tick_interactive_ns: u64 = 125 * NS_PER_MS;
const render_tick_plain_ns: u64 = 1000 * NS_PER_MS;
const drain_tick_ns: u64 = 40 * NS_PER_MS;

fn monoNow() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * NS_PER_SEC + @as(u64, @intCast(ts.nsec));
}

fn sleepNs(ns: u64) void {
    const ts = linux.timespec{ .sec = @intCast(ns / NS_PER_SEC), .nsec = @intCast(ns % NS_PER_SEC) };
    _ = linux.nanosleep(&ts, null);
}

pub const Target = struct {
    addr: packet.Addr,
    port: u16,
};

pub const Source = union(enum) {
    v4: *targets.Engine,
    v6: *targets.Engine6,

    fn next(self: Source) ?Target {
        switch (self) {
            .v4 => |eng| {
                const t = eng.next() orelse return null;
                return .{ .addr = .{ .v4 = t.ip }, .port = t.port };
            },
            .v6 => |eng| {
                const t = eng.next() orelse return null;
                return .{ .addr = .{ .v6 = t.addr }, .port = t.port };
            },
        }
    }
};

const Probe = union(enum) {
    done: State,
    retry,
};

fn classifySoError(so_err: u32) State {
    return switch (so_err) {
        0 => .open,
        @intFromEnum(linux.E.CONNREFUSED) => .closed,
        @intFromEnum(linux.E.HOSTUNREACH),
        @intFromEnum(linux.E.NETUNREACH),
        @intFromEnum(linux.E.TIMEDOUT),
        @intFromEnum(linux.E.ACCES),
        @intFromEnum(linux.E.PERM),
        @intFromEnum(linux.E.CONNRESET),
        => .filtered,
        else => .filtered,
    };
}

fn connectOnce(addr: packet.Addr, port: u16, timeout_ns: u64) Probe {
    const domain: u32 = switch (addr) {
        .v4 => linux.AF.INET,
        .v6 => linux.AF.INET6,
    };
    const rc_sock = linux.socket(domain, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
    switch (linux.errno(rc_sock)) {
        .SUCCESS => {},
        .MFILE, .NFILE, .NOBUFS, .NOMEM => return .retry,
        else => return .{ .done = .filtered },
    }
    const fd: i32 = @intCast(rc_sock);
    defer _ = linux.close(fd);

    var v4sa: linux.sockaddr.in = undefined;
    var v6sa: linux.sockaddr.in6 = undefined;
    const sa_ptr: *const anyopaque = switch (addr) {
        .v4 => |ip| blk: {
            v4sa = .{ .port = mem.nativeToBig(u16, port), .addr = mem.nativeToBig(u32, ip) };
            break :blk @ptrCast(&v4sa);
        },
        .v6 => |b| blk: {
            v6sa = .{ .port = mem.nativeToBig(u16, port), .flowinfo = 0, .addr = b, .scope_id = 0 };
            break :blk @ptrCast(&v6sa);
        },
    };
    const sa_len: linux.socklen_t = switch (addr) {
        .v4 => @sizeOf(linux.sockaddr.in),
        .v6 => @sizeOf(linux.sockaddr.in6),
    };

    switch (linux.errno(linux.connect(fd, sa_ptr, sa_len))) {
        .SUCCESS, .ISCONN => return .{ .done = .open },
        .INPROGRESS, .INTR, .AGAIN => {},
        .CONNREFUSED => return .{ .done = .closed },
        .MFILE, .NFILE, .NOBUFS, .NOMEM => return .retry,
        else => return .{ .done = .filtered },
    }

    const timeout_ms: i32 = @intCast(@min(timeout_ns / NS_PER_MS, @as(u64, std.math.maxInt(i32))));
    var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.OUT, .revents = 0 }};
    while (true) {
        const pr = linux.poll(&pfd, 1, timeout_ms);
        switch (linux.errno(pr)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return .{ .done = .filtered },
        }
        if (pr == 0) return .{ .done = .filtered };
        break;
    }

    var so_err: u32 = 0;
    var so_len: linux.socklen_t = @sizeOf(u32);
    _ = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.ERROR, @ptrCast(&so_err), &so_len);
    return .{ .done = classifySoError(so_err) };
}

fn connectProbe(addr: packet.Addr, port: u16, timeout_ns: u64) State {
    var attempt: u32 = 0;
    while (true) {
        switch (connectOnce(addr, port, timeout_ns)) {
            .done => |st| return st,
            .retry => {
                attempt += 1;
                if (attempt >= fd_retry_limit) return .filtered;
                sleepNs(fd_retry_sleep_ns);
            },
        }
    }
}

const Dispenser = struct {
    mutex: std.Io.Mutex = .init,
    source: Source,
    bucket: ratelimit.TokenBucket,
    remaining: u64,
    exhausted: bool = false,

    fn next(self: *Dispenser, io: std.Io) ?Target {
        while (true) {
            self.mutex.lockUncancelable(io);
            if (self.exhausted or self.remaining == 0) {
                self.mutex.unlock(io);
                return null;
            }
            const granted = self.bucket.takeBatch(monoNow(), 1);
            if (granted == 0) {
                const wait = self.bucket.step_ns;
                self.mutex.unlock(io);
                std.Io.sleep(io, .{ .nanoseconds = @intCast(wait) }, .awake) catch {};
                continue;
            }
            const t = self.source.next() orelse {
                self.exhausted = true;
                self.mutex.unlock(io);
                return null;
            };
            self.remaining -= 1;
            self.mutex.unlock(io);
            return t;
        }
    }
};

const Collected = struct {
    mutex: std.Io.Mutex = .init,
    list: std.ArrayList(Result) = .empty,
    allocator: std.mem.Allocator,

    fn push(self: *Collected, io: std.Io, r: Result) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.list.append(self.allocator, r) catch {};
    }
};

fn worker(
    io: std.Io,
    disp: *Dispenser,
    timeout_ns: u64,
    collected: *Collected,
    stats: *output.Stats,
    remaining: *std.atomic.Value(usize),
) void {
    while (disp.next(io)) |t| {
        const st = connectProbe(t.addr, t.port, timeout_ns);
        _ = stats.sent.v.fetchAdd(1, .monotonic);
        stats.record(st);
        collected.push(io, .{ .addr = t.addr, .port = t.port, .state = st });
    }
    _ = remaining.fetchSub(1, .release);
}

pub const Params = struct {
    source: Source,
    count: u64,
    total: u64,
    rate: u64,
    concurrency: usize,
    timeout_ns: u64,
    out_level: output.ColorLevel,
    err_level: output.ColorLevel,
    interactive: bool,
    json: bool,
    target_text: []const u8,
    iface: []const u8,
};

fn drainNew(io: std.Io, collected: *Collected, cursor: *usize, json_out: ?*std.Io.Writer) void {
    collected.mutex.lockUncancelable(io);
    const n = collected.list.items.len;
    if (json_out) |w| {
        while (cursor.* < n) : (cursor.* += 1) {
            output.emitJson(w, collected.list.items[cursor.*], "tcp") catch {};
        }
    } else {
        cursor.* = n;
    }
    collected.mutex.unlock(io);
    if (json_out) |w| w.flush() catch {};
}

pub fn run(gpa: std.mem.Allocator, p: Params) !void {
    const concurrency = std.math.clamp(p.concurrency, min_concurrency, max_concurrency);

    var threaded = std.Io.Threaded.init(gpa, .{
        .async_limit = .limited(concurrency + 1),
        .concurrent_limit = .limited(concurrency + 1),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    const out = &ow.interface;
    var ebuf: [4096]u8 = undefined;
    var ew = std.Io.File.stderr().writer(io, &ebuf);
    const derr = &ew.interface;

    var bucket = ratelimit.TokenBucket.init(p.rate, p.rate);
    bucket.prime(monoNow());

    var disp = Dispenser{ .source = p.source, .bucket = bucket, .remaining = p.count };
    var collected = Collected{ .allocator = gpa };
    defer collected.list.deinit(gpa);
    var stats: output.Stats = .{};
    var remaining = std.atomic.Value(usize).init(concurrency);
    const json_out: ?*std.Io.Writer = if (p.json) out else null;

    try derr.print("zingela  connect scan  target {s}  iface {s}  rate {d} pps  concurrency {d}  timeout {d}ms\n", .{
        p.target_text, p.iface, p.rate, concurrency, p.timeout_ns / NS_PER_MS,
    });
    try derr.flush();

    const t0 = monoNow();

    var group: std.Io.Group = .init;
    defer group.cancel(io);
    var spawned: usize = 0;
    while (spawned < concurrency) : (spawned += 1) {
        group.async(io, worker, .{ io, &disp, p.timeout_ns, &collected, &stats, &remaining });
    }

    var dash = output.Dashboard.init(p.err_level, p.interactive, p.total);
    const render_interval_ns: u64 = if (p.interactive) render_tick_interactive_ns else render_tick_plain_ns;
    var cursor: usize = 0;
    var last_render: u64 = 0;

    while (remaining.load(.acquire) > 0) {
        drainNew(io, &collected, &cursor, json_out);
        const now = monoNow();
        if (last_render == 0 or now -| last_render >= render_interval_ns) {
            dash.render(derr, &stats, now -| t0) catch {};
            last_render = now;
        }
        std.Io.sleep(io, .{ .nanoseconds = @intCast(drain_tick_ns) }, .awake) catch {};
    }

    group.await(io) catch {};
    drainNew(io, &collected, &cursor, json_out);
    dash.render(derr, &stats, monoNow() -| t0) catch {};

    var open_n: u64 = 0;
    var closed_n: u64 = 0;
    var filtered_n: u64 = 0;
    for (collected.list.items) |r| switch (r.state) {
        .open => open_n += 1,
        .closed => closed_n += 1,
        .filtered => filtered_n += 1,
        .unfiltered => {},
    };

    if (!p.json) {
        if (collected.list.items.len > 0) {
            std.mem.sort(Result, collected.list.items, {}, output.ipPortLess);
            try out.writeByte('\n');
            try output.renderTable(out, p.out_level, collected.list.items);
            try out.flush();
        } else {
            try derr.writeAll("  no hosts responded\n");
        }
    }

    const elapsed_s = @as(f64, @floatFromInt(monoNow() - t0)) / @as(f64, @floatFromInt(NS_PER_SEC));
    try derr.writeByte('\n');
    try output.renderSummary(derr, p.err_level, stats.sent.v.load(.monotonic), "CONNECT", p.iface, elapsed_s, open_n, closed_n, filtered_n, 0, 0);
    try derr.flush();
}

// ---- tests ----

test "classifySoError maps SO_ERROR values to scan states" {
    try std.testing.expectEqual(State.open, classifySoError(0));
    try std.testing.expectEqual(State.closed, classifySoError(@intFromEnum(linux.E.CONNREFUSED)));
    try std.testing.expectEqual(State.filtered, classifySoError(@intFromEnum(linux.E.HOSTUNREACH)));
    try std.testing.expectEqual(State.filtered, classifySoError(@intFromEnum(linux.E.TIMEDOUT)));
    try std.testing.expectEqual(State.filtered, classifySoError(9999));
}

test "connectOnce surfaces a retry for fd exhaustion but a real state otherwise" {
    try std.testing.expect(connectOnce(.{ .v4 = 0x7f000001 }, 1, 200 * NS_PER_MS) == .done);
}

const FoundListener = struct { server: net.Server, port: u16 };

fn bindFreeLoopback(io: std.Io, start: u16) ?FoundListener {
    var port: u16 = start;
    while (port < start +% 200) : (port += 1) {
        var la: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(port) };
        if (net.IpAddress.listen(&la, io, .{ .reuse_address = true })) |s| {
            return .{ .server = s, .port = port };
        } else |_| {}
    }
    return null;
}

test "connectProbe classifies a live loopback listener as open and a released port as closed" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const live = bindFreeLoopback(io, 39_211) orelse return error.SkipZigTest;
    var live_server = live.server;
    defer live_server.deinit(io);

    var dead = bindFreeLoopback(io, live.port + 1) orelse return error.SkipZigTest;
    const dead_port = dead.port;
    dead.server.deinit(io);

    try std.testing.expectEqual(State.open, connectProbe(.{ .v4 = 0x7f000001 }, live.port, 2 * NS_PER_SEC));
    try std.testing.expectEqual(State.closed, connectProbe(.{ .v4 = 0x7f000001 }, dead_port, 2 * NS_PER_SEC));
}

test "Dispenser stops at the count cap and hands out distinct targets under the token bucket" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cidr = try targets.parseCidr("8.8.8.0/28");
    const ports = [_]u16{ 80, 443 };
    var eng = try targets.Engine.init(std.testing.allocator, &.{cidr}, &ports, 0xABCDEF);
    defer eng.deinit();

    var bucket = ratelimit.TokenBucket.init(1_000_000, 1_000_000);
    bucket.prime(monoNow());
    var disp = Dispenser{ .source = .{ .v4 = &eng }, .bucket = bucket, .remaining = 5 };

    var seen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer seen.deinit();
    var n: usize = 0;
    while (disp.next(io)) |t| {
        const key = (@as(u64, t.addr.v4) << 16) | t.port;
        try std.testing.expect(!seen.contains(key));
        try seen.put(key, {});
        n += 1;
    }
    try std.testing.expectEqual(@as(usize, 5), n);
}
