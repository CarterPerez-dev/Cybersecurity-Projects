// ©AngelaMos | 2026
// service.zig

const std = @import("std");
const linux = std.os.linux;
const packet = @import("packet");
const cookie = @import("cookie");
const segment = @import("segment");
const probe = @import("probe");

pub const default_capacity: u16 = 8192;
pub const default_banner_wait_ns: u64 = 4 * std.time.ns_per_s;

const ETH_HDR_LEN: usize = 14;
const ETH_OFF_TYPE: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_MIN_IHL: usize = 20;
const IP_IHL_MASK: u8 = 0x0f;
const IP_OFF_TOTAL_LEN: usize = 2;
const IP_OFF_PROTO: usize = 9;
const IP_OFF_SRC: usize = 12;
const IP_OFF_DST: usize = 16;
const IPPROTO_TCP: u8 = 6;

const TCP_OFF_SPORT: usize = 0;
const TCP_OFF_DPORT: usize = 2;
const TCP_OFF_SEQ: usize = 4;
const TCP_OFF_ACK: usize = 8;
const TCP_OFF_DATAOFF: usize = 12;
const TCP_OFF_FLAGS: usize = 13;
const TCP_MIN_LEN: usize = 20;

fn ihlBytes(first_byte: u8) usize {
    return @as(usize, first_byte & IP_IHL_MASK) * 4;
}

pub const View = struct {
    ip_src: u32,
    ip_dst: u32,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: []const u8,
};

pub fn parse(frame: []const u8) ?View {
    if (frame.len < ETH_HDR_LEN + IP_MIN_IHL) return null;
    if (std.mem.readInt(u16, frame[ETH_OFF_TYPE..][0..2], .big) != ETHERTYPE_IPV4) return null;

    const ip = ETH_HDR_LEN;
    const ihl = ihlBytes(frame[ip]);
    if (ihl < IP_MIN_IHL or frame.len < ip + ihl) return null;
    if (frame[ip + IP_OFF_PROTO] != IPPROTO_TCP) return null;

    const total_len = std.mem.readInt(u16, frame[ip + IP_OFF_TOTAL_LEN ..][0..2], .big);
    const ip_src = std.mem.readInt(u32, frame[ip + IP_OFF_SRC ..][0..4], .big);
    const ip_dst = std.mem.readInt(u32, frame[ip + IP_OFF_DST ..][0..4], .big);

    const tcp = ip + ihl;
    if (frame.len < tcp + TCP_MIN_LEN) return null;
    const data_off = ihlBytes(frame[tcp + TCP_OFF_DATAOFF] >> 4);
    if (data_off < TCP_MIN_LEN) return null;

    const payload_start = tcp + data_off;
    const ip_end = @min(ip + @as(usize, total_len), frame.len);
    const payload: []const u8 = if (payload_start < ip_end and payload_start <= frame.len)
        frame[payload_start..@min(ip_end, frame.len)]
    else
        &.{};

    return .{
        .ip_src = ip_src,
        .ip_dst = ip_dst,
        .sport = std.mem.readInt(u16, frame[tcp + TCP_OFF_SPORT ..][0..2], .big),
        .dport = std.mem.readInt(u16, frame[tcp + TCP_OFF_DPORT ..][0..2], .big),
        .seq = std.mem.readInt(u32, frame[tcp + TCP_OFF_SEQ ..][0..4], .big),
        .ack = std.mem.readInt(u32, frame[tcp + TCP_OFF_ACK ..][0..4], .big),
        .flags = frame[tcp + TCP_OFF_FLAGS],
        .payload = payload,
    };
}

pub fn connKey(ip: u32, port: u16) u64 {
    return (@as(u64, ip) << 16) | port;
}

fn keyIp(key: u64) u32 {
    return @intCast(key >> 16);
}

fn keyPort(key: u64) u16 {
    return @truncate(key);
}

const nil: u16 = 0xffff;

pub fn ConnTable(comptime cap: u16) type {
    std.debug.assert(cap < nil);
    return struct {
        const Self = @This();

        const Node = struct {
            key: u64 = 0,
            our_port: u16 = 0,
            server_isn: u32 = 0,
            deadline: u64 = 0,
            next: u16 = nil,
        };

        buckets: [cap]u16 = [_]u16{nil} ** cap,
        pool: [cap]Node = [_]Node{.{}} ** cap,
        free_head: u16,
        count: u16 = 0,
        seed: u64 = 0,

        pub fn init(seed: u64) Self {
            var self = Self{ .free_head = 0, .seed = seed };
            var i: u16 = 0;
            while (i < cap) : (i += 1) {
                self.pool[i].next = if (i + 1 < cap) i + 1 else nil;
            }
            return self;
        }

        fn bucketOf(self: *const Self, key: u64) usize {
            const mixed = (key ^ self.seed ^ (key >> 17)) *% 0x9e3779b97f4a7c15;
            return @intCast((mixed >> 40) % cap);
        }

        pub fn get(self: *Self, key: u64) ?*Node {
            var idx = self.buckets[self.bucketOf(key)];
            while (idx != nil) : (idx = self.pool[idx].next) {
                if (self.pool[idx].key == key) return &self.pool[idx];
            }
            return null;
        }

        pub fn insert(self: *Self, key: u64, our_port: u16, server_isn: u32, deadline: u64) bool {
            if (self.get(key)) |node| {
                node.our_port = our_port;
                node.server_isn = server_isn;
                node.deadline = deadline;
                return true;
            }
            if (self.free_head == nil) return false;
            const idx = self.free_head;
            self.free_head = self.pool[idx].next;
            const b = self.bucketOf(key);
            self.pool[idx] = .{ .key = key, .our_port = our_port, .server_isn = server_isn, .deadline = deadline, .next = self.buckets[b] };
            self.buckets[b] = idx;
            self.count += 1;
            return true;
        }

        pub fn remove(self: *Self, key: u64) bool {
            const b = self.bucketOf(key);
            var idx = self.buckets[b];
            var prev: u16 = nil;
            while (idx != nil) {
                if (self.pool[idx].key == key) {
                    if (prev == nil) self.buckets[b] = self.pool[idx].next else self.pool[prev].next = self.pool[idx].next;
                    self.pool[idx].next = self.free_head;
                    self.free_head = idx;
                    self.count -= 1;
                    return true;
                }
                prev = idx;
                idx = self.pool[idx].next;
            }
            return false;
        }

        pub fn sweepExpired(self: *Self, now: u64, ctx: anytype) void {
            var b: usize = 0;
            while (b < cap) : (b += 1) {
                var idx = self.buckets[b];
                var prev: u16 = nil;
                while (idx != nil) {
                    const nx = self.pool[idx].next;
                    if (self.pool[idx].deadline <= now) {
                        ctx.onExpired(self.pool[idx].key, self.pool[idx].our_port);
                        if (prev == nil) self.buckets[b] = nx else self.pool[prev].next = nx;
                        self.pool[idx].next = self.free_head;
                        self.free_head = idx;
                        self.count -= 1;
                    } else {
                        prev = idx;
                    }
                    idx = nx;
                }
            }
        }
    };
}

pub const Finding = struct {
    ip: u32,
    port: u16,
    info: probe.ServiceInfo,
};

pub const Sender = struct {
    ctx: *anyopaque,
    vtable: *const Vtable,

    pub const Vtable = struct {
        send: *const fn (*anyopaque, []const u8) void,
    };

    pub fn send(self: Sender, frame: []const u8) void {
        self.vtable.send(self.ctx, frame);
    }
};

pub const Sink = struct {
    ctx: *anyopaque,
    vtable: *const Vtable,

    pub const Vtable = struct {
        emit: *const fn (*anyopaque, Finding) void,
    };

    pub fn emit(self: Sink, f: Finding) void {
        self.vtable.emit(self.ctx, f);
    }
};

pub const Config = struct {
    cookie: cookie.Cookie,
    our_ip: u32,
    src_mac: [6]u8,
    gw_mac: [6]u8,
    banner_wait_ns: u64 = default_banner_wait_ns,
};

const F_FIN: u8 = packet.TcpFlag.fin;
const F_SYN: u8 = packet.TcpFlag.syn;
const F_RST: u8 = packet.TcpFlag.rst;
const F_PSH: u8 = packet.TcpFlag.psh;
const F_ACK: u8 = packet.TcpFlag.ack;

pub const Engine = struct {
    const Table = ConnTable(default_capacity);

    cfg: Config,
    table: Table,
    banners: std.atomic.Value(u64) = .{ .raw = 0 },
    probed: std.atomic.Value(u64) = .{ .raw = 0 },
    drops: std.atomic.Value(u64) = .{ .raw = 0 },

    pub fn init(cfg: Config) Engine {
        const seed = cfg.cookie.generate(0, 0, 0, 0);
        return .{ .cfg = cfg, .table = Table.init(seed) };
    }

    fn sendSegment(self: *Engine, sender: Sender, dst_ip: u32, dst_port: u16, src_port: u16, seq: u32, ack: u32, flags: u8, payload: []const u8) void {
        var buf: [segment.max_len]u8 = undefined;
        const n = segment.build(&buf, .{
            .src_mac = self.cfg.src_mac,
            .dst_mac = self.cfg.gw_mac,
            .src_ip = self.cfg.our_ip,
            .dst_ip = dst_ip,
            .src_port = src_port,
            .dst_port = dst_port,
            .seq = seq,
            .ack = ack,
            .flags = flags,
            .payload = payload,
        });
        sender.send(buf[0..n]);
    }

    fn onSynAck(self: *Engine, v: View, key: u64, now_ns: u64, sender: Sender) void {
        const our_port = v.dport;
        const c = self.cfg.cookie.seq(v.ip_src, v.sport, self.cfg.our_ip, our_port);
        if (v.ack != c +% 1) return;

        if (self.table.get(key) == null) {
            if (!self.table.insert(key, our_port, v.seq, now_ns +% self.cfg.banner_wait_ns)) {
                _ = self.drops.fetchAdd(1, .monotonic);
                return;
            }
            _ = self.probed.fetchAdd(1, .monotonic);
        }

        const payload = probe.probeFor(v.sport);
        const flags: u8 = if (payload.len > 0) F_PSH | F_ACK else F_ACK;
        self.sendSegment(sender, v.ip_src, v.sport, our_port, c +% 1, v.seq +% 1, flags, payload);
    }

    fn onData(self: *Engine, v: View, key: u64, sender: Sender, sink: Sink) void {
        const node = self.table.get(key) orelse return;
        if (v.dport != node.our_port) return;
        if (v.seq != node.server_isn +% 1) return;
        const our_port = node.our_port;

        var si: probe.ServiceInfo = .{};
        probe.classify(v.payload, &si);
        sink.emit(.{ .ip = v.ip_src, .port = v.sport, .info = si });
        _ = self.banners.fetchAdd(1, .monotonic);

        const c = self.cfg.cookie.seq(v.ip_src, v.sport, self.cfg.our_ip, our_port);
        const probe_len: u32 = @intCast(probe.probeFor(v.sport).len);
        const our_seq = c +% 1 +% probe_len;
        const their_next = v.seq +% @as(u32, @intCast(v.payload.len));
        self.sendSegment(sender, v.ip_src, v.sport, our_port, our_seq, their_next, F_RST | F_ACK, "");
        _ = self.table.remove(key);
    }

    pub fn onFrame(self: *Engine, frame: []const u8, now_ns: u64, sender: Sender, sink: Sink) void {
        const v = parse(frame) orelse return;
        if (v.ip_dst != self.cfg.our_ip) return;
        const key = connKey(v.ip_src, v.sport);

        const syn = (v.flags & F_SYN) != 0;
        const ack = (v.flags & F_ACK) != 0;
        const rst = (v.flags & F_RST) != 0;
        const fin = (v.flags & F_FIN) != 0;

        if (syn and ack and !rst) {
            self.onSynAck(v, key, now_ns, sender);
        } else if (ack and !syn and !rst and v.payload.len > 0) {
            self.onData(v, key, sender, sink);
        } else if (rst or fin) {
            _ = self.table.remove(key);
        }
    }

    const SweepCtx = struct {
        engine: *Engine,
        sender: Sender,

        fn onExpired(self: *SweepCtx, key: u64, our_port: u16) void {
            const eng = self.engine;
            const ip = keyIp(key);
            const port = keyPort(key);
            const c = eng.cfg.cookie.seq(ip, port, eng.cfg.our_ip, our_port);
            const probe_len: u32 = @intCast(probe.probeFor(port).len);
            eng.sendSegment(self.sender, ip, port, our_port, c +% 1 +% probe_len, 0, F_RST, "");
        }
    };

    pub fn sweep(self: *Engine, now_ns: u64, sender: Sender) void {
        var ctx = SweepCtx{ .engine = self, .sender = sender };
        self.table.sweepExpired(now_ns, &ctx);
    }

    pub fn flushAll(self: *Engine, sender: Sender) void {
        self.sweep(std.math.maxInt(u64), sender);
    }

    pub fn inFlight(self: *const Engine) u16 {
        return self.table.count;
    }
};

pub const OpenError = error{
    NeedCapNetRaw,
    SocketFailed,
    IfIndexFailed,
    BindFailed,
};

const POLL_TICK_MS: i32 = 100;

pub const Socket = struct {
    fd: i32,
    sll: linux.sockaddr.ll,

    pub fn open(ifname: []const u8) OpenError!Socket {
        const rc_sock = linux.socket(
            linux.AF.PACKET,
            linux.SOCK.RAW,
            std.mem.nativeToBig(u16, @as(u16, linux.ETH.P.IP)),
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
        sll.protocol = std.mem.nativeToBig(u16, @as(u16, linux.ETH.P.IP));
        sll.ifindex = ifindex;
        if (linux.errno(linux.bind(fd, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll))) != .SUCCESS)
            return error.BindFailed;

        return .{ .fd = fd, .sll = sll };
    }

    pub fn recv(self: *Socket, buf: []u8, timeout_ms: i32) ?usize {
        var pfd = [_]linux.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN, .revents = 0 }};
        const pr = linux.poll(&pfd, 1, timeout_ms);
        switch (linux.errno(pr)) {
            .SUCCESS => {},
            else => return null,
        }
        if (pr == 0) return null;
        const rc = linux.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            else => return null,
        }
    }

    fn sendImpl(ctx: *anyopaque, frame: []const u8) void {
        const self: *Socket = @ptrCast(@alignCast(ctx));
        _ = linux.sendto(self.fd, frame.ptr, frame.len, 0, @ptrCast(&self.sll), @sizeOf(linux.sockaddr.ll));
    }

    const send_vtable = Sender.Vtable{ .send = sendImpl };

    pub fn sender(self: *Socket) Sender {
        return .{ .ctx = self, .vtable = &send_vtable };
    }

    pub fn close(self: *Socket) void {
        _ = linux.close(self.fd);
    }
};

fn monoNow() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const RECV_BUF_LEN: usize = 2048;

pub fn run(
    engine: *Engine,
    socket: *Socket,
    sink: Sink,
    tx_done: *std.atomic.Value(bool),
    drain_window_ns: u64,
    hard_cap_ns: u64,
) void {
    const sender = socket.sender();
    var buf: [RECV_BUF_LEN]u8 = undefined;
    const start = monoNow();
    const hard_deadline = start +| hard_cap_ns;
    var drain_anchor: ?u64 = null;
    var last_sweep: u64 = start;
    const sweep_interval_ns: u64 = 50 * std.time.ns_per_ms;

    while (true) {
        var now = monoNow();
        if (now >= hard_deadline) break;
        if (tx_done.load(.acquire)) {
            if (drain_anchor == null) drain_anchor = now;
            const past_window = now >= drain_anchor.? + drain_window_ns;
            if (past_window and engine.inFlight() == 0) break;
        }

        if (socket.recv(&buf, POLL_TICK_MS)) |n| {
            now = monoNow();
            engine.onFrame(buf[0..n], now, sender, sink);
        }
        const sweep_now = monoNow();
        if (sweep_now -| last_sweep >= sweep_interval_ns) {
            engine.sweep(sweep_now, sender);
            last_sweep = sweep_now;
        }
    }

    engine.flushAll(sender);
}

// ---- tests ----

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

const our_ip: u32 = 0x0a000001;
const our_mac = [6]u8{ 0x02, 0, 0, 0, 0, 0x01 };
const gw_mac = [6]u8{ 0x02, 0, 0, 0, 0, 0x02 };
const server_ip: u32 = 0xac200002;

fn testCfg() Config {
    return .{ .cookie = cookie.Cookie.init(test_key), .our_ip = our_ip, .src_mac = our_mac, .gw_mac = gw_mac };
}

const FakeSender = struct {
    frames: std.ArrayList([]u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) FakeSender {
        return .{ .frames = .empty, .allocator = allocator };
    }

    fn deinit(self: *FakeSender) void {
        for (self.frames.items) |f| self.allocator.free(f);
        self.frames.deinit(self.allocator);
    }

    fn sendImpl(ctx: *anyopaque, frame: []const u8) void {
        const self: *FakeSender = @ptrCast(@alignCast(ctx));
        const copy = self.allocator.dupe(u8, frame) catch return;
        self.frames.append(self.allocator, copy) catch {};
    }

    const vtable = Sender.Vtable{ .send = sendImpl };

    fn sender(self: *FakeSender) Sender {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

const FakeSink = struct {
    findings: std.ArrayList(Finding),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) FakeSink {
        return .{ .findings = .empty, .allocator = allocator };
    }

    fn deinit(self: *FakeSink) void {
        self.findings.deinit(self.allocator);
    }

    fn emitImpl(ctx: *anyopaque, f: Finding) void {
        const self: *FakeSink = @ptrCast(@alignCast(ctx));
        self.findings.append(self.allocator, f) catch {};
    }

    const vtable = Sink.Vtable{ .emit = emitImpl };

    fn sink(self: *FakeSink) Sink {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

fn buildServerFrame(buf: *[segment.max_len]u8, sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: []const u8) []const u8 {
    const n = segment.build(buf, .{
        .src_mac = gw_mac,
        .dst_mac = our_mac,
        .src_ip = server_ip,
        .dst_ip = our_ip,
        .src_port = sport,
        .dst_port = dport,
        .seq = seq,
        .ack = ack,
        .flags = flags,
        .payload = payload,
    });
    return buf[0..n];
}

test "ConnTable inserts, finds, removes, and reports full" {
    var t = ConnTable(4).init(0);
    try std.testing.expect(t.insert(connKey(1, 10), 40000, 0x1000, 100));
    try std.testing.expect(t.insert(connKey(2, 20), 40001, 0x2000, 200));
    try std.testing.expect(t.insert(connKey(3, 30), 40002, 0x3000, 300));
    try std.testing.expect(t.insert(connKey(4, 40), 40003, 0x4000, 400));
    try std.testing.expect(!t.insert(connKey(5, 50), 40004, 0x5000, 500));

    try std.testing.expect(t.get(connKey(2, 20)) != null);
    try std.testing.expectEqual(@as(u16, 40001), t.get(connKey(2, 20)).?.our_port);
    try std.testing.expect(t.remove(connKey(2, 20)));
    try std.testing.expect(t.get(connKey(2, 20)) == null);
    try std.testing.expect(t.insert(connKey(5, 50), 40004, 0x5000, 500));
    try std.testing.expectEqual(@as(u16, 4), t.count);
}

const CountCtx = struct {
    n: usize = 0,
    fn onExpired(self: *CountCtx, key: u64, our_port: u16) void {
        _ = key;
        _ = our_port;
        self.n += 1;
    }
};

test "ConnTable sweepExpired removes only entries past their deadline" {
    var t = ConnTable(8).init(0);
    _ = t.insert(connKey(1, 10), 40000, 0x1000, 100);
    _ = t.insert(connKey(2, 20), 40001, 0x2000, 500);
    _ = t.insert(connKey(3, 30), 40002, 0x3000, 100);
    var ctx = CountCtx{};
    t.sweepExpired(300, &ctx);
    try std.testing.expectEqual(@as(usize, 2), ctx.n);
    try std.testing.expectEqual(@as(u16, 1), t.count);
    try std.testing.expect(t.get(connKey(2, 20)) != null);
    try std.testing.expect(t.get(connKey(1, 10)) == null);
}

test "a valid SYN-ACK completes the handshake with an ACK and tracks the connection" {
    var fs = FakeSender.init(std.testing.allocator);
    defer fs.deinit();
    var fk = FakeSink.init(std.testing.allocator);
    defer fk.deinit();

    var eng = Engine.init(testCfg());
    const ck = cookie.Cookie.init(test_key);
    const c = ck.seq(server_ip, 22, our_ip, 40000);

    var buf: [segment.max_len]u8 = undefined;
    const synack = buildServerFrame(&buf, 22, 40000, 0xCAFE0000, c +% 1, F_SYN | F_ACK, "");
    eng.onFrame(synack, 1000, fs.sender(), fk.sink());

    try std.testing.expectEqual(@as(usize, 1), fs.frames.items.len);
    const ackv = parse(fs.frames.items[0]).?;
    try std.testing.expectEqual(@as(u32, c +% 1), ackv.seq);
    try std.testing.expectEqual(@as(u32, 0xCAFE0000 +% 1), ackv.ack);
    try std.testing.expect((ackv.flags & F_ACK) != 0 and (ackv.flags & F_SYN) == 0);
    try std.testing.expectEqual(@as(u16, 1), eng.inFlight());
    try std.testing.expectEqual(@as(u64, 1), eng.probed.load(.monotonic));
}

test "a SYN-ACK with a forged ack is rejected and never tracked" {
    var fs = FakeSender.init(std.testing.allocator);
    defer fs.deinit();
    var fk = FakeSink.init(std.testing.allocator);
    defer fk.deinit();

    var eng = Engine.init(testCfg());
    var buf: [segment.max_len]u8 = undefined;
    const synack = buildServerFrame(&buf, 22, 40000, 0xCAFE0000, 0xDEADBEEF, F_SYN | F_ACK, "");
    eng.onFrame(synack, 1000, fs.sender(), fk.sink());

    try std.testing.expectEqual(@as(usize, 0), fs.frames.items.len);
    try std.testing.expectEqual(@as(u16, 0), eng.inFlight());
}

test "a data segment on a tracked connection yields a finding and a closing RST" {
    var fs = FakeSender.init(std.testing.allocator);
    defer fs.deinit();
    var fk = FakeSink.init(std.testing.allocator);
    defer fk.deinit();

    var eng = Engine.init(testCfg());
    const ck = cookie.Cookie.init(test_key);
    const c = ck.seq(server_ip, 22, our_ip, 40000);

    var b1: [segment.max_len]u8 = undefined;
    const synack = buildServerFrame(&b1, 22, 40000, 0xCAFE0000, c +% 1, F_SYN | F_ACK, "");
    eng.onFrame(synack, 1000, fs.sender(), fk.sink());

    var b2: [segment.max_len]u8 = undefined;
    const banner = "SSH-2.0-OpenSSH_9.6p1\r\n";
    const data = buildServerFrame(&b2, 22, 40000, 0xCAFE0001, c +% 1, F_PSH | F_ACK, banner);
    eng.onFrame(data, 1100, fs.sender(), fk.sink());

    try std.testing.expectEqual(@as(usize, 1), fk.findings.items.len);
    const f = fk.findings.items[0];
    try std.testing.expectEqual(server_ip, f.ip);
    try std.testing.expectEqual(@as(u16, 22), f.port);
    try std.testing.expectEqualStrings("ssh", f.info.service);
    try std.testing.expectEqualStrings("OpenSSH_9.6p1", f.info.infoSlice());

    try std.testing.expectEqual(@as(usize, 2), fs.frames.items.len);
    const rstv = parse(fs.frames.items[1]).?;
    try std.testing.expect((rstv.flags & F_RST) != 0);
    try std.testing.expectEqual(@as(u16, 0), eng.inFlight());
    try std.testing.expectEqual(@as(u64, 1), eng.banners.load(.monotonic));
}

test "a data segment with a forged sequence number is rejected (anti-injection)" {
    var fs = FakeSender.init(std.testing.allocator);
    defer fs.deinit();
    var fk = FakeSink.init(std.testing.allocator);
    defer fk.deinit();

    var eng = Engine.init(testCfg());
    const ck = cookie.Cookie.init(test_key);
    const c = ck.seq(server_ip, 22, our_ip, 40000);

    var b1: [segment.max_len]u8 = undefined;
    const synack = buildServerFrame(&b1, 22, 40000, 0xCAFE0000, c +% 1, F_SYN | F_ACK, "");
    eng.onFrame(synack, 1000, fs.sender(), fk.sink());

    var b2: [segment.max_len]u8 = undefined;
    const forged = buildServerFrame(&b2, 22, 40000, 0xDEADBEEF, c +% 1, F_PSH | F_ACK, "SSH-2.0-EVIL_INJECTED\r\n");
    eng.onFrame(forged, 1100, fs.sender(), fk.sink());

    try std.testing.expectEqual(@as(usize, 0), fk.findings.items.len);
    try std.testing.expectEqual(@as(u16, 1), eng.inFlight());

    var b3: [segment.max_len]u8 = undefined;
    const genuine = buildServerFrame(&b3, 22, 40000, 0xCAFE0001, c +% 1, F_PSH | F_ACK, "SSH-2.0-RealBanner\r\n");
    eng.onFrame(genuine, 1200, fs.sender(), fk.sink());
    try std.testing.expectEqual(@as(usize, 1), fk.findings.items.len);
    try std.testing.expectEqualStrings("ssh", fk.findings.items[0].info.service);
    try std.testing.expectEqualStrings("RealBanner", fk.findings.items[0].info.infoSlice());
}

test "a data segment for an untracked connection is ignored" {
    var fs = FakeSender.init(std.testing.allocator);
    defer fs.deinit();
    var fk = FakeSink.init(std.testing.allocator);
    defer fk.deinit();

    var eng = Engine.init(testCfg());
    var buf: [segment.max_len]u8 = undefined;
    const data = buildServerFrame(&buf, 22, 40000, 0xCAFE0001, 0x1234, F_PSH | F_ACK, "hello");
    eng.onFrame(data, 1100, fs.sender(), fk.sink());

    try std.testing.expectEqual(@as(usize, 0), fk.findings.items.len);
    try std.testing.expectEqual(@as(usize, 0), fs.frames.items.len);
}

test "an HTTP port sends a GET probe on the completing ACK" {
    var fs = FakeSender.init(std.testing.allocator);
    defer fs.deinit();
    var fk = FakeSink.init(std.testing.allocator);
    defer fk.deinit();

    var eng = Engine.init(testCfg());
    const ck = cookie.Cookie.init(test_key);
    const c = ck.seq(server_ip, 80, our_ip, 40000);

    var buf: [segment.max_len]u8 = undefined;
    const synack = buildServerFrame(&buf, 80, 40000, 0x1000, c +% 1, F_SYN | F_ACK, "");
    eng.onFrame(synack, 1000, fs.sender(), fk.sink());

    const ackv = parse(fs.frames.items[0]).?;
    try std.testing.expect((ackv.flags & F_PSH) != 0);
    try std.testing.expect(std.mem.indexOf(u8, ackv.payload, "GET /") != null);
}

test "an expired connection is swept with a RST and the drop counter tracks backpressure" {
    var fs = FakeSender.init(std.testing.allocator);
    defer fs.deinit();

    var eng = Engine.init(testCfg());
    const ck = cookie.Cookie.init(test_key);
    const c = ck.seq(server_ip, 22, our_ip, 40000);
    var buf: [segment.max_len]u8 = undefined;
    var fk = FakeSink.init(std.testing.allocator);
    defer fk.deinit();
    const synack = buildServerFrame(&buf, 22, 40000, 0xCAFE0000, c +% 1, F_SYN | F_ACK, "");
    eng.onFrame(synack, 1000, fs.sender(), fk.sink());
    try std.testing.expectEqual(@as(u16, 1), eng.inFlight());

    eng.sweep(1000 + default_banner_wait_ns + 1, fs.sender());
    try std.testing.expectEqual(@as(u16, 0), eng.inFlight());
    const rstv = parse(fs.frames.items[fs.frames.items.len - 1]).?;
    try std.testing.expect((rstv.flags & F_RST) != 0);
}

test "parse strips ethernet padding using the IP total-length field" {
    var frame = [_]u8{0} ** 64;
    std.mem.writeInt(u16, frame[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV4, .big);
    frame[ETH_HDR_LEN] = 0x45;
    const total_len: u16 = 20 + 20 + 3;
    std.mem.writeInt(u16, frame[ETH_HDR_LEN + IP_OFF_TOTAL_LEN ..][0..2], total_len, .big);
    frame[ETH_HDR_LEN + IP_OFF_PROTO] = IPPROTO_TCP;
    std.mem.writeInt(u32, frame[ETH_HDR_LEN + IP_OFF_SRC ..][0..4], server_ip, .big);
    std.mem.writeInt(u32, frame[ETH_HDR_LEN + IP_OFF_DST ..][0..4], our_ip, .big);
    const tcp = ETH_HDR_LEN + IP_MIN_IHL;
    frame[tcp + TCP_OFF_DATAOFF] = 0x50;
    frame[tcp + TCP_MIN_LEN] = 'a';
    frame[tcp + TCP_MIN_LEN + 1] = 'b';
    frame[tcp + TCP_MIN_LEN + 2] = 'c';

    const v = parse(&frame).?;
    try std.testing.expectEqualStrings("abc", v.payload);
}
