// ©AngelaMos | 2026
// scancmd.zig

const std = @import("std");
const targets = @import("targets");
const template = @import("template");
const udp = @import("udp");
const ratelimit = @import("ratelimit");
const packet_io = @import("packet_io");
const cookie = @import("cookie");
const tx = @import("tx");
const rx = @import("rx");
const dedup = @import("dedup");
const netutil = @import("netutil");
const output = @import("output");
const stealth = @import("stealth");
const service = @import("service");
const connect = @import("connect");
const rawprobe = @import("rawprobe");
const ndp = @import("ndp");

const default_iface = "lo";
const default_rate: u64 = 10_000;
const default_src_port: u16 = 40_000;
const default_udp_src_span: u16 = 8_192;
const default_wait_ms: i32 = 2_000;
const ns_per_ms: u64 = 1_000_000;
const ns_per_sec: u64 = 1_000_000_000;
const default_tcp_ports = [_]u16{80};
const default_udp_ports = [_]u16{ 53, 123, 161 };
const dedup_capacity: usize = 1024;
const queue_capacity: usize = 2048;
const drain_batch: usize = 256;
const finding_queue_capacity: usize = 256;
const finding_drain_batch: usize = 64;
const drain_tick_ns: u64 = 50 * ns_per_ms;
const render_tick_interactive_ns: u64 = 125 * ns_per_ms;
const render_tick_plain_ns: u64 = 1_000 * ns_per_ms;
const rx_hard_cap_floor_ns: u64 = 60 * ns_per_sec;
const min_dashboard_cols: u16 = 64;

const need_cap_hint =
    "scan: need CAP_NET_RAW + CAP_NET_ADMIN. Grant once, then re-run (no sudo):\n" ++
    "  sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela\nSkipping.\n";

const concurrency_hint =
    "scan: this system cannot launch concurrent TX/RX (needs >= 2 worker threads).\n";

const authorized_warning =
    "scan: stealth/evasion features require explicit authorization.\n" ++
    "Re-run with --authorized-scan ONLY against systems you own or are\n" ++
    "contractually authorized to test. Unauthorized scanning is a crime\n" ++
    "under the CFAA and equivalent statutes worldwide.\n\n" ++
    "  stealth flags: --os-template --scan-type --jitter --source-port-rotation --decoys --suppress-rst\n\n" ++
    stealth.omitted_help ++ "\n";

const TxSink = struct {
    backend: *packet_io.Backend,
    sent: *output.Counter,

    pub fn submit(self: *TxSink, frame: []const u8) bool {
        if (self.backend.submit(frame)) {
            _ = self.sent.fetchAdd(1, .monotonic);
            return true;
        }
        return false;
    }

    pub fn kick(self: *TxSink) void {
        self.backend.kick();
    }
};

const FindingSink = struct {
    queue: *std.Io.Queue(service.Finding),
    io: std.Io,

    fn emitImpl(ctx: *anyopaque, f: service.Finding) void {
        const self: *FindingSink = @ptrCast(@alignCast(ctx));
        self.queue.putOne(self.io, f) catch {};
    }

    const vtable = service.Sink.Vtable{ .emit = emitImpl };

    pub fn sink(self: *FindingSink) service.Sink {
        return .{ .ctx = self, .vtable = &vtable };
    }
};

fn txWorkerImpl(
    engine: *targets.Engine,
    tmpl: anytype,
    bucket: *ratelimit.TokenBucket,
    sink: *TxSink,
    max_packets: u64,
    budget_ns: u64,
    tx_done: *std.atomic.Value(bool),
) u64 {
    var clock = netutil.RealClock{};
    const deadline_ns = clock.now() +| budget_ns;
    const sent = tx.run(engine, tmpl, bucket, sink, &clock, max_packets, deadline_ns);
    tx_done.store(true, .release);
    return sent;
}

fn txWorkerTcp(engine: *targets.Engine, tmpl: *const template.SynTemplate, bucket: *ratelimit.TokenBucket, sink: *TxSink, max_packets: u64, budget_ns: u64, tx_done: *std.atomic.Value(bool)) u64 {
    return txWorkerImpl(engine, tmpl, bucket, sink, max_packets, budget_ns, tx_done);
}

fn txWorkerUdp(engine: *targets.Engine, tmpl: *const udp.UdpTemplate, bucket: *ratelimit.TokenBucket, sink: *TxSink, max_packets: u64, budget_ns: u64, tx_done: *std.atomic.Value(bool)) u64 {
    return txWorkerImpl(engine, tmpl, bucket, sink, max_packets, budget_ns, tx_done);
}

fn rxWorkerTcp(receiver: *rx.Receiver, clf: rx.TcpClassifier, dd: *dedup.Dedup, sink: *rx.QueueSink, rx_done: *std.atomic.Value(bool)) void {
    rx.run(receiver, clf, dd, sink);
    rx_done.store(true, .release);
}

fn rxWorkerUdp(receiver: *rx.Receiver, ck: cookie.Cookie, base: u16, span: u16, dd: *dedup.Dedup, sink: *rx.QueueSink, rx_done: *std.atomic.Value(bool)) void {
    rx.run(receiver, rx.UdpClassifier{ .ck = ck, .base = base, .span = span }, dd, sink);
    rx_done.store(true, .release);
}

fn svcWorker(
    engine: *service.Engine,
    socket: *service.Socket,
    sink: service.Sink,
    tx_done: *std.atomic.Value(bool),
    drain_window_ns: u64,
    hard_cap_ns: u64,
    svc_done: *std.atomic.Value(bool),
) void {
    service.run(engine, socket, sink, tx_done, drain_window_ns, hard_cap_ns);
    svc_done.store(true, .release);
}

fn drainFindings(
    io: std.Io,
    queue: *std.Io.Queue(service.Finding),
    buf: []service.Finding,
    findings: *std.ArrayList(service.Finding),
    dd: *dedup.Dedup,
    allocator: std.mem.Allocator,
    json_out: ?*std.Io.Writer,
) void {
    while (true) {
        const n = queue.get(io, buf, 0) catch return;
        if (n == 0) return;
        for (buf[0..n]) |f| {
            if (!dd.insert(service.connKey(f.ip, f.port))) continue;
            findings.append(allocator, f) catch continue;
            if (json_out) |w| output.emitServiceJson(w, .{
                .ip = f.ip,
                .port = f.port,
                .service = f.info.service,
                .info = f.info.infoSlice(),
                .tls = f.info.tls,
            }) catch {};
        }
        if (n < buf.len) return;
    }
}

fn findingLess(_: void, a: service.Finding, b: service.Finding) bool {
    if (a.ip != b.ip) return a.ip < b.ip;
    return a.port < b.port;
}

fn renderServiceTable(out: *std.Io.Writer, level: output.ColorLevel, allocator: std.mem.Allocator, items: []service.Finding) !void {
    const rows = try allocator.alloc(output.ServiceRow, items.len);
    for (items, 0..) |*f, i| rows[i] = .{
        .ip = f.ip,
        .port = f.port,
        .service = f.info.service,
        .info = f.info.infoSlice(),
        .tls = f.info.tls,
    };
    try output.renderServices(out, level, rows);
}

fn absorb(
    batch: []const rx.Result,
    found: *std.ArrayList(rx.Result),
    allocator: std.mem.Allocator,
    stats: *output.Stats,
    json_out: ?*std.Io.Writer,
    proto: []const u8,
) void {
    for (batch) |r| {
        found.append(allocator, r) catch continue;
        stats.record(r.state);
        if (json_out) |w| output.emitJson(w, r, proto) catch {};
    }
}

fn drainQueue(
    io: std.Io,
    queue: *std.Io.Queue(rx.Result),
    buf: []rx.Result,
    found: *std.ArrayList(rx.Result),
    allocator: std.mem.Allocator,
    stats: *output.Stats,
    json_out: ?*std.Io.Writer,
    proto: []const u8,
) void {
    while (true) {
        const n = queue.get(io, buf, 0) catch return;
        if (n == 0) return;
        absorb(buf[0..n], found, allocator, stats, json_out, proto);
        if (n < buf.len) return;
    }
}

fn terminalCols(fd: i32) ?u16 {
    var ws: std.posix.winsize = undefined;
    const rc = std.os.linux.ioctl(fd, std.os.linux.T.IOCGWINSZ, @intFromPtr(&ws));
    if (std.os.linux.errno(rc) != .SUCCESS) return null;
    if (ws.col == 0) return null;
    return ws.col;
}

fn txWorkerV6(engine: *targets.Engine6, tmpl: *const template.SynTemplate6, bucket: *ratelimit.TokenBucket, sink: *TxSink, max_packets: u64, budget_ns: u64, tx_done: *std.atomic.Value(bool)) u64 {
    var clock = netutil.RealClock{};
    const deadline_ns = clock.now() +| budget_ns;
    const sent = tx.runV6(engine, tmpl, bucket, sink, &clock, max_packets, deadline_ns);
    tx_done.store(true, .release);
    return sent;
}

fn rxWorkerV6(receiver: *rx.Receiver, clf: rx.TcpClassifier6, dd: *dedup.Dedup, sink: *rx.QueueSink, rx_done: *std.atomic.Value(bool)) void {
    rx.run(receiver, clf, dd, sink);
    rx_done.store(true, .release);
}

fn resolveV6Gateway(io: std.Io, args: []const []const u8, ifname: []const u8, src_ip6: [16]u8, src_mac: [6]u8, derr: *std.Io.Writer) !?[6]u8 {
    _ = io;
    if (netutil.getFlag(args, "--gw-mac")) |m| return try netutil.parseMac(m);
    const next_hop = if (netutil.getFlag(args, "--gw-ip6")) |g| try netutil.parseIpv6(g) else netutil.defaultGateway6(ifname) orelse {
        try derr.writeAll("scan: IPv6 raw scan needs a next hop: pass --gw-mac <mac>, or --gw-ip6 <addr> to resolve it via NDP\n");
        try derr.flush();
        return null;
    };
    return ndp.resolve(ifname, src_ip6, src_mac, next_hop, 1500) catch |e| {
        try derr.print("scan: NDP neighbor resolution failed ({s}); pass --gw-mac explicitly\n", .{@errorName(e)});
        try derr.flush();
        return null;
    };
}

fn runV6Scan(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8, env: *std.process.Environ.Map, target_text: []const u8, ifname: []const u8, rate: u64, backend_choice: packet_io.Choice, derr: *std.Io.Writer) !void {
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    const out = &ow.interface;

    if (netutil.hasFlag(args, "--udp")) {
        try derr.writeAll("scan: IPv6 UDP scanning is not supported yet; run a TCP SYN scan or --connect\n");
        try derr.flush();
        return;
    }
    if (netutil.getFlag(args, "--scan-type") != null or netutil.getFlag(args, "--os-template") != null or
        netutil.getFlag(args, "--decoys") != null or netutil.getFlag(args, "--jitter") != null or
        netutil.hasFlag(args, "--source-port-rotation"))
    {
        try derr.writeAll("  note: stealth/scan-type options are not yet wired for IPv6; running a plain SYN scan\n");
    }

    const ports = if (netutil.getFlag(args, "--ports")) |p| try netutil.parsePorts(allocator, p) else try allocator.dupe(u16, &default_tcp_ports);
    const src_port = if (netutil.getFlag(args, "--src-port")) |p| try std.fmt.parseInt(u16, p, 10) else default_src_port;
    const wait_ms = if (netutil.getFlag(args, "--wait")) |w| try std.fmt.parseInt(i32, w, 10) else default_wait_ms;
    const json = netutil.hasFlag(args, "--json");
    const max_hosts = if (netutil.getFlag(args, "--max-hosts")) |m| try std.fmt.parseInt(u64, m, 10) else targets.default_max_hosts6;

    var seed: u64 = undefined;
    if (netutil.getFlag(args, "--seed")) |s| {
        seed = try std.fmt.parseInt(u64, s, 10);
    } else {
        var seed_bytes: [8]u8 = undefined;
        try io.randomSecure(&seed_bytes);
        seed = std.mem.readInt(u64, &seed_bytes, .little);
    }

    const src_ip6 = if (netutil.getFlag(args, "--src-ip6")) |s| try netutil.parseIpv6(s) else netutil.resolveSrcIp6(ifname) catch {
        try derr.print("scan: no IPv6 source address on '{s}' (assign one, or pass --src-ip6 <addr>)\n", .{ifname});
        try derr.flush();
        return;
    };
    const src_mac = try netutil.resolveSrcMac(ifname);
    const gw_mac = (try resolveV6Gateway(io, args, ifname, src_ip6, src_mac, derr)) orelse return;

    const cidr = targets.parseCidr6(target_text) catch |e| {
        try derr.print("scan: invalid IPv6 target '{s}' ({s})\n", .{ target_text, @errorName(e) });
        try derr.flush();
        return;
    };
    var eng = targets.Engine6.init(allocator, cidr, ports, seed, max_hosts) catch |e| switch (e) {
        error.PrefixTooLarge => {
            try derr.print("scan: IPv6 prefix '{s}' is too large to enumerate (over --max-hosts {d}); narrow the prefix or raise --max-hosts\n", .{ target_text, max_hosts });
            try derr.flush();
            return;
        },
        else => return e,
    };
    defer eng.deinit();
    const count = if (netutil.getFlag(args, "--count")) |c| try std.fmt.parseInt(u64, c, 10) else eng.total;

    const ck = try cookie.Cookie.random(io);
    const tmpl = template.SynTemplate6.init(.{
        .src_mac = src_mac,
        .dst_mac = gw_mac,
        .src_ip = src_ip6,
        .src_port = src_port,
        .cookie = ck,
    });
    var bucket = ratelimit.TokenBucket.init(rate, rate);

    const choice = output.parseColorChoice(netutil.getFlag(args, "--color"));
    const out_level = output.envLevel(io, std.Io.File.stdout(), env, choice);
    const err_level = output.envLevel(io, std.Io.File.stderr(), env, choice);
    const stderr_tty = std.Io.File.stderr().isTty(io) catch false;
    const wide_enough = if (terminalCols(2)) |c| c >= min_dashboard_cols else true;
    const interactive = stderr_tty and wide_enough;

    const dash_total = @min(count, eng.total);
    const drain_window_ns: u64 = @as(u64, @intCast(@max(wait_ms, 0))) * ns_per_ms;
    const est_tx_ns: u64 = if (rate > 0) (dash_total / rate) *| ns_per_sec else rx_hard_cap_floor_ns;
    const tx_budget_ns: u64 = (est_tx_ns *| 4) +| rx_hard_cap_floor_ns;
    const hard_cap_ns: u64 = tx_budget_ns +| drain_window_ns;

    var backend = packet_io.select(allocator, ifname, backend_choice, .{}, .{}, derr) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try derr.writeAll(need_cap_hint);
            try derr.flush();
            return;
        },
        error.XdpNotCompiledIn => {
            try derr.writeAll("scan: --backend xdp needs a build with -Dxdp\n");
            try derr.flush();
            return;
        },
        else => return err,
    };
    defer backend.close();
    try derr.print("  using {s}\n", .{packet_io.kindLabel(backend.kind())});

    var tx_done = std.atomic.Value(bool).init(false);
    var rx_done = std.atomic.Value(bool).init(false);

    var receiver = rx.Receiver.open(ifname, rx.ETH_P_IPV6, &tx_done, drain_window_ns, hard_cap_ns) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try derr.writeAll(need_cap_hint);
            try derr.flush();
            return;
        },
        else => return err,
    };
    defer receiver.close();

    var dd = try dedup.Dedup.init(allocator, dedup_capacity);
    defer dd.deinit();
    var qbuf: [queue_capacity]rx.Result = undefined;
    var queue = std.Io.Queue(rx.Result).init(&qbuf);

    var found_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer found_arena.deinit();
    const found_alloc = found_arena.allocator();
    var found: std.ArrayList(rx.Result) = .empty;

    var stats: output.Stats = .{};
    const json_out: ?*std.Io.Writer = if (json) out else null;

    try derr.print("zingela  SYN scan (IPv6)  target {s}  iface {s}  rate {d} pps  ports {d}\n", .{ target_text, ifname, rate, ports.len });
    try derr.flush();

    var clock = netutil.RealClock{};
    const t0 = clock.now();

    var tx_sink = TxSink{ .backend = &backend, .sent = &stats.sent.v };
    var rx_sink = rx.QueueSink{ .queue = &queue, .io = io };

    var tx_fut = (io.concurrent(txWorkerV6, .{ &eng, &tmpl, &bucket, &tx_sink, count, tx_budget_ns, &tx_done })) catch {
        try derr.writeAll(concurrency_hint);
        try derr.flush();
        return;
    };
    var rx_fut = (io.concurrent(rxWorkerV6, .{ &receiver, rx.TcpClassifier6{ .ck = ck }, &dd, &rx_sink, &rx_done })) catch {
        _ = tx_fut.await(io);
        try derr.writeAll(concurrency_hint);
        try derr.flush();
        return;
    };

    var dash = output.Dashboard.init(err_level, interactive, dash_total);
    const render_interval_ns: u64 = if (interactive) render_tick_interactive_ns else render_tick_plain_ns;
    var drain_buf: [drain_batch]rx.Result = undefined;
    var last_render: u64 = 0;

    while (!(tx_done.load(.acquire) and rx_done.load(.acquire))) {
        drainQueue(io, &queue, drain_buf[0..], &found, found_alloc, &stats, json_out, "tcp");
        if (json) out.flush() catch {};
        const now = clock.now();
        if (last_render == 0 or now -| last_render >= render_interval_ns) {
            dash.render(derr, &stats, now -| t0) catch {};
            last_render = now;
        }
        clock.sleepNs(drain_tick_ns);
    }

    const sent = tx_fut.await(io);
    rx_fut.await(io);
    queue.close(io);
    drainQueue(io, &queue, drain_buf[0..], &found, found_alloc, &stats, json_out, "tcp");
    if (json) out.flush() catch {};
    dash.render(derr, &stats, clock.now() -| t0) catch {};

    var open_n: u64 = 0;
    var closed_n: u64 = 0;
    var filtered_n: u64 = 0;
    var unfiltered_n: u64 = 0;
    for (found.items) |r| switch (r.state) {
        .open => open_n += 1,
        .closed => closed_n += 1,
        .filtered => filtered_n += 1,
        .unfiltered => unfiltered_n += 1,
    };

    if (!json) {
        if (found.items.len > 0) {
            std.mem.sort(rx.Result, found.items, {}, output.ipPortLess);
            try out.writeByte('\n');
            try output.renderTable(out, out_level, found.items);
            try out.flush();
        } else {
            try derr.writeAll("  no open, closed, or filtered responses observed\n");
            if (sent > 0) try derr.writeAll("  (if a cloud/VM hypervisor is filtering raw sends upstream, retry with --connect)\n");
        }
    }

    const elapsed_s = @as(f64, @floatFromInt(clock.now() - t0)) / @as(f64, @floatFromInt(ns_per_sec));
    try derr.writeByte('\n');
    try output.renderSummary(derr, err_level, sent, "SYN", ifname, elapsed_s, open_n, closed_n, filtered_n, unfiltered_n, 0);
    try derr.flush();
}

fn runConnect(
    io: std.Io,
    allocator: std.mem.Allocator,
    args: []const []const u8,
    env: *std.process.Environ.Map,
    target_text: []const u8,
    ifname: []const u8,
    rate: u64,
    is_udp: bool,
    json: bool,
    derr: *std.Io.Writer,
) !void {
    if (is_udp) {
        try derr.writeAll("scan: connect mode is TCP-only; --udp is not supported with --backend connect\n");
        try derr.flush();
        return;
    }
    if (netutil.hasFlag(args, "--banners")) {
        try derr.writeAll("  note: --banners is unavailable in connect mode; reporting open/closed/filtered only\n");
    }

    const ports = if (netutil.getFlag(args, "--ports")) |p|
        try netutil.parsePorts(allocator, p)
    else
        try allocator.dupe(u16, &default_tcp_ports);

    var seed: u64 = undefined;
    if (netutil.getFlag(args, "--seed")) |s| {
        seed = try std.fmt.parseInt(u64, s, 10);
    } else {
        var seed_bytes: [8]u8 = undefined;
        try io.randomSecure(&seed_bytes);
        seed = std.mem.readInt(u64, &seed_bytes, .little);
    }

    const concurrency = if (netutil.getFlag(args, "--concurrency")) |c| try std.fmt.parseInt(usize, c, 10) else connect.default_concurrency;
    const timeout_ms = if (netutil.getFlag(args, "--connect-timeout")) |t| try std.fmt.parseInt(u64, t, 10) else connect.default_timeout_ms;
    const max_hosts = if (netutil.getFlag(args, "--max-hosts")) |m| try std.fmt.parseInt(u64, m, 10) else targets.default_max_hosts6;

    const choice = output.parseColorChoice(netutil.getFlag(args, "--color"));
    const out_level = output.envLevel(io, std.Io.File.stdout(), env, choice);
    const err_level = output.envLevel(io, std.Io.File.stderr(), env, choice);
    const stderr_tty = std.Io.File.stderr().isTty(io) catch false;
    const wide_enough = if (terminalCols(2)) |c| c >= min_dashboard_cols else true;
    const interactive = stderr_tty and wide_enough;
    try derr.flush();

    if (std.mem.indexOfScalar(u8, target_text, ':') != null) {
        const cidr = targets.parseCidr6(target_text) catch |e| {
            try derr.print("scan: invalid IPv6 target '{s}' ({s})\n", .{ target_text, @errorName(e) });
            try derr.flush();
            return;
        };
        var eng = targets.Engine6.init(allocator, cidr, ports, seed, max_hosts) catch |e| switch (e) {
            error.PrefixTooLarge => {
                try derr.print("scan: IPv6 prefix '{s}' is too large to enumerate (over --max-hosts {d}); narrow the prefix or raise --max-hosts\n", .{ target_text, max_hosts });
                try derr.flush();
                return;
            },
            else => return e,
        };
        defer eng.deinit();
        const count = if (netutil.getFlag(args, "--count")) |c| try std.fmt.parseInt(u64, c, 10) else eng.total;
        try connect.run(allocator, .{
            .source = .{ .v6 = &eng },
            .count = count,
            .total = @min(count, eng.total),
            .rate = rate,
            .concurrency = concurrency,
            .timeout_ns = timeout_ms *| ns_per_ms,
            .out_level = out_level,
            .err_level = err_level,
            .interactive = interactive,
            .json = json,
            .target_text = target_text,
            .iface = ifname,
        });
        return;
    }

    const cidr = try targets.parseCidr(target_text);
    var eng = try targets.Engine.init(allocator, &.{cidr}, ports, seed);
    defer eng.deinit();
    const count = if (netutil.getFlag(args, "--count")) |c| try std.fmt.parseInt(u64, c, 10) else eng.total;

    try connect.run(allocator, .{
        .source = .{ .v4 = &eng },
        .count = count,
        .total = @min(count, eng.total),
        .rate = rate,
        .concurrency = concurrency,
        .timeout_ns = timeout_ms *| ns_per_ms,
        .out_level = out_level,
        .err_level = err_level,
        .interactive = interactive,
        .json = json,
        .target_text = target_text,
        .iface = ifname,
    });
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8, env: *std.process.Environ.Map) !void {
    var obuf: [4096]u8 = undefined;
    var ow = std.Io.File.stdout().writer(io, &obuf);
    const out = &ow.interface;

    var ebuf: [4096]u8 = undefined;
    var ew = std.Io.File.stderr().writer(io, &ebuf);
    const derr = &ew.interface;

    const target_text = netutil.getFlag(args, "--target") orelse {
        try derr.writeAll("scan: --target <cidr> is required (e.g. --target 10.0.0.0/24)\n");
        try derr.flush();
        return;
    };
    const ifname = netutil.getFlag(args, "--iface") orelse default_iface;
    const rate = if (netutil.getFlag(args, "--rate")) |r| try std.fmt.parseInt(u64, r, 10) else default_rate;
    const src_port = if (netutil.getFlag(args, "--src-port")) |p| try std.fmt.parseInt(u16, p, 10) else default_src_port;
    const wait_ms = if (netutil.getFlag(args, "--wait")) |w| try std.fmt.parseInt(i32, w, 10) else default_wait_ms;
    const json = netutil.hasFlag(args, "--json");
    const is_udp = netutil.hasFlag(args, "--udp");
    const banners_flag = netutil.hasFlag(args, "--banners");

    const backend_arg = netutil.getFlag(args, "--backend");
    const connect_mode = netutil.hasFlag(args, "--connect") or
        (backend_arg != null and std.mem.eql(u8, backend_arg.?, "connect"));
    if (connect_mode) {
        return runConnect(io, allocator, args, env, target_text, ifname, rate, is_udp, json, derr);
    }

    const backend_choice = packet_io.parseChoice(backend_arg) orelse {
        try derr.writeAll("scan: --backend must be one of auto, xdp, afpacket, connect\n");
        try derr.flush();
        return;
    };

    if (backend_choice == .auto) {
        const raw_status = rawprobe.probe(ifname);
        if (raw_status != .ok) {
            try derr.print("  raw sends unavailable on '{s}' ({s}); falling back to unprivileged connect scan\n", .{ ifname, raw_status.reason() });
            try derr.writeAll("  (force the raw engine with --backend afpacket, or select it directly with --connect)\n");
            try derr.flush();
            return runConnect(io, allocator, args, env, target_text, ifname, rate, is_udp, json, derr);
        }
    }

    if (std.mem.indexOfScalar(u8, target_text, ':') != null) {
        return runV6Scan(io, allocator, args, env, target_text, ifname, rate, backend_choice, derr);
    }

    var scfg = stealth.parse(allocator, io, args) catch |e| switch (e) {
        error.AuthorizationRequired => {
            try derr.writeAll(authorized_warning);
            try derr.flush();
            return;
        },
        error.BadOsTemplate => {
            try derr.writeAll("scan: --os-template must be none, masscan, linux, windows, or macos\n");
            try derr.flush();
            return;
        },
        error.BadScanType => {
            try derr.writeAll("scan: --scan-type must be syn, fin, null, xmas, maimon, ack, or window\n");
            try derr.flush();
            return;
        },
        error.BadJitterMode => {
            try derr.writeAll("scan: --jitter must be poisson or none\n");
            try derr.flush();
            return;
        },
        error.BadDecoySpec => {
            try derr.writeAll("scan: --decoys must be comma-separated IPv4 addresses and/or RND:N\n");
            try derr.flush();
            return;
        },
        error.TooManyDecoys => {
            try derr.print("scan: at most {d} decoys allowed\n", .{stealth.max_decoys});
            try derr.flush();
            return;
        },
        error.OutOfMemory => return e,
    };
    defer scfg.deinit(allocator);

    if (is_udp and (scfg.profile != .none or scfg.scan != .syn or scfg.rotate or scfg.decoys.len > 0 or scfg.suppress_rst)) {
        try derr.writeAll("  note: --os-template/--scan-type/--source-port-rotation/--decoys/--suppress-rst apply to TCP scans; ignored for --udp\n");
    }
    if (is_udp and banners_flag) {
        try derr.writeAll("  note: --banners is a TCP feature; ignored for --udp\n");
    }
    const banners = banners_flag and !is_udp and scfg.scan == .syn;
    if (banners_flag and !is_udp and scfg.scan != .syn) {
        try derr.writeAll("  note: --banners needs a full handshake; ignored for non-SYN scan types\n");
    }

    const udp_base: u16 = src_port;
    const udp_span: u16 = @intCast(@min(@as(u32, default_udp_src_span), 65536 - @as(u32, udp_base)));
    const proto_json: []const u8 = if (is_udp) "udp" else "tcp";
    const probe_label: []const u8 = if (is_udp) "UDP" else "SYN";

    const ports = if (netutil.getFlag(args, "--ports")) |p|
        try netutil.parsePorts(allocator, p)
    else if (is_udp)
        try allocator.dupe(u16, &default_udp_ports)
    else
        try allocator.dupe(u16, &default_tcp_ports);
    const gw_mac = if (netutil.getFlag(args, "--gw-mac")) |m| try netutil.parseMac(m) else [_]u8{0} ** 6;
    const src_ip = if (netutil.getFlag(args, "--src-ip")) |s| try netutil.parseIpv4(s) else try netutil.resolveSrcIp(ifname);
    const src_mac = try netutil.resolveSrcMac(ifname);

    const choice = output.parseColorChoice(netutil.getFlag(args, "--color"));
    const out_level = output.envLevel(io, std.Io.File.stdout(), env, choice);
    const err_level = output.envLevel(io, std.Io.File.stderr(), env, choice);
    const stderr_tty = std.Io.File.stderr().isTty(io) catch false;
    const wide_enough = if (terminalCols(2)) |c| c >= min_dashboard_cols else true;
    const interactive = stderr_tty and wide_enough;

    var seed: u64 = undefined;
    if (netutil.getFlag(args, "--seed")) |s| {
        seed = try std.fmt.parseInt(u64, s, 10);
    } else {
        var seed_bytes: [8]u8 = undefined;
        try io.randomSecure(&seed_bytes);
        seed = std.mem.readInt(u64, &seed_bytes, .little);
    }

    const cidr = try targets.parseCidr(target_text);
    var eng = try targets.Engine.init(allocator, &.{cidr}, ports, seed);
    defer eng.deinit();
    const count = if (netutil.getFlag(args, "--count")) |c| try std.fmt.parseInt(u64, c, 10) else eng.total;
    const frames_per_probe: u64 = if (is_udp) 1 else 1 + @as(u64, @intCast(scfg.decoys.len));
    const dash_total = @min(count, eng.total) *| frames_per_probe;

    const ck = try cookie.Cookie.random(io);
    const rot_span: u16 = if (scfg.rotate) @intCast(@min(@as(u32, scfg.rotate_span), 65536 - @as(u32, src_port))) else 0;
    const tcp_tmpl = template.SynTemplate.init(.{
        .src_mac = src_mac,
        .dst_mac = gw_mac,
        .src_ip = src_ip,
        .src_port = src_port,
        .cookie = ck,
        .profile = scfg.profile,
        .scan = scfg.scan,
        .rotate = scfg.rotate,
        .rotate_base = src_port,
        .rotate_span = rot_span,
        .decoys = scfg.decoys,
    });
    const udp_tmpl = udp.UdpTemplate.init(.{
        .src_mac = src_mac,
        .dst_mac = gw_mac,
        .src_ip = src_ip,
        .src_port_base = udp_base,
        .src_port_span = udp_span,
        .cookie = ck,
    });
    var bucket = ratelimit.TokenBucket.init(rate, rate);
    if (scfg.jitter) bucket = bucket.withJitter(seed);

    var backend = packet_io.select(allocator, ifname, backend_choice, .{}, .{}, derr) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try derr.writeAll(need_cap_hint);
            try derr.flush();
            return;
        },
        error.XdpNotCompiledIn => {
            try derr.writeAll("scan: --backend xdp needs a build with -Dxdp\n");
            try derr.flush();
            return;
        },
        else => return err,
    };
    defer backend.close();
    try derr.print("  using {s}\n", .{packet_io.kindLabel(backend.kind())});

    if (scfg.profile != .none or scfg.scan != .syn or scfg.jitter or scfg.rotate or scfg.decoys.len > 0) {
        try derr.print("  stealth: template={s} scan={s} jitter={s} rotate={s} decoys={d}\n", .{
            @tagName(scfg.profile),
            @tagName(scfg.scan),
            if (scfg.jitter) "on" else "off",
            if (scfg.rotate) "on" else "off",
            scfg.decoys.len,
        });
    }

    var supp: ?stealth.RstSuppressor = null;
    if ((scfg.suppress_rst or banners) and !is_udp) {
        const lo = src_port;
        const hi = if (scfg.rotate) src_port +| (rot_span -| 1) else src_port;
        supp = stealth.RstSuppressor.install(allocator, io, src_ip, lo, hi) catch |e| blk: {
            try derr.print("  note: RST-suppression unavailable ({s})", .{@errorName(e)});
            if (banners) try derr.writeAll("; banner grabs may be unreliable (the kernel RSTs the SYN-ACK)");
            try derr.writeByte('\n');
            break :blk null;
        };
    }
    defer if (supp) |*s| s.teardown();
    if (supp) |*s| {
        var hbuf: [160]u8 = undefined;
        try derr.print("  RST-suppression active (cleanup if hard-killed: {s})\n", .{s.cleanupHint(&hbuf)});
    }

    var tx_done = std.atomic.Value(bool).init(false);
    var rx_done = std.atomic.Value(bool).init(false);

    const drain_window_ns: u64 = @as(u64, @intCast(@max(wait_ms, 0))) * ns_per_ms;
    const est_tx_ns: u64 = if (rate > 0) (dash_total / rate) *| ns_per_sec else rx_hard_cap_floor_ns;
    const tx_budget_ns: u64 = (est_tx_ns *| 4) +| rx_hard_cap_floor_ns;
    const hard_cap_ns: u64 = tx_budget_ns +| drain_window_ns;

    const banner_wait_ns: u64 = service.default_banner_wait_ns;
    const svc_drain_window_ns: u64 = @max(drain_window_ns, banner_wait_ns +| ns_per_sec);
    const svc_hard_cap_ns: u64 = tx_budget_ns +| svc_drain_window_ns;

    var banners_active = banners;
    var svc_socket: service.Socket = undefined;
    var svc_socket_open = false;
    var svc_engine: ?*service.Engine = null;
    if (banners_active) {
        if (service.Socket.open(ifname)) |s| {
            svc_socket = s;
            svc_socket_open = true;
            errdefer svc_socket.close();
            const svc_eng = try allocator.create(service.Engine);
            svc_eng.* = service.Engine.init(.{
                .cookie = ck,
                .our_ip = src_ip,
                .src_mac = src_mac,
                .gw_mac = gw_mac,
                .banner_wait_ns = banner_wait_ns,
            });
            svc_engine = svc_eng;
        } else |e| {
            try derr.print("  note: banner engine socket unavailable ({s}); continuing port-scan only\n", .{@errorName(e)});
            banners_active = false;
        }
    }
    defer if (svc_socket_open) svc_socket.close();

    var fqbuf: [finding_queue_capacity]service.Finding = undefined;
    var finding_queue = std.Io.Queue(service.Finding).init(&fqbuf);
    var finding_sink = FindingSink{ .queue = &finding_queue, .io = io };
    var svc_done = std.atomic.Value(bool).init(true);
    var findings: std.ArrayList(service.Finding) = .empty;
    var fdedup = try dedup.Dedup.init(allocator, dedup_capacity);
    defer fdedup.deinit();

    var receiver = rx.Receiver.open(ifname, rx.ETH_P_IP, &tx_done, drain_window_ns, hard_cap_ns) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try derr.writeAll(need_cap_hint);
            try derr.flush();
            return;
        },
        else => return err,
    };
    defer receiver.close();

    var dd = try dedup.Dedup.init(allocator, dedup_capacity);
    defer dd.deinit();

    var qbuf: [queue_capacity]rx.Result = undefined;
    var queue = std.Io.Queue(rx.Result).init(&qbuf);

    var found_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer found_arena.deinit();
    const found_alloc = found_arena.allocator();
    var found: std.ArrayList(rx.Result) = .empty;

    var stats: output.Stats = .{};
    const json_out: ?*std.Io.Writer = if (json) out else null;

    try derr.print("zingela  {s} scan  target {s}  iface {s}  rate {d} pps  ports {d}\n", .{ probe_label, target_text, ifname, rate, ports.len });
    try derr.flush();

    var clock = netutil.RealClock{};
    const t0 = clock.now();

    var tx_sink = TxSink{ .backend = &backend, .sent = &stats.sent.v };
    var rx_sink = rx.QueueSink{ .queue = &queue, .io = io };

    const tx_res = if (is_udp)
        io.concurrent(txWorkerUdp, .{ &eng, &udp_tmpl, &bucket, &tx_sink, count, tx_budget_ns, &tx_done })
    else
        io.concurrent(txWorkerTcp, .{ &eng, &tcp_tmpl, &bucket, &tx_sink, count, tx_budget_ns, &tx_done });
    var tx_fut = tx_res catch {
        try derr.writeAll(concurrency_hint);
        try derr.flush();
        return;
    };
    const rx_res = if (is_udp)
        io.concurrent(rxWorkerUdp, .{ &receiver, ck, udp_base, udp_span, &dd, &rx_sink, &rx_done })
    else
        io.concurrent(rxWorkerTcp, .{ &receiver, rx.TcpClassifier{ .ck = ck, .scan = scfg.scan }, &dd, &rx_sink, &rx_done });
    var rx_fut = rx_res catch {
        _ = tx_fut.await(io);
        try derr.writeAll(concurrency_hint);
        try derr.flush();
        return;
    };

    const SvcFuture = @typeInfo(@TypeOf(io.concurrent(svcWorker, .{
        svc_engine orelse undefined, &svc_socket, finding_sink.sink(), &tx_done, svc_drain_window_ns, svc_hard_cap_ns, &svc_done,
    }))).error_union.payload;
    var svc_fut: ?SvcFuture = null;
    if (banners_active) {
        svc_done.store(false, .release);
        if (io.concurrent(svcWorker, .{
            svc_engine.?, &svc_socket, finding_sink.sink(), &tx_done, svc_drain_window_ns, svc_hard_cap_ns, &svc_done,
        })) |f| {
            svc_fut = f;
        } else |_| {
            svc_done.store(true, .release);
            banners_active = false;
            try derr.writeAll("  note: banner engine could not launch a worker thread; continuing port-scan only\n");
        }
    }

    var dash = output.Dashboard.init(err_level, interactive, dash_total);
    dash.banners_mode = banners_active;
    const render_interval_ns: u64 = if (interactive) render_tick_interactive_ns else render_tick_plain_ns;
    var drain_buf: [drain_batch]rx.Result = undefined;
    var finding_buf: [finding_drain_batch]service.Finding = undefined;
    var last_render: u64 = 0;

    while (!(tx_done.load(.acquire) and rx_done.load(.acquire) and svc_done.load(.acquire))) {
        drainQueue(io, &queue, drain_buf[0..], &found, found_alloc, &stats, json_out, proto_json);
        if (banners_active) {
            drainFindings(io, &finding_queue, finding_buf[0..], &findings, &fdedup, found_alloc, json_out);
            stats.banners.v.store(svc_engine.?.banners.load(.monotonic), .monotonic);
        }
        if (json) out.flush() catch {};
        const now = clock.now();
        if (last_render == 0 or now -| last_render >= render_interval_ns) {
            dash.render(derr, &stats, now -| t0) catch {};
            last_render = now;
        }
        clock.sleepNs(drain_tick_ns);
    }

    const sent = tx_fut.await(io);
    rx_fut.await(io);
    if (svc_fut) |*f| f.await(io);
    queue.close(io);
    drainQueue(io, &queue, drain_buf[0..], &found, found_alloc, &stats, json_out, proto_json);
    if (banners_active) {
        finding_queue.close(io);
        drainFindings(io, &finding_queue, finding_buf[0..], &findings, &fdedup, found_alloc, json_out);
        stats.banners.v.store(svc_engine.?.banners.load(.monotonic), .monotonic);
    }
    if (json) out.flush() catch {};

    dash.render(derr, &stats, clock.now() -| t0) catch {};

    var open_n: u64 = 0;
    var closed_n: u64 = 0;
    var filtered_n: u64 = 0;
    var unfiltered_n: u64 = 0;
    for (found.items) |r| switch (r.state) {
        .open => open_n += 1,
        .closed => closed_n += 1,
        .filtered => filtered_n += 1,
        .unfiltered => unfiltered_n += 1,
    };

    if (!json) {
        if (found.items.len > 0) {
            std.mem.sort(rx.Result, found.items, {}, output.ipPortLess);
            try out.writeByte('\n');
            try output.renderTable(out, out_level, found.items);
            try out.flush();
        } else {
            try derr.writeAll("  no open, closed, or filtered responses observed\n");
            if (sent > 0) try derr.writeAll("  (if a cloud/VM hypervisor is filtering raw sends upstream, retry with --connect)\n");
        }
        if (findings.items.len > 0) {
            std.mem.sort(service.Finding, findings.items, {}, findingLess);
            try out.writeByte('\n');
            try renderServiceTable(out, out_level, found_alloc, findings.items);
            try out.flush();
        }
    }

    const elapsed_s = @as(f64, @floatFromInt(clock.now() - t0)) / @as(f64, @floatFromInt(ns_per_sec));
    try derr.writeByte('\n');
    try output.renderSummary(derr, err_level, sent, probe_label, ifname, elapsed_s, open_n, closed_n, filtered_n, unfiltered_n, stats.banners.v.load(.monotonic));
    if (banners_active) {
        const drops = svc_engine.?.drops.load(.monotonic);
        if (drops > 0) try derr.print("  note: {d} banner connection(s) dropped under backpressure (conn-table full at {d})\n", .{ drops, service.default_capacity });
    }
    if (is_udp) {
        const answered = open_n + closed_n + filtered_n + unfiltered_n;
        try output.renderUnanswered(derr, err_level, sent -| answered);
    }
    try derr.flush();
}
