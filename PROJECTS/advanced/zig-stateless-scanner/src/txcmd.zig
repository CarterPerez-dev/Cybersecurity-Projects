// ©AngelaMos | 2026
// txcmd.zig

const std = @import("std");
const targets = @import("targets");
const template = @import("template");
const ratelimit = @import("ratelimit");
const packet_io = @import("packet_io");
const cookie = @import("cookie");
const tx = @import("tx");
const netutil = @import("netutil");
const stealth = @import("stealth");

const authorized_warning =
    "tx: stealth/evasion features require --authorized-scan. Use ONLY on systems you\n" ++
    "own or are authorized to test; unauthorized scanning is a crime (CFAA et al.).\n\n" ++
    stealth.omitted_help ++ "\n";

const getFlag = netutil.getFlag;
const parseIpv4 = netutil.parseIpv4;
const parseMac = netutil.parseMac;
const parsePorts = netutil.parsePorts;
const resolveSrcIp = netutil.resolveSrcIp;
const resolveSrcMac = netutil.resolveSrcMac;
const RealClock = netutil.RealClock;

const default_iface = "lo";
const default_rate: u64 = 10_000;
const default_src_port: u16 = 40_000;
const default_ports = [_]u16{80};
const ns_per_sec: u64 = 1_000_000_000;
const tx_budget_floor_ns: u64 = 60 * ns_per_sec;

pub fn run(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;

    const target_text = getFlag(args, "--target") orelse {
        try out.writeAll("tx: --target <cidr> is required (e.g. --target 10.0.0.0/24)\n");
        try out.flush();
        return;
    };
    const ifname = getFlag(args, "--iface") orelse default_iface;
    const rate = if (getFlag(args, "--rate")) |r| try std.fmt.parseInt(u64, r, 10) else default_rate;
    const src_port = if (getFlag(args, "--src-port")) |p| try std.fmt.parseInt(u16, p, 10) else default_src_port;

    const ports = if (getFlag(args, "--ports")) |p| try parsePorts(allocator, p) else try allocator.dupe(u16, &default_ports);
    const gw_mac = if (getFlag(args, "--gw-mac")) |m| try parseMac(m) else [_]u8{0} ** 6;
    const src_ip = if (getFlag(args, "--src-ip")) |s| try parseIpv4(s) else try resolveSrcIp(ifname);
    const src_mac = try resolveSrcMac(ifname);

    var seed: u64 = undefined;
    if (getFlag(args, "--seed")) |s| {
        seed = try std.fmt.parseInt(u64, s, 10);
    } else {
        var seed_bytes: [8]u8 = undefined;
        try io.randomSecure(&seed_bytes);
        seed = std.mem.readInt(u64, &seed_bytes, .little);
    }

    var scfg = stealth.parse(allocator, io, args) catch |e| switch (e) {
        error.AuthorizationRequired => {
            try out.writeAll(authorized_warning);
            try out.flush();
            return;
        },
        error.OutOfMemory => return e,
        else => {
            try out.print("tx: invalid stealth flag ({s})\n", .{@errorName(e)});
            try out.flush();
            return;
        },
    };
    defer scfg.deinit(allocator);

    const cidr = try targets.parseCidr(target_text);
    var eng = try targets.Engine.init(allocator, &.{cidr}, ports, seed);
    defer eng.deinit();

    const count = if (getFlag(args, "--count")) |c| try std.fmt.parseInt(u64, c, 10) else eng.total;

    const ck = try cookie.Cookie.random(io);
    const rot_span: u16 = if (scfg.rotate) @intCast(@min(@as(u32, scfg.rotate_span), 65536 - @as(u32, src_port))) else 0;
    const tmpl = template.SynTemplate.init(.{
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
    var bucket = ratelimit.TokenBucket.init(rate, rate);
    if (scfg.jitter) bucket = bucket.withJitter(seed);

    const backend_choice = packet_io.parseChoice(getFlag(args, "--backend")) orelse {
        try out.writeAll("tx: --backend must be one of auto, xdp, afpacket\n");
        try out.flush();
        return;
    };
    var backend = packet_io.select(allocator, ifname, backend_choice, .{}, .{}, out) catch |err| switch (err) {
        error.NeedCapNetRaw => {
            try out.writeAll("tx: need CAP_NET_RAW + CAP_NET_ADMIN. Grant once, then re-run (no sudo):\n  sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela\nSkipping.\n");
            try out.flush();
            return;
        },
        error.XdpNotCompiledIn => {
            try out.writeAll("tx: --backend xdp needs a build with -Dxdp\n");
            try out.flush();
            return;
        },
        else => return err,
    };
    defer backend.close();
    try out.print("tx: using {s}\n", .{packet_io.kindLabel(backend.kind())});

    if (scfg.profile != .none or scfg.scan != .syn or scfg.jitter or scfg.rotate or scfg.decoys.len > 0) {
        try out.print("tx: stealth template={s} scan={s} jitter={s} rotate={s} decoys={d}\n", .{
            @tagName(scfg.profile),
            @tagName(scfg.scan),
            if (scfg.jitter) "on" else "off",
            if (scfg.rotate) "on" else "off",
            scfg.decoys.len,
        });
    }

    var supp: ?stealth.RstSuppressor = null;
    if (scfg.suppress_rst) {
        const lo = src_port;
        const hi = if (scfg.rotate) src_port +| (rot_span -| 1) else src_port;
        supp = stealth.RstSuppressor.install(allocator, io, src_ip, lo, hi) catch |e| blk: {
            try out.print("tx: RST-suppression unavailable ({s}); continuing without it\n", .{@errorName(e)});
            break :blk null;
        };
    }
    defer if (supp) |*s| s.teardown();

    var clock = RealClock{};
    const t0 = clock.now();
    const est_tx_ns: u64 = if (rate > 0) (count / rate) *| ns_per_sec else tx_budget_floor_ns;
    const deadline_ns = t0 +| (est_tx_ns *| 4) +| tx_budget_floor_ns;
    const sent = tx.run(&eng, &tmpl, &bucket, &backend, &clock, count, deadline_ns);
    const elapsed_ns = clock.now() - t0;

    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
    const pps = if (elapsed_s > 0) @as(f64, @floatFromInt(sent)) / elapsed_s else 0;
    try out.print("tx: sent {d} SYN frames on {s} in {d:.3}s ({d:.0} pps)\n", .{ sent, ifname, elapsed_s, pps });
    try out.flush();
}
