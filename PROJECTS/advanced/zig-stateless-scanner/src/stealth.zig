// ©AngelaMos | 2026
// stealth.zig

const std = @import("std");
const linux = std.os.linux;
const packet = @import("packet");
const netutil = @import("netutil");

pub const default_rotate_span: u16 = 8192;
pub const max_decoys: usize = 16;
pub const random_ip_attempts: usize = 64;

const routable_fallback_ip: u32 = 0x01010101;

pub const ParseError = error{
    AuthorizationRequired,
    BadOsTemplate,
    BadScanType,
    BadJitterMode,
    BadDecoySpec,
    TooManyDecoys,
    OutOfMemory,
};

pub const RstError = error{
    IptablesSpawnFailed,
    IptablesFailed,
    OutOfMemory,
};

pub const Config = struct {
    authorized: bool = false,
    profile: packet.OsProfile = .none,
    scan: packet.ScanType = .syn,
    jitter: bool = false,
    rotate: bool = false,
    rotate_span: u16 = default_rotate_span,
    suppress_rst: bool = false,
    decoys: []const u32 = &.{},

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        if (self.decoys.len > 0) allocator.free(self.decoys);
        self.decoys = &.{};
    }
};

pub fn parse(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) ParseError!Config {
    const os_flag = netutil.getFlag(args, "--os-template");
    const scan_flag = netutil.getFlag(args, "--scan-type");
    const jitter_flag = netutil.getFlag(args, "--jitter");
    const rotate_flag = netutil.hasFlag(args, "--source-port-rotation");
    const decoy_flag = netutil.getFlag(args, "--decoys");
    const suppress_flag = netutil.hasFlag(args, "--suppress-rst");

    const requested = os_flag != null or scan_flag != null or jitter_flag != null or
        rotate_flag or decoy_flag != null or suppress_flag;

    if (!requested) return .{};
    if (!netutil.hasFlag(args, "--authorized-scan")) return error.AuthorizationRequired;

    var cfg = Config{ .authorized = true, .rotate = rotate_flag, .suppress_rst = suppress_flag };
    errdefer cfg.deinit(allocator);

    if (os_flag) |t| cfg.profile = packet.OsProfile.parse(t) orelse return error.BadOsTemplate;
    if (scan_flag) |t| cfg.scan = packet.ScanType.parse(t) orelse return error.BadScanType;
    if (jitter_flag) |t| {
        if (std.mem.eql(u8, t, "poisson")) {
            cfg.jitter = true;
        } else if (std.mem.eql(u8, t, "none")) {
            cfg.jitter = false;
        } else return error.BadJitterMode;
    }
    if (decoy_flag) |spec| cfg.decoys = try parseDecoys(allocator, io, spec);

    return cfg;
}

fn parseDecoys(allocator: std.mem.Allocator, io: std.Io, spec: []const u8) ParseError![]const u32 {
    var list: std.ArrayList(u32) = .empty;
    errdefer list.deinit(allocator);

    var it = std.mem.splitScalar(u8, spec, ',');
    while (it.next()) |tok| {
        if (tok.len == 0) continue;
        if (list.items.len >= max_decoys) return error.TooManyDecoys;
        if (std.mem.startsWith(u8, tok, "RND:")) {
            const n = std.fmt.parseInt(usize, tok[4..], 10) catch return error.BadDecoySpec;
            var made: usize = 0;
            while (made < n) : (made += 1) {
                if (list.items.len >= max_decoys) return error.TooManyDecoys;
                try list.append(allocator, randomNonBogon(io));
            }
        } else {
            const ip = netutil.parseIpv4(tok) catch return error.BadDecoySpec;
            try list.append(allocator, ip);
        }
    }
    if (list.items.len == 0) return error.BadDecoySpec;
    return list.toOwnedSlice(allocator);
}

fn randomNonBogon(io: std.Io) u32 {
    var attempts: usize = 0;
    while (attempts < random_ip_attempts) : (attempts += 1) {
        var b: [4]u8 = undefined;
        io.randomSecure(&b) catch continue;
        const ip = std.mem.readInt(u32, &b, .big);
        if (!isBogonV4(ip)) return ip;
    }
    return routable_fallback_ip;
}

fn inNet(ip: u32, net: u32, bits: u5) bool {
    const sh: u5 = @intCast(32 - @as(u32, bits));
    const mask: u32 = ~@as(u32, 0) << sh;
    return (ip & mask) == (net & mask);
}

pub fn isBogonV4(ip: u32) bool {
    if (ip >> 28 == 0xE) return true;
    if (ip >> 28 == 0xF) return true;
    return inNet(ip, 0x00000000, 8) or
        inNet(ip, 0x0A000000, 8) or
        inNet(ip, 0x64400000, 10) or
        inNet(ip, 0x7F000000, 8) or
        inNet(ip, 0xA9FE0000, 16) or
        inNet(ip, 0xAC100000, 12) or
        inNet(ip, 0xC0000000, 24) or
        inNet(ip, 0xC0000200, 24) or
        inNet(ip, 0xC0586300, 24) or
        inNet(ip, 0xC0A80000, 16) or
        inNet(ip, 0xC6120000, 15) or
        inNet(ip, 0xC6336400, 24) or
        inNet(ip, 0xCB007100, 24);
}

const pr_cap_ambient: i32 = 47;
const pr_cap_ambient_raise: usize = 2;
const cap_net_admin: usize = 12;

fn raiseAmbientNetAdmin() void {
    _ = linux.prctl(pr_cap_ambient, pr_cap_ambient_raise, cap_net_admin, 0, 0);
}

pub fn ipToStr(buf: *[15]u8, ip: u32) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff,
    }) catch unreachable;
}

pub const RstSuppressor = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    ip_str: []u8,
    range_str: []u8,
    installed: bool,

    pub fn install(allocator: std.mem.Allocator, io: std.Io, src_ip: u32, lo: u16, hi: u16) RstError!RstSuppressor {
        var ipbuf: [15]u8 = undefined;
        const ip_str = try allocator.dupe(u8, ipToStr(&ipbuf, src_ip));
        errdefer allocator.free(ip_str);
        const range_str = try std.fmt.allocPrint(allocator, "{d}:{d}", .{ lo, hi });
        errdefer allocator.free(range_str);

        var self = RstSuppressor{
            .allocator = allocator,
            .io = io,
            .ip_str = ip_str,
            .range_str = range_str,
            .installed = false,
        };

        raiseAmbientNetAdmin();
        self.runIptables("-D") catch {};
        try self.runIptables("-I");
        self.installed = true;
        return self;
    }

    fn runIptables(self: *RstSuppressor, action: []const u8) RstError!void {
        const args = [_][]const u8{
            "iptables",     action, "OUTPUT", "-p",  "tcp",
            "-s",           self.ip_str, "--sport", self.range_str,
            "--tcp-flags",  "RST",  "RST",    "-j",  "DROP",
        };
        const res = std.process.run(self.allocator, self.io, .{ .argv = &args }) catch return error.IptablesSpawnFailed;
        defer self.allocator.free(res.stdout);
        defer self.allocator.free(res.stderr);
        switch (res.term) {
            .exited => |code| if (code != 0) return error.IptablesFailed,
            else => return error.IptablesFailed,
        }
    }

    pub fn cleanupHint(self: *const RstSuppressor, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "iptables -D OUTPUT -p tcp -s {s} --sport {s} --tcp-flags RST RST -j DROP", .{ self.ip_str, self.range_str }) catch "";
    }

    pub fn teardown(self: *RstSuppressor) void {
        if (self.installed) {
            self.runIptables("-D") catch {};
            self.installed = false;
        }
        self.allocator.free(self.ip_str);
        self.allocator.free(self.range_str);
    }
};

pub const omitted_help =
    \\  deliberately omitted (obsolete in 2026; rationale + citations in learn/ + AUDIT-M8):
    \\    idle/zombie scan      modern OSes randomize IP-ID; the side channel is dead
    \\    fragmentation         Snort 3.x and Suricata fully reassemble before matching
    \\    TTL manipulation      inline IPS normalize TTL; FortiGuard ships a signature
    \\    MAC / source routing  L2-only or RFC 5095-deprecated; never crosses a hop
    \\    bad-checksum probe    a firewall-reveal recon trick, not evasion
;

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(std.testing.allocator, .{});
}

test "no stealth flags yields the inert default config" {
    var threaded = testIo();
    defer threaded.deinit();
    const args = [_][]const u8{ "scan", "--target", "10.0.0.0/24" };
    var cfg = try parse(std.testing.allocator, threaded.io(), &args);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expect(!cfg.authorized);
    try std.testing.expectEqual(packet.OsProfile.none, cfg.profile);
    try std.testing.expectEqual(packet.ScanType.syn, cfg.scan);
    try std.testing.expect(!cfg.jitter and !cfg.rotate and !cfg.suppress_rst);
}

test "any stealth flag without --authorized-scan is refused" {
    var threaded = testIo();
    defer threaded.deinit();
    inline for (.{
        &[_][]const u8{ "scan", "--os-template", "linux" },
        &[_][]const u8{ "scan", "--scan-type", "fin" },
        &[_][]const u8{ "scan", "--jitter", "poisson" },
        &[_][]const u8{ "scan", "--source-port-rotation" },
        &[_][]const u8{ "scan", "--decoys", "8.8.8.8" },
        &[_][]const u8{ "scan", "--suppress-rst" },
    }) |args| {
        try std.testing.expectError(error.AuthorizationRequired, parse(std.testing.allocator, threaded.io(), args));
    }
}

test "authorized stealth parses every knob" {
    var threaded = testIo();
    defer threaded.deinit();
    const args = [_][]const u8{
        "scan",         "--authorized-scan",   "--os-template", "windows",
        "--scan-type",  "ack",                 "--jitter",      "poisson",
        "--source-port-rotation", "--suppress-rst",
    };
    var cfg = try parse(std.testing.allocator, threaded.io(), &args);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expect(cfg.authorized);
    try std.testing.expectEqual(packet.OsProfile.windows, cfg.profile);
    try std.testing.expectEqual(packet.ScanType.ack, cfg.scan);
    try std.testing.expect(cfg.jitter and cfg.rotate and cfg.suppress_rst);
}

test "bad stealth values are rejected with distinct errors" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(error.BadOsTemplate, parse(std.testing.allocator, io, &[_][]const u8{ "scan", "--authorized-scan", "--os-template", "plan9" }));
    try std.testing.expectError(error.BadScanType, parse(std.testing.allocator, io, &[_][]const u8{ "scan", "--authorized-scan", "--scan-type", "banana" }));
    try std.testing.expectError(error.BadJitterMode, parse(std.testing.allocator, io, &[_][]const u8{ "scan", "--authorized-scan", "--jitter", "chaos" }));
    try std.testing.expectError(error.BadDecoySpec, parse(std.testing.allocator, io, &[_][]const u8{ "scan", "--authorized-scan", "--decoys", "999.1.1.1" }));
}

test "explicit decoys parse to their addresses" {
    var threaded = testIo();
    defer threaded.deinit();
    const args = [_][]const u8{ "scan", "--authorized-scan", "--decoys", "8.8.8.8,1.1.1.1" };
    var cfg = try parse(std.testing.allocator, threaded.io(), &args);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u32, &.{ 0x08080808, 0x01010101 }, cfg.decoys);
}

test "RND decoys are non-bogon and bounded" {
    var threaded = testIo();
    defer threaded.deinit();
    const args = [_][]const u8{ "scan", "--authorized-scan", "--decoys", "RND:8" };
    var cfg = try parse(std.testing.allocator, threaded.io(), &args);
    defer cfg.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 8), cfg.decoys.len);
    for (cfg.decoys) |ip| try std.testing.expect(!isBogonV4(ip));

    try std.testing.expectError(error.TooManyDecoys, parse(std.testing.allocator, threaded.io(), &[_][]const u8{ "scan", "--authorized-scan", "--decoys", "RND:99" }));
}

test "isBogonV4 flags reserved space and passes public addresses" {
    try std.testing.expect(isBogonV4(0x00000001));
    try std.testing.expect(isBogonV4(0x0A000001));
    try std.testing.expect(isBogonV4(0x7F000001));
    try std.testing.expect(isBogonV4(0xC0A80001));
    try std.testing.expect(isBogonV4(0xAC100001));
    try std.testing.expect(isBogonV4(0xA9FE0001));
    try std.testing.expect(isBogonV4(0x64400001));
    try std.testing.expect(isBogonV4(0xE0000001));
    try std.testing.expect(isBogonV4(0xFFFFFFFF));
    try std.testing.expect(isBogonV4(0xC0586301));
    try std.testing.expect(!isBogonV4(0x08080808));
    try std.testing.expect(!isBogonV4(0x01010101));
    try std.testing.expect(!isBogonV4(0x2D2D2D2D));
}

test "ipToStr renders dotted quads" {
    var buf: [15]u8 = undefined;
    try std.testing.expectEqualStrings("10.0.0.1", ipToStr(&buf, 0x0A000001));
    try std.testing.expectEqualStrings("255.255.255.255", ipToStr(&buf, 0xFFFFFFFF));
}

test "the RST cleanup hint is an exact iptables delete line" {
    var buf: [15]u8 = undefined;
    var rbuf: [16]u8 = undefined;
    const ip_str = std.testing.allocator.dupe(u8, ipToStr(&buf, 0x0A000001)) catch unreachable;
    defer std.testing.allocator.free(ip_str);
    const range_str = std.fmt.bufPrint(&rbuf, "{d}:{d}", .{ 40000, 48191 }) catch unreachable;
    const owned_range = std.testing.allocator.dupe(u8, range_str) catch unreachable;
    defer std.testing.allocator.free(owned_range);
    var supp = RstSuppressor{ .allocator = std.testing.allocator, .io = undefined, .ip_str = ip_str, .range_str = owned_range, .installed = false };
    var hintbuf: [128]u8 = undefined;
    const hint = supp.cleanupHint(&hintbuf);
    try std.testing.expect(std.mem.indexOf(u8, hint, "iptables -D OUTPUT") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, "10.0.0.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, "40000:48191") != null);
    try std.testing.expect(std.mem.indexOf(u8, hint, "--tcp-flags RST RST -j DROP") != null);
}
