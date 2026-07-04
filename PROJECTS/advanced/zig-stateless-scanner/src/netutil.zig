// ©AngelaMos | 2026
// netutil.zig

const std = @import("std");
const linux = std.os.linux;

pub fn getFlag(args: []const []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], name)) return args[i + 1];
    }
    return null;
}

pub fn hasFlag(args: []const []const u8, name: []const u8) bool {
    for (args) |a| {
        if (std.mem.eql(u8, a, name)) return true;
    }
    return false;
}

pub fn parseIpv4(text: []const u8) !u32 {
    var addr: u32 = 0;
    var octets: usize = 0;
    var it = std.mem.splitScalar(u8, text, '.');
    while (it.next()) |part| {
        if (octets == 4) return error.InvalidIpv4;
        const octet = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpv4;
        addr = (addr << 8) | octet;
        octets += 1;
    }
    if (octets != 4) return error.InvalidIpv4;
    return addr;
}

fn parseV6Groups(text: []const u8, out: *[8]u16) !usize {
    if (text.len == 0) return 0;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, text, ':');
    while (it.next()) |part| {
        if (n >= 8) return error.InvalidIpv6;
        if (part.len == 0 or part.len > 4) return error.InvalidIpv6;
        for (part) |c| if (!std.ascii.isHex(c)) return error.InvalidIpv6;
        out[n] = std.fmt.parseInt(u16, part, 16) catch return error.InvalidIpv6;
        n += 1;
    }
    return n;
}

pub fn parseIpv6(text: []const u8) ![16]u8 {
    if (text.len == 0 or text.len > 45) return error.InvalidIpv6;
    var out = [_]u8{0} ** 16;

    if (std.mem.indexOf(u8, text, "::")) |pos| {
        if (std.mem.indexOf(u8, text[pos + 2 ..], "::") != null) return error.InvalidIpv6;
        var left: [8]u16 = undefined;
        var right: [8]u16 = undefined;
        const ln = try parseV6Groups(text[0..pos], &left);
        const rn = try parseV6Groups(text[pos + 2 ..], &right);
        if (ln + rn > 7) return error.InvalidIpv6;
        for (0..ln) |i| std.mem.writeInt(u16, out[i * 2 ..][0..2], left[i], .big);
        for (0..rn) |i| std.mem.writeInt(u16, out[(8 - rn + i) * 2 ..][0..2], right[i], .big);
        return out;
    }

    var groups: [8]u16 = undefined;
    const n = try parseV6Groups(text, &groups);
    if (n != 8) return error.InvalidIpv6;
    for (0..8) |i| std.mem.writeInt(u16, out[i * 2 ..][0..2], groups[i], .big);
    return out;
}

pub fn parseMac(text: []const u8) ![6]u8 {
    var mac: [6]u8 = undefined;
    var octets: usize = 0;
    var it = std.mem.splitScalar(u8, text, ':');
    while (it.next()) |part| {
        if (octets == 6) return error.InvalidMac;
        mac[octets] = std.fmt.parseInt(u8, part, 16) catch return error.InvalidMac;
        octets += 1;
    }
    if (octets != 6) return error.InvalidMac;
    return mac;
}

pub fn parsePorts(allocator: std.mem.Allocator, text: []const u8) ![]u16 {
    var list: std.ArrayList(u16) = .empty;
    errdefer list.deinit(allocator);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        const port = std.fmt.parseInt(u16, part, 10) catch return error.InvalidPort;
        try list.append(allocator, port);
    }
    if (list.items.len == 0) return error.InvalidPort;
    return list.toOwnedSlice(allocator);
}

fn ifaceQuery(ifname: []const u8, request: u32) !linux.sockaddr {
    const rc_sock = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    if (linux.errno(rc_sock) != .SUCCESS) return error.ResolveSocketFailed;
    const fd: i32 = @intCast(rc_sock);
    defer _ = linux.close(fd);

    var ifr = std.mem.zeroes(linux.ifreq);
    if (ifname.len >= ifr.ifrn.name.len) return error.IfNameTooLong;
    @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
    if (linux.errno(linux.ioctl(fd, request, @intFromPtr(&ifr))) != .SUCCESS) return error.IfQueryFailed;
    return ifr.ifru.addr;
}

pub fn resolveSrcIp(ifname: []const u8) !u32 {
    const sa = try ifaceQuery(ifname, linux.SIOCGIFADDR);
    return std.mem.readInt(u32, sa.data[2..6], .big);
}

pub fn resolveSrcMac(ifname: []const u8) ![6]u8 {
    const sa = try ifaceQuery(ifname, linux.SIOCGIFHWADDR);
    return sa.data[0..6].*;
}

fn parseIfInet6(contents: []const u8, ifname: []const u8) ?[16]u8 {
    var fallback: ?[16]u8 = null;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeAny(u8, line, " \t");
        const addr_hex = it.next() orelse continue;
        _ = it.next() orelse continue;
        _ = it.next() orelse continue;
        const scope = it.next() orelse continue;
        _ = it.next() orelse continue;
        const dev = it.next() orelse continue;
        if (!std.mem.eql(u8, dev, ifname)) continue;
        if (addr_hex.len != 32) continue;
        var addr: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&addr, addr_hex) catch continue;
        if (std.mem.eql(u8, scope, "00")) return addr;
        if (fallback == null) fallback = addr;
    }
    return fallback;
}

pub fn resolveSrcIp6(ifname: []const u8) ![16]u8 {
    const rc = linux.openat(linux.AT.FDCWD, "/proc/net/if_inet6", .{}, 0);
    if (linux.errno(rc) != .SUCCESS) return error.NoV6Address;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    var buf: [16384]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n_rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        switch (linux.errno(n_rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.NoV6Address,
        }
        const n: usize = @intCast(n_rc);
        if (n == 0) break;
        total += n;
    }
    return parseIfInet6(buf[0..total], ifname) orelse error.NoV6Address;
}

fn parseIpv6Route(contents: []const u8, ifname: []const u8) ?[16]u8 {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeAny(u8, line, " \t");
        const dest = it.next() orelse continue;
        const dest_plen = it.next() orelse continue;
        _ = it.next() orelse continue;
        _ = it.next() orelse continue;
        const nexthop = it.next() orelse continue;
        var i: usize = 0;
        while (i < 4) : (i += 1) _ = it.next() orelse break;
        const dev = it.next() orelse continue;
        if (!std.mem.eql(u8, dev, ifname)) continue;
        if (!std.mem.eql(u8, dest_plen, "00")) continue;
        if (dest.len != 32 or nexthop.len != 32) continue;
        var addr: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&addr, nexthop) catch continue;
        if (std.mem.allEqual(u8, &addr, 0)) continue;
        return addr;
    }
    return null;
}

pub fn defaultGateway6(ifname: []const u8) ?[16]u8 {
    const rc = linux.openat(linux.AT.FDCWD, "/proc/net/ipv6_route", .{}, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var buf: [65536]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n_rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        switch (linux.errno(n_rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return null,
        }
        const n: usize = @intCast(n_rc);
        if (n == 0) break;
        total += n;
    }
    return parseIpv6Route(buf[0..total], ifname);
}

pub const RealClock = struct {
    pub fn now(_: *RealClock) u64 {
        var ts: linux.timespec = undefined;
        _ = linux.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
    }
    pub fn sleepNs(_: *RealClock, ns: u64) void {
        const ts = linux.timespec{
            .sec = @intCast(ns / 1_000_000_000),
            .nsec = @intCast(ns % 1_000_000_000),
        };
        _ = linux.nanosleep(&ts, null);
    }
};

test "parseIpv4 round-trips dotted quads" {
    try std.testing.expectEqual(@as(u32, 0x7f000001), try parseIpv4("127.0.0.1"));
    try std.testing.expectEqual(@as(u32, 0x08080808), try parseIpv4("8.8.8.8"));
    try std.testing.expectError(error.InvalidIpv4, parseIpv4("1.2.3"));
    try std.testing.expectError(error.InvalidIpv4, parseIpv4("256.0.0.1"));
}

test "parseIpv6 handles compression, full form, and edge positions" {
    try std.testing.expectEqual([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, try parseIpv6("::1"));
    try std.testing.expectEqual([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, try parseIpv6("::"));
    try std.testing.expectEqual([16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, try parseIpv6("fe80::"));
    const a = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqual(a, try parseIpv6("2001:db8::1"));
    try std.testing.expectEqual(a, try parseIpv6("2001:db8:0:0:0:0:0:1"));
    try std.testing.expectEqual(a, try parseIpv6("2001:0db8:0000:0000:0000:0000:0000:0001"));
    try std.testing.expectEqual([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, try parseIpv6("2001:db8:1::1"));
    try std.testing.expectEqual([16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0, 1 }, try parseIpv6("::ffff:c0a8:1"));
}

test "parseIpv6 rejects malformed literals" {
    try std.testing.expectError(error.InvalidIpv6, parseIpv6(""));
    try std.testing.expectError(error.InvalidIpv6, parseIpv6("1:2:3"));
    try std.testing.expectError(error.InvalidIpv6, parseIpv6(":1"));
    try std.testing.expectError(error.InvalidIpv6, parseIpv6("1::2::3"));
    try std.testing.expectError(error.InvalidIpv6, parseIpv6("gggg::"));
    try std.testing.expectError(error.InvalidIpv6, parseIpv6("1:2:3:4:5:6:7:8:9"));
    try std.testing.expectError(error.InvalidIpv6, parseIpv6("12345::"));
    try std.testing.expectError(error.InvalidIpv6, parseIpv6("2001:+db8::1"));
    try std.testing.expectError(error.InvalidIpv6, parseIpv6("2001:d_b8::1"));
}

test "parseIfInet6 prefers a global-scope address and falls back to link-local" {
    const contents =
        "fe80000000000000e81e99fffeae865d 1b245 40 20 80 veth0\n" ++
        "20010db8000000000000000000000001 1b245 40 00 80 veth0\n" ++
        "00000000000000000000000000000001 00001 80 10 80 lo\n";
    const g = parseIfInet6(contents, "veth0").?;
    try std.testing.expectEqual([16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, g);

    const only_ll = "fe80000000000000e81e99fffeae865d 1b245 40 20 80 eth9\n";
    const ll = parseIfInet6(only_ll, "eth9").?;
    try std.testing.expectEqual(@as(u8, 0xfe), ll[0]);
    try std.testing.expectEqual(@as(u8, 0x80), ll[1]);

    try std.testing.expect(parseIfInet6(contents, "eth0") == null);
}

test "parseIpv6Route returns the default-route nexthop for the matching iface" {
    const contents =
        "20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 veth0\n" ++
        "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 veth0\n";
    const gw = parseIpv6Route(contents, "veth0").?;
    try std.testing.expectEqual([16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, gw);
    try std.testing.expect(parseIpv6Route(contents, "eth9") == null);
}

test "parseMac parses colon-separated hex" {
    try std.testing.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, try parseMac("aa:bb:cc:dd:ee:ff"));
    try std.testing.expectEqual([_]u8{0} ** 6, try parseMac("00:00:00:00:00:00"));
    try std.testing.expectError(error.InvalidMac, parseMac("aa:bb:cc"));
}

test "parsePorts parses a comma list and rejects empty" {
    const ports = try parsePorts(std.testing.allocator, "80,443,22");
    defer std.testing.allocator.free(ports);
    try std.testing.expectEqualSlices(u16, &.{ 80, 443, 22 }, ports);
    try std.testing.expectError(error.InvalidPort, parsePorts(std.testing.allocator, ""));
}

test "getFlag finds values and tolerates missing" {
    const args = [_][]const u8{ "tx", "--iface", "eth0", "--rate", "5000" };
    try std.testing.expectEqualStrings("eth0", getFlag(&args, "--iface").?);
    try std.testing.expectEqualStrings("5000", getFlag(&args, "--rate").?);
    try std.testing.expect(getFlag(&args, "--target") == null);
}

test "hasFlag detects a valueless boolean flag in any position" {
    const args = [_][]const u8{ "scan", "--target", "10.0.0.0/24", "--json" };
    try std.testing.expect(hasFlag(&args, "--json"));
    try std.testing.expect(hasFlag(&args, "scan"));
    try std.testing.expect(!hasFlag(&args, "--nope"));
}
