// ©AngelaMos | 2026
// ndp.zig

const std = @import("std");
const linux = std.os.linux;
const packet = @import("packet");

const ETH_P_ALL: u16 = 0x0003;
const ethertype_ipv6: u16 = 0x86dd;
const ip6_version_tc_flow: u32 = 0x60000000;
const ip6_next_icmpv6: u8 = 58;
const ndp_hop_limit: u8 = 255;

const icmp6_ns: u8 = 135;
const icmp6_na: u8 = 136;
const opt_src_lladdr: u8 = 1;

const eth_len: usize = 14;
const ip6_len: usize = 40;
const ns_len: usize = 24;
const opt_len: usize = 8;
pub const solicit_frame_len: usize = eth_len + ip6_len + ns_len + opt_len;

const icmp6_off: usize = eth_len + ip6_len;
const na_target_off: usize = icmp6_off + 8;

const NS_PER_MS: u64 = 1_000_000;
const NS_PER_SEC: u64 = 1_000_000_000;

fn solicitedNodeMulticast(target: [16]u8) [16]u8 {
    return [16]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, target[13], target[14], target[15] };
}

fn multicastMac(target: [16]u8) [6]u8 {
    return [6]u8{ 0x33, 0x33, 0xff, target[13], target[14], target[15] };
}

pub fn buildSolicit(our_ip6: [16]u8, our_mac: [6]u8, target: [16]u8) [solicit_frame_len]u8 {
    var frame = [_]u8{0} ** solicit_frame_len;
    const mcast = solicitedNodeMulticast(target);

    const eth = packet.EthHdr{
        .dst = multicastMac(target),
        .src = our_mac,
        .ethertype = std.mem.nativeToBig(u16, ethertype_ipv6),
    };
    @memcpy(frame[0..eth_len], std.mem.asBytes(&eth));

    const ip6 = packet.Ipv6Hdr{
        .version_tc_flow = std.mem.nativeToBig(u32, ip6_version_tc_flow),
        .payload_len = std.mem.nativeToBig(u16, ns_len + opt_len),
        .next_header = ip6_next_icmpv6,
        .hop_limit = ndp_hop_limit,
        .src = our_ip6,
        .dst = mcast,
    };
    @memcpy(frame[eth_len .. eth_len + ip6_len], std.mem.asBytes(&ip6));

    frame[icmp6_off] = icmp6_ns;
    frame[icmp6_off + 1] = 0;
    @memcpy(frame[icmp6_off + 8 .. icmp6_off + 24], &target);
    frame[icmp6_off + 24] = opt_src_lladdr;
    frame[icmp6_off + 25] = 1;
    @memcpy(frame[icmp6_off + 26 .. icmp6_off + 32], &our_mac);

    const ck = packet.pseudoChecksum6(our_ip6, mcast, ip6_next_icmpv6, frame[icmp6_off..]);
    std.mem.writeInt(u16, frame[icmp6_off + 2 ..][0..2], ck, .big);
    return frame;
}

pub fn matchNa(frame: []const u8, target: [16]u8) ?[6]u8 {
    if (frame.len < eth_len + ip6_len + 24) return null;
    if (std.mem.readInt(u16, frame[12..14], .big) != ethertype_ipv6) return null;
    if (frame[eth_len + 6] != ip6_next_icmpv6) return null;
    if (frame[eth_len + 7] != ndp_hop_limit) return null;
    if (frame[icmp6_off] != icmp6_na) return null;
    if (frame[icmp6_off + 1] != 0) return null;
    if (target[0] == 0xff) return null;
    if (!std.mem.eql(u8, frame[na_target_off .. na_target_off + 16], &target)) return null;
    return frame[6..12].*;
}

const OpenError = error{ NeedCapNetRaw, Failed };

fn openBound(ifname: []const u8) OpenError!struct { fd: i32, sll: linux.sockaddr.ll } {
    const rc_sock = linux.socket(linux.AF.PACKET, linux.SOCK.RAW, std.mem.nativeToBig(u16, ETH_P_ALL));
    switch (linux.errno(rc_sock)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NeedCapNetRaw,
        else => return error.Failed,
    }
    const fd: i32 = @intCast(rc_sock);
    errdefer _ = linux.close(fd);

    var ifr = std.mem.zeroes(linux.ifreq);
    if (ifname.len >= ifr.ifrn.name.len) return error.Failed;
    @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&ifr))) != .SUCCESS) return error.Failed;

    var sll = std.mem.zeroes(linux.sockaddr.ll);
    sll.family = linux.AF.PACKET;
    sll.protocol = std.mem.nativeToBig(u16, ETH_P_ALL);
    sll.ifindex = ifr.ifru.ivalue;
    if (linux.errno(linux.bind(fd, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll))) != .SUCCESS) return error.Failed;
    return .{ .fd = fd, .sll = sll };
}

fn monoMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), NS_PER_MS);
}

pub const ResolveError = error{ NeedCapNetRaw, SocketFailed, NoNeighbor };

pub fn resolve(ifname: []const u8, our_ip6: [16]u8, our_mac: [6]u8, target: [16]u8, timeout_ms: i64) ResolveError![6]u8 {
    const s = openBound(ifname) catch |e| return switch (e) {
        error.NeedCapNetRaw => error.NeedCapNetRaw,
        error.Failed => error.SocketFailed,
    };
    defer _ = linux.close(s.fd);
    var sll = s.sll;

    const frame = buildSolicit(our_ip6, our_mac, target);
    var send_round: usize = 0;
    while (send_round < 3) : (send_round += 1) {
        _ = linux.sendto(s.fd, &frame, frame.len, 0, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll));
    }

    var buf: [2048]u8 = undefined;
    const deadline = monoMs() + timeout_ms;
    while (monoMs() < deadline) {
        var pfd = [_]linux.pollfd{.{ .fd = s.fd, .events = linux.POLL.IN, .revents = 0 }};
        const pr = linux.poll(&pfd, 1, 50);
        switch (linux.errno(pr)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.NoNeighbor,
        }
        if (pr == 0) continue;
        const rc = linux.recvfrom(s.fd, &buf, buf.len, 0, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN => continue,
            else => return error.NoNeighbor,
        }
        const n: usize = @intCast(rc);
        if (matchNa(buf[0..n], target)) |mac| return mac;
    }
    return error.NoNeighbor;
}

// ---- tests ----

const k_our_ip6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
const k_our_mac = [6]u8{ 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01 };
const k_target = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x22, 0x33 };

test "solicited-node multicast + MAC derive from the target's low 24 bits" {
    try std.testing.expectEqual([16]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x11, 0x22, 0x33 }, solicitedNodeMulticast(k_target));
    try std.testing.expectEqual([6]u8{ 0x33, 0x33, 0xff, 0x11, 0x22, 0x33 }, multicastMac(k_target));
}

test "buildSolicit produces a hop-limit-255 NS with a self-verifying ICMPv6 checksum" {
    const f = buildSolicit(k_our_ip6, k_our_mac, k_target);
    try std.testing.expectEqual(@as(usize, 86), f.len);
    try std.testing.expectEqual(@as(u16, ethertype_ipv6), std.mem.readInt(u16, f[12..14], .big));
    try std.testing.expectEqualSlices(u8, &multicastMac(k_target), f[0..6]);
    try std.testing.expectEqual(ndp_hop_limit, f[eth_len + 7]);
    try std.testing.expectEqual(icmp6_ns, f[icmp6_off]);
    try std.testing.expectEqualSlices(u8, &k_target, f[icmp6_off + 8 .. icmp6_off + 24]);
    try std.testing.expectEqualSlices(u8, &k_our_mac, f[icmp6_off + 26 .. icmp6_off + 32]);
    const mcast = solicitedNodeMulticast(k_target);
    try std.testing.expectEqual(@as(u16, 0), packet.pseudoChecksum6(k_our_ip6, mcast, ip6_next_icmpv6, f[icmp6_off..]));
}

test "matchNa returns the neighbor MAC for a matching advertisement and rejects mismatches" {
    const neighbor_mac = [6]u8{ 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    var na = [_]u8{0} ** 78;
    @memcpy(na[6..12], &neighbor_mac);
    std.mem.writeInt(u16, na[12..14], ethertype_ipv6, .big);
    na[eth_len + 6] = ip6_next_icmpv6;
    na[eth_len + 7] = ndp_hop_limit;
    na[icmp6_off] = icmp6_na;
    @memcpy(na[na_target_off .. na_target_off + 16], &k_target);
    try std.testing.expectEqual(neighbor_mac, matchNa(&na, k_target).?);

    var low_hop = na;
    low_hop[eth_len + 7] = 64;
    try std.testing.expect(matchNa(&low_hop, k_target) == null);

    var wrong = k_target;
    wrong[15] = 0x99;
    try std.testing.expect(matchNa(&na, wrong) == null);

    na[icmp6_off] = icmp6_ns;
    try std.testing.expect(matchNa(&na, k_target) == null);
}
