// ©AngelaMos | 2026
// template.zig

const std = @import("std");
const packet = @import("packet");
const cookie = @import("cookie");

const ethertype_ipv4: u16 = 0x0800;
const ipv4_version_ihl: u8 = 0x45;
const ip_proto_tcp: u8 = 6;
const ip_flag_dont_fragment: u16 = 0x4000;
const default_ttl: u8 = 64;
const ip_id_mix: u32 = 0x9e3779b1;

const eth_len: usize = 14;
const ip_len: usize = 20;
const tcp_len: usize = 20;
const l4_off: usize = eth_len + ip_len;
const opts_off: usize = l4_off + tcp_len;

const ip_id_off: usize = eth_len + 4;
const ip_checksum_off: usize = eth_len + 10;
const ip_src_off: usize = eth_len + 12;
const ip_dst_off: usize = eth_len + 16;
const tcp_src_off: usize = l4_off;
const tcp_dst_off: usize = l4_off + 2;
const tcp_seq_off: usize = l4_off + 4;
const tcp_ack_off: usize = l4_off + 8;
const tcp_data_off_off: usize = l4_off + 12;
const tcp_flags_off: usize = l4_off + 13;
const tcp_window_off: usize = l4_off + 14;
const tcp_checksum_off: usize = l4_off + 16;

pub const SynTemplate = struct {
    pub const max_frame_len: usize = opts_off + packet.max_syn_options_len;

    base: [max_frame_len]u8,
    frame_len: usize,
    src_ip: u32,
    src_ip_be: u32,
    src_port: u16,
    cookie: cookie.Cookie,
    scan: packet.ScanType,
    vary_ip_id: bool,
    rotate: bool,
    rotate_base: u16,
    rotate_span: u16,
    decoys: []const u32,

    pub const Config = struct {
        src_mac: [6]u8,
        dst_mac: [6]u8,
        src_ip: u32,
        src_port: u16,
        cookie: cookie.Cookie,
        profile: packet.OsProfile = .none,
        scan: packet.ScanType = .syn,
        rotate: bool = false,
        rotate_base: u16 = 0,
        rotate_span: u16 = 0,
        decoys: []const u32 = &.{},
    };

    pub fn init(cfg: Config) SynTemplate {
        const opts = cfg.profile.options();
        const tcp_total = tcp_len + opts.len;
        const data_off_words: u8 = @intCast(tcp_total / 4);

        var base: [max_frame_len]u8 = [_]u8{0} ** max_frame_len;

        const eth = packet.EthHdr{
            .dst = cfg.dst_mac,
            .src = cfg.src_mac,
            .ethertype = std.mem.nativeToBig(u16, ethertype_ipv4),
        };
        @memcpy(base[0..eth_len], std.mem.asBytes(&eth));

        const ip = packet.Ipv4Hdr{
            .version_ihl = ipv4_version_ihl,
            .tos = 0,
            .total_len = std.mem.nativeToBig(u16, @intCast(ip_len + tcp_total)),
            .id = 0,
            .flags_frag = std.mem.nativeToBig(u16, ip_flag_dont_fragment),
            .ttl = default_ttl,
            .protocol = ip_proto_tcp,
            .checksum = 0,
            .src = std.mem.nativeToBig(u32, cfg.src_ip),
            .dst = 0,
        };
        @memcpy(base[eth_len..l4_off], std.mem.asBytes(&ip));

        const tcp = packet.TcpHdr{
            .src_port = std.mem.nativeToBig(u16, cfg.src_port),
            .dst_port = 0,
            .seq = 0,
            .ack = 0,
            .data_off_ns = data_off_words << 4,
            .flags = cfg.scan.probeFlags(),
            .window = std.mem.nativeToBig(u16, cfg.profile.window()),
            .checksum = 0,
            .urgent = 0,
        };
        @memcpy(base[l4_off..opts_off], std.mem.asBytes(&tcp));

        if (opts.len > 0) @memcpy(base[opts_off .. opts_off + opts.len], opts);

        return .{
            .base = base,
            .frame_len = opts_off + opts.len,
            .src_ip = cfg.src_ip,
            .src_ip_be = std.mem.nativeToBig(u32, cfg.src_ip),
            .src_port = cfg.src_port,
            .cookie = cfg.cookie,
            .scan = cfg.scan,
            .vary_ip_id = cfg.profile.variesIpId(),
            .rotate = cfg.rotate,
            .rotate_base = cfg.rotate_base,
            .rotate_span = cfg.rotate_span,
            .decoys = cfg.decoys,
        };
    }

    pub fn variantCount(self: *const SynTemplate) usize {
        return 1 + self.decoys.len;
    }

    pub fn srcPortFor(self: *const SynTemplate, dst_ip: u32, dst_port: u16) u16 {
        return if (self.rotate)
            self.cookie.udpSrcPort(dst_ip, dst_port, self.src_ip, self.rotate_base, self.rotate_span)
        else
            self.src_port;
    }

    pub fn stamp(self: *const SynTemplate, out: *[max_frame_len]u8, dst_ip: u32, dst_port: u16) usize {
        const n = self.frame_len;
        @memcpy(out[0..n], self.base[0..n]);

        if (self.vary_ip_id) {
            const id: u16 = @truncate((dst_ip *% ip_id_mix) ^ @as(u32, dst_port));
            std.mem.writeInt(u16, out[ip_id_off..][0..2], id, .big);
        }
        std.mem.writeInt(u32, out[ip_dst_off..][0..4], dst_ip, .big);
        std.mem.writeInt(u16, out[ip_checksum_off..][0..2], 0, .big);
        const ip_ck = packet.checksum(out[eth_len..l4_off]);
        std.mem.writeInt(u16, out[ip_checksum_off..][0..2], ip_ck, .big);

        const src_port = self.srcPortFor(dst_ip, dst_port);
        std.mem.writeInt(u16, out[tcp_src_off..][0..2], src_port, .big);
        std.mem.writeInt(u16, out[tcp_dst_off..][0..2], dst_port, .big);

        const ck = self.cookie.seq(dst_ip, dst_port, self.src_ip, src_port);
        if (self.scan.cookieInAck()) {
            std.mem.writeInt(u32, out[tcp_seq_off..][0..4], 0, .big);
            std.mem.writeInt(u32, out[tcp_ack_off..][0..4], ck, .big);
        } else {
            std.mem.writeInt(u32, out[tcp_seq_off..][0..4], ck, .big);
            std.mem.writeInt(u32, out[tcp_ack_off..][0..4], 0, .big);
        }

        std.mem.writeInt(u16, out[tcp_checksum_off..][0..2], 0, .big);
        const dst_be = std.mem.nativeToBig(u32, dst_ip);
        const tcp_ck = packet.tcpChecksum(self.src_ip_be, dst_be, out[l4_off..n]);
        std.mem.writeInt(u16, out[tcp_checksum_off..][0..2], tcp_ck, .big);
        return n;
    }

    pub fn stampVariant(self: *const SynTemplate, out: *[max_frame_len]u8, dst_ip: u32, dst_port: u16, variant: usize) usize {
        const n = self.stamp(out, dst_ip, dst_port);
        if (variant == 0) return n;

        const decoy_src = self.decoys[variant - 1];
        const decoy_src_be = std.mem.nativeToBig(u32, decoy_src);
        std.mem.writeInt(u32, out[ip_src_off..][0..4], decoy_src, .big);
        std.mem.writeInt(u16, out[ip_checksum_off..][0..2], 0, .big);
        const ip_ck = packet.checksum(out[eth_len..l4_off]);
        std.mem.writeInt(u16, out[ip_checksum_off..][0..2], ip_ck, .big);

        std.mem.writeInt(u16, out[tcp_checksum_off..][0..2], 0, .big);
        const dst_be = std.mem.nativeToBig(u32, dst_ip);
        const tcp_ck = packet.tcpChecksum(decoy_src_be, dst_be, out[l4_off..n]);
        std.mem.writeInt(u16, out[tcp_checksum_off..][0..2], tcp_ck, .big);
        return n;
    }
};

const ethertype_ipv6: u16 = 0x86dd;
const ip6_version_tc_flow: u32 = 0x60000000;
const ip6_next_tcp: u8 = 6;
const default_hop_limit: u8 = 64;

const ip6_len: usize = 40;
const l4_off6: usize = eth_len + ip6_len;
const opts_off6: usize = l4_off6 + tcp_len;

const ip6_payload_len_off: usize = eth_len + 4;
const ip6_dst_off: usize = eth_len + 24;
const tcp6_src_off: usize = l4_off6;
const tcp6_dst_off: usize = l4_off6 + 2;
const tcp6_seq_off: usize = l4_off6 + 4;
const tcp6_ack_off: usize = l4_off6 + 8;
const tcp6_checksum_off: usize = l4_off6 + 16;

pub const SynTemplate6 = struct {
    pub const max_frame_len: usize = opts_off6 + packet.max_syn_options_len;

    base: [max_frame_len]u8,
    frame_len: usize,
    src_ip: [16]u8,
    src_port: u16,
    cookie: cookie.Cookie,
    scan: packet.ScanType,

    pub const Config = struct {
        src_mac: [6]u8,
        dst_mac: [6]u8,
        src_ip: [16]u8,
        src_port: u16,
        cookie: cookie.Cookie,
        profile: packet.OsProfile = .none,
        scan: packet.ScanType = .syn,
    };

    pub fn init(cfg: Config) SynTemplate6 {
        const opts = cfg.profile.options();
        const tcp_total = tcp_len + opts.len;
        const data_off_words: u8 = @intCast(tcp_total / 4);

        var base: [max_frame_len]u8 = [_]u8{0} ** max_frame_len;

        const eth = packet.EthHdr{
            .dst = cfg.dst_mac,
            .src = cfg.src_mac,
            .ethertype = std.mem.nativeToBig(u16, ethertype_ipv6),
        };
        @memcpy(base[0..eth_len], std.mem.asBytes(&eth));

        const ip6 = packet.Ipv6Hdr{
            .version_tc_flow = std.mem.nativeToBig(u32, ip6_version_tc_flow),
            .payload_len = std.mem.nativeToBig(u16, @intCast(tcp_total)),
            .next_header = ip6_next_tcp,
            .hop_limit = default_hop_limit,
            .src = cfg.src_ip,
            .dst = [_]u8{0} ** 16,
        };
        @memcpy(base[eth_len..l4_off6], std.mem.asBytes(&ip6));

        const tcp = packet.TcpHdr{
            .src_port = std.mem.nativeToBig(u16, cfg.src_port),
            .dst_port = 0,
            .seq = 0,
            .ack = 0,
            .data_off_ns = data_off_words << 4,
            .flags = cfg.scan.probeFlags(),
            .window = std.mem.nativeToBig(u16, cfg.profile.window()),
            .checksum = 0,
            .urgent = 0,
        };
        @memcpy(base[l4_off6..opts_off6], std.mem.asBytes(&tcp));
        if (opts.len > 0) @memcpy(base[opts_off6 .. opts_off6 + opts.len], opts);

        return .{
            .base = base,
            .frame_len = opts_off6 + opts.len,
            .src_ip = cfg.src_ip,
            .src_port = cfg.src_port,
            .cookie = cfg.cookie,
            .scan = cfg.scan,
        };
    }

    pub fn stamp(self: *const SynTemplate6, out: *[max_frame_len]u8, dst_ip: [16]u8, dst_port: u16) usize {
        const n = self.frame_len;
        @memcpy(out[0..n], self.base[0..n]);

        @memcpy(out[ip6_dst_off .. ip6_dst_off + 16], &dst_ip);
        std.mem.writeInt(u16, out[tcp6_dst_off..][0..2], dst_port, .big);

        const ck = self.cookie.seq6(dst_ip, dst_port, self.src_ip, self.src_port);
        if (self.scan.cookieInAck()) {
            std.mem.writeInt(u32, out[tcp6_seq_off..][0..4], 0, .big);
            std.mem.writeInt(u32, out[tcp6_ack_off..][0..4], ck, .big);
        } else {
            std.mem.writeInt(u32, out[tcp6_seq_off..][0..4], ck, .big);
            std.mem.writeInt(u32, out[tcp6_ack_off..][0..4], 0, .big);
        }

        std.mem.writeInt(u16, out[tcp6_checksum_off..][0..2], 0, .big);
        const tcp_ck = packet.tcpChecksum6(self.src_ip, dst_ip, out[l4_off6..n]);
        std.mem.writeInt(u16, out[tcp6_checksum_off..][0..2], tcp_ck, .big);
        return n;
    }
};

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

const v6_src = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const v6_dst = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99 };

fn testTemplate6(profile: packet.OsProfile) SynTemplate6 {
    return SynTemplate6.init(.{
        .src_mac = .{ 0x02, 0, 0, 0, 0, 1 },
        .dst_mac = .{ 0x02, 0, 0, 0, 0, 2 },
        .src_ip = v6_src,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .profile = profile,
    });
}

test "the bare IPv6 SYN template stamps an 74-byte frame with a self-verifying TCP checksum" {
    const tmpl = testTemplate6(.none);
    var frame: [SynTemplate6.max_frame_len]u8 = undefined;
    const len = tmpl.stamp(&frame, v6_dst, 443);

    try std.testing.expectEqual(@as(usize, 14 + 40 + 20), len);
    try std.testing.expectEqual(@as(u16, ethertype_ipv6), std.mem.readInt(u16, frame[12..14], .big));
    try std.testing.expectEqual(@as(u8, 0x60), frame[14] & 0xf0);
    try std.testing.expectEqual(ip6_next_tcp, frame[14 + 6]);
    try std.testing.expectEqual(@as(u16, 20), std.mem.readInt(u16, frame[ip6_payload_len_off..][0..2], .big));
    try std.testing.expectEqualSlices(u8, &v6_dst, frame[ip6_dst_off .. ip6_dst_off + 16]);
    try std.testing.expectEqual(@as(u16, 0), packet.tcpChecksum6(v6_src, v6_dst, frame[l4_off6..len]));
}

test "the IPv6 SYN carries the SipHash6 seq and the Linux option chain self-verifies" {
    const tmpl = testTemplate6(.linux);
    var frame: [SynTemplate6.max_frame_len]u8 = undefined;
    const len = tmpl.stamp(&frame, v6_dst, 22);

    try std.testing.expectEqual(@as(usize, 14 + 40 + 20 + 20), len);
    const ck = cookie.Cookie.init(test_key);
    const want_seq = ck.seq6(v6_dst, 22, v6_src, 40000);
    try std.testing.expectEqual(want_seq, std.mem.readInt(u32, frame[tcp6_seq_off..][0..4], .big));
    try std.testing.expectEqual(@as(u16, 40), std.mem.readInt(u16, frame[ip6_payload_len_off..][0..2], .big));
    try std.testing.expectEqualSlices(u8, packet.OsProfile.linux.options(), frame[opts_off6..len]);
    try std.testing.expectEqual(@as(u16, 0), packet.tcpChecksum6(v6_src, v6_dst, frame[l4_off6..len]));
}

test "two IPv6 targets produce two different seqs" {
    const tmpl = testTemplate6(.none);
    var a: [SynTemplate6.max_frame_len]u8 = undefined;
    var b: [SynTemplate6.max_frame_len]u8 = undefined;
    var dst2 = v6_dst;
    dst2[15] = 0x98;
    _ = tmpl.stamp(&a, v6_dst, 443);
    _ = tmpl.stamp(&b, dst2, 443);
    try std.testing.expect(!std.mem.eql(u8, a[tcp6_seq_off..][0..4], b[tcp6_seq_off..][0..4]));
}

fn testTemplate(profile: packet.OsProfile, scan: packet.ScanType) SynTemplate {
    return SynTemplate.init(.{
        .src_mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .dst_mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .profile = profile,
        .scan = scan,
    });
}

test "the bare profile stamps a 54-byte frame with self-verifying IP and TCP checksums" {
    const tmpl = testTemplate(.none, .syn);
    var frame: [SynTemplate.max_frame_len]u8 = undefined;
    const len = tmpl.stamp(&frame, 0x08080808, 443);

    try std.testing.expectEqual(@as(usize, 54), len);
    try std.testing.expectEqual(@as(u16, 0), packet.checksum(frame[14..34]));
    const ip_src = std.mem.nativeToBig(u32, 0x0a000001);
    const ip_dst = std.mem.nativeToBig(u32, 0x08080808);
    try std.testing.expectEqual(@as(u16, 0), packet.tcpChecksum(ip_src, ip_dst, frame[34..len]));
}

test "stamp writes the destination and the SipHash seq" {
    const tmpl = testTemplate(.none, .syn);
    var frame: [SynTemplate.max_frame_len]u8 = undefined;
    _ = tmpl.stamp(&frame, 0x08080808, 443);

    try std.testing.expectEqual(@as(u32, 0x08080808), std.mem.readInt(u32, frame[30..34], .big));
    try std.testing.expectEqual(@as(u16, 443), std.mem.readInt(u16, frame[36..38], .big));
    const ck = cookie.Cookie.init(test_key);
    const want_seq = ck.seq(0x08080808, 443, 0x0a000001, 40000);
    try std.testing.expectEqual(want_seq, std.mem.readInt(u32, frame[38..42], .big));
}

test "two different targets produce two different seqs" {
    const tmpl = testTemplate(.none, .syn);
    var a: [SynTemplate.max_frame_len]u8 = undefined;
    var b: [SynTemplate.max_frame_len]u8 = undefined;
    _ = tmpl.stamp(&a, 0x08080808, 443);
    _ = tmpl.stamp(&b, 0x08080808, 80);
    try std.testing.expect(!std.mem.eql(u8, a[38..42], b[38..42]));
}

test "the Linux profile stamps a 74-byte frame carrying the option chain, checksums self-verify" {
    const tmpl = testTemplate(.linux, .syn);
    var frame: [SynTemplate.max_frame_len]u8 = undefined;
    const len = tmpl.stamp(&frame, 0x08080808, 443);

    try std.testing.expectEqual(@as(usize, 54 + 20), len);
    try std.testing.expectEqual(@as(u8, 0xa0), frame[tcp_data_off_off]);
    try std.testing.expectEqual(@as(u16, 60), std.mem.readInt(u16, frame[16..18], .big));
    try std.testing.expectEqual(@as(u16, 64240), std.mem.readInt(u16, frame[tcp_window_off..][0..2], .big));
    try std.testing.expectEqualSlices(u8, packet.OsProfile.linux.options(), frame[54..len]);

    try std.testing.expectEqual(@as(u16, 0), packet.checksum(frame[14..34]));
    const ip_src = std.mem.nativeToBig(u32, 0x0a000001);
    const ip_dst = std.mem.nativeToBig(u32, 0x08080808);
    try std.testing.expectEqual(@as(u16, 0), packet.tcpChecksum(ip_src, ip_dst, frame[34..len]));
}

test "windows and macos profiles produce well-formed variable-length frames" {
    inline for (.{
        .{ packet.OsProfile.windows, @as(usize, 54 + 12), @as(u8, 0x80) },
        .{ packet.OsProfile.macos, @as(usize, 54 + 24), @as(u8, 0xb0) },
    }) |case| {
        const tmpl = testTemplate(case[0], .syn);
        var frame: [SynTemplate.max_frame_len]u8 = undefined;
        const len = tmpl.stamp(&frame, 0x01020304, 22);
        try std.testing.expectEqual(case[1], len);
        try std.testing.expectEqual(case[2], frame[tcp_data_off_off]);
        try std.testing.expectEqual(@as(u16, @intCast(len - 14)), std.mem.readInt(u16, frame[16..18], .big));
        const ip_src = std.mem.nativeToBig(u32, 0x0a000001);
        const ip_dst = std.mem.nativeToBig(u32, 0x01020304);
        try std.testing.expectEqual(@as(u16, 0), packet.checksum(frame[14..34]));
        try std.testing.expectEqual(@as(u16, 0), packet.tcpChecksum(ip_src, ip_dst, frame[34..len]));
    }
}

test "the SYN flag byte follows the scan type" {
    const flags_off = tcp_flags_off;
    var frame: [SynTemplate.max_frame_len]u8 = undefined;
    _ = testTemplate(.none, .fin).stamp(&frame, 0x08080808, 80);
    try std.testing.expectEqual(packet.TcpFlag.fin, frame[flags_off]);
    _ = testTemplate(.none, .xmas).stamp(&frame, 0x08080808, 80);
    try std.testing.expectEqual(packet.TcpFlag.fin | packet.TcpFlag.psh | packet.TcpFlag.urg, frame[flags_off]);
    _ = testTemplate(.none, .null_scan).stamp(&frame, 0x08080808, 80);
    try std.testing.expectEqual(@as(u8, 0), frame[flags_off]);
}

test "an ack-flag scan carries the cookie in the ack field and leaves seq zero" {
    const tmpl = testTemplate(.none, .ack);
    var frame: [SynTemplate.max_frame_len]u8 = undefined;
    _ = tmpl.stamp(&frame, 0x08080808, 80);
    const ck = cookie.Cookie.init(test_key);
    const want = ck.seq(0x08080808, 80, 0x0a000001, 40000);
    try std.testing.expectEqual(want, std.mem.readInt(u32, frame[42..46], .big));
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, frame[38..42], .big));
}

test "source-port rotation stays in range and keeps the seq cookie consistent with the written port" {
    const tmpl = SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .rotate = true,
        .rotate_base = 40000,
        .rotate_span = 8192,
    });
    var frame: [SynTemplate.max_frame_len]u8 = undefined;
    _ = tmpl.stamp(&frame, 0x08080808, 443);

    const sport = std.mem.readInt(u16, frame[34..36], .big);
    try std.testing.expect(sport >= 40000 and sport < 48192);

    const ck = cookie.Cookie.init(test_key);
    const want_seq = ck.seq(0x08080808, 443, 0x0a000001, sport);
    try std.testing.expectEqual(want_seq, std.mem.readInt(u32, frame[38..42], .big));
}

test "two different targets rotate to two different source ports" {
    const tmpl = SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .rotate = true,
        .rotate_base = 40000,
        .rotate_span = 8192,
    });
    var a: [SynTemplate.max_frame_len]u8 = undefined;
    var b: [SynTemplate.max_frame_len]u8 = undefined;
    _ = tmpl.stamp(&a, 0x08080808, 443);
    _ = tmpl.stamp(&b, 0x09090909, 443);
    try std.testing.expect(!std.mem.eql(u8, a[34..36], b[34..36]));
}

test "variantCount counts the real probe plus every decoy" {
    const decoys = [_]u32{ 0x01010101, 0x02020202, 0x03030303 };
    const tmpl = SynTemplate.init(.{
        .src_mac = .{0} ** 6,
        .dst_mac = .{0} ** 6,
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .decoys = &decoys,
    });
    try std.testing.expectEqual(@as(usize, 4), tmpl.variantCount());
    const plain = testTemplate(.none, .syn);
    try std.testing.expectEqual(@as(usize, 1), plain.variantCount());
}

test "decoy variants carry a spoofed source with self-verifying IP and TCP checksums" {
    const decoys = [_]u32{ 0xC0A80063, 0x08080404 };
    const tmpl = SynTemplate.init(.{
        .src_mac = .{ 0x02, 0, 0, 0, 0, 1 },
        .dst_mac = .{ 0x02, 0, 0, 0, 0, 2 },
        .src_ip = 0x0a000001,
        .src_port = 40000,
        .cookie = cookie.Cookie.init(test_key),
        .decoys = &decoys,
    });
    var real: [SynTemplate.max_frame_len]u8 = undefined;
    var decoy: [SynTemplate.max_frame_len]u8 = undefined;

    const rn = tmpl.stampVariant(&real, 0x08080808, 443, 0);
    try std.testing.expectEqual(@as(u32, 0x0a000001), std.mem.readInt(u32, real[26..30], .big));

    const dn = tmpl.stampVariant(&decoy, 0x08080808, 443, 1);
    try std.testing.expectEqual(rn, dn);
    try std.testing.expectEqual(@as(u32, 0xC0A80063), std.mem.readInt(u32, decoy[26..30], .big));

    try std.testing.expectEqual(@as(u16, 0), packet.checksum(decoy[14..34]));
    const decoy_src_be = std.mem.nativeToBig(u32, 0xC0A80063);
    const dst_be = std.mem.nativeToBig(u32, 0x08080808);
    try std.testing.expectEqual(@as(u16, 0), packet.tcpChecksum(decoy_src_be, dst_be, decoy[34..dn]));

    try std.testing.expect(!std.mem.eql(u8, real[26..30], decoy[26..30]));
    try std.testing.expectEqualSlices(u8, real[30..34], decoy[30..34]);
}

test "windows and macos profiles vary the IP id per target while linux and bare keep it zero" {
    var a: [SynTemplate.max_frame_len]u8 = undefined;
    var b: [SynTemplate.max_frame_len]u8 = undefined;

    inline for (.{ packet.OsProfile.windows, packet.OsProfile.macos }) |p| {
        const tmpl = testTemplate(p, .syn);
        _ = tmpl.stamp(&a, 0x08080808, 443);
        _ = tmpl.stamp(&b, 0x09090909, 443);
        const id_a = std.mem.readInt(u16, a[18..20], .big);
        const id_b = std.mem.readInt(u16, b[18..20], .big);
        try std.testing.expect(id_a != id_b);
        try std.testing.expectEqual(@as(u16, 0), packet.checksum(a[14..34]));
    }

    _ = testTemplate(.linux, .syn).stamp(&a, 0x08080808, 443);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, a[18..20], .big));
    _ = testTemplate(.none, .syn).stamp(&a, 0x08080808, 443);
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, a[18..20], .big));
}
