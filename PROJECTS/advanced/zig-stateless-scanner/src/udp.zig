// ©AngelaMos | 2026
// udp.zig

const std = @import("std");
const packet = @import("packet");
const cookie = @import("cookie");
const payloads = @import("payloads");

const ethertype_ipv4: u16 = 0x0800;
const ipv4_version_ihl: u8 = 0x45;
const ip_proto_udp: u8 = 17;
const ip_flag_dont_fragment: u16 = 0x4000;
const default_ttl: u8 = 64;

const eth_len: usize = 14;
const ip_len: usize = 20;
const udp_len: usize = 8;
const l4_off: usize = eth_len + ip_len;
const payload_off: usize = l4_off + udp_len;

const ip_total_len_off: usize = eth_len + 2;
const ip_checksum_off: usize = eth_len + 10;
const ip_dst_off: usize = eth_len + 16;
const udp_src_off: usize = l4_off;
const udp_dst_off: usize = l4_off + 2;
const udp_len_off: usize = l4_off + 4;
const udp_checksum_off: usize = l4_off + 6;

pub const UdpTemplate = struct {
    pub const max_frame_len: usize = payload_off + payloads.max_len;

    base: [payload_off]u8,
    src_ip_be: u32,
    src_ip: u32,
    src_port_base: u16,
    src_port_span: u16,
    cookie: cookie.Cookie,

    pub const Config = struct {
        src_mac: [6]u8,
        dst_mac: [6]u8,
        src_ip: u32,
        src_port_base: u16,
        src_port_span: u16,
        cookie: cookie.Cookie,
    };

    pub fn init(cfg: Config) UdpTemplate {
        var base: [payload_off]u8 = undefined;

        const eth = packet.EthHdr{
            .dst = cfg.dst_mac,
            .src = cfg.src_mac,
            .ethertype = std.mem.nativeToBig(u16, ethertype_ipv4),
        };
        @memcpy(base[0..eth_len], std.mem.asBytes(&eth));

        const ip = packet.Ipv4Hdr{
            .version_ihl = ipv4_version_ihl,
            .tos = 0,
            .total_len = 0,
            .id = 0,
            .flags_frag = std.mem.nativeToBig(u16, ip_flag_dont_fragment),
            .ttl = default_ttl,
            .protocol = ip_proto_udp,
            .checksum = 0,
            .src = std.mem.nativeToBig(u32, cfg.src_ip),
            .dst = 0,
        };
        @memcpy(base[eth_len..l4_off], std.mem.asBytes(&ip));

        const udp = packet.UdpHdr{
            .src_port = 0,
            .dst_port = 0,
            .length = 0,
            .checksum = 0,
        };
        @memcpy(base[l4_off..payload_off], std.mem.asBytes(&udp));

        return .{
            .base = base,
            .src_ip_be = std.mem.nativeToBig(u32, cfg.src_ip),
            .src_ip = cfg.src_ip,
            .src_port_base = cfg.src_port_base,
            .src_port_span = cfg.src_port_span,
            .cookie = cfg.cookie,
        };
    }

    pub fn stamp(self: *const UdpTemplate, out: *[max_frame_len]u8, dst_ip: u32, dst_port: u16) usize {
        const payload = payloads.lookup(dst_port);
        const udp_total = udp_len + payload.len;
        const ip_total = ip_len + udp_total;
        const frame_len = eth_len + ip_total;

        @memcpy(out[0..payload_off], &self.base);
        @memcpy(out[payload_off .. payload_off + payload.len], payload);

        std.mem.writeInt(u16, out[ip_total_len_off..][0..2], @intCast(ip_total), .big);
        std.mem.writeInt(u32, out[ip_dst_off..][0..4], dst_ip, .big);
        std.mem.writeInt(u16, out[ip_checksum_off..][0..2], 0, .big);
        const ip_ck = packet.checksum(out[eth_len..l4_off]);
        std.mem.writeInt(u16, out[ip_checksum_off..][0..2], ip_ck, .big);

        const src_port = self.cookie.udpSrcPort(dst_ip, dst_port, self.src_ip, self.src_port_base, self.src_port_span);
        std.mem.writeInt(u16, out[udp_src_off..][0..2], src_port, .big);
        std.mem.writeInt(u16, out[udp_dst_off..][0..2], dst_port, .big);
        std.mem.writeInt(u16, out[udp_len_off..][0..2], @intCast(udp_total), .big);
        std.mem.writeInt(u16, out[udp_checksum_off..][0..2], 0, .big);
        const dst_be = std.mem.nativeToBig(u32, dst_ip);
        const udp_ck = packet.udpChecksum(self.src_ip_be, dst_be, out[l4_off .. payload_off + payload.len]);
        std.mem.writeInt(u16, out[udp_checksum_off..][0..2], udp_ck, .big);

        return frame_len;
    }

    pub fn variantCount(_: *const UdpTemplate) usize {
        return 1;
    }

    pub fn stampVariant(self: *const UdpTemplate, out: *[max_frame_len]u8, dst_ip: u32, dst_port: u16, variant: usize) usize {
        _ = variant;
        return self.stamp(out, dst_ip, dst_port);
    }
};

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

const our_ip: u32 = 0x0a000001;
const their_ip: u32 = 0x08080808;
const base_port: u16 = 40000;
const span: u16 = 8192;

fn testTemplate(ck: cookie.Cookie) UdpTemplate {
    return UdpTemplate.init(.{
        .src_mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .dst_mac = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
        .src_ip = our_ip,
        .src_port_base = base_port,
        .src_port_span = span,
        .cookie = ck,
    });
}

test "stamped UDP frame carries self-verifying IP and UDP checksums" {
    const ck = cookie.Cookie.init(test_key);
    const tmpl = testTemplate(ck);
    var frame: [UdpTemplate.max_frame_len]u8 = undefined;
    const len = tmpl.stamp(&frame, their_ip, 53);

    try std.testing.expectEqual(@as(u16, 0), packet.checksum(frame[eth_len..l4_off]));
    const src_be = std.mem.nativeToBig(u32, our_ip);
    const dst_be = std.mem.nativeToBig(u32, their_ip);
    try std.testing.expectEqual(@as(u16, 0xffff), packet.udpChecksum(src_be, dst_be, frame[l4_off..len]));
    try std.testing.expect(std.mem.readInt(u16, frame[udp_checksum_off..][0..2], .big) != 0);
}

test "stamp selects the per-protocol payload and computes the frame length" {
    const ck = cookie.Cookie.init(test_key);
    const tmpl = testTemplate(ck);
    var frame: [UdpTemplate.max_frame_len]u8 = undefined;

    const known = payloads.lookup(53);
    const len53 = tmpl.stamp(&frame, their_ip, 53);
    try std.testing.expectEqual(payload_off + known.len, len53);
    try std.testing.expectEqualSlices(u8, known, frame[payload_off..len53]);
    try std.testing.expectEqual(@as(u16, @intCast(udp_len + known.len)), std.mem.readInt(u16, frame[udp_len_off..][0..2], .big));

    const len80 = tmpl.stamp(&frame, their_ip, 80);
    try std.testing.expectEqual(payload_off, len80);
}

test "stamp writes the cookie-derived UDP source port" {
    const ck = cookie.Cookie.init(test_key);
    const tmpl = testTemplate(ck);
    var frame: [UdpTemplate.max_frame_len]u8 = undefined;
    _ = tmpl.stamp(&frame, their_ip, 53);
    const want = ck.udpSrcPort(their_ip, 53, our_ip, base_port, span);
    try std.testing.expectEqual(want, std.mem.readInt(u16, frame[udp_src_off..][0..2], .big));
    try std.testing.expect(want >= base_port and want < base_port + span);
}

test "stamp writes destination, port, and the UDP protocol number" {
    const ck = cookie.Cookie.init(test_key);
    const tmpl = testTemplate(ck);
    var frame: [UdpTemplate.max_frame_len]u8 = undefined;
    _ = tmpl.stamp(&frame, their_ip, 161);
    try std.testing.expectEqual(their_ip, std.mem.readInt(u32, frame[ip_dst_off..][0..4], .big));
    try std.testing.expectEqual(@as(u16, 161), std.mem.readInt(u16, frame[udp_dst_off..][0..2], .big));
    try std.testing.expectEqual(ip_proto_udp, frame[eth_len + 9]);
}

test "two different target ports produce two different source ports" {
    const ck = cookie.Cookie.init(test_key);
    const tmpl = testTemplate(ck);
    var a: [UdpTemplate.max_frame_len]u8 = undefined;
    var b: [UdpTemplate.max_frame_len]u8 = undefined;
    _ = tmpl.stamp(&a, their_ip, 53);
    _ = tmpl.stamp(&b, their_ip, 123);
    try std.testing.expect(!std.mem.eql(u8, a[udp_src_off..][0..2], b[udp_src_off..][0..2]));
}
