// ©AngelaMos | 2026
// segment.zig

const std = @import("std");
const packet = @import("packet");

const eth_len: usize = 14;
const ip_len: usize = 20;
const tcp_len: usize = 20;
const l4_off: usize = eth_len + ip_len;
const payload_off: usize = l4_off + tcp_len;

const ip_checksum_off: usize = eth_len + 10;
const tcp_checksum_off: usize = l4_off + 16;

const ethertype_ipv4: u16 = 0x0800;
const ipv4_version_ihl: u8 = 0x45;
const ip_proto_tcp: u8 = 6;
const ip_flag_dont_fragment: u16 = 0x4000;
const default_ttl: u8 = 64;
const tcp_data_off_5words: u8 = 0x50;
const default_window: u16 = 65535;

pub const max_payload: usize = 128;
pub const max_len: usize = payload_off + max_payload;

pub const Params = struct {
    src_mac: [6]u8,
    dst_mac: [6]u8,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16 = default_window,
    payload: []const u8 = &.{},
};

pub fn build(out: *[max_len]u8, p: Params) usize {
    std.debug.assert(p.payload.len <= max_payload);
    const total = payload_off + p.payload.len;

    const eth = packet.EthHdr{
        .dst = p.dst_mac,
        .src = p.src_mac,
        .ethertype = std.mem.nativeToBig(u16, ethertype_ipv4),
    };
    @memcpy(out[0..eth_len], std.mem.asBytes(&eth));

    const ip = packet.Ipv4Hdr{
        .version_ihl = ipv4_version_ihl,
        .tos = 0,
        .total_len = std.mem.nativeToBig(u16, @intCast(ip_len + tcp_len + p.payload.len)),
        .id = 0,
        .flags_frag = std.mem.nativeToBig(u16, ip_flag_dont_fragment),
        .ttl = default_ttl,
        .protocol = ip_proto_tcp,
        .checksum = 0,
        .src = std.mem.nativeToBig(u32, p.src_ip),
        .dst = std.mem.nativeToBig(u32, p.dst_ip),
    };
    @memcpy(out[eth_len..l4_off], std.mem.asBytes(&ip));
    const ip_ck = packet.checksum(out[eth_len..l4_off]);
    std.mem.writeInt(u16, out[ip_checksum_off..][0..2], ip_ck, .big);

    const tcp = packet.TcpHdr{
        .src_port = std.mem.nativeToBig(u16, p.src_port),
        .dst_port = std.mem.nativeToBig(u16, p.dst_port),
        .seq = std.mem.nativeToBig(u32, p.seq),
        .ack = std.mem.nativeToBig(u32, p.ack),
        .data_off_ns = tcp_data_off_5words,
        .flags = p.flags,
        .window = std.mem.nativeToBig(u16, p.window),
        .checksum = 0,
        .urgent = 0,
    };
    @memcpy(out[l4_off..payload_off], std.mem.asBytes(&tcp));
    if (p.payload.len > 0) @memcpy(out[payload_off..total], p.payload);

    const src_be = std.mem.nativeToBig(u32, p.src_ip);
    const dst_be = std.mem.nativeToBig(u32, p.dst_ip);
    const tcp_ck = packet.tcpChecksum(src_be, dst_be, out[l4_off..total]);
    std.mem.writeInt(u16, out[tcp_checksum_off..][0..2], tcp_ck, .big);

    return total;
}

const test_src_mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const test_dst_mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const test_src_ip: u32 = 0x0a000001;
const test_dst_ip: u32 = 0x08080808;

fn selfVerifies(out: *[max_len]u8, n: usize) !void {
    try std.testing.expectEqual(@as(u16, 0), packet.checksum(out[eth_len..l4_off]));
    const src_be = std.mem.nativeToBig(u32, test_src_ip);
    const dst_be = std.mem.nativeToBig(u32, test_dst_ip);
    try std.testing.expectEqual(@as(u16, 0), packet.tcpChecksum(src_be, dst_be, out[l4_off..n]));
}

test "a bare ACK is 54 bytes with self-verifying IP and TCP checksums" {
    var out: [max_len]u8 = undefined;
    const n = build(&out, .{
        .src_mac = test_src_mac,
        .dst_mac = test_dst_mac,
        .src_ip = test_src_ip,
        .dst_ip = test_dst_ip,
        .src_port = 40000,
        .dst_port = 22,
        .seq = 0x1000_0001,
        .ack = 0xCAFE_BABF,
        .flags = packet.TcpFlag.ack,
    });
    try std.testing.expectEqual(@as(usize, 54), n);
    try selfVerifies(&out, n);
}

test "seq, ack, ports, and flags land at the wire offsets" {
    var out: [max_len]u8 = undefined;
    const n = build(&out, .{
        .src_mac = test_src_mac,
        .dst_mac = test_dst_mac,
        .src_ip = test_src_ip,
        .dst_ip = test_dst_ip,
        .src_port = 40001,
        .dst_port = 443,
        .seq = 0xDEAD_BEEF,
        .ack = 0x0102_0304,
        .flags = packet.TcpFlag.rst | packet.TcpFlag.ack,
    });
    try std.testing.expectEqual(@as(u16, 40001), std.mem.readInt(u16, out[l4_off..][0..2], .big));
    try std.testing.expectEqual(@as(u16, 443), std.mem.readInt(u16, out[l4_off + 2 ..][0..2], .big));
    try std.testing.expectEqual(@as(u32, 0xDEAD_BEEF), std.mem.readInt(u32, out[l4_off + 4 ..][0..4], .big));
    try std.testing.expectEqual(@as(u32, 0x0102_0304), std.mem.readInt(u32, out[l4_off + 8 ..][0..4], .big));
    try std.testing.expectEqual(@as(u8, 0x50), out[l4_off + 12]);
    try std.testing.expectEqual(packet.TcpFlag.rst | packet.TcpFlag.ack, out[l4_off + 13]);
    try selfVerifies(&out, n);
}

test "a PSH-ACK with a probe payload carries the bytes and self-verifies" {
    const probe = "GET / HTTP/1.0\r\n\r\n";
    var out: [max_len]u8 = undefined;
    const n = build(&out, .{
        .src_mac = test_src_mac,
        .dst_mac = test_dst_mac,
        .src_ip = test_src_ip,
        .dst_ip = test_dst_ip,
        .src_port = 40002,
        .dst_port = 80,
        .seq = 0x2000_0002,
        .ack = 0x3000_0003,
        .flags = packet.TcpFlag.psh | packet.TcpFlag.ack,
        .payload = probe,
    });
    try std.testing.expectEqual(@as(usize, 54 + probe.len), n);
    try std.testing.expectEqualSlices(u8, probe, out[payload_off..n]);
    try std.testing.expectEqual(@as(u16, @intCast(ip_len + tcp_len + probe.len)), std.mem.readInt(u16, out[eth_len + 2 ..][0..2], .big));
    try selfVerifies(&out, n);
}

test "the ethernet header carries both MACs and the IPv4 ethertype" {
    var out: [max_len]u8 = undefined;
    _ = build(&out, .{
        .src_mac = test_src_mac,
        .dst_mac = test_dst_mac,
        .src_ip = test_src_ip,
        .dst_ip = test_dst_ip,
        .src_port = 40000,
        .dst_port = 22,
        .seq = 1,
        .ack = 2,
        .flags = packet.TcpFlag.ack,
    });
    try std.testing.expectEqualSlices(u8, &test_dst_mac, out[0..6]);
    try std.testing.expectEqualSlices(u8, &test_src_mac, out[6..12]);
    try std.testing.expectEqual(@as(u16, 0x0800), std.mem.readInt(u16, out[12..14], .big));
}

comptime {
    std.debug.assert(payload_off == 54);
    std.debug.assert(max_len == 54 + max_payload);
}
