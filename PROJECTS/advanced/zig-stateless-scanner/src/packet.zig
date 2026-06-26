// ©AngelaMos | 2026
// packet.zig

const std = @import("std");

pub const EthHdr = extern struct {
    dst: [6]u8,
    src: [6]u8,
    ethertype: u16,
};

pub const Ipv4Hdr = extern struct {
    version_ihl: u8,
    tos: u8,
    total_len: u16,
    id: u16,
    flags_frag: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: u32,
    dst: u32,
};

pub const TcpHdr = extern struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_off_ns: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
};

comptime {
    std.debug.assert(@sizeOf(EthHdr) == 14);
    std.debug.assert(@sizeOf(Ipv4Hdr) == 20);
    std.debug.assert(@sizeOf(TcpHdr) == 20);
}

pub fn checksum(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        const word = (@as(u16, bytes[i]) << 8) | @as(u16, bytes[i + 1]);
        sum += word;
    }
    if (i < bytes.len) {
        sum += @as(u32, bytes[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

test "header sizes are wire-exact" {
    try std.testing.expectEqual(@as(usize, 14), @sizeOf(EthHdr));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(Ipv4Hdr));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(TcpHdr));
}

test "RFC 1071 checksum matches the canonical IPv4 KAT (0xb861)" {
    const hdr = [_]u8{
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };
    try std.testing.expectEqual(@as(u16, 0xb861), checksum(&hdr));
}
