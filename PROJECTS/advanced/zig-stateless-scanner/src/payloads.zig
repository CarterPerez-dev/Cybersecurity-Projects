// ©AngelaMos | 2026
// payloads.zig

const std = @import("std");

const Entry = struct { port: u16, payload: []const u8 };

const ntp_client = [_]u8{0x1b} ++ [_]u8{0} ** 47;

const dns_version_bind = [_]u8{
    0x13, 0x37,
    0x01, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x07, 'v',
    'e',  'r',
    's',  'i',
    'o',  'n',
    0x04, 'b',
    'i',  'n',
    'd',  0x00,
    0x00, 0x10,
    0x00, 0x03,
};

const snmp_get_public = [_]u8{
    0x30, 0x26,
    0x02, 0x01,
    0x00, 0x04,
    0x06, 'p',
    'u',  'b',
    'l',  'i',
    'c',  0xa0,
    0x19, 0x02,
    0x01, 0x00,
    0x02, 0x01,
    0x00, 0x02,
    0x01, 0x00,
    0x30, 0x0e,
    0x30, 0x0c,
    0x06, 0x08,
    0x2b, 0x06,
    0x01, 0x02,
    0x01, 0x01,
    0x01, 0x00,
    0x05, 0x00,
};

const netbios_node_status = [_]u8{
    0x13, 0x37,
    0x00, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x20, 'C',
    'K',
} ++ ([_]u8{'A'} ** 30) ++ [_]u8{
    0x00,
    0x00,
    0x21,
    0x00,
    0x01,
};

const ssdp_msearch =
    "M-SEARCH * HTTP/1.1\r\n" ++
    "HOST:239.255.255.250:1900\r\n" ++
    "MAN:\"ssdp:discover\"\r\n" ++
    "MX:1\r\n" ++
    "ST:ssdp:all\r\n" ++
    "\r\n";

const mdns_services = [_]u8{
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x09, '_',
    's',  'e',
    'r',  'v',
    'i',  'c',
    'e',  's',
    0x07, '_',
    'd',  'n',
    's',  '-',
    's',  'd',
    0x04, '_',
    'u',  'd',
    'p',  0x05,
    'l',  'o',
    'c',  'a',
    'l',  0x00,
    0x00, 0x0c,
    0x00, 0x01,
};

const table = [_]Entry{
    .{ .port = 53, .payload = &dns_version_bind },
    .{ .port = 123, .payload = &ntp_client },
    .{ .port = 137, .payload = &netbios_node_status },
    .{ .port = 161, .payload = &snmp_get_public },
    .{ .port = 1900, .payload = ssdp_msearch },
    .{ .port = 5353, .payload = &mdns_services },
};

pub fn lookup(port: u16) []const u8 {
    inline for (table) |e| {
        if (e.port == port) return e.payload;
    }
    return &.{};
}

pub const max_len: usize = blk: {
    var m: usize = 0;
    for (table) |e| {
        if (e.payload.len > m) m = e.payload.len;
    }
    break :blk m;
};

test "lookup returns the protocol payload for a known port and empty for the rest" {
    try std.testing.expectEqual(@as(usize, 48), lookup(123).len);
    try std.testing.expectEqualSlices(u8, &ntp_client, lookup(123));
    try std.testing.expectEqual(@as(usize, 0), lookup(80).len);
    try std.testing.expectEqual(@as(usize, 0), lookup(0).len);
}

test "NTP client probe is a 48-byte LI=0 VN=3 Mode=3 request" {
    const p = lookup(123);
    try std.testing.expectEqual(@as(usize, 48), p.len);
    try std.testing.expectEqual(@as(u8, 0x1b), p[0]);
}

test "DNS probe is a well-formed single-question version.bind CH TXT query" {
    const p = lookup(53);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, p[4..6], .big));
    var name: [16]u8 = undefined;
    var w: usize = 0;
    var i: usize = 12;
    while (p[i] != 0) {
        const len = p[i];
        i += 1;
        if (w != 0) {
            name[w] = '.';
            w += 1;
        }
        @memcpy(name[w .. w + len], p[i .. i + len]);
        w += len;
        i += len;
    }
    try std.testing.expectEqualStrings("version.bind", name[0..w]);
    try std.testing.expectEqual(@as(u16, 0x0010), std.mem.readInt(u16, p[i + 1 ..][0..2], .big));
    try std.testing.expectEqual(@as(u16, 0x0003), std.mem.readInt(u16, p[i + 3 ..][0..2], .big));
}

test "SNMP probe is a v1 GetRequest for community public with a matching outer length" {
    const p = lookup(161);
    try std.testing.expectEqual(@as(u8, 0x30), p[0]);
    try std.testing.expectEqual(@as(usize, p[1]) + 2, p.len);
    try std.testing.expect(std.mem.indexOf(u8, p, "public") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, p, 0xa0) != null);
}

test "NetBIOS probe carries the encoded wildcard name and NBSTAT type" {
    const p = lookup(137);
    try std.testing.expectEqual(@as(usize, 50), p.len);
    try std.testing.expect(std.mem.indexOf(u8, p, "CKAAAA") != null);
    try std.testing.expectEqual(@as(u16, 0x0021), std.mem.readInt(u16, p[p.len - 4 ..][0..2], .big));
}

test "SSDP probe is an M-SEARCH discover" {
    const p = lookup(1900);
    try std.testing.expect(std.mem.startsWith(u8, p, "M-SEARCH * HTTP/1.1"));
    try std.testing.expect(std.mem.indexOf(u8, p, "ssdp:discover") != null);
}

test "mDNS probe enumerates DNS-SD services over PTR" {
    const p = lookup(5353);
    try std.testing.expect(std.mem.indexOf(u8, p, "_services") != null);
    try std.testing.expect(std.mem.indexOf(u8, p, "_dns-sd") != null);
    try std.testing.expectEqual(@as(u16, 0x000c), std.mem.readInt(u16, p[p.len - 4 ..][0..2], .big));
}

test "max_len equals the longest table payload" {
    var m: usize = 0;
    for (table) |e| {
        if (e.payload.len > m) m = e.payload.len;
    }
    try std.testing.expectEqual(m, max_len);
    try std.testing.expect(max_len >= 48);
}
