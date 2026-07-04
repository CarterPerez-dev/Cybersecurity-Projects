// ©AngelaMos | 2026
// cookie.zig

const std = @import("std");

pub const Cookie = struct {
    key: [16]u8,

    pub fn init(key: [16]u8) Cookie {
        return .{ .key = key };
    }

    pub fn random(io: std.Io) !Cookie {
        var key: [16]u8 = undefined;
        try io.randomSecure(&key);
        return .{ .key = key };
    }

    pub fn generate(self: Cookie, ip_them: u32, port_them: u16, ip_me: u32, port_me: u16) u64 {
        var data: [12]u8 = undefined;
        std.mem.writeInt(u32, data[0..4], ip_them, .big);
        std.mem.writeInt(u16, data[4..6], port_them, .big);
        std.mem.writeInt(u32, data[6..10], ip_me, .big);
        std.mem.writeInt(u16, data[10..12], port_me, .big);
        return std.hash.SipHash64(2, 4).toInt(&data, &self.key);
    }

    pub fn seq(self: Cookie, ip_them: u32, port_them: u16, ip_me: u32, port_me: u16) u32 {
        return @truncate(self.generate(ip_them, port_them, ip_me, port_me));
    }

    pub fn validateSynAck(self: Cookie, ack: u32, ip_them: u32, port_them: u16, ip_me: u32, port_me: u16) bool {
        return ack == self.seq(ip_them, port_them, ip_me, port_me) +% 1;
    }

    pub fn udpSrcPort(self: Cookie, ip_them: u32, port_them: u16, ip_me: u32, base: u16, span: u16) u16 {
        const s: u32 = if (span == 0) 1 else span;
        const off: u32 = @intCast(self.generate(ip_them, port_them, ip_me, 0) % s);
        return @intCast((@as(u32, base) + off) & 0xffff);
    }

    pub fn generate6(self: Cookie, ip_them: [16]u8, port_them: u16, ip_me: [16]u8, port_me: u16) u64 {
        var data: [36]u8 = undefined;
        @memcpy(data[0..16], &ip_them);
        std.mem.writeInt(u16, data[16..18], port_them, .big);
        @memcpy(data[18..34], &ip_me);
        std.mem.writeInt(u16, data[34..36], port_me, .big);
        return std.hash.SipHash64(2, 4).toInt(&data, &self.key);
    }

    pub fn seq6(self: Cookie, ip_them: [16]u8, port_them: u16, ip_me: [16]u8, port_me: u16) u32 {
        return @truncate(self.generate6(ip_them, port_them, ip_me, port_me));
    }

    pub fn validateSynAck6(self: Cookie, ack: u32, ip_them: [16]u8, port_them: u16, ip_me: [16]u8, port_me: u16) bool {
        return ack == self.seq6(ip_them, port_them, ip_me, port_me) +% 1;
    }
};

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

test "SipHash64(2,4) reproduces the reference empty-message vector" {
    try std.testing.expectEqual(
        @as(u64, 0x726fdb47dd0e0e31),
        std.hash.SipHash64(2, 4).toInt("", &test_key),
    );
}

test "cookie is deterministic for a fixed key + 4-tuple (golden KAT)" {
    const c = Cookie.init(test_key);
    const a = c.generate(0x0a000001, 443, 0xc0a80002, 51000);
    const b = c.generate(0x0a000001, 443, 0xc0a80002, 51000);
    try std.testing.expectEqual(a, b);
    try std.testing.expectEqual(@as(u64, 0x559a4e08e1deb9a7), a);
}

test "seq is the low 32 bits of the cookie" {
    const c = Cookie.init(test_key);
    const full = c.generate(0x0a000001, 443, 0xc0a80002, 51000);
    try std.testing.expectEqual(@as(u32, @truncate(full)), c.seq(0x0a000001, 443, 0xc0a80002, 51000));
}

test "validateSynAck accepts ack == seq + 1 and rejects others" {
    const c = Cookie.init(test_key);
    const s = c.seq(0x0a000001, 443, 0xc0a80002, 51000);
    try std.testing.expect(c.validateSynAck(s +% 1, 0x0a000001, 443, 0xc0a80002, 51000));
    try std.testing.expect(!c.validateSynAck(s, 0x0a000001, 443, 0xc0a80002, 51000));
    try std.testing.expect(!c.validateSynAck(s +% 2, 0x0a000001, 443, 0xc0a80002, 51000));
}

test "validateSynAck wraps at the u32 boundary" {
    const seq_max: u32 = 0xFFFFFFFF;
    try std.testing.expectEqual(@as(u32, 0), seq_max +% 1);
}

test "udpSrcPort is deterministic and stays inside [base, base+span)" {
    const c = Cookie.init(test_key);
    const base: u16 = 40000;
    const span: u16 = 8192;
    const a = c.udpSrcPort(0x08080808, 53, 0x0a000001, base, span);
    const b = c.udpSrcPort(0x08080808, 53, 0x0a000001, base, span);
    try std.testing.expectEqual(a, b);
    try std.testing.expect(a >= base and a < base + span);
}

test "udpSrcPort excludes port_me from the tuple so RX can recompute it" {
    const c = Cookie.init(test_key);
    const full = c.generate(0x08080808, 53, 0x0a000001, 0);
    const want: u16 = @intCast((@as(u32, 40000) + @as(u32, @intCast(full % 8192))) & 0xffff);
    try std.testing.expectEqual(want, c.udpSrcPort(0x08080808, 53, 0x0a000001, 40000, 8192));
}

test "udpSrcPort separates distinct targets" {
    const c = Cookie.init(test_key);
    const p53 = c.udpSrcPort(0x08080808, 53, 0x0a000001, 40000, 8192);
    const p123 = c.udpSrcPort(0x08080808, 123, 0x0a000001, 40000, 8192);
    try std.testing.expect(p53 != p123);
}

const v6_them = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11 };
const v6_me = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22 };

test "generate6 is deterministic for a fixed key + IPv6 4-tuple" {
    const c = Cookie.init(test_key);
    const a = c.generate6(v6_them, 443, v6_me, 51000);
    const b = c.generate6(v6_them, 443, v6_me, 51000);
    try std.testing.expectEqual(a, b);
}

test "seq6 is the low 32 bits and validateSynAck6 accepts seq+1 with u32 wrap" {
    const c = Cookie.init(test_key);
    const full = c.generate6(v6_them, 443, v6_me, 51000);
    const s = c.seq6(v6_them, 443, v6_me, 51000);
    try std.testing.expectEqual(@as(u32, @truncate(full)), s);
    try std.testing.expect(c.validateSynAck6(s +% 1, v6_them, 443, v6_me, 51000));
    try std.testing.expect(!c.validateSynAck6(s, v6_them, 443, v6_me, 51000));
    try std.testing.expect(!c.validateSynAck6(s +% 2, v6_them, 443, v6_me, 51000));
}

test "generate6 separates distinct addresses and ports" {
    const c = Cookie.init(test_key);
    var other = v6_them;
    other[15] = 0x12;
    try std.testing.expect(c.generate6(v6_them, 443, v6_me, 51000) != c.generate6(other, 443, v6_me, 51000));
    try std.testing.expect(c.generate6(v6_them, 443, v6_me, 51000) != c.generate6(v6_them, 80, v6_me, 51000));
}

test "v4 and v6 cookies over analogous tuples do not collide" {
    const c = Cookie.init(test_key);
    const v4 = c.generate(0x0a000001, 443, 0xc0a80002, 51000);
    const v6 = c.generate6(v6_them, 443, v6_me, 51000);
    try std.testing.expect(v4 != v6);
}
