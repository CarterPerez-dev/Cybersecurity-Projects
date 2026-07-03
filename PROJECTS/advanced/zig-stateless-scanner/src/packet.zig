// ©AngelaMos | 2026
// packet.zig

const std = @import("std");
const builtin = @import("builtin");

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

pub const UdpHdr = extern struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

comptime {
    std.debug.assert(@sizeOf(EthHdr) == 14);
    std.debug.assert(@sizeOf(Ipv4Hdr) == 20);
    std.debug.assert(@sizeOf(TcpHdr) == 20);
    std.debug.assert(@sizeOf(UdpHdr) == 8);
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

pub fn checksumSimd(bytes: []const u8) u16 {
    const lanes = comptime (std.simd.suggestVectorLength(u16) orelse 8);
    const stride = lanes * 2;
    const native_le = builtin.cpu.arch.endian() == .little;

    var acc: @Vector(lanes, u32) = @splat(0);
    var i: usize = 0;
    while (i + stride <= bytes.len) : (i += stride) {
        const block: [stride]u8 = bytes[i..][0..stride].*;
        var words: @Vector(lanes, u16) = @bitCast(block);
        if (native_le) words = @byteSwap(words);
        acc += @as(@Vector(lanes, u32), words);
    }

    var sum: u32 = @reduce(.Add, acc);
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u32, bytes[i]) << 8) | @as(u32, bytes[i + 1]);
    }
    if (i < bytes.len) {
        sum += @as(u32, bytes[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

pub fn incrementalUpdate(old_check: u16, old_word: u16, new_word: u16) u16 {
    var sum: u32 = @as(u32, ~old_check) + @as(u32, ~old_word) + @as(u32, new_word);
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

pub fn tcpChecksum(src_be: u32, dst_be: u32, segment: []const u8) u16 {
    var pseudo: [12]u8 = undefined;
    @memcpy(pseudo[0..4], std.mem.asBytes(&src_be));
    @memcpy(pseudo[4..8], std.mem.asBytes(&dst_be));
    pseudo[8] = 0;
    pseudo[9] = 6;
    std.mem.writeInt(u16, pseudo[10..12], @intCast(segment.len), .big);

    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < pseudo.len) : (i += 2) {
        sum += (@as(u32, pseudo[i]) << 8) | @as(u32, pseudo[i + 1]);
    }
    i = 0;
    while (i + 1 < segment.len) : (i += 2) {
        sum += (@as(u32, segment[i]) << 8) | @as(u32, segment[i + 1]);
    }
    if (i < segment.len) {
        sum += @as(u32, segment[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @truncate(sum));
}

pub fn udpChecksum(src_be: u32, dst_be: u32, segment: []const u8) u16 {
    var pseudo: [12]u8 = undefined;
    @memcpy(pseudo[0..4], std.mem.asBytes(&src_be));
    @memcpy(pseudo[4..8], std.mem.asBytes(&dst_be));
    pseudo[8] = 0;
    pseudo[9] = 17;
    std.mem.writeInt(u16, pseudo[10..12], @intCast(segment.len), .big);

    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < pseudo.len) : (i += 2) {
        sum += (@as(u32, pseudo[i]) << 8) | @as(u32, pseudo[i + 1]);
    }
    i = 0;
    while (i + 1 < segment.len) : (i += 2) {
        sum += (@as(u32, segment[i]) << 8) | @as(u32, segment[i + 1]);
    }
    if (i < segment.len) {
        sum += @as(u32, segment[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    const folded: u16 = ~@as(u16, @truncate(sum));
    return if (folded == 0) 0xffff else folded;
}

pub const TcpFlag = struct {
    pub const fin: u8 = 0x01;
    pub const syn: u8 = 0x02;
    pub const rst: u8 = 0x04;
    pub const psh: u8 = 0x08;
    pub const ack: u8 = 0x10;
    pub const urg: u8 = 0x20;
};

pub const ScanType = enum {
    syn,
    fin,
    null_scan,
    xmas,
    maimon,
    ack,
    window,

    pub fn probeFlags(self: ScanType) u8 {
        return switch (self) {
            .syn => TcpFlag.syn,
            .fin => TcpFlag.fin,
            .null_scan => 0,
            .xmas => TcpFlag.fin | TcpFlag.psh | TcpFlag.urg,
            .maimon => TcpFlag.fin | TcpFlag.ack,
            .ack, .window => TcpFlag.ack,
        };
    }

    pub fn cookieInAck(self: ScanType) bool {
        return switch (self) {
            .maimon, .ack, .window => true,
            else => false,
        };
    }

    pub fn seqConsumed(self: ScanType) u32 {
        return switch (self) {
            .syn, .fin, .xmas => 1,
            else => 0,
        };
    }

    pub fn parse(text: []const u8) ?ScanType {
        const map = .{
            .{ "syn", ScanType.syn },
            .{ "fin", ScanType.fin },
            .{ "null", ScanType.null_scan },
            .{ "xmas", ScanType.xmas },
            .{ "maimon", ScanType.maimon },
            .{ "ack", ScanType.ack },
            .{ "window", ScanType.window },
        };
        inline for (map) |entry| {
            if (std.mem.eql(u8, text, entry[0])) return entry[1];
        }
        return null;
    }
};

const opt_eol: u8 = 0;
const opt_nop: u8 = 1;
const opt_mss: u8 = 2;
const opt_mss_len: u8 = 4;
const opt_wscale: u8 = 3;
const opt_wscale_len: u8 = 3;
const opt_sack_perm: u8 = 4;
const opt_sack_perm_len: u8 = 2;
const opt_ts: u8 = 8;
const opt_ts_len: u8 = 10;

const mss_ethernet_hi: u8 = 0x05;
const mss_ethernet_lo: u8 = 0xb4;

const wscale_linux: u8 = 7;
const wscale_windows: u8 = 8;
const wscale_macos: u8 = 6;

const window_minimal: u16 = 1024;
const window_linux: u16 = 64240;
const window_windows: u16 = 64240;
const window_macos: u16 = 65535;

const syn_opts_masscan = [_]u8{ opt_mss, opt_mss_len, mss_ethernet_hi, mss_ethernet_lo };

const syn_opts_linux = [_]u8{
    opt_mss,       opt_mss_len, mss_ethernet_hi, mss_ethernet_lo,
    opt_sack_perm, opt_sack_perm_len,
    opt_ts,        opt_ts_len,  0,               0,
    0,             0,           0,               0,
    0,             0,           opt_nop,         opt_wscale,
    opt_wscale_len, wscale_linux,
};

const syn_opts_windows = [_]u8{
    opt_mss,     opt_mss_len,   mss_ethernet_hi, mss_ethernet_lo,
    opt_nop,     opt_wscale,    opt_wscale_len,  wscale_windows,
    opt_nop,     opt_nop,       opt_sack_perm,   opt_sack_perm_len,
};

const syn_opts_macos = [_]u8{
    opt_mss,     opt_mss_len,   mss_ethernet_hi, mss_ethernet_lo,
    opt_nop,     opt_wscale,    opt_wscale_len,  wscale_macos,
    opt_nop,     opt_nop,       opt_ts,          opt_ts_len,
    0,           0,             0,               0,
    0,           0,             0,               0,
    opt_sack_perm, opt_sack_perm_len, opt_eol,   opt_eol,
};

pub const max_syn_options_len: usize = syn_opts_macos.len;

pub const OsProfile = enum {
    none,
    masscan,
    linux,
    windows,
    macos,

    pub fn options(self: OsProfile) []const u8 {
        return switch (self) {
            .none => &.{},
            .masscan => &syn_opts_masscan,
            .linux => &syn_opts_linux,
            .windows => &syn_opts_windows,
            .macos => &syn_opts_macos,
        };
    }

    pub fn window(self: OsProfile) u16 {
        return switch (self) {
            .none, .masscan => window_minimal,
            .linux => window_linux,
            .windows => window_windows,
            .macos => window_macos,
        };
    }

    pub fn tsValOffset(self: OsProfile) ?usize {
        return switch (self) {
            .linux => 8,
            .macos => 12,
            else => null,
        };
    }

    pub fn variesIpId(self: OsProfile) bool {
        return switch (self) {
            .windows, .macos => true,
            else => false,
        };
    }

    pub fn parse(text: []const u8) ?OsProfile {
        const map = .{
            .{ "none", OsProfile.none },
            .{ "masscan", OsProfile.masscan },
            .{ "linux", OsProfile.linux },
            .{ "windows", OsProfile.windows },
            .{ "macos", OsProfile.macos },
        };
        inline for (map) |entry| {
            if (std.mem.eql(u8, text, entry[0])) return entry[1];
        }
        return null;
    }
};

pub fn optionKinds(opts: []const u8, out: []u8) usize {
    var i: usize = 0;
    var n: usize = 0;
    while (i < opts.len) {
        const kind = opts[i];
        if (kind == opt_eol) break;
        if (n < out.len) {
            out[n] = kind;
            n += 1;
        }
        if (kind == opt_nop) {
            i += 1;
            continue;
        }
        if (i + 1 >= opts.len) break;
        const len = opts[i + 1];
        if (len < 2) break;
        i += len;
    }
    return n;
}

comptime {
    std.debug.assert((@sizeOf(TcpHdr) + syn_opts_masscan.len) % 4 == 0);
    std.debug.assert((@sizeOf(TcpHdr) + syn_opts_linux.len) % 4 == 0);
    std.debug.assert((@sizeOf(TcpHdr) + syn_opts_windows.len) % 4 == 0);
    std.debug.assert((@sizeOf(TcpHdr) + syn_opts_macos.len) % 4 == 0);
    std.debug.assert(syn_opts_linux.len == 20);
    std.debug.assert(syn_opts_windows.len == 12);
    std.debug.assert(syn_opts_macos.len == 24);
}

test "header sizes are wire-exact" {
    try std.testing.expectEqual(@as(usize, 14), @sizeOf(EthHdr));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(Ipv4Hdr));
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(TcpHdr));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(UdpHdr));
}

test "RFC 1071 checksum matches the canonical IPv4 KAT (0xb861)" {
    const hdr = [_]u8{
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };
    try std.testing.expectEqual(@as(u16, 0xb861), checksum(&hdr));
}

test "SIMD checksum matches the canonical IPv4 KAT (0xb861)" {
    const hdr = [_]u8{
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7,
    };
    try std.testing.expectEqual(@as(u16, 0xb861), checksumSimd(&hdr));
}

test "SIMD checksum equals scalar checksum for every length 0..256" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_1624_517A);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    var len: usize = 0;
    while (len <= 256) : (len += 1) {
        rand.bytes(buf[0..len]);
        try std.testing.expectEqual(checksum(buf[0..len]), checksumSimd(buf[0..len]));
    }
}

test "RFC 1624 incremental update matches the RFC section 4 worked example" {
    try std.testing.expectEqual(@as(u16, 0x0000), incrementalUpdate(0xDD2F, 0x5555, 0x3285));
}

test "incremental update equals a full recompute for random single-word edits" {
    var prng = std.Random.DefaultPrng.init(0x1624_DEAD_BEEF_0001);
    const rand = prng.random();
    var hdr: [20]u8 = undefined;
    var trial: usize = 0;
    while (trial < 4096) : (trial += 1) {
        rand.bytes(&hdr);
        std.mem.writeInt(u16, hdr[10..12], 0, .big);
        const old_check = checksum(&hdr);
        const word_index = rand.uintLessThan(usize, 9) * 2;
        const off = if (word_index >= 10) word_index + 2 else word_index;
        const old_word = std.mem.readInt(u16, hdr[off..][0..2], .big);
        const new_word = rand.int(u16);
        std.mem.writeInt(u16, hdr[off..][0..2], new_word, .big);
        const full = checksum(&hdr);
        try std.testing.expectEqual(full, incrementalUpdate(old_check, old_word, new_word));
    }
}

test "tcpChecksum self-verifies: a segment with its correct checksum folds to 0" {
    var tcp = TcpHdr{
        .src_port = std.mem.nativeToBig(u16, 54321),
        .dst_port = std.mem.nativeToBig(u16, 80),
        .seq = std.mem.nativeToBig(u32, 0xdead_beef),
        .ack = 0,
        .data_off_ns = 0x50,
        .flags = 0x02,
        .window = std.mem.nativeToBig(u16, 1024),
        .checksum = 0,
        .urgent = 0,
    };
    const src = std.mem.nativeToBig(u32, 0x7f000001);
    const dst = std.mem.nativeToBig(u32, 0x7f000001);
    tcp.checksum = std.mem.nativeToBig(u16, tcpChecksum(src, dst, std.mem.asBytes(&tcp)));
    try std.testing.expectEqual(@as(u16, 0), tcpChecksum(src, dst, std.mem.asBytes(&tcp)));
}

test "udpChecksum self-verifies: a correct datagram re-sums to the 0xFFFF all-ones marker" {
    const src = std.mem.nativeToBig(u32, 0x7f000001);
    const dst = std.mem.nativeToBig(u32, 0x08080808);
    var seg: [12]u8 = undefined;
    var hdr = UdpHdr{
        .src_port = std.mem.nativeToBig(u16, 40000),
        .dst_port = std.mem.nativeToBig(u16, 53),
        .length = std.mem.nativeToBig(u16, 12),
        .checksum = 0,
    };
    @memcpy(seg[0..8], std.mem.asBytes(&hdr));
    @memcpy(seg[8..12], "abcd");
    const ck = udpChecksum(src, dst, &seg);
    try std.testing.expect(ck != 0);
    hdr.checksum = std.mem.nativeToBig(u16, ck);
    @memcpy(seg[0..8], std.mem.asBytes(&hdr));
    try std.testing.expectEqual(@as(u16, 0xffff), udpChecksum(src, dst, &seg));
}

test "udpChecksum maps a computed 0x0000 to 0xFFFF (IPv4 UDP quirk)" {
    try std.testing.expectEqual(@as(u16, 0xffff), udpChecksum(0, 0, &[_]u8{ 0xff, 0xec }));
    try std.testing.expect(udpChecksum(0, 0, &[_]u8{ 0xff, 0xec }) != 0);
}

test "the Linux SYN option chain decodes to the authoritative JA4T kind list 2-4-8-1-3" {
    var kinds: [16]u8 = undefined;
    const n = optionKinds(OsProfile.linux.options(), &kinds);
    try std.testing.expectEqualSlices(u8, &.{ 2, 4, 8, 1, 3 }, kinds[0..n]);
}

test "the Windows SYN option chain omits the timestamp (kinds 2-1-3-1-1-4)" {
    var kinds: [16]u8 = undefined;
    const n = optionKinds(OsProfile.windows.options(), &kinds);
    try std.testing.expectEqualSlices(u8, &.{ 2, 1, 3, 1, 1, 4 }, kinds[0..n]);
    for (kinds[0..n]) |k| try std.testing.expect(k != 8);
}

test "the macOS SYN option chain carries the timestamp before SACK (kinds 2-1-3-1-1-8-4)" {
    var kinds: [16]u8 = undefined;
    const n = optionKinds(OsProfile.macos.options(), &kinds);
    try std.testing.expectEqualSlices(u8, &.{ 2, 1, 3, 1, 1, 8, 4 }, kinds[0..n]);
}

test "the masscan profile sends exactly one MSS option and the fingerprintable 1024 window" {
    var kinds: [16]u8 = undefined;
    const n = optionKinds(OsProfile.masscan.options(), &kinds);
    try std.testing.expectEqualSlices(u8, &.{2}, kinds[0..n]);
    try std.testing.expectEqual(@as(u16, 1024), OsProfile.masscan.window());
}

test "the bare profile sends no options" {
    try std.testing.expectEqual(@as(usize, 0), OsProfile.none.options().len);
}

test "every OS profile advertises the ethernet MSS 1460" {
    for ([_]OsProfile{ .masscan, .linux, .windows, .macos }) |p| {
        const opts = p.options();
        try std.testing.expectEqual(opt_mss, opts[0]);
        try std.testing.expectEqual(@as(u16, 1460), std.mem.readInt(u16, opts[2..4], .big));
    }
}

test "the timestamp offset points at four zero bytes inside the option chain" {
    inline for ([_]OsProfile{ .linux, .macos }) |p| {
        const off = p.tsValOffset().?;
        const opts = p.options();
        try std.testing.expectEqual(opt_ts, opts[off - 2]);
        try std.testing.expectEqual(opt_ts_len, opts[off - 1]);
        try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, opts[off..][0..4], .big));
    }
    try std.testing.expect(OsProfile.windows.tsValOffset() == null);
}

test "scan-type probe flags match the RFC 793 flag combinations" {
    try std.testing.expectEqual(TcpFlag.syn, ScanType.syn.probeFlags());
    try std.testing.expectEqual(TcpFlag.fin, ScanType.fin.probeFlags());
    try std.testing.expectEqual(@as(u8, 0), ScanType.null_scan.probeFlags());
    try std.testing.expectEqual(TcpFlag.fin | TcpFlag.psh | TcpFlag.urg, ScanType.xmas.probeFlags());
    try std.testing.expectEqual(TcpFlag.fin | TcpFlag.ack, ScanType.maimon.probeFlags());
    try std.testing.expectEqual(TcpFlag.ack, ScanType.ack.probeFlags());
    try std.testing.expectEqual(TcpFlag.ack, ScanType.window.probeFlags());
}

test "ack-flag scans carry the cookie in the ack field, seq-scans in the seq field" {
    for ([_]ScanType{ .maimon, .ack, .window }) |st| try std.testing.expect(st.cookieInAck());
    for ([_]ScanType{ .syn, .fin, .null_scan, .xmas }) |st| try std.testing.expect(!st.cookieInAck());
}

test "seqConsumed reflects whether the probe advances the sequence space" {
    for ([_]ScanType{ .syn, .fin, .xmas }) |st| try std.testing.expectEqual(@as(u32, 1), st.seqConsumed());
    for ([_]ScanType{ .null_scan, .maimon, .ack, .window }) |st| try std.testing.expectEqual(@as(u32, 0), st.seqConsumed());
}

test "scan-type and OS-profile parsers round-trip the CLI spellings" {
    try std.testing.expectEqual(ScanType.null_scan, ScanType.parse("null").?);
    try std.testing.expectEqual(ScanType.window, ScanType.parse("window").?);
    try std.testing.expect(ScanType.parse("bogus") == null);
    try std.testing.expectEqual(OsProfile.macos, OsProfile.parse("macos").?);
    try std.testing.expect(OsProfile.parse("bogus") == null);
}
