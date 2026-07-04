// ©AngelaMos | 2026
// classify.zig

const std = @import("std");
const packet = @import("packet");
const cookie = @import("cookie");

pub const State = enum { open, closed, filtered, unfiltered };

pub const Result = struct {
    addr: packet.Addr,
    port: u16,
    state: State,

    pub fn v4(ip: u32, port: u16, state: State) Result {
        return .{ .addr = .{ .v4 = ip }, .port = port, .state = state };
    }

    pub fn v6(a: [16]u8, port: u16, state: State) Result {
        return .{ .addr = .{ .v6 = a }, .port = port, .state = state };
    }
};

const ETH_HDR_LEN: usize = 14;
const ETH_OFF_TYPE: usize = 12;
const ETHERTYPE_IPV4: u16 = 0x0800;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IP_MIN_IHL: usize = 20;
const IP_IHL_MASK: u8 = 0x0f;
const IP_WORD_BYTES: usize = 4;
const IP_OFF_PROTO: usize = 9;
const IP_OFF_SRC: usize = 12;
const IP_OFF_DST: usize = 16;

const INNER_TCP_MIN_LEN: usize = 8;
const INNER_UDP_MIN_LEN: usize = 8;

const UDP_OFF_SPORT: usize = 0;
const UDP_OFF_DPORT: usize = 2;
const UDP_MIN_LEN: usize = 8;

const ICMP_CODE_PORT_UNREACH: u8 = 3;

const TCP_OFF_SPORT: usize = 0;
const TCP_OFF_DPORT: usize = 2;
const TCP_OFF_SEQ: usize = 4;
const TCP_OFF_ACK: usize = 8;
const TCP_OFF_FLAGS: usize = 13;
const TCP_OFF_WINDOW: usize = 14;
const TCP_MIN_LEN: usize = 20;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;

const ICMP_HDR_LEN: usize = 8;
const ICMP_TYPE_DEST_UNREACH: u8 = 3;
const ICMP_OFF_TYPE: usize = 0;
const ICMP_OFF_CODE: usize = 1;

const ETHERTYPE_IPV6: u16 = 0x86dd;
const IP6_HDR_LEN: usize = 40;
const IP6_OFF_NEXT: usize = 6;
const IP6_OFF_SRC: usize = 8;
const IP6_OFF_DST: usize = 24;
const IPPROTO_ICMPV6: u8 = 58;
const ICMP6_TYPE_DEST_UNREACH: u8 = 1;
const ICMP6_ERR_HDR_LEN: usize = 8;

fn icmpCodeIsFilteredForSyn(code: u8) bool {
    return switch (code) {
        1, 2, 3, 9, 10, 13 => true,
        else => false,
    };
}

fn icmpCodeIsFilteredForUdp(code: u8) bool {
    return switch (code) {
        1, 2, 9, 10, 13 => true,
        else => false,
    };
}

fn ihlBytes(first_byte: u8) usize {
    return @as(usize, first_byte & IP_IHL_MASK) * IP_WORD_BYTES;
}

pub fn classify(frame: []const u8, ck: cookie.Cookie) ?Result {
    return classifyTcp(frame, ck, .syn);
}

pub fn classifyTcp(frame: []const u8, ck: cookie.Cookie, scan: packet.ScanType) ?Result {
    if (frame.len < ETH_HDR_LEN + IP_MIN_IHL) return null;
    if (std.mem.readInt(u16, frame[ETH_OFF_TYPE..][0..2], .big) != ETHERTYPE_IPV4) return null;

    const ip = ETH_HDR_LEN;
    const ihl = ihlBytes(frame[ip]);
    if (ihl < IP_MIN_IHL or frame.len < ip + ihl) return null;

    const proto = frame[ip + IP_OFF_PROTO];
    const ip_src = std.mem.readInt(u32, frame[ip + IP_OFF_SRC ..][0..4], .big);
    const ip_dst = std.mem.readInt(u32, frame[ip + IP_OFF_DST ..][0..4], .big);

    if (proto == IPPROTO_TCP) {
        const tcp = ip + ihl;
        if (frame.len < tcp + TCP_MIN_LEN) return null;
        const sport = std.mem.readInt(u16, frame[tcp + TCP_OFF_SPORT ..][0..2], .big);
        const dport = std.mem.readInt(u16, frame[tcp + TCP_OFF_DPORT ..][0..2], .big);
        const seqno = std.mem.readInt(u32, frame[tcp + TCP_OFF_SEQ ..][0..4], .big);
        const ackno = std.mem.readInt(u32, frame[tcp + TCP_OFF_ACK ..][0..4], .big);
        const flags = frame[tcp + TCP_OFF_FLAGS];
        const window = std.mem.readInt(u16, frame[tcp + TCP_OFF_WINDOW ..][0..2], .big);

        const cookie_val = ck.seq(ip_src, sport, ip_dst, dport);
        const has_rst = (flags & TCP_FLAG_RST) != 0;

        switch (scan) {
            .syn => {
                const is_synack = (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK);
                if (is_synack and ackno == cookie_val +% 1)
                    return Result.v4(ip_src, sport, .open);
                if (has_rst and (flags & TCP_FLAG_ACK) != 0 and ackno == cookie_val +% 1)
                    return Result.v4(ip_src, sport, .closed);
                return null;
            },
            .fin, .null_scan, .xmas => {
                if (has_rst and ackno == cookie_val +% scan.seqConsumed())
                    return Result.v4(ip_src, sport, .closed);
                return null;
            },
            .maimon => {
                if (has_rst and seqno == cookie_val)
                    return Result.v4(ip_src, sport, .closed);
                return null;
            },
            .ack => {
                if (has_rst and seqno == cookie_val)
                    return Result.v4(ip_src, sport, .unfiltered);
                return null;
            },
            .window => {
                if (has_rst and seqno == cookie_val)
                    return Result.v4(ip_src, sport, if (window != 0) .open else .closed);
                return null;
            },
        }
    }

    if (proto == IPPROTO_ICMP) {
        const icmp = ip + ihl;
        if (frame.len < icmp + ICMP_HDR_LEN) return null;
        if (frame[icmp + ICMP_OFF_TYPE] != ICMP_TYPE_DEST_UNREACH) return null;
        if (!icmpCodeIsFilteredForSyn(frame[icmp + ICMP_OFF_CODE])) return null;

        const inner = icmp + ICMP_HDR_LEN;
        if (frame.len < inner + IP_MIN_IHL) return null;
        const inner_ihl = ihlBytes(frame[inner]);
        if (inner_ihl < IP_MIN_IHL) return null;
        if (frame[inner + IP_OFF_PROTO] != IPPROTO_TCP) return null;

        const inner_src = std.mem.readInt(u32, frame[inner + IP_OFF_SRC ..][0..4], .big);
        const inner_dst = std.mem.readInt(u32, frame[inner + IP_OFF_DST ..][0..4], .big);
        const inner_tcp = inner + inner_ihl;
        if (frame.len < inner_tcp + INNER_TCP_MIN_LEN) return null;
        const inner_sport = std.mem.readInt(u16, frame[inner_tcp + TCP_OFF_SPORT ..][0..2], .big);
        const inner_dport = std.mem.readInt(u16, frame[inner_tcp + TCP_OFF_DPORT ..][0..2], .big);
        const inner_seq = std.mem.readInt(u32, frame[inner_tcp + TCP_OFF_SEQ ..][0..4], .big);

        if (inner_seq == ck.seq(inner_dst, inner_dport, inner_src, inner_sport))
            return Result.v4(inner_dst, inner_dport, .filtered);
        return null;
    }

    return null;
}

pub fn classifyUdp(frame: []const u8, ck: cookie.Cookie, base: u16, span: u16) ?Result {
    if (frame.len < ETH_HDR_LEN + IP_MIN_IHL) return null;
    if (std.mem.readInt(u16, frame[ETH_OFF_TYPE..][0..2], .big) != ETHERTYPE_IPV4) return null;

    const ip = ETH_HDR_LEN;
    const ihl = ihlBytes(frame[ip]);
    if (ihl < IP_MIN_IHL or frame.len < ip + ihl) return null;

    const proto = frame[ip + IP_OFF_PROTO];
    const ip_src = std.mem.readInt(u32, frame[ip + IP_OFF_SRC ..][0..4], .big);
    const ip_dst = std.mem.readInt(u32, frame[ip + IP_OFF_DST ..][0..4], .big);

    if (proto == IPPROTO_UDP) {
        const udp = ip + ihl;
        if (frame.len < udp + UDP_MIN_LEN) return null;
        const sport = std.mem.readInt(u16, frame[udp + UDP_OFF_SPORT ..][0..2], .big);
        const dport = std.mem.readInt(u16, frame[udp + UDP_OFF_DPORT ..][0..2], .big);
        if (dport == ck.udpSrcPort(ip_src, sport, ip_dst, base, span))
            return Result.v4(ip_src, sport, .open);
        return null;
    }

    if (proto == IPPROTO_ICMP) {
        const icmp = ip + ihl;
        if (frame.len < icmp + ICMP_HDR_LEN) return null;
        if (frame[icmp + ICMP_OFF_TYPE] != ICMP_TYPE_DEST_UNREACH) return null;
        const code = frame[icmp + ICMP_OFF_CODE];
        const state: State = if (code == ICMP_CODE_PORT_UNREACH)
            .closed
        else if (icmpCodeIsFilteredForUdp(code))
            .filtered
        else
            return null;

        const inner = icmp + ICMP_HDR_LEN;
        if (frame.len < inner + IP_MIN_IHL) return null;
        const inner_ihl = ihlBytes(frame[inner]);
        if (inner_ihl < IP_MIN_IHL) return null;
        if (frame[inner + IP_OFF_PROTO] != IPPROTO_UDP) return null;

        const inner_src = std.mem.readInt(u32, frame[inner + IP_OFF_SRC ..][0..4], .big);
        const inner_dst = std.mem.readInt(u32, frame[inner + IP_OFF_DST ..][0..4], .big);
        const inner_udp = inner + inner_ihl;
        if (frame.len < inner_udp + INNER_UDP_MIN_LEN) return null;
        const inner_sport = std.mem.readInt(u16, frame[inner_udp + UDP_OFF_SPORT ..][0..2], .big);
        const inner_dport = std.mem.readInt(u16, frame[inner_udp + UDP_OFF_DPORT ..][0..2], .big);

        if (inner_sport == ck.udpSrcPort(inner_dst, inner_dport, inner_src, base, span))
            return Result.v4(inner_dst, inner_dport, state);
        return null;
    }

    return null;
}

pub fn classifyTcp6(frame: []const u8, ck: cookie.Cookie, scan: packet.ScanType) ?Result {
    if (frame.len < ETH_HDR_LEN + IP6_HDR_LEN) return null;
    if (std.mem.readInt(u16, frame[ETH_OFF_TYPE..][0..2], .big) != ETHERTYPE_IPV6) return null;

    const ip = ETH_HDR_LEN;
    const next = frame[ip + IP6_OFF_NEXT];
    const src: [16]u8 = frame[ip + IP6_OFF_SRC ..][0..16].*;
    const dst: [16]u8 = frame[ip + IP6_OFF_DST ..][0..16].*;

    if (next == IPPROTO_TCP) {
        const tcp = ip + IP6_HDR_LEN;
        if (frame.len < tcp + TCP_MIN_LEN) return null;
        const sport = std.mem.readInt(u16, frame[tcp + TCP_OFF_SPORT ..][0..2], .big);
        const dport = std.mem.readInt(u16, frame[tcp + TCP_OFF_DPORT ..][0..2], .big);
        const seqno = std.mem.readInt(u32, frame[tcp + TCP_OFF_SEQ ..][0..4], .big);
        const ackno = std.mem.readInt(u32, frame[tcp + TCP_OFF_ACK ..][0..4], .big);
        const flags = frame[tcp + TCP_OFF_FLAGS];
        const window = std.mem.readInt(u16, frame[tcp + TCP_OFF_WINDOW ..][0..2], .big);

        const cookie_val = ck.seq6(src, sport, dst, dport);
        const has_rst = (flags & TCP_FLAG_RST) != 0;

        switch (scan) {
            .syn => {
                const is_synack = (flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK);
                if (is_synack and ackno == cookie_val +% 1)
                    return Result.v6(src, sport, .open);
                if (has_rst and (flags & TCP_FLAG_ACK) != 0 and ackno == cookie_val +% 1)
                    return Result.v6(src, sport, .closed);
                return null;
            },
            .fin, .null_scan, .xmas => {
                if (has_rst and ackno == cookie_val +% scan.seqConsumed())
                    return Result.v6(src, sport, .closed);
                return null;
            },
            .maimon => {
                if (has_rst and seqno == cookie_val)
                    return Result.v6(src, sport, .closed);
                return null;
            },
            .ack => {
                if (has_rst and seqno == cookie_val)
                    return Result.v6(src, sport, .unfiltered);
                return null;
            },
            .window => {
                if (has_rst and seqno == cookie_val)
                    return Result.v6(src, sport, if (window != 0) .open else .closed);
                return null;
            },
        }
    }

    if (next == IPPROTO_ICMPV6) {
        const icmp = ip + IP6_HDR_LEN;
        if (frame.len < icmp + ICMP6_ERR_HDR_LEN) return null;
        if (frame[icmp + ICMP_OFF_TYPE] != ICMP6_TYPE_DEST_UNREACH) return null;

        const inner = icmp + ICMP6_ERR_HDR_LEN;
        if (frame.len < inner + IP6_HDR_LEN) return null;
        if (frame[inner + IP6_OFF_NEXT] != IPPROTO_TCP) return null;

        const inner_src: [16]u8 = frame[inner + IP6_OFF_SRC ..][0..16].*;
        const inner_dst: [16]u8 = frame[inner + IP6_OFF_DST ..][0..16].*;
        const inner_tcp = inner + IP6_HDR_LEN;
        if (frame.len < inner_tcp + INNER_TCP_MIN_LEN) return null;
        const inner_sport = std.mem.readInt(u16, frame[inner_tcp + TCP_OFF_SPORT ..][0..2], .big);
        const inner_dport = std.mem.readInt(u16, frame[inner_tcp + TCP_OFF_DPORT ..][0..2], .big);
        const inner_seq = std.mem.readInt(u32, frame[inner_tcp + TCP_OFF_SEQ ..][0..4], .big);

        if (inner_seq == ck.seq6(inner_dst, inner_dport, inner_src, inner_sport))
            return Result.v6(inner_dst, inner_dport, .filtered);
        return null;
    }

    return null;
}

pub const TcpClassifier = struct {
    ck: cookie.Cookie,
    scan: packet.ScanType = .syn,

    pub fn match(self: TcpClassifier, frame: []const u8) ?Result {
        return classifyTcp(frame, self.ck, self.scan);
    }
};

pub const TcpClassifier6 = struct {
    ck: cookie.Cookie,
    scan: packet.ScanType = .syn,

    pub fn match(self: TcpClassifier6, frame: []const u8) ?Result {
        return classifyTcp6(frame, self.ck, self.scan);
    }
};

pub const UdpClassifier = struct {
    ck: cookie.Cookie,
    base: u16,
    span: u16,

    pub fn match(self: UdpClassifier, frame: []const u8) ?Result {
        return classifyUdp(frame, self.ck, self.base, self.span);
    }
};

comptime {
    std.debug.assert(@sizeOf(packet.EthHdr) == ETH_HDR_LEN);
    std.debug.assert(@sizeOf(packet.Ipv4Hdr) == IP_MIN_IHL);
    std.debug.assert(@sizeOf(packet.TcpHdr) == TCP_MIN_LEN);
    std.debug.assert(@sizeOf(packet.UdpHdr) == UDP_MIN_LEN);
}

const test_key = [16]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

const our_ip: u32 = 0x0a000001;
const our_port: u16 = 40000;
const their_ip: u32 = 0x08080808;
const their_port: u16 = 80;

fn buildTcpReply(buf: *[54]u8, ip_src: u32, ip_dst: u32, sport: u16, dport: u16, seq: u32, ack: u32, flags: u8) void {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV4, .big);
    buf[ETH_HDR_LEN] = 0x45;
    buf[ETH_HDR_LEN + IP_OFF_PROTO] = IPPROTO_TCP;
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_SRC ..][0..4], ip_src, .big);
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_DST ..][0..4], ip_dst, .big);
    const tcp = ETH_HDR_LEN + IP_MIN_IHL;
    std.mem.writeInt(u16, buf[tcp + TCP_OFF_SPORT ..][0..2], sport, .big);
    std.mem.writeInt(u16, buf[tcp + TCP_OFF_DPORT ..][0..2], dport, .big);
    std.mem.writeInt(u32, buf[tcp + TCP_OFF_SEQ ..][0..4], seq, .big);
    std.mem.writeInt(u32, buf[tcp + TCP_OFF_ACK ..][0..4], ack, .big);
    buf[tcp + TCP_OFF_FLAGS] = flags;
}

fn buildIcmpUnreach(buf: *[128]u8, code: u8, inner_src: u32, inner_dst: u32, inner_sport: u16, inner_dport: u16, inner_seq: u32) usize {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV4, .big);
    buf[ETH_HDR_LEN] = 0x45;
    buf[ETH_HDR_LEN + IP_OFF_PROTO] = IPPROTO_ICMP;
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_SRC ..][0..4], inner_dst, .big);
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_DST ..][0..4], inner_src, .big);
    const icmp = ETH_HDR_LEN + IP_MIN_IHL;
    buf[icmp + ICMP_OFF_TYPE] = ICMP_TYPE_DEST_UNREACH;
    buf[icmp + ICMP_OFF_CODE] = code;
    const inner = icmp + ICMP_HDR_LEN;
    buf[inner] = 0x45;
    buf[inner + IP_OFF_PROTO] = IPPROTO_TCP;
    std.mem.writeInt(u32, buf[inner + IP_OFF_SRC ..][0..4], inner_src, .big);
    std.mem.writeInt(u32, buf[inner + IP_OFF_DST ..][0..4], inner_dst, .big);
    const inner_tcp = inner + IP_MIN_IHL;
    std.mem.writeInt(u16, buf[inner_tcp + TCP_OFF_SPORT ..][0..2], inner_sport, .big);
    std.mem.writeInt(u16, buf[inner_tcp + TCP_OFF_DPORT ..][0..2], inner_dport, .big);
    std.mem.writeInt(u32, buf[inner_tcp + TCP_OFF_SEQ ..][0..4], inner_seq, .big);
    return inner_tcp + ICMP_HDR_LEN;
}

test "validated SYN-ACK classifies as open" {
    const ck = cookie.Cookie.init(test_key);
    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0xCAFEBABE, our_seq +% 1, TCP_FLAG_SYN | TCP_FLAG_ACK);
    const r = classify(&f, ck).?;
    try std.testing.expectEqual(State.open, r.state);
    try std.testing.expectEqual(their_ip, r.addr.v4);
    try std.testing.expectEqual(their_port, r.port);
}

test "SYN-ACK with a wrong ack is rejected (anti-spoof)" {
    const ck = cookie.Cookie.init(test_key);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0xCAFEBABE, 0xDEADBEEF, TCP_FLAG_SYN | TCP_FLAG_ACK);
    try std.testing.expect(classify(&f, ck) == null);
}

test "validated RST/ACK classifies as closed" {
    const ck = cookie.Cookie.init(test_key);
    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0, our_seq +% 1, TCP_FLAG_RST | TCP_FLAG_ACK);
    const r = classify(&f, ck).?;
    try std.testing.expectEqual(State.closed, r.state);
    try std.testing.expectEqual(their_ip, r.addr.v4);
    try std.testing.expectEqual(their_port, r.port);
}

test "RST/ACK with a wrong ack is rejected" {
    const ck = cookie.Cookie.init(test_key);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0, 0x11112222, TCP_FLAG_RST | TCP_FLAG_ACK);
    try std.testing.expect(classify(&f, ck) == null);
}

test "bare RST without ACK is dropped as unvalidated" {
    const ck = cookie.Cookie.init(test_key);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0, 0, TCP_FLAG_RST);
    try std.testing.expect(classify(&f, ck) == null);
}

test "validated ICMP dest-unreachable classifies as filtered" {
    const ck = cookie.Cookie.init(test_key);
    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [128]u8 = undefined;
    const len = buildIcmpUnreach(&f, 3, our_ip, their_ip, our_port, their_port, our_seq);
    const r = classify(f[0..len], ck).?;
    try std.testing.expectEqual(State.filtered, r.state);
    try std.testing.expectEqual(their_ip, r.addr.v4);
    try std.testing.expectEqual(their_port, r.port);
}

test "ICMP with a mismatched inner seq is rejected" {
    const ck = cookie.Cookie.init(test_key);
    var f: [128]u8 = undefined;
    const len = buildIcmpUnreach(&f, 3, our_ip, their_ip, our_port, their_port, 0x99999999);
    try std.testing.expect(classify(f[0..len], ck) == null);
}

test "ICMP with a non-filtered code is ignored" {
    const ck = cookie.Cookie.init(test_key);
    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [128]u8 = undefined;
    const len = buildIcmpUnreach(&f, 4, our_ip, their_ip, our_port, their_port, our_seq);
    try std.testing.expect(classify(f[0..len], ck) == null);
}

test "non-IPv4 ethertype is ignored" {
    const ck = cookie.Cookie.init(test_key);
    var f: [54]u8 = undefined;
    buildTcpReply(&f, their_ip, our_ip, their_port, our_port, 0, 0, TCP_FLAG_SYN | TCP_FLAG_ACK);
    std.mem.writeInt(u16, f[ETH_OFF_TYPE..][0..2], 0x0806, .big);
    try std.testing.expect(classify(&f, ck) == null);
}

test "runt frames return null instead of reading out of bounds" {
    const ck = cookie.Cookie.init(test_key);
    var tiny = [_]u8{0} ** 20;
    try std.testing.expect(classify(&tiny, ck) == null);
    var empty = [_]u8{};
    try std.testing.expect(classify(&empty, ck) == null);
}

const udp_base: u16 = 40000;
const udp_span: u16 = 8192;
const udp_port: u16 = 53;

fn buildUdpReply(buf: *[42]u8, ip_src: u32, ip_dst: u32, sport: u16, dport: u16) void {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV4, .big);
    buf[ETH_HDR_LEN] = 0x45;
    buf[ETH_HDR_LEN + IP_OFF_PROTO] = IPPROTO_UDP;
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_SRC ..][0..4], ip_src, .big);
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_DST ..][0..4], ip_dst, .big);
    const udp = ETH_HDR_LEN + IP_MIN_IHL;
    std.mem.writeInt(u16, buf[udp + UDP_OFF_SPORT ..][0..2], sport, .big);
    std.mem.writeInt(u16, buf[udp + UDP_OFF_DPORT ..][0..2], dport, .big);
}

fn buildIcmpUdpUnreach(buf: *[128]u8, code: u8, inner_src: u32, inner_dst: u32, inner_sport: u16, inner_dport: u16) usize {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV4, .big);
    buf[ETH_HDR_LEN] = 0x45;
    buf[ETH_HDR_LEN + IP_OFF_PROTO] = IPPROTO_ICMP;
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_SRC ..][0..4], inner_dst, .big);
    std.mem.writeInt(u32, buf[ETH_HDR_LEN + IP_OFF_DST ..][0..4], inner_src, .big);
    const icmp = ETH_HDR_LEN + IP_MIN_IHL;
    buf[icmp + ICMP_OFF_TYPE] = ICMP_TYPE_DEST_UNREACH;
    buf[icmp + ICMP_OFF_CODE] = code;
    const inner = icmp + ICMP_HDR_LEN;
    buf[inner] = 0x45;
    buf[inner + IP_OFF_PROTO] = IPPROTO_UDP;
    std.mem.writeInt(u32, buf[inner + IP_OFF_SRC ..][0..4], inner_src, .big);
    std.mem.writeInt(u32, buf[inner + IP_OFF_DST ..][0..4], inner_dst, .big);
    const inner_udp = inner + IP_MIN_IHL;
    std.mem.writeInt(u16, buf[inner_udp + UDP_OFF_SPORT ..][0..2], inner_sport, .big);
    std.mem.writeInt(u16, buf[inner_udp + UDP_OFF_DPORT ..][0..2], inner_dport, .big);
    return inner_udp + INNER_UDP_MIN_LEN;
}

test "validated UDP response classifies as open" {
    const ck = cookie.Cookie.init(test_key);
    const our_src = ck.udpSrcPort(their_ip, udp_port, our_ip, udp_base, udp_span);
    var f: [42]u8 = undefined;
    buildUdpReply(&f, their_ip, our_ip, udp_port, our_src);
    const r = classifyUdp(&f, ck, udp_base, udp_span).?;
    try std.testing.expectEqual(State.open, r.state);
    try std.testing.expectEqual(their_ip, r.addr.v4);
    try std.testing.expectEqual(udp_port, r.port);
}

test "UDP response to a non-cookie destination port is rejected (anti-spoof)" {
    const ck = cookie.Cookie.init(test_key);
    var f: [42]u8 = undefined;
    buildUdpReply(&f, their_ip, our_ip, udp_port, 12345);
    try std.testing.expect(classifyUdp(&f, ck, udp_base, udp_span) == null);
}

test "validated ICMP port-unreachable (type 3 code 3) classifies as closed for UDP" {
    const ck = cookie.Cookie.init(test_key);
    const our_src = ck.udpSrcPort(their_ip, udp_port, our_ip, udp_base, udp_span);
    var f: [128]u8 = undefined;
    const len = buildIcmpUdpUnreach(&f, 3, our_ip, their_ip, our_src, udp_port);
    const r = classifyUdp(f[0..len], ck, udp_base, udp_span).?;
    try std.testing.expectEqual(State.closed, r.state);
    try std.testing.expectEqual(their_ip, r.addr.v4);
    try std.testing.expectEqual(udp_port, r.port);
}

test "validated ICMP type 3 code 1 classifies as filtered for UDP" {
    const ck = cookie.Cookie.init(test_key);
    const our_src = ck.udpSrcPort(their_ip, udp_port, our_ip, udp_base, udp_span);
    var f: [128]u8 = undefined;
    const len = buildIcmpUdpUnreach(&f, 1, our_ip, their_ip, our_src, udp_port);
    const r = classifyUdp(f[0..len], ck, udp_base, udp_span).?;
    try std.testing.expectEqual(State.filtered, r.state);
    try std.testing.expectEqual(their_ip, r.addr.v4);
    try std.testing.expectEqual(udp_port, r.port);
}

test "ICMP UDP-unreachable with a mismatched inner source port is rejected" {
    const ck = cookie.Cookie.init(test_key);
    var f: [128]u8 = undefined;
    const len = buildIcmpUdpUnreach(&f, 3, our_ip, their_ip, 9999, udp_port);
    try std.testing.expect(classifyUdp(f[0..len], ck, udp_base, udp_span) == null);
}

test "ICMP UDP-unreachable with a non-unreachable type is ignored" {
    const ck = cookie.Cookie.init(test_key);
    const our_src = ck.udpSrcPort(their_ip, udp_port, our_ip, udp_base, udp_span);
    var f: [128]u8 = undefined;
    const len = buildIcmpUdpUnreach(&f, 3, our_ip, their_ip, our_src, udp_port);
    f[ETH_HDR_LEN + IP_MIN_IHL + ICMP_OFF_TYPE] = 8;
    try std.testing.expect(classifyUdp(f[0..len], ck, udp_base, udp_span) == null);
}

test "classifyUdp ignores non-IPv4 and runt frames" {
    const ck = cookie.Cookie.init(test_key);
    var f: [42]u8 = undefined;
    buildUdpReply(&f, their_ip, our_ip, udp_port, ck.udpSrcPort(their_ip, udp_port, our_ip, udp_base, udp_span));
    std.mem.writeInt(u16, f[ETH_OFF_TYPE..][0..2], 0x0806, .big);
    try std.testing.expect(classifyUdp(&f, ck, udp_base, udp_span) == null);
    var tiny = [_]u8{0} ** 20;
    try std.testing.expect(classifyUdp(&tiny, ck, udp_base, udp_span) == null);
}

test "the same ICMP code 3 is closed for UDP but filtered for a TCP SYN scan" {
    const ck = cookie.Cookie.init(test_key);
    const our_src = ck.udpSrcPort(their_ip, udp_port, our_ip, udp_base, udp_span);
    var f: [128]u8 = undefined;
    const len = buildIcmpUdpUnreach(&f, 3, our_ip, their_ip, our_src, udp_port);
    try std.testing.expectEqual(State.closed, classifyUdp(f[0..len], ck, udp_base, udp_span).?.state);
    try std.testing.expect(icmpCodeIsFilteredForSyn(3));
    try std.testing.expect(!icmpCodeIsFilteredForUdp(3));
}

test "classifier adapters route each frame to the right protocol path" {
    const ck = cookie.Cookie.init(test_key);

    const our_seq = ck.seq(their_ip, their_port, our_ip, our_port);
    var tcp_f: [54]u8 = undefined;
    buildTcpReply(&tcp_f, their_ip, our_ip, their_port, our_port, 0xCAFEBABE, our_seq +% 1, TCP_FLAG_SYN | TCP_FLAG_ACK);
    const tcp_clf = TcpClassifier{ .ck = ck };
    try std.testing.expectEqual(State.open, tcp_clf.match(&tcp_f).?.state);

    const our_src = ck.udpSrcPort(their_ip, udp_port, our_ip, udp_base, udp_span);
    var udp_f: [42]u8 = undefined;
    buildUdpReply(&udp_f, their_ip, our_ip, udp_port, our_src);
    const udp_clf = UdpClassifier{ .ck = ck, .base = udp_base, .span = udp_span };
    try std.testing.expectEqual(State.open, udp_clf.match(&udp_f).?.state);
    try std.testing.expect(tcp_clf.match(&udp_f) == null);
}

fn flagScanReply(buf: *[54]u8, seq: u32, ack: u32, flags: u8) void {
    buildTcpReply(buf, their_ip, our_ip, their_port, our_port, seq, ack, flags);
}

test "FIN and Xmas scans classify a cookie-1 RST as closed and reject a wrong ack" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;

    for ([_]packet.ScanType{ .fin, .xmas }) |st| {
        flagScanReply(&f, 0, cv +% 1, TCP_FLAG_RST | TCP_FLAG_ACK);
        try std.testing.expectEqual(State.closed, classifyTcp(&f, ck, st).?.state);
        flagScanReply(&f, 0, cv +% 5, TCP_FLAG_RST | TCP_FLAG_ACK);
        try std.testing.expect(classifyTcp(&f, ck, st) == null);
    }
}

test "NULL scan expects the RST ack to equal the cookie exactly (no sequence consumed)" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    flagScanReply(&f, 0, cv, TCP_FLAG_RST | TCP_FLAG_ACK);
    try std.testing.expectEqual(State.closed, classifyTcp(&f, ck, .null_scan).?.state);
    flagScanReply(&f, 0, cv +% 1, TCP_FLAG_RST | TCP_FLAG_ACK);
    try std.testing.expect(classifyTcp(&f, ck, .null_scan) == null);
}

test "a FIN scan does not classify a SYN-ACK (open ports stay silent)" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    flagScanReply(&f, 0xCAFEBABE, cv +% 1, TCP_FLAG_SYN | TCP_FLAG_ACK);
    try std.testing.expect(classifyTcp(&f, ck, .fin) == null);
}

test "Maimon scan matches the RST sequence to the ack-field cookie" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    flagScanReply(&f, cv, 0, TCP_FLAG_RST);
    try std.testing.expectEqual(State.closed, classifyTcp(&f, ck, .maimon).?.state);
    flagScanReply(&f, cv +% 3, 0, TCP_FLAG_RST);
    try std.testing.expect(classifyTcp(&f, ck, .maimon) == null);
}

test "ACK scan reports a validated RST as unfiltered, not open or closed" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    flagScanReply(&f, cv, 0, TCP_FLAG_RST);
    try std.testing.expectEqual(State.unfiltered, classifyTcp(&f, ck, .ack).?.state);
    flagScanReply(&f, cv +% 7, 0, TCP_FLAG_RST);
    try std.testing.expect(classifyTcp(&f, ck, .ack) == null);
}

test "Window scan reads the RST window: nonzero is open, zero is closed" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq(their_ip, their_port, our_ip, our_port);
    const win_off = ETH_HDR_LEN + IP_MIN_IHL + TCP_OFF_WINDOW;
    var f: [54]u8 = undefined;

    flagScanReply(&f, cv, 0, TCP_FLAG_RST);
    std.mem.writeInt(u16, f[win_off..][0..2], 8192, .big);
    try std.testing.expectEqual(State.open, classifyTcp(&f, ck, .window).?.state);

    flagScanReply(&f, cv, 0, TCP_FLAG_RST);
    std.mem.writeInt(u16, f[win_off..][0..2], 0, .big);
    try std.testing.expectEqual(State.closed, classifyTcp(&f, ck, .window).?.state);
}

test "the scan-type classifier adapter threads the mode into classifyTcp" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq(their_ip, their_port, our_ip, our_port);
    var f: [54]u8 = undefined;
    flagScanReply(&f, cv, 0, TCP_FLAG_RST);
    const ack_clf = TcpClassifier{ .ck = ck, .scan = .ack };
    try std.testing.expectEqual(State.unfiltered, ack_clf.match(&f).?.state);
    const syn_clf = TcpClassifier{ .ck = ck };
    try std.testing.expect(syn_clf.match(&f) == null);
}

const our_ip6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
const their_ip6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99 };
const our_port6: u16 = 40000;
const their_port6: u16 = 80;

fn buildTcp6Reply(buf: *[74]u8, src: [16]u8, dst: [16]u8, sport: u16, dport: u16, seq: u32, ack: u32, flags: u8) void {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV6, .big);
    buf[ETH_HDR_LEN] = 0x60;
    buf[ETH_HDR_LEN + IP6_OFF_NEXT] = IPPROTO_TCP;
    @memcpy(buf[ETH_HDR_LEN + IP6_OFF_SRC ..][0..16], &src);
    @memcpy(buf[ETH_HDR_LEN + IP6_OFF_DST ..][0..16], &dst);
    const tcp = ETH_HDR_LEN + IP6_HDR_LEN;
    std.mem.writeInt(u16, buf[tcp + TCP_OFF_SPORT ..][0..2], sport, .big);
    std.mem.writeInt(u16, buf[tcp + TCP_OFF_DPORT ..][0..2], dport, .big);
    std.mem.writeInt(u32, buf[tcp + TCP_OFF_SEQ ..][0..4], seq, .big);
    std.mem.writeInt(u32, buf[tcp + TCP_OFF_ACK ..][0..4], ack, .big);
    buf[tcp + TCP_OFF_FLAGS] = flags;
}

fn buildIcmp6Unreach(buf: *[122]u8, code: u8, inner_src: [16]u8, inner_dst: [16]u8, inner_sport: u16, inner_dport: u16, inner_seq: u32) usize {
    @memset(buf, 0);
    std.mem.writeInt(u16, buf[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV6, .big);
    buf[ETH_HDR_LEN] = 0x60;
    buf[ETH_HDR_LEN + IP6_OFF_NEXT] = IPPROTO_ICMPV6;
    const icmp = ETH_HDR_LEN + IP6_HDR_LEN;
    buf[icmp + ICMP_OFF_TYPE] = ICMP6_TYPE_DEST_UNREACH;
    buf[icmp + ICMP_OFF_CODE] = code;
    const inner = icmp + ICMP6_ERR_HDR_LEN;
    buf[inner] = 0x60;
    buf[inner + IP6_OFF_NEXT] = IPPROTO_TCP;
    @memcpy(buf[inner + IP6_OFF_SRC ..][0..16], &inner_src);
    @memcpy(buf[inner + IP6_OFF_DST ..][0..16], &inner_dst);
    const inner_tcp = inner + IP6_HDR_LEN;
    std.mem.writeInt(u16, buf[inner_tcp + TCP_OFF_SPORT ..][0..2], inner_sport, .big);
    std.mem.writeInt(u16, buf[inner_tcp + TCP_OFF_DPORT ..][0..2], inner_dport, .big);
    std.mem.writeInt(u32, buf[inner_tcp + TCP_OFF_SEQ ..][0..4], inner_seq, .big);
    return inner_tcp + INNER_TCP_MIN_LEN;
}

test "validated IPv6 SYN-ACK classifies as open with the responder address" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq6(their_ip6, their_port6, our_ip6, our_port6);
    var f: [74]u8 = undefined;
    buildTcp6Reply(&f, their_ip6, our_ip6, their_port6, our_port6, 0xCAFEBABE, cv +% 1, TCP_FLAG_SYN | TCP_FLAG_ACK);
    const r = classifyTcp6(&f, ck, .syn).?;
    try std.testing.expectEqual(State.open, r.state);
    try std.testing.expectEqualSlices(u8, &their_ip6, &r.addr.v6);
    try std.testing.expectEqual(their_port6, r.port);
}

test "IPv6 SYN-ACK with a wrong ack is rejected, RST/ACK is closed" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq6(their_ip6, their_port6, our_ip6, our_port6);
    var f: [74]u8 = undefined;
    buildTcp6Reply(&f, their_ip6, our_ip6, their_port6, our_port6, 0, 0xDEADBEEF, TCP_FLAG_SYN | TCP_FLAG_ACK);
    try std.testing.expect(classifyTcp6(&f, ck, .syn) == null);

    buildTcp6Reply(&f, their_ip6, our_ip6, their_port6, our_port6, 0, cv +% 1, TCP_FLAG_RST | TCP_FLAG_ACK);
    try std.testing.expectEqual(State.closed, classifyTcp6(&f, ck, .syn).?.state);
}

test "validated ICMPv6 destination-unreachable classifies as filtered for the probed target" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq6(their_ip6, their_port6, our_ip6, our_port6);
    var f: [122]u8 = undefined;
    const len = buildIcmp6Unreach(&f, 4, our_ip6, their_ip6, our_port6, their_port6, cv);
    const r = classifyTcp6(f[0..len], ck, .syn).?;
    try std.testing.expectEqual(State.filtered, r.state);
    try std.testing.expectEqualSlices(u8, &their_ip6, &r.addr.v6);
    try std.testing.expectEqual(their_port6, r.port);

    const bad = buildIcmp6Unreach(&f, 4, our_ip6, their_ip6, our_port6, their_port6, 0x99999999);
    try std.testing.expect(classifyTcp6(f[0..bad], ck, .syn) == null);
}

test "classifyTcp6 ignores IPv4 frames and runt frames" {
    const ck = cookie.Cookie.init(test_key);
    var f: [74]u8 = undefined;
    buildTcp6Reply(&f, their_ip6, our_ip6, their_port6, our_port6, 0, ck.seq6(their_ip6, their_port6, our_ip6, our_port6) +% 1, TCP_FLAG_SYN | TCP_FLAG_ACK);
    std.mem.writeInt(u16, f[ETH_OFF_TYPE..][0..2], ETHERTYPE_IPV4, .big);
    try std.testing.expect(classifyTcp6(&f, ck, .syn) == null);
    var tiny = [_]u8{0} ** 30;
    try std.testing.expect(classifyTcp6(&tiny, ck, .syn) == null);
}

test "the IPv6 classifier adapter threads the scan mode" {
    const ck = cookie.Cookie.init(test_key);
    const cv = ck.seq6(their_ip6, their_port6, our_ip6, our_port6);
    var f: [74]u8 = undefined;
    buildTcp6Reply(&f, their_ip6, our_ip6, their_port6, our_port6, 0xCAFEBABE, cv +% 1, TCP_FLAG_SYN | TCP_FLAG_ACK);
    const clf = TcpClassifier6{ .ck = ck };
    try std.testing.expectEqual(State.open, clf.match(&f).?.state);
}
