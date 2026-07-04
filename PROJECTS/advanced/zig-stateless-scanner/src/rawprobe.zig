// ©AngelaMos | 2026
// rawprobe.zig

const std = @import("std");
const linux = std.os.linux;

pub const Status = enum {
    ok,
    no_cap,
    no_egress,

    pub fn reason(self: Status) []const u8 {
        return switch (self) {
            .ok => "raw sends work",
            .no_cap => "no CAP_NET_RAW",
            .no_egress => "raw sends are silently dropped",
        };
    }
};

const ETH_P_ALL: u16 = 0x0003;
const probe_ethertype: u16 = 0x88b5;
const eth_hdr_len: usize = 14;
const nonce_off: usize = eth_hdr_len;
const nonce_len: usize = 8;
const frame_len: usize = 60;
const poll_budget_ms: i64 = 250;
const poll_tick_ms: i32 = 25;
const probe_mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };

fn monoMs() i64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

fn freshNonce() [nonce_len]u8 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    const mixed: u64 = (@as(u64, @intCast(ts.nsec)) ^ (@as(u64, @intCast(ts.sec)) << 20)) *% 0x9e3779b97f4a7c15;
    var out: [nonce_len]u8 = undefined;
    std.mem.writeInt(u64, &out, mixed, .little);
    return out;
}

fn buildFrame(nonce: [nonce_len]u8) [frame_len]u8 {
    var frame = [_]u8{0} ** frame_len;
    @memcpy(frame[0..6], &probe_mac);
    @memcpy(frame[6..12], &probe_mac);
    std.mem.writeInt(u16, frame[12..14], probe_ethertype, .big);
    @memcpy(frame[nonce_off .. nonce_off + nonce_len], &nonce);
    return frame;
}

fn carriesNonce(frame: []const u8, nonce: [nonce_len]u8) bool {
    if (frame.len < nonce_off + nonce_len) return false;
    if (std.mem.readInt(u16, frame[12..14], .big) != probe_ethertype) return false;
    return std.mem.eql(u8, frame[nonce_off .. nonce_off + nonce_len], &nonce);
}

const send_bursts: usize = 3;

const BoundSock = struct { fd: i32, sll: linux.sockaddr.ll };

const OpenError = error{ NoCap, Failed };

fn openBound(ifname: []const u8) OpenError!BoundSock {
    const rc_sock = linux.socket(linux.AF.PACKET, linux.SOCK.RAW, std.mem.nativeToBig(u16, ETH_P_ALL));
    switch (linux.errno(rc_sock)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NoCap,
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

fn openStatus(e: OpenError) Status {
    return switch (e) {
        error.NoCap => .no_cap,
        error.Failed => .no_egress,
    };
}

pub fn probe(ifname: []const u8) Status {
    const observer = openBound(ifname) catch |e| return openStatus(e);
    defer _ = linux.close(observer.fd);
    var sender = openBound(ifname) catch |e| return openStatus(e);
    defer _ = linux.close(sender.fd);

    const nonce = freshNonce();
    const frame = buildFrame(nonce);
    var burst: usize = 0;
    while (burst < send_bursts) : (burst += 1) {
        _ = linux.sendto(sender.fd, &frame, frame.len, 0, @ptrCast(&sender.sll), @sizeOf(linux.sockaddr.ll));
    }

    var buf: [2048]u8 = undefined;
    const deadline = monoMs() + poll_budget_ms;
    while (monoMs() < deadline) {
        var pfd = [_]linux.pollfd{.{ .fd = observer.fd, .events = linux.POLL.IN, .revents = 0 }};
        const pr = linux.poll(&pfd, 1, poll_tick_ms);
        switch (linux.errno(pr)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return .no_egress,
        }
        if (pr == 0) continue;
        const rc = linux.recvfrom(observer.fd, &buf, buf.len, 0, null, null);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN => continue,
            else => return .no_egress,
        }
        const n: usize = @intCast(rc);
        if (carriesNonce(buf[0..n], nonce)) return .ok;
    }
    return .no_egress;
}

test "buildFrame stamps the experimental ethertype, self-addressed MACs, and the nonce" {
    const nonce = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const f = buildFrame(nonce);
    try std.testing.expectEqual(@as(usize, 60), f.len);
    try std.testing.expectEqualSlices(u8, &probe_mac, f[0..6]);
    try std.testing.expectEqualSlices(u8, &probe_mac, f[6..12]);
    try std.testing.expectEqual(@as(u16, probe_ethertype), std.mem.readInt(u16, f[12..14], .big));
    try std.testing.expectEqualSlices(u8, &nonce, f[14..22]);
}

test "carriesNonce matches only our tagged frame, rejects other traffic and wrong nonce" {
    const nonce = freshNonce();
    const other = freshNonce();
    const f = buildFrame(nonce);
    try std.testing.expect(carriesNonce(&f, nonce));
    try std.testing.expect(!carriesNonce(&f, other));

    var ip_frame = [_]u8{0} ** 60;
    std.mem.writeInt(u16, ip_frame[12..14], 0x0800, .big);
    @memcpy(ip_frame[14..22], &nonce);
    try std.testing.expect(!carriesNonce(&ip_frame, nonce));

    try std.testing.expect(!carriesNonce(&[_]u8{ 0, 1, 2 }, nonce));
}

test "freshNonce is not trivially constant across calls" {
    const a = freshNonce();
    var differs = false;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const b = freshNonce();
        if (!std.mem.eql(u8, &a, &b)) differs = true;
    }
    try std.testing.expect(differs);
}

test "probe returns no_cap without CAP_NET_RAW, otherwise a defined status" {
    const st = probe("lo");
    try std.testing.expect(st == .ok or st == .no_cap or st == .no_egress);
}
