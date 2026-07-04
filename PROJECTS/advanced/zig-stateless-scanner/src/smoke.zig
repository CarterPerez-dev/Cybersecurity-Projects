// ©AngelaMos | 2026
// smoke.zig

const std = @import("std");
const linux = std.os.linux;
const packet = @import("packet");

fn build_syn(dst_port: u16) [54]u8 {
    var frame: [54]u8 = undefined;

    const eth = packet.EthHdr{
        .dst = .{0} ** 6,
        .src = .{0} ** 6,
        .ethertype = std.mem.nativeToBig(u16, 0x0800),
    };
    @memcpy(frame[0..14], std.mem.asBytes(&eth));

    var ip = packet.Ipv4Hdr{
        .version_ihl = 0x45,
        .tos = 0,
        .total_len = std.mem.nativeToBig(u16, 40),
        .id = 0,
        .flags_frag = std.mem.nativeToBig(u16, 0x4000),
        .ttl = 64,
        .protocol = 6,
        .checksum = 0,
        .src = std.mem.nativeToBig(u32, 0x7f000001),
        .dst = std.mem.nativeToBig(u32, 0x7f000001),
    };
    ip.checksum = std.mem.nativeToBig(u16, packet.checksum(std.mem.asBytes(&ip)));
    @memcpy(frame[14..34], std.mem.asBytes(&ip));

    var tcp = packet.TcpHdr{
        .src_port = std.mem.nativeToBig(u16, 54321),
        .dst_port = std.mem.nativeToBig(u16, dst_port),
        .seq = std.mem.nativeToBig(u32, 0xdead_beef),
        .ack = 0,
        .data_off_ns = 0x50,
        .flags = 0x02,
        .window = std.mem.nativeToBig(u16, 1024),
        .checksum = 0,
        .urgent = 0,
    };

    tcp.checksum = std.mem.nativeToBig(u16, packet.tcpChecksum(ip.src, ip.dst, std.mem.asBytes(&tcp)));
    @memcpy(frame[34..54], std.mem.asBytes(&tcp));

    return frame;
}

pub fn run(io: std.Io, ifname: []const u8) !void {
    var buf: [256]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;

    const rc_sock = linux.socket(
        linux.AF.PACKET,
        linux.SOCK.RAW,
        std.mem.nativeToBig(u16, @as(u16, linux.ETH.P.IP)),
    );
    switch (linux.errno(rc_sock)) {
        .SUCCESS => {},
        .PERM, .ACCES => {
            try out.writeAll("smoke: need CAP_NET_RAW. Grant it once, then re-run (no sudo):\n  sudo setcap cap_net_raw,cap_net_admin=eip ./zig-out/bin/zingela\n  ./zig-out/bin/zingela smoke\nSkipping.\n");
            try out.flush();
            return;
        },
        else => |e| {
            try out.print("smoke: socket() failed: {s}\n", .{@tagName(e)});
            try out.flush();
            return error.SocketFailed;
        },
    }
    const fd: i32 = @intCast(rc_sock);
    defer _ = linux.close(fd);

    var ifr = std.mem.zeroes(linux.ifreq);
    if (ifname.len >= ifr.ifrn.name.len) {
        try out.print("smoke: interface name too long: {s}\n", .{ifname});
        try out.flush();
        return error.IfNameTooLong;
    }
    @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
    if (linux.errno(linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&ifr))) != .SUCCESS) {
        try out.print("smoke: SIOCGIFINDEX failed for {s}\n", .{ifname});
        try out.flush();
        return error.IfIndexFailed;
    }
    const ifindex: i32 = ifr.ifru.ivalue;

    var sll = std.mem.zeroes(linux.sockaddr.ll);
    sll.family = linux.AF.PACKET;
    sll.protocol = std.mem.nativeToBig(u16, @as(u16, linux.ETH.P.IP));
    sll.ifindex = ifindex;
    if (linux.errno(linux.bind(fd, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll))) != .SUCCESS) {
        try out.writeAll("smoke: bind() failed\n");
        try out.flush();
        return error.BindFailed;
    }

    const frame = build_syn(80);
    const rc_send = linux.sendto(fd, &frame, frame.len, 0, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll));
    if (linux.errno(rc_send) != .SUCCESS) {
        try out.writeAll("smoke: sendto() failed\n");
        try out.flush();
        return error.SendFailed;
    }

    try out.print("smoke: OK. Sent {d} bytes (one SYN -> 127.0.0.1:80) on {s} via AF_PACKET.\n", .{ rc_send, ifname });
    try out.flush();
}

test "built SYN frame is 54 bytes and IP checksum self-verifies" {
    const frame = build_syn(80);
    try std.testing.expectEqual(@as(usize, 54), frame.len);
    try std.testing.expectEqual(@as(u16, 0), packet.checksum(frame[14..34]));
}
