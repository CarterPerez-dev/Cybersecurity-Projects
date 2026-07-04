// ©AngelaMos | 2026
// afpacket.zig

const std = @import("std");
const packet = @import("packet");

const TPACKET_ALIGNMENT: usize = 16;

fn tpacketAlign(x: usize) usize {
    return (x + TPACKET_ALIGNMENT - 1) & ~(TPACKET_ALIGNMENT - 1);
}

pub const tpacket2_hdr = extern struct {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [4]u8,
};

const TP_STATUS_AVAILABLE: u32 = 0;
const TP_STATUS_SEND_REQUEST: u32 = 1;
const DATA_OFFSET: usize = 32;

comptime {
    std.debug.assert(@sizeOf(tpacket2_hdr) == 32);
    std.debug.assert(DATA_OFFSET == tpacketAlign(@sizeOf(tpacket2_hdr)));
}

pub const Ring = struct {
    buf: []u8,
    frame_size: usize,
    frame_nr: usize,
    next: usize,

    pub fn init(buf: []u8, frame_size: usize, frame_nr: usize) Ring {
        return .{ .buf = buf, .frame_size = frame_size, .frame_nr = frame_nr, .next = 0 };
    }

    fn header(self: Ring, idx: usize) *tpacket2_hdr {
        return @ptrCast(@alignCast(self.buf.ptr + idx * self.frame_size));
    }

    pub fn reserve(self: *Ring) ?usize {
        const idx = self.next;
        const hdr = self.header(idx);
        if (@atomicLoad(u32, &hdr.tp_status, .monotonic) != TP_STATUS_AVAILABLE) return null;
        self.next = (self.next + 1) % self.frame_nr;
        return idx;
    }

    pub fn fill(self: *Ring, idx: usize, frame: []const u8) void {
        std.debug.assert(frame.len + DATA_OFFSET <= self.frame_size);
        const hdr = self.header(idx);
        const data = self.buf[idx * self.frame_size + DATA_OFFSET ..][0..frame.len];
        @memcpy(data, frame);
        hdr.tp_len = @intCast(frame.len);
        @atomicStore(u32, &hdr.tp_status, TP_STATUS_SEND_REQUEST, .monotonic);
    }
};

const linux = std.os.linux;

pub const OpenError = error{
    NeedCapNetRaw,
    SocketFailed,
    IfIndexFailed,
    SetSockOptFailed,
    MmapFailed,
    BindFailed,
};

pub const RingConfig = struct {
    frame_size: u32 = 2048,
    block_size: u32 = 1 << 22,
    block_nr: u32 = 4,
};

pub const Backend = struct {
    fd: i32,
    ring: Ring,
    map: []align(std.heap.page_size_min) u8,
    sll: linux.sockaddr.ll,

    pub fn open(ifname: []const u8, cfg: RingConfig) OpenError!Backend {
        const rc_sock = linux.socket(
            linux.AF.PACKET,
            linux.SOCK.RAW,
            std.mem.nativeToBig(u16, @as(u16, linux.ETH.P.IP)),
        );
        switch (linux.errno(rc_sock)) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.NeedCapNetRaw,
            else => return error.SocketFailed,
        }
        const fd: i32 = @intCast(rc_sock);
        errdefer _ = linux.close(fd);

        var ifr = std.mem.zeroes(linux.ifreq);
        if (ifname.len >= ifr.ifrn.name.len) return error.IfIndexFailed;
        @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
        if (linux.errno(linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&ifr))) != .SUCCESS)
            return error.IfIndexFailed;
        const ifindex: i32 = ifr.ifru.ivalue;

        var ver: u32 = @intFromEnum(linux.tpacket_versions.V2);
        if (linux.errno(linux.setsockopt(fd, linux.SOL.PACKET, linux.PACKET.VERSION, std.mem.asBytes(&ver), @sizeOf(u32))) != .SUCCESS)
            return error.SetSockOptFailed;

        const frame_nr = (cfg.block_size / cfg.frame_size) * cfg.block_nr;
        var req = linux.tpacket_req3{
            .block_size = cfg.block_size,
            .block_nr = cfg.block_nr,
            .frame_size = cfg.frame_size,
            .frame_nr = frame_nr,
            .retire_blk_tov = 0,
            .sizeof_priv = 0,
            .feature_req_word = 0,
        };
        if (linux.errno(linux.setsockopt(fd, linux.SOL.PACKET, linux.PACKET.TX_RING, std.mem.asBytes(&req), @sizeOf(@TypeOf(req)))) != .SUCCESS)
            return error.SetSockOptFailed;

        var bypass: u32 = 1;
        _ = linux.setsockopt(fd, linux.SOL.PACKET, linux.PACKET.QDISC_BYPASS, std.mem.asBytes(&bypass), @sizeOf(u32));

        const ring_sz: usize = @as(usize, cfg.block_size) * cfg.block_nr;
        const rc_map = linux.mmap(null, ring_sz, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED }, fd, 0);
        if (linux.errno(rc_map) != .SUCCESS) return error.MmapFailed;
        const map_ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(rc_map);
        const map = map_ptr[0..ring_sz];
        errdefer _ = linux.munmap(map.ptr, ring_sz);

        var sll = std.mem.zeroes(linux.sockaddr.ll);
        sll.family = linux.AF.PACKET;
        sll.protocol = std.mem.nativeToBig(u16, @as(u16, linux.ETH.P.IP));
        sll.ifindex = ifindex;
        if (linux.errno(linux.bind(fd, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll))) != .SUCCESS)
            return error.BindFailed;

        return .{
            .fd = fd,
            .ring = Ring.init(map, cfg.frame_size, frame_nr),
            .map = map,
            .sll = sll,
        };
    }

    pub fn submit(self: *Backend, frame: []const u8) bool {
        const idx = self.ring.reserve() orelse return false;
        self.ring.fill(idx, frame);
        return true;
    }

    pub fn kick(self: *Backend) void {
        var dummy: u8 = 0;
        _ = linux.sendto(self.fd, @ptrCast(&dummy), 0, 0, @ptrCast(&self.sll), @sizeOf(linux.sockaddr.ll));
    }

    pub fn close(self: *Backend) void {
        _ = linux.munmap(self.map.ptr, self.map.len);
        _ = linux.close(self.fd);
    }
};

test "tpacket2_hdr is the wire-exact 32 bytes" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(tpacket2_hdr));
}

test "Ring reserve cycles all frames then returns null when full" {
    const frame_size: usize = 2048;
    const frame_nr: usize = 4;
    const buf = try std.testing.allocator.alloc(u8, frame_size * frame_nr);
    defer std.testing.allocator.free(buf);
    @memset(buf, 0);
    var ring = Ring.init(buf, frame_size, frame_nr);

    var i: usize = 0;
    while (i < frame_nr) : (i += 1) {
        const idx = ring.reserve() orelse return error.UnexpectedFull;
        ring.fill(idx, &[_]u8{ 0xAA, 0xBB });
    }
    try std.testing.expect(ring.reserve() == null);
}

test "fill writes len, SEND_REQUEST status, and the frame bytes at the data offset" {
    const frame_size: usize = 2048;
    const buf = try std.testing.allocator.alloc(u8, frame_size);
    defer std.testing.allocator.free(buf);
    @memset(buf, 0);
    var ring = Ring.init(buf, frame_size, 1);

    const idx = ring.reserve().?;
    const payload = [_]u8{ 1, 2, 3, 4, 5 };
    ring.fill(idx, &payload);

    const hdr: *const tpacket2_hdr = @ptrCast(@alignCast(buf.ptr));
    try std.testing.expectEqual(@as(u32, payload.len), hdr.tp_len);
    try std.testing.expectEqual(TP_STATUS_SEND_REQUEST, @atomicLoad(u32, &hdr.tp_status, .monotonic));
    try std.testing.expectEqualSlices(u8, &payload, buf[DATA_OFFSET .. DATA_OFFSET + payload.len]);
}

test "a kernel-drained slot (status reset to AVAILABLE) is reusable" {
    const frame_size: usize = 2048;
    const buf = try std.testing.allocator.alloc(u8, frame_size);
    defer std.testing.allocator.free(buf);
    @memset(buf, 0);
    var ring = Ring.init(buf, frame_size, 1);

    const idx0 = ring.reserve().?;
    ring.fill(idx0, &[_]u8{0x01});
    try std.testing.expect(ring.reserve() == null);

    const hdr: *tpacket2_hdr = @ptrCast(@alignCast(buf.ptr));
    @atomicStore(u32, &hdr.tp_status, TP_STATUS_AVAILABLE, .monotonic);
    try std.testing.expect(ring.reserve() != null);
}
