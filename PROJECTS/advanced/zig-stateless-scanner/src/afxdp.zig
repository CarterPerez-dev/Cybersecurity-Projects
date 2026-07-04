// ©AngelaMos | 2026
// afxdp.zig

const std = @import("std");
const xdp = @import("xdp");
const linux = std.os.linux;

const page = std.heap.page_size_min;

pub const Mode = enum { zerocopy, copy };

pub const OpenError = error{
    NeedCapNetRaw,
    SocketFailed,
    IfIndexFailed,
    UmemAllocFailed,
    UmemRegFailed,
    RingSetupFailed,
    MmapOffsetsFailed,
    RingMmapFailed,
    BindFailed,
    BadConfig,
    OutOfMemory,
};

pub const Config = struct {
    frame_size: u32 = 2048,
    num_frames: u32 = 4096,
    tx_size: u32 = 2048,
    comp_size: u32 = 2048,
    fill_size: u32 = 2048,
    queue_id: u32 = 0,
};

fn setU32(fd: i32, name: u32, val: u32) OpenError!void {
    var v = val;
    if (linux.errno(linux.setsockopt(fd, xdp.SOL_XDP, name, std.mem.asBytes(&v), @sizeOf(u32))) != .SUCCESS)
        return error.RingSetupFailed;
}

fn mapRing(fd: i32, len: usize, pg: u64) OpenError![]align(page) u8 {
    const rc = linux.mmap(null, len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .SHARED, .POPULATE = true }, fd, @intCast(pg));
    if (linux.errno(rc) != .SUCCESS) return error.RingMmapFailed;
    const ptr: [*]align(page) u8 = @ptrFromInt(rc);
    return ptr[0..len];
}

fn ringPtr(comptime T: type, map: []align(page) u8, offset: u64) T {
    return @ptrCast(@alignCast(map.ptr + @as(usize, @intCast(offset))));
}

pub const Backend = struct {
    allocator: std.mem.Allocator,
    fd: i32,
    mode: Mode,
    frame_size: u32,
    umem: []align(page) u8,
    tx_map: []align(page) u8,
    comp_map: []align(page) u8,
    tx: xdp.Prod,
    comp: xdp.Comp,
    frames: xdp.FrameStack,
    frame_backing: []u64,

    pub fn open(allocator: std.mem.Allocator, ifname: []const u8, mode: Mode, cfg: Config) OpenError!Backend {
        if (!std.math.isPowerOfTwo(cfg.tx_size) or !std.math.isPowerOfTwo(cfg.comp_size) or !std.math.isPowerOfTwo(cfg.fill_size))
            return error.BadConfig;
        if (cfg.frame_size != 2048 and cfg.frame_size != 4096) return error.BadConfig;
        if (cfg.num_frames < cfg.tx_size or cfg.num_frames < cfg.comp_size) return error.BadConfig;

        const rc_sock = linux.socket(xdp.AF_XDP, linux.SOCK.RAW, 0);
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
        const ifindex: u32 = @intCast(ifr.ifru.ivalue);

        const umem_len: usize = @as(usize, cfg.num_frames) * cfg.frame_size;
        const rc_umem = linux.mmap(null, umem_len, .{ .READ = true, .WRITE = true }, .{ .TYPE = .PRIVATE, .ANONYMOUS = true }, -1, 0);
        if (linux.errno(rc_umem) != .SUCCESS) return error.UmemAllocFailed;
        const umem_ptr: [*]align(page) u8 = @ptrFromInt(rc_umem);
        const umem = umem_ptr[0..umem_len];
        errdefer _ = linux.munmap(umem.ptr, umem.len);

        var reg = xdp.UmemReg{
            .addr = @intFromPtr(umem.ptr),
            .len = umem_len,
            .chunk_size = cfg.frame_size,
            .headroom = 0,
            .flags = 0,
            .tx_metadata_len = 0,
        };
        if (linux.errno(linux.setsockopt(fd, xdp.SOL_XDP, xdp.sockopt.UMEM_REG, std.mem.asBytes(&reg), @sizeOf(xdp.UmemReg))) != .SUCCESS)
            return error.UmemRegFailed;

        try setU32(fd, xdp.sockopt.UMEM_FILL_RING, cfg.fill_size);
        try setU32(fd, xdp.sockopt.UMEM_COMPLETION_RING, cfg.comp_size);
        try setU32(fd, xdp.sockopt.TX_RING, cfg.tx_size);

        var off = std.mem.zeroes(xdp.MmapOffsets);
        var off_len: linux.socklen_t = @sizeOf(xdp.MmapOffsets);
        if (linux.errno(linux.getsockopt(fd, xdp.SOL_XDP, xdp.sockopt.MMAP_OFFSETS, std.mem.asBytes(&off), &off_len)) != .SUCCESS)
            return error.MmapOffsetsFailed;

        const comp_len: usize = @as(usize, @intCast(off.cr.desc)) + @as(usize, cfg.comp_size) * @sizeOf(u64);
        const comp_map = try mapRing(fd, comp_len, xdp.pgoff.COMPLETION_RING);
        errdefer _ = linux.munmap(comp_map.ptr, comp_map.len);

        const tx_len: usize = @as(usize, @intCast(off.tx.desc)) + @as(usize, cfg.tx_size) * @sizeOf(xdp.Desc);
        const tx_map = try mapRing(fd, tx_len, xdp.pgoff.TX_RING);
        errdefer _ = linux.munmap(tx_map.ptr, tx_map.len);

        const frame_backing = try allocator.alloc(u64, cfg.num_frames);
        errdefer allocator.free(frame_backing);

        const tx = xdp.Prod{
            .producer = ringPtr(*u32, tx_map, off.tx.producer),
            .consumer = ringPtr(*u32, tx_map, off.tx.consumer),
            .ring = ringPtr([*]xdp.Desc, tx_map, off.tx.desc),
            .mask = cfg.tx_size - 1,
            .size = cfg.tx_size,
        };
        const comp = xdp.Comp{
            .producer = ringPtr(*u32, comp_map, off.cr.producer),
            .consumer = ringPtr(*u32, comp_map, off.cr.consumer),
            .ring = ringPtr([*]u64, comp_map, off.cr.desc),
            .mask = cfg.comp_size - 1,
            .size = cfg.comp_size,
        };

        const zc: u16 = if (mode == .zerocopy) xdp.bind_flags.ZEROCOPY else xdp.bind_flags.COPY;
        var sxdp = linux.sockaddr.xdp{
            .flags = xdp.bind_flags.USE_NEED_WAKEUP | zc,
            .ifindex = ifindex,
            .queue_id = cfg.queue_id,
            .shared_umem_fd = 0,
        };
        switch (linux.errno(linux.bind(fd, @ptrCast(&sxdp), @sizeOf(linux.sockaddr.xdp)))) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.NeedCapNetRaw,
            else => return error.BindFailed,
        }

        var actual_mode = mode;
        var xopt = xdp.Options{ .flags = 0 };
        var xopt_len: linux.socklen_t = @sizeOf(xdp.Options);
        if (linux.errno(linux.getsockopt(fd, xdp.SOL_XDP, xdp.sockopt.OPTIONS, std.mem.asBytes(&xopt), &xopt_len)) == .SUCCESS) {
            actual_mode = if ((xopt.flags & xdp.OPTIONS_ZEROCOPY) != 0) .zerocopy else .copy;
        }

        return .{
            .allocator = allocator,
            .fd = fd,
            .mode = actual_mode,
            .frame_size = cfg.frame_size,
            .umem = umem,
            .tx_map = tx_map,
            .comp_map = comp_map,
            .tx = tx,
            .comp = comp,
            .frames = xdp.FrameStack.init(frame_backing, cfg.num_frames, cfg.frame_size),
            .frame_backing = frame_backing,
        };
    }

    pub fn submit(self: *Backend, frame: []const u8) bool {
        if (frame.len > self.frame_size) return false;
        const off = self.frames.pop() orelse return false;
        const slot = self.tx.reserve() orelse {
            self.frames.push(off);
            return false;
        };
        const o: usize = @intCast(off);
        @memcpy(self.umem[o..][0..frame.len], frame);
        self.tx.write(slot, .{ .addr = off, .len = @intCast(frame.len), .options = 0 });
        return true;
    }

    pub fn kick(self: *Backend) void {
        self.tx.publish();
        var dummy: u8 = 0;
        _ = linux.sendto(self.fd, @ptrCast(&dummy), 0, linux.MSG.DONTWAIT, null, 0);
        const n = self.comp.peek();
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            self.frames.push(self.comp.addrAt(i));
        }
        if (n > 0) self.comp.release(n);
    }

    pub fn close(self: *Backend) void {
        _ = linux.munmap(self.tx_map.ptr, self.tx_map.len);
        _ = linux.munmap(self.comp_map.ptr, self.comp_map.len);
        _ = linux.munmap(self.umem.ptr, self.umem.len);
        self.allocator.free(self.frame_backing);
        _ = linux.close(self.fd);
    }

    pub fn zerocopy(self: *const Backend) bool {
        return self.mode == .zerocopy;
    }
};

test "Config rejects non-power-of-two rings and illegal chunk sizes" {
    const bad_ring = Backend.open(std.testing.allocator, "lo", .copy, .{ .tx_size = 1000 });
    try std.testing.expectError(error.BadConfig, bad_ring);
    const bad_chunk = Backend.open(std.testing.allocator, "lo", .copy, .{ .frame_size = 1024 });
    try std.testing.expectError(error.BadConfig, bad_chunk);
    const too_few = Backend.open(std.testing.allocator, "lo", .copy, .{ .num_frames = 512, .tx_size = 2048 });
    try std.testing.expectError(error.BadConfig, too_few);
}
