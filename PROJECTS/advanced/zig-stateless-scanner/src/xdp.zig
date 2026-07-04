// ©AngelaMos | 2026
// xdp.zig

const std = @import("std");
const linux = std.os.linux;

pub const AF_XDP: u32 = linux.AF.XDP;
pub const SOL_XDP: i32 = linux.SOL.XDP;

pub const bind_flags = struct {
    pub const SHARED_UMEM: u16 = 1 << 0;
    pub const COPY: u16 = 1 << 1;
    pub const ZEROCOPY: u16 = 1 << 2;
    pub const USE_NEED_WAKEUP: u16 = 1 << 3;
};

pub const umem_flags = struct {
    pub const UNALIGNED_CHUNK: u32 = 1 << 0;
};

pub const sockopt = struct {
    pub const MMAP_OFFSETS: u32 = 1;
    pub const RX_RING: u32 = 2;
    pub const TX_RING: u32 = 3;
    pub const UMEM_REG: u32 = 4;
    pub const UMEM_FILL_RING: u32 = 5;
    pub const UMEM_COMPLETION_RING: u32 = 6;
    pub const STATISTICS: u32 = 7;
    pub const OPTIONS: u32 = 8;
};

pub const RING_NEED_WAKEUP: u32 = 1 << 0;
pub const OPTIONS_ZEROCOPY: u32 = 1 << 0;

pub const pgoff = struct {
    pub const RX_RING: u64 = 0;
    pub const TX_RING: u64 = 0x80000000;
    pub const FILL_RING: u64 = 0x100000000;
    pub const COMPLETION_RING: u64 = 0x180000000;
};

comptime {
    std.debug.assert(bind_flags.COPY == linux.XDP.COPY);
    std.debug.assert(bind_flags.ZEROCOPY == linux.XDP.ZEROCOPY);
    std.debug.assert(bind_flags.USE_NEED_WAKEUP == linux.XDP.USE_NEED_WAKEUP);
    std.debug.assert(sockopt.MMAP_OFFSETS == linux.XDP.MMAP_OFFSETS);
    std.debug.assert(sockopt.TX_RING == linux.XDP.TX_RING);
    std.debug.assert(sockopt.UMEM_REG == linux.XDP.UMEM_REG);
    std.debug.assert(sockopt.UMEM_FILL_RING == linux.XDP.UMEM_FILL_RING);
    std.debug.assert(sockopt.UMEM_COMPLETION_RING == linux.XDP.UMEM_COMPLETION_RING);
    std.debug.assert(sockopt.OPTIONS == linux.XDP.OPTIONS);
    std.debug.assert(OPTIONS_ZEROCOPY == linux.XDP.OPTIONS_ZEROCOPY);
    std.debug.assert(pgoff.TX_RING == linux.XDP.PGOFF_TX_RING);
    std.debug.assert(pgoff.FILL_RING == linux.XDP.UMEM_PGOFF_FILL_RING);
    std.debug.assert(pgoff.COMPLETION_RING == linux.XDP.UMEM_PGOFF_COMPLETION_RING);
}

pub const UmemReg = extern struct {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
};

pub const RingOffset = extern struct {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
};

pub const MmapOffsets = extern struct {
    rx: RingOffset,
    tx: RingOffset,
    fr: RingOffset,
    cr: RingOffset,
};

pub const Desc = extern struct {
    addr: u64,
    len: u32,
    options: u32,
};

pub const Options = extern struct {
    flags: u32,
};

comptime {
    std.debug.assert(@sizeOf(UmemReg) == 32);
    std.debug.assert(@sizeOf(RingOffset) == 32);
    std.debug.assert(@sizeOf(MmapOffsets) == 128);
    std.debug.assert(@sizeOf(Desc) == 16);
    std.debug.assert(@sizeOf(Options) == 4);
    std.debug.assert(@sizeOf(linux.sockaddr.xdp) == 16);
}

pub const Prod = struct {
    producer: *u32,
    consumer: *u32,
    ring: [*]Desc,
    mask: u32,
    size: u32,
    cached_prod: u32 = 0,
    cached_cons: u32 = 0,

    pub fn reserve(self: *Prod) ?u32 {
        if (self.cached_prod -% self.cached_cons == self.size) {
            self.cached_cons = @atomicLoad(u32, self.consumer, .acquire);
            if (self.cached_prod -% self.cached_cons == self.size) return null;
        }
        const slot = self.cached_prod & self.mask;
        self.cached_prod +%= 1;
        return slot;
    }

    pub fn write(self: *Prod, slot: u32, desc: Desc) void {
        self.ring[slot] = desc;
    }

    pub fn publish(self: *Prod) void {
        @atomicStore(u32, self.producer, self.cached_prod, .release);
    }
};

pub const Comp = struct {
    producer: *u32,
    consumer: *u32,
    ring: [*]u64,
    mask: u32,
    size: u32,
    cached_prod: u32 = 0,
    cached_cons: u32 = 0,

    pub fn peek(self: *Comp) u32 {
        var avail = self.cached_prod -% self.cached_cons;
        if (avail == 0) {
            self.cached_prod = @atomicLoad(u32, self.producer, .acquire);
            avail = self.cached_prod -% self.cached_cons;
        }
        return avail;
    }

    pub fn addrAt(self: *const Comp, i: u32) u64 {
        return self.ring[(self.cached_cons +% i) & self.mask];
    }

    pub fn release(self: *Comp, n: u32) void {
        self.cached_cons +%= n;
        @atomicStore(u32, self.consumer, self.cached_cons, .release);
    }
};

pub const FrameStack = struct {
    free: []u64,
    top: usize,

    pub fn init(buf: []u64, num_frames: u32, frame_size: u32) FrameStack {
        var i: u32 = 0;
        while (i < num_frames) : (i += 1) {
            buf[i] = @as(u64, i) * frame_size;
        }
        return .{ .free = buf, .top = num_frames };
    }

    pub fn pop(self: *FrameStack) ?u64 {
        if (self.top == 0) return null;
        self.top -= 1;
        return self.free[self.top];
    }

    pub fn push(self: *FrameStack, addr: u64) void {
        std.debug.assert(self.top < self.free.len);
        self.free[self.top] = addr;
        self.top += 1;
    }

    pub fn available(self: *const FrameStack) usize {
        return self.top;
    }
};

test "FrameStack lays out frame offsets, pops LIFO, and reports empty" {
    var buf: [4]u64 = undefined;
    var fs = FrameStack.init(&buf, 4, 2048);
    try std.testing.expectEqual(@as(usize, 4), fs.available());
    try std.testing.expectEqual(@as(u64, 6144), fs.pop().?);
    try std.testing.expectEqual(@as(u64, 4096), fs.pop().?);
    fs.push(4096);
    try std.testing.expectEqual(@as(u64, 4096), fs.pop().?);
    try std.testing.expectEqual(@as(u64, 2048), fs.pop().?);
    try std.testing.expectEqual(@as(u64, 0), fs.pop().?);
    try std.testing.expect(fs.pop() == null);
}

test "Prod.reserve backpressures at ring size and recovers as the kernel consumes" {
    const size: u32 = 4;
    var producer: u32 = 0;
    var consumer: u32 = 0;
    var ring: [size]Desc = undefined;
    var p = Prod{ .producer = &producer, .consumer = &consumer, .ring = &ring, .mask = size - 1, .size = size };

    var got: u32 = 0;
    while (p.reserve()) |slot| {
        p.write(slot, .{ .addr = got, .len = 1, .options = 0 });
        got += 1;
    }
    try std.testing.expectEqual(size, got);
    try std.testing.expect(p.reserve() == null);

    p.publish();
    try std.testing.expectEqual(size, @atomicLoad(u32, &producer, .acquire));

    @atomicStore(u32, &consumer, 2, .release);
    try std.testing.expect(p.reserve() != null);
    try std.testing.expect(p.reserve() != null);
    try std.testing.expect(p.reserve() == null);
}

test "Comp.peek sees kernel completions and release advances the consumer" {
    const size: u32 = 4;
    var producer: u32 = 0;
    var consumer: u32 = 0;
    var ring: [size]u64 = undefined;
    var c = Comp{ .producer = &producer, .consumer = &consumer, .ring = &ring, .mask = size - 1, .size = size };

    try std.testing.expectEqual(@as(u32, 0), c.peek());

    ring[0] = 0;
    ring[1] = 2048;
    ring[2] = 4096;
    @atomicStore(u32, &producer, 3, .release);

    try std.testing.expectEqual(@as(u32, 3), c.peek());
    try std.testing.expectEqual(@as(u64, 0), c.addrAt(0));
    try std.testing.expectEqual(@as(u64, 2048), c.addrAt(1));
    try std.testing.expectEqual(@as(u64, 4096), c.addrAt(2));
    c.release(3);
    try std.testing.expectEqual(@as(u32, 3), @atomicLoad(u32, &consumer, .acquire));
    try std.testing.expectEqual(@as(u32, 0), c.peek());
}

test "TX and completion rings recycle a bounded UMEM frame pool across kicks" {
    const size: u32 = 8;
    const num_frames: u32 = 8;
    const frame_size: u32 = 2048;

    var tx_prod: u32 = 0;
    var tx_cons: u32 = 0;
    var tx_ring: [size]Desc = undefined;
    var cq_prod: u32 = 0;
    var cq_cons: u32 = 0;
    var cq_ring: [size]u64 = undefined;

    var tx = Prod{ .producer = &tx_prod, .consumer = &tx_cons, .ring = &tx_ring, .mask = size - 1, .size = size };
    var cq = Comp{ .producer = &cq_prod, .consumer = &cq_cons, .ring = &cq_ring, .mask = size - 1, .size = size };

    var fb: [num_frames]u64 = undefined;
    var frames = FrameStack.init(&fb, num_frames, frame_size);

    var total_sent: u32 = 0;
    var round: u32 = 0;
    while (round < 4) : (round += 1) {
        var i: u32 = 0;
        while (i < size) : (i += 1) {
            const off = frames.pop() orelse break;
            const slot = tx.reserve() orelse {
                frames.push(off);
                break;
            };
            tx.write(slot, .{ .addr = off, .len = 54, .options = 0 });
            total_sent += 1;
        }
        tx.publish();

        const published = @atomicLoad(u32, &tx_prod, .acquire);
        var kc = @atomicLoad(u32, &tx_cons, .monotonic);
        var kp = @atomicLoad(u32, &cq_prod, .monotonic);
        while (kc != published) : (kc +%= 1) {
            cq_ring[kc & (size - 1)] = tx_ring[kc & (size - 1)].addr;
            kp +%= 1;
        }
        @atomicStore(u32, &tx_cons, kc, .release);
        @atomicStore(u32, &cq_prod, kp, .release);

        const n = cq.peek();
        var k: u32 = 0;
        while (k < n) : (k += 1) frames.push(cq.addrAt(k));
        if (n > 0) cq.release(n);
    }

    try std.testing.expect(total_sent > num_frames);
    try std.testing.expectEqual(@as(usize, num_frames), frames.available());
}
