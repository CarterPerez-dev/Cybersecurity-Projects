// ©AngelaMos | 2026
// dedup.zig

const std = @import("std");

const EMPTY: u64 = std.math.maxInt(u64);
const LOAD_NUM: usize = 7;
const LOAD_DEN: usize = 10;
const FMIX64_MUL: u64 = 0xff51afd7ed558ccd;
const FMIX64_SHIFT: u6 = 33;

pub const Dedup = struct {
    allocator: std.mem.Allocator,
    slots: []u64,
    mask: usize,
    len: usize,

    pub fn init(allocator: std.mem.Allocator, capacity_pow2: usize) !Dedup {
        std.debug.assert(capacity_pow2 >= 2 and std.math.isPowerOfTwo(capacity_pow2));
        const slots = try allocator.alloc(u64, capacity_pow2);
        @memset(slots, EMPTY);
        return .{ .allocator = allocator, .slots = slots, .mask = capacity_pow2 - 1, .len = 0 };
    }

    pub fn deinit(self: *Dedup) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    fn mix(k: u64) u64 {
        var x = k;
        x ^= x >> FMIX64_SHIFT;
        x *%= FMIX64_MUL;
        x ^= x >> FMIX64_SHIFT;
        return x;
    }

    const PlaceResult = enum { inserted, duplicate, full };

    fn place(slots: []u64, mask: usize, k: u64) PlaceResult {
        var i: usize = @intCast(mix(k) & mask);
        var probes: usize = 0;
        while (probes <= mask) : (probes += 1) {
            if (slots[i] == EMPTY) {
                slots[i] = k;
                return .inserted;
            }
            if (slots[i] == k) return .duplicate;
            i = (i + 1) & mask;
        }
        return .full;
    }

    fn grow(self: *Dedup) !void {
        const new_cap = (self.mask + 1) * 2;
        const new_slots = try self.allocator.alloc(u64, new_cap);
        @memset(new_slots, EMPTY);
        const new_mask = new_cap - 1;
        for (self.slots) |s| {
            if (s != EMPTY) _ = place(new_slots, new_mask, s);
        }
        self.allocator.free(self.slots);
        self.slots = new_slots;
        self.mask = new_mask;
    }

    pub fn insert(self: *Dedup, k: u64) bool {
        if ((self.len + 1) * LOAD_DEN > (self.mask + 1) * LOAD_NUM) {
            self.grow() catch {};
        }
        return switch (place(self.slots, self.mask, k)) {
            .inserted => blk: {
                self.len += 1;
                break :blk true;
            },
            .duplicate => false,
            .full => true,
        };
    }
};

fn key(ip: u32, port: u16) u64 {
    return (@as(u64, ip) << 16) | port;
}

test "first insert is new, second of same key is duplicate" {
    var d = try Dedup.init(std.testing.allocator, 16);
    defer d.deinit();
    try std.testing.expect(d.insert(key(0x08080808, 80)));
    try std.testing.expect(!d.insert(key(0x08080808, 80)));
    try std.testing.expectEqual(@as(usize, 1), d.len);
}

test "same ip different ports are distinct" {
    var d = try Dedup.init(std.testing.allocator, 16);
    defer d.deinit();
    try std.testing.expect(d.insert(key(0x08080808, 80)));
    try std.testing.expect(d.insert(key(0x08080808, 443)));
    try std.testing.expect(!d.insert(key(0x08080808, 80)));
    try std.testing.expectEqual(@as(usize, 2), d.len);
}

test "distinct keys are all retained across growth" {
    var d = try Dedup.init(std.testing.allocator, 4);
    defer d.deinit();
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        try std.testing.expect(d.insert(key(0x08080000 + i, 80)));
    }
    try std.testing.expectEqual(@as(usize, 1000), d.len);
    i = 0;
    while (i < 1000) : (i += 1) {
        try std.testing.expect(!d.insert(key(0x08080000 + i, 80)));
    }
    try std.testing.expectEqual(@as(usize, 1000), d.len);
}

test "the all-ones sentinel cannot collide with a real key" {
    const max_key = key(0xffffffff, 0xffff);
    try std.testing.expect(max_key != EMPTY);
    try std.testing.expectEqual(@as(u64, 0x0000ffffffffffff), max_key);
}
