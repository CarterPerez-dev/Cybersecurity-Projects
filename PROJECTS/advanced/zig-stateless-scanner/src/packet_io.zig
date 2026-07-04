// ©AngelaMos | 2026
// packet_io.zig

const std = @import("std");
const build_config = @import("build_config");
const afpacket = @import("afpacket");
const afxdp = @import("afxdp");

pub const Kind = enum { afpacket, afxdp_copy, afxdp_zerocopy };
pub const Choice = enum { auto, xdp, afpacket };

pub const Backend = union(enum) {
    afpacket: afpacket.Backend,
    afxdp: afxdp.Backend,

    pub fn submit(self: *Backend, frame: []const u8) bool {
        return switch (self.*) {
            inline else => |*b| b.submit(frame),
        };
    }

    pub fn kick(self: *Backend) void {
        switch (self.*) {
            inline else => |*b| b.kick(),
        }
    }

    pub fn close(self: *Backend) void {
        switch (self.*) {
            inline else => |*b| b.close(),
        }
    }

    pub fn kind(self: *const Backend) Kind {
        return switch (self.*) {
            .afpacket => .afpacket,
            .afxdp => |*b| if (b.zerocopy()) .afxdp_zerocopy else .afxdp_copy,
        };
    }
};

pub const SelectError = error{XdpNotCompiledIn} || afxdp.OpenError || afpacket.OpenError;

pub fn parseChoice(text: ?[]const u8) ?Choice {
    const t = text orelse return .auto;
    if (std.mem.eql(u8, t, "auto")) return .auto;
    if (std.mem.eql(u8, t, "xdp")) return .xdp;
    if (std.mem.eql(u8, t, "afpacket")) return .afpacket;
    return null;
}

pub fn kindLabel(k: Kind) []const u8 {
    return switch (k) {
        .afpacket => "AF_PACKET (PACKET_TX_RING)",
        .afxdp_copy => "AF_XDP (copy / XDP_SKB mode)",
        .afxdp_zerocopy => "AF_XDP (zero-copy)",
    };
}

fn note(diag: ?*std.Io.Writer, comptime fmt: []const u8, args: anytype) void {
    if (diag) |w| {
        w.print("  backend: " ++ fmt ++ "\n", args) catch {};
    }
}

pub fn select(
    allocator: std.mem.Allocator,
    ifname: []const u8,
    choice: Choice,
    xdp_cfg: afxdp.Config,
    afp_cfg: afpacket.RingConfig,
    diag: ?*std.Io.Writer,
) SelectError!Backend {
    if (choice == .xdp and !build_config.xdp) return error.XdpNotCompiledIn;

    const want_xdp = build_config.xdp and choice != .afpacket;
    if (want_xdp) {
        if (afxdp.Backend.open(allocator, ifname, .zerocopy, xdp_cfg)) |b| {
            return .{ .afxdp = b };
        } else |err| {
            note(diag, "AF_XDP zero-copy unavailable ({s})", .{@errorName(err)});
        }
        if (afxdp.Backend.open(allocator, ifname, .copy, xdp_cfg)) |b| {
            return .{ .afxdp = b };
        } else |err| {
            if (choice == .xdp) return err;
            note(diag, "AF_XDP copy mode unavailable ({s}); using AF_PACKET", .{@errorName(err)});
        }
    }
    return .{ .afpacket = try afpacket.Backend.open(ifname, afp_cfg) };
}

test "parseChoice maps flag text, defaults to auto, and rejects unknown values" {
    try std.testing.expectEqual(Choice.auto, parseChoice(null).?);
    try std.testing.expectEqual(Choice.auto, parseChoice("auto").?);
    try std.testing.expectEqual(Choice.xdp, parseChoice("xdp").?);
    try std.testing.expectEqual(Choice.afpacket, parseChoice("afpacket").?);
    try std.testing.expect(parseChoice("nonsense") == null);
}

test "forcing --backend xdp without a -Dxdp build is rejected up front" {
    if (!build_config.xdp) {
        const r = select(std.testing.allocator, "lo", .xdp, .{}, .{}, null);
        try std.testing.expectError(error.XdpNotCompiledIn, r);
    }
}

test "kindLabel covers every backend kind" {
    try std.testing.expect(kindLabel(.afpacket).len > 0);
    try std.testing.expect(kindLabel(.afxdp_copy).len > 0);
    try std.testing.expect(kindLabel(.afxdp_zerocopy).len > 0);
}
