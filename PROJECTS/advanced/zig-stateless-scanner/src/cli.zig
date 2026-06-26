// ©AngelaMos | 2026
// cli.zig

const std = @import("std");
const build_config = @import("build_config");

const reset = "\x1b[0m";

const banner_art =
    \\  ____  _                 _
    \\ |_  /(_) _ _   __ _  ___| | __ _
    \\  / / | || ' \ / _` |/ -_) |/ _` |
    \\ /___||_||_||_|\__, |\___|_|\__,_|
    \\               |___/
;

pub fn colorEnabled(io: std.Io) bool {
    return std.Io.File.stdout().isTty(io) catch false;
}

pub fn printBanner(io: std.Io) !void {
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    if (colorEnabled(io)) {
        try out.print("\x1b[38;2;000;200;255m{s}{s}\n", .{ banner_art, reset });
    } else {
        try out.print("{s}\n", .{banner_art});
    }
    try out.print("  zingela {s}  stateless mass scanner (Zig 0.16)\n\n", .{build_config.version});
    try out.flush();
}

pub fn printVersion(io: std.Io) !void {
    var buf: [64]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    try out.print("zingela {s}\n", .{build_config.version});
    try out.flush();
}

pub fn printHelp(io: std.Io) !void {
    try printBanner(io);
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    try out.writeAll(
        \\usage: zingela <command> [options]
        \\
        \\commands:
        \\  smoke [ifname]   send one hand-built SYN via AF_PACKET (default ifname: lo)
        \\  --version, -V    print version
        \\  --help, -h       print this help
        \\
    );
    try out.flush();
}

test "version string is non-empty" {
    try std.testing.expect(build_config.version.len > 0);
}
