// ©AngelaMos | 2026
// main.zig

const std = @import("std");
const cli = @import("cli");
const smoke = @import("smoke");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    const cmd: []const u8 = if (args.len > 1) args[1] else "";

    if (std.mem.eql(u8, cmd, "--version") or std.mem.eql(u8, cmd, "-V")) {
        return cli.printVersion(io);
    }
    if (std.mem.eql(u8, cmd, "smoke")) {
        const ifname: []const u8 = if (args.len > 2) args[2] else "lo";
        return smoke.run(io, ifname);
    }
    return cli.printHelp(io);
}
