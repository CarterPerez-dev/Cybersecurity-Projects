// ©AngelaMos | 2026
// build.zig

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const opts = b.addOptions();
    opts.addOption([]const u8, "version", "0.0.0-m2");

    const packet_mod = b.createModule(.{
        .root_source_file = b.path("src/packet.zig"),
        .target = target,
        .optimize = optimize,
    });

    const cli_mod = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_mod.addOptions("build_config", opts);

    const smoke_mod = b.createModule(.{
        .root_source_file = b.path("src/smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    smoke_mod.addImport("packet", packet_mod);

    const cookie_mod = b.createModule(.{
        .root_source_file = b.path("src/cookie.zig"),
        .target = target,
        .optimize = optimize,
    });

    const numtheory_mod = b.createModule(.{
        .root_source_file = b.path("src/numtheory.zig"),
        .target = target,
        .optimize = optimize,
    });

    const targets_mod = b.createModule(.{
        .root_source_file = b.path("src/targets.zig"),
        .target = target,
        .optimize = optimize,
    });
    targets_mod.addImport("numtheory", numtheory_mod);

    const exe = b.addExecutable(.{
        .name = "zingela",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .strip = optimize != .Debug,
        }),
    });
    exe.root_module.addImport("cli", cli_mod);
    exe.root_module.addImport("smoke", smoke_mod);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run zingela");
    run_step.dependOn(&run_cmd.step);

    const smoke_cmd = b.addSystemCommand(&.{b.getInstallPath(.bin, "zingela")});
    smoke_cmd.addArg("smoke");
    if (b.args) |args| smoke_cmd.addArgs(args);
    smoke_cmd.step.dependOn(b.getInstallStep());
    const smoke_step = b.step("smoke", "AF_PACKET ground-truth smoke on the installed binary (setcap it first)");
    smoke_step.dependOn(&smoke_cmd.step);

    const test_step = b.step("test", "Run unit tests");
    const test_mods = [_]*std.Build.Module{ packet_mod, cli_mod, smoke_mod, cookie_mod, numtheory_mod, targets_mod };
    for (test_mods) |mod| {
        const t = b.addTest(.{ .root_module = mod });
        const rt = b.addRunArtifact(t);
        test_step.dependOn(&rt.step);
    }
}
