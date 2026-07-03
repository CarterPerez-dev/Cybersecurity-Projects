// ©AngelaMos | 2026
// build.zig

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xdp_enabled = b.option(bool, "xdp", "Enable the AF_XDP TX backend (pure-syscall, no libxdp; needs CAP_NET_ADMIN at runtime)") orelse false;

    const opts = b.addOptions();
    opts.addOption([]const u8, "version", "0.0.0-m8");
    opts.addOption(bool, "xdp", xdp_enabled);
    const build_config_mod = opts.createModule();

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
    cli_mod.addImport("build_config", build_config_mod);

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

    const ratelimit_mod = b.createModule(.{
        .root_source_file = b.path("src/ratelimit.zig"),
        .target = target,
        .optimize = optimize,
    });

    const template_mod = b.createModule(.{
        .root_source_file = b.path("src/template.zig"),
        .target = target,
        .optimize = optimize,
    });
    template_mod.addImport("packet", packet_mod);
    template_mod.addImport("cookie", cookie_mod);

    const payloads_mod = b.createModule(.{
        .root_source_file = b.path("src/payloads.zig"),
        .target = target,
        .optimize = optimize,
    });

    const udp_mod = b.createModule(.{
        .root_source_file = b.path("src/udp.zig"),
        .target = target,
        .optimize = optimize,
    });
    udp_mod.addImport("packet", packet_mod);
    udp_mod.addImport("cookie", cookie_mod);
    udp_mod.addImport("payloads", payloads_mod);

    const afpacket_mod = b.createModule(.{
        .root_source_file = b.path("src/afpacket.zig"),
        .target = target,
        .optimize = optimize,
    });
    afpacket_mod.addImport("packet", packet_mod);

    const xdp_mod = b.createModule(.{
        .root_source_file = b.path("src/xdp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const afxdp_mod = b.createModule(.{
        .root_source_file = b.path("src/afxdp.zig"),
        .target = target,
        .optimize = optimize,
    });
    afxdp_mod.addImport("xdp", xdp_mod);

    const packet_io_mod = b.createModule(.{
        .root_source_file = b.path("src/packet_io.zig"),
        .target = target,
        .optimize = optimize,
    });
    packet_io_mod.addImport("afpacket", afpacket_mod);
    packet_io_mod.addImport("afxdp", afxdp_mod);
    packet_io_mod.addImport("build_config", build_config_mod);

    const tx_mod = b.createModule(.{
        .root_source_file = b.path("src/tx.zig"),
        .target = target,
        .optimize = optimize,
    });
    tx_mod.addImport("targets", targets_mod);
    tx_mod.addImport("template", template_mod);
    tx_mod.addImport("ratelimit", ratelimit_mod);
    tx_mod.addImport("cookie", cookie_mod);
    tx_mod.addImport("packet", packet_mod);

    const classify_mod = b.createModule(.{
        .root_source_file = b.path("src/classify.zig"),
        .target = target,
        .optimize = optimize,
    });
    classify_mod.addImport("packet", packet_mod);
    classify_mod.addImport("cookie", cookie_mod);

    const output_mod = b.createModule(.{
        .root_source_file = b.path("src/output.zig"),
        .target = target,
        .optimize = optimize,
    });
    output_mod.addImport("classify", classify_mod);
    cli_mod.addImport("output", output_mod);

    const dedup_mod = b.createModule(.{
        .root_source_file = b.path("src/dedup.zig"),
        .target = target,
        .optimize = optimize,
    });

    const rx_mod = b.createModule(.{
        .root_source_file = b.path("src/rx.zig"),
        .target = target,
        .optimize = optimize,
    });
    rx_mod.addImport("classify", classify_mod);
    rx_mod.addImport("dedup", dedup_mod);
    rx_mod.addImport("cookie", cookie_mod);

    const netutil_mod = b.createModule(.{
        .root_source_file = b.path("src/netutil.zig"),
        .target = target,
        .optimize = optimize,
    });

    const stealth_mod = b.createModule(.{
        .root_source_file = b.path("src/stealth.zig"),
        .target = target,
        .optimize = optimize,
    });
    stealth_mod.addImport("packet", packet_mod);
    stealth_mod.addImport("netutil", netutil_mod);

    const txcmd_mod = b.createModule(.{
        .root_source_file = b.path("src/txcmd.zig"),
        .target = target,
        .optimize = optimize,
    });
    txcmd_mod.addImport("targets", targets_mod);
    txcmd_mod.addImport("template", template_mod);
    txcmd_mod.addImport("ratelimit", ratelimit_mod);
    txcmd_mod.addImport("packet_io", packet_io_mod);
    txcmd_mod.addImport("cookie", cookie_mod);
    txcmd_mod.addImport("tx", tx_mod);
    txcmd_mod.addImport("netutil", netutil_mod);
    txcmd_mod.addImport("stealth", stealth_mod);

    const scancmd_mod = b.createModule(.{
        .root_source_file = b.path("src/scancmd.zig"),
        .target = target,
        .optimize = optimize,
    });
    scancmd_mod.addImport("targets", targets_mod);
    scancmd_mod.addImport("template", template_mod);
    scancmd_mod.addImport("udp", udp_mod);
    scancmd_mod.addImport("ratelimit", ratelimit_mod);
    scancmd_mod.addImport("packet_io", packet_io_mod);
    scancmd_mod.addImport("cookie", cookie_mod);
    scancmd_mod.addImport("tx", tx_mod);
    scancmd_mod.addImport("rx", rx_mod);
    scancmd_mod.addImport("dedup", dedup_mod);
    scancmd_mod.addImport("netutil", netutil_mod);
    scancmd_mod.addImport("output", output_mod);
    scancmd_mod.addImport("stealth", stealth_mod);

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
    exe.root_module.addImport("txcmd", txcmd_mod);
    exe.root_module.addImport("scancmd", scancmd_mod);
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
    const test_mods = [_]*std.Build.Module{ packet_mod, cli_mod, smoke_mod, cookie_mod, numtheory_mod, targets_mod, ratelimit_mod, template_mod, payloads_mod, udp_mod, afpacket_mod, xdp_mod, afxdp_mod, packet_io_mod, tx_mod, txcmd_mod, classify_mod, dedup_mod, rx_mod, netutil_mod, stealth_mod, output_mod, scancmd_mod };
    for (test_mods) |mod| {
        const t = b.addTest(.{ .root_module = mod });
        const rt = b.addRunArtifact(t);
        test_step.dependOn(&rt.step);
    }
}
