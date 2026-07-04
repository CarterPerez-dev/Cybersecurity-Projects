// ©AngelaMos | 2026
// build.zig

const std = @import("std");

const zingela_version = "0.0.0-m11";

const ReleaseTarget = struct {
    query: std.Target.Query,
    asset: []const u8,
};

const release_targets = [_]ReleaseTarget{
    .{ .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl }, .asset = "zingela-x86_64-linux-musl" },
    .{ .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl }, .asset = "zingela-aarch64-linux-musl" },
};

const Built = struct {
    exe: *std.Build.Step.Compile,
    test_mods: []const *std.Build.Module,
    packet: *std.Build.Module,
    cookie: *std.Build.Module,
    targets: *std.Build.Module,
    template: *std.Build.Module,
    dedup: *std.Build.Module,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xdp_enabled = b.option(bool, "xdp", "Enable the AF_XDP TX backend (pure-syscall, no libxdp; needs CAP_NET_ADMIN at runtime)") orelse false;

    const host = buildZingela(b, target, optimize, xdp_enabled);
    b.installArtifact(host.exe);

    const run_cmd = b.addRunArtifact(host.exe);
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
    for (host.test_mods) |mod| {
        const t = b.addTest(.{ .root_module = mod });
        const rt = b.addRunArtifact(t);
        test_step.dependOn(&rt.step);
    }

    const bench_src = buildZingela(b, target, .ReleaseFast, xdp_enabled);
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_mod.addImport("packet", bench_src.packet);
    bench_mod.addImport("cookie", bench_src.cookie);
    bench_mod.addImport("targets", bench_src.targets);
    bench_mod.addImport("template", bench_src.template);
    bench_mod.addImport("dedup", bench_src.dedup);
    const bench_exe = b.addExecutable(.{ .name = "zingela-bench", .root_module = bench_mod });
    const bench_run = b.addRunArtifact(bench_exe);
    if (b.args) |args| bench_run.addArgs(args);
    const bench_step = b.step("bench", "Run the hot-path microbenchmarks (ReleaseFast, measured on this host)");
    bench_step.dependOn(&bench_run.step);

    const release_step = b.step("release", "Build static musl release binaries for every distribution target");
    for (release_targets) |rt| {
        const resolved = b.resolveTargetQuery(rt.query);
        const built = buildZingela(b, resolved, .ReleaseSafe, xdp_enabled);
        const inst = b.addInstallArtifact(built.exe, .{
            .dest_dir = .{ .override = .{ .custom = "release" } },
            .dest_sub_path = rt.asset,
        });
        release_step.dependOn(&inst.step);
    }
}

fn buildZingela(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    xdp_enabled: bool,
) Built {
    const opts = b.addOptions();
    opts.addOption([]const u8, "version", zingela_version);
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

    const segment_mod = b.createModule(.{
        .root_source_file = b.path("src/segment.zig"),
        .target = target,
        .optimize = optimize,
    });
    segment_mod.addImport("packet", packet_mod);

    const regex_mod = b.createModule(.{
        .root_source_file = b.path("src/regex.zig"),
        .target = target,
        .optimize = optimize,
    });

    const probe_mod = b.createModule(.{
        .root_source_file = b.path("src/probe.zig"),
        .target = target,
        .optimize = optimize,
    });
    probe_mod.addImport("regex", regex_mod);

    const service_mod = b.createModule(.{
        .root_source_file = b.path("src/service.zig"),
        .target = target,
        .optimize = optimize,
    });
    service_mod.addImport("packet", packet_mod);
    service_mod.addImport("cookie", cookie_mod);
    service_mod.addImport("segment", segment_mod);
    service_mod.addImport("probe", probe_mod);

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
    output_mod.addImport("packet", packet_mod);
    cli_mod.addImport("output", output_mod);

    const connect_mod = b.createModule(.{
        .root_source_file = b.path("src/connect.zig"),
        .target = target,
        .optimize = optimize,
    });
    connect_mod.addImport("classify", classify_mod);
    connect_mod.addImport("packet", packet_mod);
    connect_mod.addImport("targets", targets_mod);
    connect_mod.addImport("ratelimit", ratelimit_mod);
    connect_mod.addImport("output", output_mod);

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

    const rawprobe_mod = b.createModule(.{
        .root_source_file = b.path("src/rawprobe.zig"),
        .target = target,
        .optimize = optimize,
    });

    targets_mod.addImport("netutil", netutil_mod);
    tx_mod.addImport("netutil", netutil_mod);

    const ndp_mod = b.createModule(.{
        .root_source_file = b.path("src/ndp.zig"),
        .target = target,
        .optimize = optimize,
    });
    ndp_mod.addImport("packet", packet_mod);

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
    scancmd_mod.addImport("service", service_mod);
    scancmd_mod.addImport("connect", connect_mod);
    scancmd_mod.addImport("rawprobe", rawprobe_mod);
    scancmd_mod.addImport("ndp", ndp_mod);

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

    const test_mods = b.allocator.dupe(*std.Build.Module, &.{
        packet_mod,   cli_mod,       smoke_mod,     cookie_mod,  numtheory_mod,
        targets_mod,  ratelimit_mod, template_mod,  segment_mod, regex_mod,
        probe_mod,    service_mod,   payloads_mod,  udp_mod,     afpacket_mod,
        xdp_mod,      afxdp_mod,     packet_io_mod, tx_mod,      txcmd_mod,
        classify_mod, dedup_mod,     rx_mod,        netutil_mod, rawprobe_mod,
        ndp_mod,      stealth_mod,   output_mod,    connect_mod, scancmd_mod,
    }) catch @panic("OOM");

    return .{
        .exe = exe,
        .test_mods = test_mods,
        .packet = packet_mod,
        .cookie = cookie_mod,
        .targets = targets_mod,
        .template = template_mod,
        .dedup = dedup_mod,
    };
}
