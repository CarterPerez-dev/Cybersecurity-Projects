// ©AngelaMos | 2026
// bench.zig

const std = @import("std");
const linux = std.os.linux;
const packet = @import("packet");
const cookie = @import("cookie");
const targets = @import("targets");
const template = @import("template");
const dedup = @import("dedup");

const warmup_frac: u64 = 16;
const iters_checksum_small: u64 = 100_000_000;
const iters_checksum_mtu: u64 = 5_000_000;
const iters_cookie: u64 = 100_000_000;
const iters_stamp: u64 = 30_000_000;
const dedup_keys: u64 = 4_000_000;
const dedup_cap: usize = 1 << 23;
const spread_multiplier: u64 = 0x9E3779B97F4A7C15;
const engine_cidr = "1.0.0.0/8";
const engine_port: u16 = 80;
const engine_seed: u64 = 0xC0FFEE;
const small_len: usize = 40;
const mtu_len: usize = 1500;
const cookie_key = [_]u8{0x42} ** 16;
const bench_src_ip: u32 = 0x0A000001;
const bench_src_port: u16 = 0xC000;
const bench_them_ip: u32 = 0x08080808;
const bench_dst_ip: u32 = 0x01020304;
const bench_src_mac = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const bench_dst_mac = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };

fn monoNow() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn report(name: []const u8, iters: u64, ns_total: u64, bytes_per_op: u64) void {
    if (iters == 0 or ns_total == 0) {
        std.debug.print("  {s:<38} no measurement (0 iterations or 0 ns)\n", .{name});
        return;
    }
    const fi: f64 = @floatFromInt(iters);
    const fns: f64 = @floatFromInt(ns_total);
    const ns_per = fns / fi;
    const mops = fi / (fns / 1e9) / 1e6;
    if (bytes_per_op > 0) {
        const total_bytes: f64 = @floatFromInt(iters * bytes_per_op);
        const gbps = total_bytes / fns;
        std.debug.print("  {s:<38} {d:>9.2} ns/op  {d:>9.1} Mops/s  {d:>7.2} GB/s\n", .{ name, ns_per, mops, gbps });
    } else {
        std.debug.print("  {s:<38} {d:>9.2} ns/op  {d:>9.1} Mops/s\n", .{ name, ns_per, mops });
    }
}

fn benchChecksum(name: []const u8, iters: u64, buf: []u8, comptime f: fn ([]const u8) u16) u64 {
    var acc: u64 = 0;
    var w: u64 = 0;
    while (w < iters / warmup_frac) : (w += 1) {
        buf[0] = @truncate(w);
        acc +%= f(buf);
    }
    acc = 0;
    const t0 = monoNow();
    var i: u64 = 0;
    while (i < iters) : (i += 1) {
        buf[0] = @truncate(i);
        buf[buf.len - 1] = @truncate(i >> 8);
        acc +%= f(buf);
    }
    report(name, iters, monoNow() - t0, buf.len);
    return acc;
}

fn benchCookieGen(ck: cookie.Cookie) u64 {
    var acc: u64 = 0;
    var w: u64 = 0;
    while (w < iters_cookie / warmup_frac) : (w += 1) {
        acc +%= ck.generate(bench_them_ip +% @as(u32, @truncate(w)), @truncate(w), bench_src_ip, bench_src_port);
    }
    acc = 0;
    const t0 = monoNow();
    var i: u64 = 0;
    while (i < iters_cookie) : (i += 1) {
        const ip: u32 = bench_them_ip +% @as(u32, @truncate(i));
        acc +%= ck.generate(ip, @truncate(i), bench_src_ip, bench_src_port);
    }
    report("cookie generate (SipHash)", iters_cookie, monoNow() - t0, 0);
    return acc;
}

fn benchCookieValidate(ck: cookie.Cookie) u64 {
    var acc: u64 = 0;
    var w: u64 = 0;
    while (w < iters_cookie / warmup_frac) : (w += 1) {
        const ip: u32 = bench_them_ip +% @as(u32, @truncate(w));
        const ack: u32 = @truncate(w *% spread_multiplier);
        acc +%= @intFromBool(ck.validateSynAck(ack, ip, @truncate(w), bench_src_ip, bench_src_port));
    }
    acc = 0;
    var i: u64 = 0;
    const t0 = monoNow();
    while (i < iters_cookie) : (i += 1) {
        const ip: u32 = bench_them_ip +% @as(u32, @truncate(i));
        const ack: u32 = @truncate(i *% spread_multiplier);
        acc +%= @intFromBool(ck.validateSynAck(ack, ip, @truncate(i), bench_src_ip, bench_src_port));
    }
    report("cookie validate (SipHash)", iters_cookie, monoNow() - t0, 0);
    return acc;
}

fn benchStamp() u64 {
    const ck = cookie.Cookie.init(cookie_key);
    const tmpl = template.SynTemplate.init(.{
        .src_mac = bench_src_mac,
        .dst_mac = bench_dst_mac,
        .src_ip = bench_src_ip,
        .src_port = bench_src_port,
        .cookie = ck,
    });
    var out: [template.SynTemplate.max_frame_len]u8 = undefined;
    var acc: u64 = 0;
    var w: u64 = 0;
    while (w < iters_stamp / warmup_frac) : (w += 1) {
        const n = tmpl.stamp(&out, bench_dst_ip +% @as(u32, @truncate(w)), @truncate(w));
        acc +%= out[n - 1];
    }
    acc = 0;
    const t0 = monoNow();
    var i: u64 = 0;
    while (i < iters_stamp) : (i += 1) {
        const ip: u32 = bench_dst_ip +% @as(u32, @truncate(i));
        const n = tmpl.stamp(&out, ip, @truncate(i));
        acc +%= @as(u64, out[n - 1]) +% n;
    }
    report("SYN template stamp (full frame)", iters_stamp, monoNow() - t0, 0);
    return acc;
}

fn benchEngine(alloc: std.mem.Allocator) !u64 {
    const range = try targets.parseCidr(engine_cidr);
    const ports = [_]u16{engine_port};
    var eng = try targets.Engine.init(alloc, &.{range}, &ports, engine_seed);
    defer eng.deinit();
    var acc: u64 = 0;
    var count: u64 = 0;
    const t0 = monoNow();
    while (eng.next()) |t| {
        acc +%= @as(u64, t.ip) +% t.port;
        count += 1;
    }
    report("address engine next() [/8 traversal]", count, monoNow() - t0, 0);
    return acc;
}

fn benchDedup(alloc: std.mem.Allocator) !u64 {
    var d = try dedup.Dedup.init(alloc, dedup_cap);
    defer d.deinit();
    var acc: u64 = 0;
    const t0 = monoNow();
    var i: u64 = 0;
    while (i < dedup_keys) : (i += 1) {
        acc +%= @intFromBool(d.insert(i *% spread_multiplier));
    }
    report("dedup insert (empty -> 4M, 2^23 slots)", dedup_keys, monoNow() - t0, 0);
    return acc;
}

pub fn main() !void {
    const alloc = std.heap.page_allocator;
    var sink: u64 = 0;

    std.debug.print("\nzingela hot-path microbenchmarks  (ReleaseFast, this host)\n", .{});
    std.debug.print("each op varies its input per iteration; results fold into a printed sink to defeat elision\n\n", .{});

    var buf: [mtu_len]u8 = undefined;
    for (&buf, 0..) |*byte, i| byte.* = @truncate(i *% 131 +% 7);

    sink +%= benchChecksum("RFC1071 checksum scalar (40B)", iters_checksum_small, buf[0..small_len], packet.checksum);
    sink +%= benchChecksum("RFC1071 checksum SIMD   (40B)", iters_checksum_small, buf[0..small_len], packet.checksumSimd);
    sink +%= benchChecksum("RFC1071 checksum scalar (1500B)", iters_checksum_mtu, buf[0..mtu_len], packet.checksum);
    sink +%= benchChecksum("RFC1071 checksum SIMD   (1500B)", iters_checksum_mtu, buf[0..mtu_len], packet.checksumSimd);

    const ck = cookie.Cookie.init(cookie_key);
    sink +%= benchCookieGen(ck);
    sink +%= benchCookieValidate(ck);

    sink +%= benchStamp();
    sink +%= try benchEngine(alloc);
    sink +%= try benchDedup(alloc);

    std.debug.print("\nanti-elision sink: 0x{x}\n", .{sink});
}
