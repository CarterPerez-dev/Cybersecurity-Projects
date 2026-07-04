// ©AngelaMos | 2026
// output.zig

const std = @import("std");
const classify = @import("classify");
const packet = @import("packet");

pub const State = classify.State;
pub const Result = classify.Result;

const esc = "\x1b";
const sgr_reset = "\x1b[0m";
const clear_line = "\x1b[2K";
const block_full = "\u{2588}";
const block_light = "\u{2591}";
const gutter_bar = "\u{258e}";
const box_h = "\u{2500}";

const cache_line = std.atomic.cache_line;

pub const Counter = std.atomic.Value(u64);

pub const Padded = struct {
    v: Counter align(cache_line) = .{ .raw = 0 },
    _pad: [cache_line - @sizeOf(Counter)]u8 = undefined,
};

pub const Stats = struct {
    sent: Padded = .{},
    found: Padded = .{},
    open: Padded = .{},
    closed: Padded = .{},
    filtered: Padded = .{},
    unfiltered: Padded = .{},
    banners: Padded = .{},

    pub fn record(self: *Stats, st: State) void {
        _ = self.found.v.fetchAdd(1, .monotonic);
        switch (st) {
            .open => _ = self.open.v.fetchAdd(1, .monotonic),
            .closed => _ = self.closed.v.fetchAdd(1, .monotonic),
            .filtered => _ = self.filtered.v.fetchAdd(1, .monotonic),
            .unfiltered => _ = self.unfiltered.v.fetchAdd(1, .monotonic),
        }
    }
};

const Rgb = struct { r: u8, g: u8, b: u8 };

const violet_light = Rgb{ .r = 167, .g = 139, .b = 250 };
const violet_mid = Rgb{ .r = 139, .g = 92, .b = 246 };
const violet_deep = Rgb{ .r = 109, .g = 74, .b = 255 };
const neon_green = Rgb{ .r = 74, .g = 222, .b = 128 };
const chrome_gray = Rgb{ .r = 120, .g = 120, .b = 140 };
const bright_white = Rgb{ .r = 230, .g = 230, .b = 240 };
const soft_amber = Rgb{ .r = 217, .g = 164, .b = 74 };

pub const ColorLevel = enum { none, ansi256, truecolor };
pub const ColorChoice = enum { auto, always, never };

pub fn parseColorChoice(text: ?[]const u8) ColorChoice {
    const t = text orelse return .auto;
    if (std.mem.eql(u8, t, "always")) return .always;
    if (std.mem.eql(u8, t, "never")) return .never;
    return .auto;
}

pub fn resolveLevel(choice: ColorChoice, colored: bool, truecolor: bool) ColorLevel {
    return switch (choice) {
        .never => .none,
        .always => if (truecolor) .truecolor else .ansi256,
        .auto => if (!colored) .none else if (truecolor) .truecolor else .ansi256,
    };
}

pub fn detectLevel(
    io: std.Io,
    file: std.Io.File,
    choice: ColorChoice,
    no_color: bool,
    clicolor_force: bool,
    truecolor: bool,
) ColorLevel {
    switch (choice) {
        .never => return .none,
        .always => return resolveLevel(.always, true, truecolor),
        .auto => {
            const mode = std.Io.Terminal.Mode.detect(io, file, no_color, clicolor_force) catch return .none;
            const colored = switch (mode) {
                .no_color => false,
                else => true,
            };
            return resolveLevel(.auto, colored, truecolor);
        },
    }
}

pub fn envLevel(io: std.Io, file: std.Io.File, env: *std.process.Environ.Map, choice: ColorChoice) ColorLevel {
    const no_color = if (env.get("NO_COLOR")) |v| v.len > 0 else false;
    const clicolor_force = if (env.get("CLICOLOR_FORCE")) |v| (v.len > 0 and !std.mem.eql(u8, v, "0")) else false;
    const colorterm = env.get("COLORTERM") orelse "";
    const truecolor = std.mem.eql(u8, colorterm, "truecolor") or std.mem.eql(u8, colorterm, "24bit");
    return detectLevel(io, file, choice, no_color, clicolor_force, truecolor);
}

pub fn bannerWordmark(out: *std.Io.Writer, level: ColorLevel, art: []const u8) !void {
    if (level == .none) {
        try out.print("{s}\n", .{art});
        return;
    }
    const span_lines: f32 = 4.0;
    var it = std.mem.splitScalar(u8, art, '\n');
    var i: usize = 0;
    while (it.next()) |line| : (i += 1) {
        const t = @min(@as(f32, @floatFromInt(i)), span_lines) / span_lines;
        try setFg(out, level, violetAt(t));
        try out.print("{s}\n", .{line});
    }
    try resetFg(out, level);
}

fn to256(c: Rgb) u8 {
    const r6: u16 = (@as(u16, c.r) * 5 + 127) / 255;
    const g6: u16 = (@as(u16, c.g) * 5 + 127) / 255;
    const b6: u16 = (@as(u16, c.b) * 5 + 127) / 255;
    return @intCast(16 + 36 * r6 + 6 * g6 + b6);
}

fn setFg(out: *std.Io.Writer, level: ColorLevel, c: Rgb) !void {
    switch (level) {
        .none => {},
        .truecolor => try out.print("\x1b[38;2;{d};{d};{d}m", .{ c.r, c.g, c.b }),
        .ansi256 => try out.print("\x1b[38;5;{d}m", .{to256(c)}),
    }
}

fn resetFg(out: *std.Io.Writer, level: ColorLevel) !void {
    if (level != .none) try out.writeAll(sgr_reset);
}

fn span(out: *std.Io.Writer, level: ColorLevel, c: Rgb, text: []const u8) !void {
    try setFg(out, level, c);
    try out.writeAll(text);
    try resetFg(out, level);
}

fn lerpByte(a: u8, b: u8, t: f32) u8 {
    const af: f32 = @floatFromInt(a);
    const bf: f32 = @floatFromInt(b);
    return @intFromFloat(std.math.clamp(af + (bf - af) * t, 0.0, 255.0));
}

fn lerp(a: Rgb, b: Rgb, t: f32) Rgb {
    return .{ .r = lerpByte(a.r, b.r, t), .g = lerpByte(a.g, b.g, t), .b = lerpByte(a.b, b.b, t) };
}

fn violetAt(t: f32) Rgb {
    const tc = std.math.clamp(t, 0.0, 1.0);
    if (tc <= 0.5) return lerp(violet_light, violet_mid, tc * 2.0);
    return lerp(violet_mid, violet_deep, (tc - 0.5) * 2.0);
}

fn gradientText(out: *std.Io.Writer, level: ColorLevel, text: []const u8) !void {
    if (level == .none) {
        try out.writeAll(text);
        return;
    }
    const n = text.len;
    for (text, 0..) |ch, i| {
        const t: f32 = if (n <= 1) 0.0 else @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(n - 1));
        try setFg(out, level, violetAt(t));
        try out.writeByte(ch);
    }
    try resetFg(out, level);
}

const bar_width: usize = 22;

fn progressBar(out: *std.Io.Writer, level: ColorLevel, frac: f64) !void {
    const clamped = std.math.clamp(frac, 0.0, 1.0);
    const filled: usize = @intFromFloat(clamped * @as(f64, @floatFromInt(bar_width)));
    var i: usize = 0;
    while (i < bar_width) : (i += 1) {
        if (i < filled) {
            const t: f32 = if (bar_width <= 1) 0.0 else @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(bar_width - 1));
            try setFg(out, level, violetAt(t));
            try out.writeAll(block_full);
        } else {
            try setFg(out, level, chrome_gray);
            try out.writeAll(block_light);
        }
    }
    try resetFg(out, level);
}

fn writeThousands(out: *std.Io.Writer, n: u64) !void {
    var buf: [24]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{d}", .{n}) catch return;
    for (s, 0..) |ch, i| {
        if (i != 0 and (s.len - i) % 3 == 0) try out.writeByte(',');
        try out.writeByte(ch);
    }
}

fn writeClock(out: *std.Io.Writer, secs: u64) !void {
    try out.print("{d:0>2}:{d:0>2}:{d:0>2}", .{ secs / 3600, (secs % 3600) / 60, secs % 60 });
}

fn writeIp(out: *std.Io.Writer, ip: u32) !void {
    try out.print("{d}.{d}.{d}.{d}", .{ (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff });
}

pub const max_addr_str: usize = 45;

fn writeIp6(out: *std.Io.Writer, b: [16]u8) !void {
    var groups: [8]u16 = undefined;
    for (0..8) |i| groups[i] = (@as(u16, b[i * 2]) << 8) | b[i * 2 + 1];

    var best_start: usize = 8;
    var best_len: usize = 1;
    var i: usize = 0;
    while (i < 8) {
        if (groups[i] != 0) {
            i += 1;
            continue;
        }
        var j = i + 1;
        while (j < 8 and groups[j] == 0) j += 1;
        if (j - i > best_len) {
            best_len = j - i;
            best_start = i;
        }
        i = j;
    }
    const compress = best_start < 8;

    var k: usize = 0;
    var first = true;
    while (k < 8) {
        if (compress and k == best_start) {
            try out.writeAll("::");
            k += best_len;
            first = true;
            continue;
        }
        if (!first) try out.writeByte(':');
        try out.print("{x}", .{groups[k]});
        first = false;
        k += 1;
    }
}

fn writeAddr(out: *std.Io.Writer, addr: packet.Addr) !void {
    switch (addr) {
        .v4 => |ip| try writeIp(out, ip),
        .v6 => |b| try writeIp6(out, b),
    }
}

fn addrWidth(addr: packet.Addr) usize {
    var buf: [max_addr_str]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    writeAddr(&w, addr) catch return max_addr_str;
    return w.end;
}

fn stateName(st: State) []const u8 {
    return switch (st) {
        .open => "open",
        .closed => "closed",
        .filtered => "filtered",
        .unfiltered => "unfiltered",
    };
}

fn stateLabel(st: State) []const u8 {
    return switch (st) {
        .open => "OPEN",
        .closed => "CLOSED",
        .filtered => "FILTERED",
        .unfiltered => "UNFILTERED",
    };
}

fn stateColor(st: State) Rgb {
    return switch (st) {
        .open => neon_green,
        .closed => chrome_gray,
        .filtered => soft_amber,
        .unfiltered => bright_white,
    };
}

pub const Dashboard = struct {
    level: ColorLevel,
    interactive: bool,
    total: u64,
    drawn: bool = false,
    banners_mode: bool = false,

    const body_lines: usize = 5;

    pub fn init(level: ColorLevel, interactive: bool, total: u64) Dashboard {
        return .{ .level = level, .interactive = interactive, .total = total };
    }

    fn gutter(self: *const Dashboard, out: *std.Io.Writer) !void {
        try out.writeAll("  ");
        try span(out, self.level, violet_mid, gutter_bar);
        try out.writeByte(' ');
    }

    pub fn render(self: *Dashboard, out: *std.Io.Writer, s: *const Stats, elapsed_ns: u64) !void {
        const sent = s.sent.v.load(.monotonic);
        const found = s.found.v.load(.monotonic);
        const op = s.open.v.load(.monotonic);
        const cl = s.closed.v.load(.monotonic);
        const fi = s.filtered.v.load(.monotonic);

        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        const pps = if (elapsed_s > 0) @as(f64, @floatFromInt(sent)) / elapsed_s else 0;
        const kpps = pps / 1000.0;
        const frac = if (self.total > 0) @as(f64, @floatFromInt(sent)) / @as(f64, @floatFromInt(self.total)) else 0;
        const pct = frac * 100.0;
        const remaining = if (self.total > sent) self.total - sent else 0;
        const eta_s: u64 = if (pps > 1.0) @intFromFloat(@as(f64, @floatFromInt(remaining)) / pps) else 0;

        if (!self.interactive) {
            try out.print(
                "[up {d:.0}s] sent {d} / {d}  found {d} (open {d} closed {d} filtered {d})",
                .{ elapsed_s, sent, self.total, found, op, cl, fi },
            );
            if (self.banners_mode) try out.print("  banners {d}", .{s.banners.v.load(.monotonic)});
            try out.print("  {d:.2} kpps\n", .{kpps});
            try out.flush();
            return;
        }

        if (self.drawn) try out.print("\x1b[{d}A", .{body_lines});
        self.drawn = true;

        try out.writeAll(clear_line);
        try out.writeAll("  ");
        try span(out, self.level, violet_mid, gutter_bar);
        try out.writeByte(' ');
        try gradientText(out, self.level, "zingela");
        try span(out, self.level, chrome_gray, "  scanning");
        try out.writeByte('\n');

        try out.writeAll(clear_line);
        try self.gutter(out);
        try span(out, self.level, chrome_gray, "rate  ");
        try setFg(out, self.level, bright_white);
        try out.print("{d:>8.2}", .{kpps});
        try span(out, self.level, chrome_gray, " kpps  ");
        try progressBar(out, self.level, frac);
        try out.writeByte(' ');
        try setFg(out, self.level, bright_white);
        try out.print("{d:>5.1}", .{pct});
        try span(out, self.level, chrome_gray, "%");
        try resetFg(out, self.level);
        try out.writeByte('\n');

        try out.writeAll(clear_line);
        try self.gutter(out);
        try span(out, self.level, chrome_gray, "sent  ");
        try setFg(out, self.level, bright_white);
        try writeThousands(out, sent);
        try span(out, self.level, chrome_gray, " / ");
        try setFg(out, self.level, chrome_gray);
        try writeThousands(out, self.total);
        try resetFg(out, self.level);
        try out.writeByte('\n');

        try out.writeAll(clear_line);
        try self.gutter(out);
        try span(out, self.level, chrome_gray, "open ");
        try setFg(out, self.level, neon_green);
        try writeThousands(out, op);
        try span(out, self.level, chrome_gray, "  closed ");
        try setFg(out, self.level, chrome_gray);
        try writeThousands(out, cl);
        try span(out, self.level, chrome_gray, "  filtered ");
        try setFg(out, self.level, soft_amber);
        try writeThousands(out, fi);
        try resetFg(out, self.level);
        try out.writeByte('\n');

        try out.writeAll(clear_line);
        try self.gutter(out);
        try span(out, self.level, chrome_gray, "found ");
        try setFg(out, self.level, neon_green);
        try writeThousands(out, found);
        try span(out, self.level, chrome_gray, "  up ");
        try setFg(out, self.level, bright_white);
        try writeClock(out, @intFromFloat(elapsed_s));
        try span(out, self.level, chrome_gray, "  eta ");
        try setFg(out, self.level, bright_white);
        try writeClock(out, eta_s);
        try resetFg(out, self.level);
        try out.writeByte('\n');

        try out.flush();
    }
};

pub fn emitJson(out: *std.Io.Writer, r: Result, proto: []const u8) !void {
    try out.print("{{\"ip\":\"", .{});
    try writeAddr(out, r.addr);
    try out.print("\",\"port\":{d},\"proto\":\"{s}\",\"state\":\"{s}\"}}\n", .{ r.port, proto, stateName(r.state) });
}

const w_host: usize = 17;
const w_port: usize = 7;
const w_state: usize = 10;

fn repeat(out: *std.Io.Writer, cell: []const u8, n: usize) !void {
    var i: usize = 0;
    while (i < n) : (i += 1) try out.writeAll(cell);
}

fn rule(out: *std.Io.Writer, level: ColorLevel, hw: usize, left: []const u8, mid: []const u8, right: []const u8) !void {
    try setFg(out, level, chrome_gray);
    try out.writeAll(left);
    try repeat(out, box_h, hw + 2);
    try out.writeAll(mid);
    try repeat(out, box_h, w_port + 2);
    try out.writeAll(mid);
    try repeat(out, box_h, w_state + 2);
    try out.writeAll(right);
    try resetFg(out, level);
    try out.writeByte('\n');
}

fn pad(out: *std.Io.Writer, n: usize) !void {
    var i: usize = 0;
    while (i < n) : (i += 1) try out.writeByte(' ');
}

pub fn renderTable(out: *std.Io.Writer, level: ColorLevel, results: []const Result) !void {
    var hw: usize = "HOST".len;
    for (results) |r| hw = @max(hw, addrWidth(r.addr));

    try out.writeAll("  ");
    try rule(out, level, hw, "\u{250c}", "\u{252c}", "\u{2510}");

    try out.writeAll("  ");
    try span(out, level, chrome_gray, "\u{2502} ");
    try setFg(out, level, bright_white);
    try out.writeAll("HOST");
    try pad(out, hw - "HOST".len);
    try span(out, level, chrome_gray, " \u{2502} ");
    try setFg(out, level, bright_white);
    try pad(out, w_port - "PORT".len);
    try out.writeAll("PORT");
    try span(out, level, chrome_gray, " \u{2502} ");
    try setFg(out, level, bright_white);
    try out.writeAll("STATE");
    try pad(out, w_state - "STATE".len);
    try span(out, level, chrome_gray, " \u{2502}");
    try out.writeByte('\n');

    try out.writeAll("  ");
    try rule(out, level, hw, "\u{251c}", "\u{253c}", "\u{2524}");

    for (results) |r| {
        var ipbuf: [max_addr_str]u8 = undefined;
        var ipw = std.Io.Writer.fixed(&ipbuf);
        try writeAddr(&ipw, r.addr);
        const ip_str = ipbuf[0..ipw.end];

        try out.writeAll("  ");
        try span(out, level, chrome_gray, "\u{2502} ");
        try setFg(out, level, bright_white);
        try out.writeAll(ip_str);
        try resetFg(out, level);
        try pad(out, hw - ip_str.len);

        try span(out, level, chrome_gray, " \u{2502} ");
        var portbuf: [5]u8 = undefined;
        const port_str = std.fmt.bufPrint(&portbuf, "{d}", .{r.port}) catch unreachable;
        try pad(out, w_port - port_str.len);
        try setFg(out, level, bright_white);
        try out.writeAll(port_str);
        try resetFg(out, level);

        try span(out, level, chrome_gray, " \u{2502} ");
        const label = stateLabel(r.state);
        try setFg(out, level, stateColor(r.state));
        try out.writeAll(label);
        try resetFg(out, level);
        try pad(out, w_state - label.len);
        try span(out, level, chrome_gray, " \u{2502}");
        try out.writeByte('\n');
    }

    try out.writeAll("  ");
    try rule(out, level, hw, "\u{2514}", "\u{2534}", "\u{2518}");
}

pub fn ipPortLess(_: void, a: Result, b: Result) bool {
    return switch (packet.Addr.order(a.addr, b.addr)) {
        .lt => true,
        .gt => false,
        .eq => a.port < b.port,
    };
}

pub const ServiceRow = struct {
    ip: u32,
    port: u16,
    service: []const u8,
    info: []const u8,
    tls: bool,
};

const w_service: usize = 11;
const w_info: usize = 34;

fn serviceRule(out: *std.Io.Writer, level: ColorLevel, left: []const u8, mid: []const u8, right: []const u8) !void {
    try setFg(out, level, chrome_gray);
    try out.writeAll(left);
    try repeat(out, box_h, w_host + 2);
    try out.writeAll(mid);
    try repeat(out, box_h, w_port + 2);
    try out.writeAll(mid);
    try repeat(out, box_h, w_service + 2);
    try out.writeAll(mid);
    try repeat(out, box_h, w_info + 2);
    try out.writeAll(right);
    try resetFg(out, level);
    try out.writeByte('\n');
}

fn renderCell(out: *std.Io.Writer, level: ColorLevel, text: []const u8, width: usize, color: Rgb) !void {
    const n = @min(text.len, width);
    try setFg(out, level, color);
    try out.writeAll(text[0..n]);
    try resetFg(out, level);
    try pad(out, width - n);
}

pub fn renderServices(out: *std.Io.Writer, level: ColorLevel, rows: []const ServiceRow) !void {
    try out.writeAll("  ");
    try serviceRule(out, level, "\u{250c}", "\u{252c}", "\u{2510}");

    try out.writeAll("  ");
    try span(out, level, chrome_gray, "\u{2502} ");
    try renderCell(out, level, "HOST", w_host, bright_white);
    try span(out, level, chrome_gray, " \u{2502} ");
    try renderCell(out, level, "PORT", w_port, bright_white);
    try span(out, level, chrome_gray, " \u{2502} ");
    try renderCell(out, level, "SERVICE", w_service, bright_white);
    try span(out, level, chrome_gray, " \u{2502} ");
    try renderCell(out, level, "VERSION / INFO", w_info, bright_white);
    try span(out, level, chrome_gray, " \u{2502}");
    try out.writeByte('\n');

    try out.writeAll("  ");
    try serviceRule(out, level, "\u{251c}", "\u{253c}", "\u{2524}");

    for (rows) |r| {
        var ipbuf: [15]u8 = undefined;
        var ipw = std.Io.Writer.fixed(&ipbuf);
        try writeIp(&ipw, r.ip);

        var portbuf: [5]u8 = undefined;
        const port_str = std.fmt.bufPrint(&portbuf, "{d}", .{r.port}) catch unreachable;

        const info_disp = if (r.info.len > 0) r.info else if (r.tls) "(encrypted)" else "";

        try out.writeAll("  ");
        try span(out, level, chrome_gray, "\u{2502} ");
        try renderCell(out, level, ipbuf[0..ipw.end], w_host, bright_white);
        try span(out, level, chrome_gray, " \u{2502} ");
        try pad(out, w_port - port_str.len);
        try setFg(out, level, bright_white);
        try out.writeAll(port_str);
        try resetFg(out, level);
        try span(out, level, chrome_gray, " \u{2502} ");
        try renderCell(out, level, r.service, w_service, neon_green);
        try span(out, level, chrome_gray, " \u{2502} ");
        try renderCell(out, level, info_disp, w_info, bright_white);
        try span(out, level, chrome_gray, " \u{2502}");
        try out.writeByte('\n');
    }

    try out.writeAll("  ");
    try serviceRule(out, level, "\u{2514}", "\u{2534}", "\u{2518}");
}

fn jsonEscape(out: *std.Io.Writer, s: []const u8) !void {
    for (s) |c| switch (c) {
        '"' => try out.writeAll("\\\""),
        '\\' => try out.writeAll("\\\\"),
        else => try out.writeByte(c),
    };
}

pub fn emitServiceJson(out: *std.Io.Writer, row: ServiceRow) !void {
    try out.writeAll("{\"ip\":\"");
    try writeIp(out, row.ip);
    try out.print("\",\"port\":{d},\"service\":\"", .{row.port});
    try jsonEscape(out, row.service);
    try out.writeAll("\",\"info\":\"");
    try jsonEscape(out, row.info);
    try out.print("\",\"tls\":{s}}}\n", .{if (row.tls) "true" else "false"});
}

pub fn renderSummary(
    out: *std.Io.Writer,
    level: ColorLevel,
    sent: u64,
    probe: []const u8,
    ifname: []const u8,
    elapsed_s: f64,
    open: u64,
    closed: u64,
    filtered: u64,
    unfiltered: u64,
    banners: u64,
) !void {
    try out.writeAll("  ");
    try span(out, level, violet_mid, gutter_bar);
    try out.writeByte(' ');
    try span(out, level, chrome_gray, "sent ");
    try setFg(out, level, bright_white);
    try writeThousands(out, sent);
    try setFg(out, level, chrome_gray);
    try out.print(" {s} on ", .{probe});
    try resetFg(out, level);
    try setFg(out, level, bright_white);
    try out.writeAll(ifname);
    try span(out, level, chrome_gray, " in ");
    try setFg(out, level, bright_white);
    try out.print("{d:.3}s", .{elapsed_s});
    try span(out, level, chrome_gray, "  \u{2192}  ");
    try setFg(out, level, neon_green);
    try writeThousands(out, open);
    try span(out, level, chrome_gray, " open  ");
    try setFg(out, level, chrome_gray);
    try writeThousands(out, closed);
    try span(out, level, chrome_gray, " closed  ");
    try setFg(out, level, soft_amber);
    try writeThousands(out, filtered);
    try span(out, level, chrome_gray, " filtered");
    if (unfiltered > 0) {
        try span(out, level, chrome_gray, "  ");
        try setFg(out, level, bright_white);
        try writeThousands(out, unfiltered);
        try span(out, level, chrome_gray, " unfiltered");
    }
    if (banners > 0) {
        try span(out, level, chrome_gray, "  \u{2192}  ");
        try setFg(out, level, neon_green);
        try writeThousands(out, banners);
        try span(out, level, chrome_gray, " banners");
    }
    try resetFg(out, level);
    try out.writeByte('\n');
}

pub fn renderUnanswered(out: *std.Io.Writer, level: ColorLevel, count: u64) !void {
    try out.writeAll("  ");
    try span(out, level, violet_mid, gutter_bar);
    try out.writeByte(' ');
    try span(out, level, chrome_gray, "open|filtered (no response) ");
    try setFg(out, level, soft_amber);
    try writeThousands(out, count);
    try resetFg(out, level);
    try out.writeByte('\n');
}

test "renderUnanswered reports the silent-port count in plain mode" {
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try renderUnanswered(&w, .none, 4094);
    const text = buf[0..w.end];
    try std.testing.expect(std.mem.indexOf(u8, text, "open|filtered (no response)") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "4,094") != null);
}

test "resolveLevel honors choice, tty state, and truecolor" {
    try std.testing.expectEqual(ColorLevel.none, resolveLevel(.never, true, true));
    try std.testing.expectEqual(ColorLevel.truecolor, resolveLevel(.always, false, true));
    try std.testing.expectEqual(ColorLevel.ansi256, resolveLevel(.always, false, false));
    try std.testing.expectEqual(ColorLevel.none, resolveLevel(.auto, false, true));
    try std.testing.expectEqual(ColorLevel.truecolor, resolveLevel(.auto, true, true));
    try std.testing.expectEqual(ColorLevel.ansi256, resolveLevel(.auto, true, false));
}

test "parseColorChoice maps flag values" {
    try std.testing.expectEqual(ColorChoice.auto, parseColorChoice(null));
    try std.testing.expectEqual(ColorChoice.always, parseColorChoice("always"));
    try std.testing.expectEqual(ColorChoice.never, parseColorChoice("never"));
    try std.testing.expectEqual(ColorChoice.auto, parseColorChoice("garbage"));
}

test "to256 maps palette anchors into the 6x6x6 cube" {
    try std.testing.expectEqual(@as(u8, 16), to256(.{ .r = 0, .g = 0, .b = 0 }));
    try std.testing.expectEqual(@as(u8, 231), to256(.{ .r = 255, .g = 255, .b = 255 }));
    try std.testing.expect(to256(neon_green) >= 16 and to256(neon_green) <= 231);
}

test "violetAt interpolates the gradient endpoints and midpoint" {
    try std.testing.expectEqual(violet_light, violetAt(0.0));
    try std.testing.expectEqual(violet_deep, violetAt(1.0));
    try std.testing.expectEqual(violet_mid, violetAt(0.5));
}

test "Padded counter is cache-line sized and aligned to prevent false sharing" {
    try std.testing.expectEqual(@as(usize, cache_line), @sizeOf(Padded));
    try std.testing.expectEqual(@as(usize, cache_line), @alignOf(Padded));
}

test "Stats.record tallies per-state and total found without cross-talk" {
    var s: Stats = .{};
    s.record(.open);
    s.record(.open);
    s.record(.closed);
    s.record(.filtered);
    try std.testing.expectEqual(@as(u64, 2), s.open.v.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), s.closed.v.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), s.filtered.v.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 4), s.found.v.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), s.sent.v.load(.monotonic));
}

test "emitJson writes one greppable NDJSON object per result with its proto" {
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try emitJson(&w, Result.v4(0x0a000005, 80, .open), "tcp");
    try std.testing.expectEqualStrings(
        "{\"ip\":\"10.0.0.5\",\"port\":80,\"proto\":\"tcp\",\"state\":\"open\"}\n",
        buf[0..w.end],
    );
    w = std.Io.Writer.fixed(&buf);
    try emitJson(&w, Result.v4(0x08080808, 53, .closed), "udp");
    try std.testing.expectEqualStrings(
        "{\"ip\":\"8.8.8.8\",\"port\":53,\"proto\":\"udp\",\"state\":\"closed\"}\n",
        buf[0..w.end],
    );
}

test "writeThousands groups digits and leaves small numbers intact" {
    var buf: [32]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeThousands(&w, 1234567);
    try std.testing.expectEqualStrings("1,234,567", buf[0..w.end]);
    w = std.Io.Writer.fixed(&buf);
    try writeThousands(&w, 42);
    try std.testing.expectEqualStrings("42", buf[0..w.end]);
}

test "renderTable with no color is plain and contains every host row" {
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const rows = [_]Result{
        Result.v4(0x0a000005, 80, .open),
        Result.v4(0x0a000006, 443, .closed),
    };
    try renderTable(&w, .none, &rows);
    const text = buf[0..w.end];
    try std.testing.expect(std.mem.indexOf(u8, text, "10.0.0.5") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "OPEN") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "10.0.0.6") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "CLOSED") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, esc) == null);
}

test "dashboard non-interactive frame is a single plain line" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    var s: Stats = .{};
    _ = s.sent.v.fetchAdd(500, .monotonic);
    s.record(.open);
    var dash = Dashboard.init(.none, false, 1000);
    try dash.render(&w, &s, 1_000_000_000);
    const text = buf[0..w.end];
    try std.testing.expect(std.mem.indexOf(u8, text, "sent 500 / 1000") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, esc) == null);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "\n"));
}

test "writeIp6 renders RFC 5952 compressed IPv6 (longest-first run, no single-group elision)" {
    const cases = .{
        .{ [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "::" },
        .{ [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, "::1" },
        .{ [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, "2001:db8::1" },
        .{ [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "fe80::" },
        .{ [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, "2001:db8:1::1" },
        .{ [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6 }, "2001:db8:1:2:3:4:5:6" },
        .{ [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0, 1 }, "::ffff:c0a8:1" },
    };
    inline for (cases) |c| {
        var buf: [max_addr_str]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try writeIp6(&w, c[0]);
        try std.testing.expectEqualStrings(c[1], buf[0..w.end]);
    }
}

test "emitJson renders an IPv6 result address" {
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const a = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try emitJson(&w, Result.v6(a, 443, .open), "tcp");
    try std.testing.expectEqualStrings(
        "{\"ip\":\"2001:db8::1\",\"port\":443,\"proto\":\"tcp\",\"state\":\"open\"}\n",
        buf[0..w.end],
    );
}

test "ipPortLess orders by ip then port" {
    const a = Result.v4(0x0a000001, 443, .open);
    const b = Result.v4(0x0a000001, 80, .open);
    const c = Result.v4(0x0a000002, 1, .open);
    try std.testing.expect(ipPortLess({}, b, a));
    try std.testing.expect(ipPortLess({}, a, c));
    try std.testing.expect(!ipPortLess({}, a, b));
}

test "emitServiceJson emits an escaped, greppable service record" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try emitServiceJson(&w, .{ .ip = 0x0a000005, .port = 22, .service = "ssh", .info = "OpenSSH_9.6p1", .tls = false });
    try std.testing.expectEqualStrings(
        "{\"ip\":\"10.0.0.5\",\"port\":22,\"service\":\"ssh\",\"info\":\"OpenSSH_9.6p1\",\"tls\":false}\n",
        buf[0..w.end],
    );
}

test "emitServiceJson escapes quotes and backslashes in the info field" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try emitServiceJson(&w, .{ .ip = 0x0a000006, .port = 443, .service = "ssl/tls", .info = "a\"b\\c", .tls = true });
    const text = buf[0..w.end];
    try std.testing.expect(std.mem.indexOf(u8, text, "\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\\\\") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\"tls\":true") != null);
}

test "renderServices lists each host, service, and version without escapes in plain mode" {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const rows = [_]ServiceRow{
        .{ .ip = 0x0a000005, .port = 22, .service = "ssh", .info = "OpenSSH_9.6p1", .tls = false },
        .{ .ip = 0x0a000006, .port = 443, .service = "ssl/tls", .info = "", .tls = true },
    };
    try renderServices(&w, .none, &rows);
    const text = buf[0..w.end];
    try std.testing.expect(std.mem.indexOf(u8, text, "10.0.0.5") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ssh") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "OpenSSH_9.6p1") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "ssl/tls") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "(encrypted)") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, esc) == null);
}
