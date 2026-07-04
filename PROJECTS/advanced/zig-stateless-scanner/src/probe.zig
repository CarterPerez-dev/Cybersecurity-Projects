// ©AngelaMos | 2026
// probe.zig

const std = @import("std");
const regex = @import("regex");

pub const max_info: usize = 96;
pub const max_banner: usize = 512;

pub const http_get = "GET / HTTP/1.0\r\n\r\n";

const http_ports = [_]u16{ 80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000 };

pub fn probeFor(port: u16) []const u8 {
    for (http_ports) |p| {
        if (p == port) return http_get;
    }
    return "";
}

pub const ServiceInfo = struct {
    service: []const u8 = "unknown",
    info: [max_info]u8 = [_]u8{0} ** max_info,
    info_len: usize = 0,
    tls: bool = false,

    pub fn infoSlice(self: *const ServiceInfo) []const u8 {
        return self.info[0..self.info_len];
    }
};

const CompiledRule = struct {
    prefix: []const u8,
    service: []const u8,
    re: ?regex.Regex,
};

fn rule(comptime prefix: []const u8, comptime service: []const u8, comptime pattern: []const u8, comptime flags: regex.Regex.Flags) CompiledRule {
    return .{
        .prefix = prefix,
        .service = service,
        .re = if (pattern.len == 0) null else (regex.Regex.compile(pattern, flags) catch @compileError("probe: bad pattern " ++ pattern)),
    };
}

const rules = blk: {
    @setEvalBranchQuota(400_000);
    break :blk [_]CompiledRule{
        rule("SSH-", "ssh", "^SSH-[\\d.]+-([^\\r\\n]+)", .{}),
        rule("HTTP/", "http", "[Ss]erver:[ \\t]*([^\\r\\n]+)", .{}),
        rule("+OK", "pop3", "^\\+OK ([^\\r\\n]+)", .{}),
        rule("* OK", "imap", "^\\* OK ([^\\r\\n]+)", .{}),
        rule("RFB ", "vnc", "^RFB (\\d+\\.\\d+)", .{}),
        rule("\xff", "telnet", "", .{}),
    };
};

fn startsWith(bytes: []const u8, prefix: []const u8) bool {
    return bytes.len >= prefix.len and std.mem.eql(u8, bytes[0..prefix.len], prefix);
}

pub fn isTls(bytes: []const u8) bool {
    if (bytes.len < 3) return false;
    const content = bytes[0];
    return (content == 0x16 or content == 0x15) and bytes[1] == 0x03 and bytes[2] <= 0x04;
}

fn sanitizeInto(out: *ServiceInfo, src: []const u8) void {
    var n: usize = 0;
    for (src) |c| {
        if (n >= max_info) break;
        out.info[n] = if (c >= 0x20 and c < 0x7f) c else '.';
        n += 1;
    }
    out.info_len = n;
}

fn firstLine(bytes: []const u8) []const u8 {
    const cut = std.mem.indexOfAny(u8, bytes, "\r\n") orelse bytes.len;
    return bytes[0..cut];
}

fn extractInfo(out: *ServiceInfo, re: *const regex.Regex, bytes: []const u8) void {
    var caps: regex.Captures = .{};
    if (re.search(bytes, &caps) != null) {
        if (caps.group(bytes, 1)) |g| sanitizeInto(out, g);
    }
}

fn resolve220(bytes: []const u8) []const u8 {
    if (std.mem.indexOf(u8, bytes, "SMTP") != null or std.mem.indexOf(u8, bytes, "ESMTP") != null) return "smtp";
    if (std.mem.indexOf(u8, bytes, "FTP") != null) return "ftp";
    return "ftp";
}

pub fn classify(bytes: []const u8, out: *ServiceInfo) void {
    out.* = .{};
    if (bytes.len == 0) return;

    if (isTls(bytes)) {
        out.service = "ssl/tls";
        out.tls = true;
        return;
    }

    if (startsWith(bytes, "220-") or startsWith(bytes, "220 ")) {
        out.service = resolve220(bytes);
        sanitizeInto(out, firstLine(bytes));
        return;
    }

    for (rules) |r| {
        if (!startsWith(bytes, r.prefix)) continue;
        out.service = r.service;
        if (r.re) |*re| extractInfo(out, re, bytes) else sanitizeInto(out, firstLine(bytes));
        return;
    }

    out.service = "unknown";
    sanitizeInto(out, firstLine(bytes));
}

// ---- tests ----

test "probeFor sends an HTTP GET on web ports and nothing elsewhere" {
    try std.testing.expectEqualStrings(http_get, probeFor(80));
    try std.testing.expectEqualStrings(http_get, probeFor(8080));
    try std.testing.expectEqualStrings("", probeFor(22));
    try std.testing.expectEqualStrings("", probeFor(443));
}

test "SSH banner classifies as ssh and extracts the software string" {
    var si: ServiceInfo = .{};
    classify("SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n", &si);
    try std.testing.expectEqualStrings("ssh", si.service);
    try std.testing.expectEqualStrings("OpenSSH_9.6p1 Debian-3", si.infoSlice());
    try std.testing.expect(!si.tls);
}

test "HTTP response classifies as http and pulls the Server header" {
    var si: ServiceInfo = .{};
    classify("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 5\r\n\r\nhello", &si);
    try std.testing.expectEqualStrings("http", si.service);
    try std.testing.expectEqualStrings("nginx/1.24.0", si.infoSlice());
}

test "SMTP and FTP both greet with 220 but disambiguate by content" {
    var si: ServiceInfo = .{};
    classify("220 mail.example.com ESMTP Postfix\r\n", &si);
    try std.testing.expectEqualStrings("smtp", si.service);
    classify("220 ProFTPD Server ready\r\n", &si);
    try std.testing.expectEqualStrings("ftp", si.service);
}

test "POP3 and IMAP greetings classify by their prefixes" {
    var si: ServiceInfo = .{};
    classify("+OK Dovecot ready.\r\n", &si);
    try std.testing.expectEqualStrings("pop3", si.service);
    try std.testing.expectEqualStrings("Dovecot ready.", si.infoSlice());
    classify("* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n", &si);
    try std.testing.expectEqualStrings("imap", si.service);
}

test "a TLS record is detected without decrypting it" {
    var si: ServiceInfo = .{};
    classify(&[_]u8{ 0x16, 0x03, 0x03, 0x00, 0x50, 0x02 }, &si);
    try std.testing.expectEqualStrings("ssl/tls", si.service);
    try std.testing.expect(si.tls);
}

test "an unrecognized banner is reported as unknown with its first line" {
    var si: ServiceInfo = .{};
    classify("GARBAGE PROTOCOL v3\r\nsecond line\r\n", &si);
    try std.testing.expectEqualStrings("unknown", si.service);
    try std.testing.expectEqualStrings("GARBAGE PROTOCOL v3", si.infoSlice());
}

test "a hostile banner cannot inject terminal escapes into the info field" {
    var si: ServiceInfo = .{};
    classify("SSH-2.0-\x1b[31mEVIL\x1b[0m\x07\r\n", &si);
    try std.testing.expectEqualStrings("ssh", si.service);
    try std.testing.expect(std.mem.indexOfScalar(u8, si.infoSlice(), 0x1b) == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, si.infoSlice(), 0x07) == null);
    try std.testing.expectEqualStrings(".[31mEVIL.[0m.", si.infoSlice());
}

test "the info field is length-capped even for a very long banner" {
    var si: ServiceInfo = .{};
    var big: [400]u8 = undefined;
    @memcpy(big[0..4], "+OK ");
    @memset(big[4..], 'A');
    classify(&big, &si);
    try std.testing.expectEqualStrings("pop3", si.service);
    try std.testing.expect(si.info_len <= max_info);
}

test "empty input yields the inert default" {
    var si: ServiceInfo = .{};
    classify("", &si);
    try std.testing.expectEqualStrings("unknown", si.service);
    try std.testing.expectEqual(@as(usize, 0), si.info_len);
}
