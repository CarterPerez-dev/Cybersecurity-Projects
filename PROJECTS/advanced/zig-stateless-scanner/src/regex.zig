// ©AngelaMos | 2026
// regex.zig

const std = @import("std");

pub const max_insts: usize = 160;
pub const max_nodes: usize = 160;
pub const max_classes: usize = 16;
pub const max_caps: usize = 8;
pub const max_repeat: usize = 512;
pub const default_budget: u32 = 200_000;
pub const max_depth: usize = 8192;

const cap_slots: usize = (max_caps + 1) * 2;

pub const CompileError = error{
    ProgramTooBig,
    TooManyNodes,
    TooManyClasses,
    TooManyCaptures,
    UnbalancedParen,
    UnbalancedClass,
    BadQuantifier,
    QuantifierOnGroup,
    TrailingBackslash,
    EmptyRepeat,
};

const Op = enum { char, any, class, match, jmp, split, save, bol, eol };

const Inst = struct {
    op: Op,
    a: u32 = 0,
    b: u32 = 0,
};

const Class = struct {
    neg: bool = false,
    bits: [32]u8 = [_]u8{0} ** 32,

    fn set(self: *Class, byte: u8) void {
        self.bits[byte >> 3] |= (@as(u8, 1) << @intCast(byte & 7));
    }

    fn setRange(self: *Class, lo: u8, hi: u8) void {
        var b: usize = lo;
        while (b <= hi) : (b += 1) self.set(@intCast(b));
        if (hi == 255) self.set(255);
    }

    fn has(self: *const Class, byte: u8) bool {
        const in = (self.bits[byte >> 3] & (@as(u8, 1) << @intCast(byte & 7))) != 0;
        return in != self.neg;
    }
};

const NodeKind = enum { empty, char, any, class, bol, eol, concat, alt, star, plus, quest, repeat, group };

const Node = struct {
    kind: NodeKind,
    ch: u8 = 0,
    class_idx: u16 = 0,
    left: u16 = 0,
    right: u16 = 0,
    greedy: bool = true,
    min: u16 = 0,
    max: u16 = 0,
    cap: i16 = -1,
};

const unbounded: u16 = 0xffff;

pub const Captures = struct {
    slots: [cap_slots]u32 = [_]u32{unset} ** cap_slots,

    const unset: u32 = 0xffff_ffff;

    pub fn group(self: *const Captures, input: []const u8, idx: usize) ?[]const u8 {
        const s = idx * 2;
        if (s + 1 >= cap_slots) return null;
        const a = self.slots[s];
        const b = self.slots[s + 1];
        if (a == unset or b == unset or b < a or b > input.len) return null;
        return input[a..b];
    }
};

pub const Regex = struct {
    insts: [max_insts]Inst = [_]Inst{.{ .op = .match }} ** max_insts,
    n_insts: usize = 0,
    classes: [max_classes]Class = [_]Class{.{}} ** max_classes,
    n_classes: usize = 0,
    n_caps: usize = 0,
    fold: bool = false,
    dotall: bool = false,

    pub const Flags = struct {
        fold: bool = false,
        dotall: bool = false,
    };

    pub fn compile(pattern: []const u8, flags: Flags) CompileError!Regex {
        var b = Builder{
            .pat = pattern,
            .fold = flags.fold,
        };
        var re: Regex = .{ .fold = flags.fold, .dotall = flags.dotall };
        const root = try b.parseAlt(&re);
        if (b.pos != pattern.len) return error.UnbalancedParen;
        try b.emit(&re, root);
        try re.push(.{ .op = .match });
        re.n_caps = b.n_caps;
        return re;
    }

    fn push(self: *Regex, inst: Inst) CompileError!void {
        if (self.n_insts >= max_insts) return error.ProgramTooBig;
        self.insts[self.n_insts] = inst;
        self.n_insts += 1;
    }

    fn addClass(self: *Regex, cls: Class) CompileError!u16 {
        if (self.n_classes >= max_classes) return error.TooManyClasses;
        const idx = self.n_classes;
        self.classes[idx] = cls;
        self.n_classes += 1;
        return @intCast(idx);
    }

    fn foldByte(self: *const Regex, c: u8) u8 {
        return if (self.fold) std.ascii.toLower(c) else c;
    }

    fn step(self: *const Regex, input: []const u8, pc0: usize, sp0: usize, caps: *Captures, budget: *u32, depth: usize) ?usize {
        if (depth > max_depth) return null;
        var pc = pc0;
        var sp = sp0;
        while (true) {
            if (budget.* == 0) return null;
            budget.* -= 1;
            const in = self.insts[pc];
            switch (in.op) {
                .char => {
                    if (sp < input.len and self.foldByte(input[sp]) == @as(u8, @intCast(in.a))) {
                        pc += 1;
                        sp += 1;
                    } else return null;
                },
                .any => {
                    if (sp < input.len and (self.dotall or input[sp] != '\n')) {
                        pc += 1;
                        sp += 1;
                    } else return null;
                },
                .class => {
                    if (sp < input.len and self.classes[in.a].has(input[sp])) {
                        pc += 1;
                        sp += 1;
                    } else return null;
                },
                .bol => {
                    if (sp == 0) {
                        pc += 1;
                    } else return null;
                },
                .eol => {
                    if (sp == input.len) {
                        pc += 1;
                    } else return null;
                },
                .save => {
                    if (in.a < cap_slots) caps.slots[in.a] = @intCast(sp);
                    pc += 1;
                },
                .jmp => pc = in.a,
                .split => {
                    const snap = caps.*;
                    if (self.step(input, in.a, sp, caps, budget, depth + 1)) |e| return e;
                    caps.* = snap;
                    pc = in.b;
                },
                .match => return sp,
            }
        }
    }

    pub fn search(self: *const Regex, input: []const u8, caps: *Captures) ?usize {
        var budget: u32 = default_budget;
        var start: usize = 0;
        while (start <= input.len) : (start += 1) {
            caps.* = .{};
            if (self.step(input, 0, start, caps, &budget, 0)) |end| {
                caps.slots[0] = @intCast(start);
                caps.slots[1] = @intCast(end);
                return end;
            }
            if (budget == 0) return null;
        }
        return null;
    }
};

const Builder = struct {
    pat: []const u8,
    pos: usize = 0,
    fold: bool,
    n_nodes: u16 = 0,
    nodes: [max_nodes]Node = undefined,
    n_caps: usize = 0,

    fn peek(self: *const Builder) ?u8 {
        return if (self.pos < self.pat.len) self.pat[self.pos] else null;
    }

    fn add(self: *Builder, node: Node) CompileError!u16 {
        if (self.n_nodes >= max_nodes) return error.TooManyNodes;
        const idx = self.n_nodes;
        self.nodes[idx] = node;
        self.n_nodes += 1;
        return idx;
    }

    fn parseAlt(self: *Builder, re: *Regex) CompileError!u16 {
        var left = try self.parseConcat(re);
        while (self.peek() == @as(u8, '|')) {
            self.pos += 1;
            const right = try self.parseConcat(re);
            left = try self.add(.{ .kind = .alt, .left = left, .right = right });
        }
        return left;
    }

    fn parseConcat(self: *Builder, re: *Regex) CompileError!u16 {
        var acc: ?u16 = null;
        while (self.peek()) |c| {
            if (c == '|' or c == ')') break;
            const piece = try self.parsePiece(re);
            acc = if (acc) |a| try self.add(.{ .kind = .concat, .left = a, .right = piece }) else piece;
        }
        return acc orelse try self.add(.{ .kind = .empty });
    }

    fn parsePiece(self: *Builder, re: *Regex) CompileError!u16 {
        const atom = try self.parseAtom(re);
        const c = self.peek() orelse return atom;
        switch (c) {
            '*', '+', '?' => {
                self.pos += 1;
                const greedy = !(self.peek() == @as(u8, '?'));
                if (!greedy) self.pos += 1;
                const kind: NodeKind = switch (c) {
                    '*' => .star,
                    '+' => .plus,
                    else => .quest,
                };
                return self.add(.{ .kind = kind, .left = atom, .greedy = greedy });
            },
            '{' => return self.parseRepeat(atom),
            else => return atom,
        }
    }

    fn parseRepeat(self: *Builder, atom: u16) CompileError!u16 {
        if (self.nodes[atom].kind == .group or self.nodes[atom].kind == .alt or self.nodes[atom].kind == .concat)
            return error.QuantifierOnGroup;
        self.pos += 1;
        const min = try self.readNumber();
        var max: u16 = min;
        if (self.peek() == @as(u8, ',')) {
            self.pos += 1;
            if (self.peek() == @as(u8, '}')) {
                max = unbounded;
            } else {
                max = try self.readNumber();
            }
        }
        if (self.peek() != @as(u8, '}')) return error.BadQuantifier;
        self.pos += 1;
        if (max != unbounded and max < min) return error.BadQuantifier;
        if (max != unbounded and max > max_repeat) return error.BadQuantifier;
        const greedy = !(self.peek() == @as(u8, '?'));
        if (!greedy) self.pos += 1;
        return self.add(.{ .kind = .repeat, .left = atom, .min = min, .max = max, .greedy = greedy });
    }

    fn readNumber(self: *Builder) CompileError!u16 {
        var n: u32 = 0;
        var seen = false;
        while (self.peek()) |c| {
            if (c < '0' or c > '9') break;
            n = n * 10 + (c - '0');
            if (n > max_repeat) n = max_repeat + 1;
            self.pos += 1;
            seen = true;
        }
        if (!seen) return error.BadQuantifier;
        return @intCast(@min(n, @as(u32, unbounded)));
    }

    fn parseAtom(self: *Builder, re: *Regex) CompileError!u16 {
        const c = self.peek() orelse return self.add(.{ .kind = .empty });
        switch (c) {
            '(' => {
                self.pos += 1;
                var cap: i16 = -1;
                if (self.pos + 1 < self.pat.len and self.pat[self.pos] == '?' and self.pat[self.pos + 1] == ':') {
                    self.pos += 2;
                } else {
                    self.n_caps += 1;
                    if (self.n_caps > max_caps) return error.TooManyCaptures;
                    cap = @intCast(self.n_caps);
                }
                const inner = try self.parseAlt(re);
                if (self.peek() != @as(u8, ')')) return error.UnbalancedParen;
                self.pos += 1;
                return self.add(.{ .kind = .group, .left = inner, .cap = cap });
            },
            '[' => return self.parseClass(re),
            '.' => {
                self.pos += 1;
                return self.add(.{ .kind = .any });
            },
            '^' => {
                self.pos += 1;
                return self.add(.{ .kind = .bol });
            },
            '$' => {
                self.pos += 1;
                return self.add(.{ .kind = .eol });
            },
            '\\' => return self.parseEscape(re),
            else => {
                self.pos += 1;
                return self.add(.{ .kind = .char, .ch = c });
            },
        }
    }

    fn parseEscape(self: *Builder, re: *Regex) CompileError!u16 {
        self.pos += 1;
        const c = self.peek() orelse return error.TrailingBackslash;
        self.pos += 1;
        switch (c) {
            'd', 'D', 'w', 'W', 's', 'S' => {
                const ci = try self.addShorthand(re, c);
                return self.add(.{ .kind = .class, .class_idx = ci });
            },
            'n' => return self.add(.{ .kind = .char, .ch = '\n' }),
            'r' => return self.add(.{ .kind = .char, .ch = '\r' }),
            't' => return self.add(.{ .kind = .char, .ch = '\t' }),
            '0' => return self.add(.{ .kind = .char, .ch = 0 }),
            else => return self.add(.{ .kind = .char, .ch = c }),
        }
    }

    fn addShorthand(self: *Builder, re: *Regex, c: u8) CompileError!u16 {
        _ = self;
        var cls = Class{};
        fillShorthand(&cls, c);
        return re.addClass(cls);
    }

    fn parseClass(self: *Builder, re: *Regex) CompileError!u16 {
        self.pos += 1;
        var cls = Class{};
        if (self.peek() == @as(u8, '^')) {
            cls.neg = true;
            self.pos += 1;
        }
        var first = true;
        while (true) {
            const c = self.peek() orelse return error.UnbalancedClass;
            if (c == ']' and !first) {
                self.pos += 1;
                break;
            }
            first = false;
            if (c == '\\') {
                self.pos += 1;
                const e = self.peek() orelse return error.TrailingBackslash;
                self.pos += 1;
                switch (e) {
                    'd', 'D', 'w', 'W', 's', 'S' => fillShorthand(&cls, e),
                    'n' => self.classSet(&cls, '\n'),
                    'r' => self.classSet(&cls, '\r'),
                    't' => self.classSet(&cls, '\t'),
                    else => self.classSet(&cls, e),
                }
                continue;
            }
            self.pos += 1;
            if (self.peek() == @as(u8, '-') and self.pos + 1 < self.pat.len and self.pat[self.pos + 1] != ']') {
                self.pos += 1;
                const hi = self.peek().?;
                self.pos += 1;
                const lo_c = c;
                if (hi < lo_c) return error.UnbalancedClass;
                cls.setRange(lo_c, hi);
                if (self.fold) {
                    self.foldRange(&cls, lo_c, hi);
                }
            } else {
                self.classSet(&cls, c);
            }
        }
        const ci = try re.addClass(cls);
        return self.add(.{ .kind = .class, .class_idx = ci });
    }

    fn classSet(self: *Builder, cls: *Class, c: u8) void {
        cls.set(c);
        if (self.fold) {
            cls.set(std.ascii.toLower(c));
            cls.set(std.ascii.toUpper(c));
        }
    }

    fn foldRange(self: *Builder, cls: *Class, lo: u8, hi: u8) void {
        _ = self;
        var b: usize = lo;
        while (b <= hi) : (b += 1) {
            const ch: u8 = @intCast(b);
            cls.set(std.ascii.toLower(ch));
            cls.set(std.ascii.toUpper(ch));
        }
    }

    fn emit(self: *Builder, re: *Regex, node_idx: u16) CompileError!void {
        const node = self.nodes[node_idx];
        switch (node.kind) {
            .empty => {},
            .char => {
                const ch = if (re.fold) std.ascii.toLower(node.ch) else node.ch;
                try re.push(.{ .op = .char, .a = ch });
            },
            .any => try re.push(.{ .op = .any }),
            .class => try re.push(.{ .op = .class, .a = node.class_idx }),
            .bol => try re.push(.{ .op = .bol }),
            .eol => try re.push(.{ .op = .eol }),
            .concat => {
                try self.emit(re, node.left);
                try self.emit(re, node.right);
            },
            .alt => {
                const isplit = re.n_insts;
                try re.push(.{ .op = .split });
                const l1 = re.n_insts;
                try self.emit(re, node.left);
                const ijmp = re.n_insts;
                try re.push(.{ .op = .jmp });
                const l2 = re.n_insts;
                try self.emit(re, node.right);
                const end = re.n_insts;
                re.insts[isplit].a = @intCast(l1);
                re.insts[isplit].b = @intCast(l2);
                re.insts[ijmp].a = @intCast(end);
            },
            .group => {
                if (node.cap >= 0) {
                    const c: usize = @intCast(node.cap);
                    try re.push(.{ .op = .save, .a = @intCast(c * 2) });
                    try self.emit(re, node.left);
                    try re.push(.{ .op = .save, .a = @intCast(c * 2 + 1) });
                } else {
                    try self.emit(re, node.left);
                }
            },
            .quest => try self.emitQuest(re, node.left, node.greedy),
            .star => try self.emitStar(re, node.left, node.greedy),
            .plus => try self.emitPlus(re, node.left, node.greedy),
            .repeat => try self.emitRepeat(re, node.left, node.min, node.max, node.greedy),
        }
    }

    fn emitQuest(self: *Builder, re: *Regex, child: u16, greedy: bool) CompileError!void {
        const isplit = re.n_insts;
        try re.push(.{ .op = .split });
        const l1 = re.n_insts;
        try self.emit(re, child);
        const end = re.n_insts;
        setSplit(re, isplit, l1, end, greedy);
    }

    fn emitStar(self: *Builder, re: *Regex, child: u16, greedy: bool) CompileError!void {
        const isplit = re.n_insts;
        try re.push(.{ .op = .split });
        const l1 = re.n_insts;
        try self.emit(re, child);
        try re.push(.{ .op = .jmp, .a = @intCast(isplit) });
        const end = re.n_insts;
        setSplit(re, isplit, l1, end, greedy);
    }

    fn emitPlus(self: *Builder, re: *Regex, child: u16, greedy: bool) CompileError!void {
        const l1 = re.n_insts;
        try self.emit(re, child);
        const isplit = re.n_insts;
        try re.push(.{ .op = .split });
        const end = re.n_insts;
        setSplit(re, isplit, l1, end, greedy);
    }

    fn emitRepeat(self: *Builder, re: *Regex, child: u16, min: u16, max: u16, greedy: bool) CompileError!void {
        var k: usize = 0;
        while (k < min) : (k += 1) try self.emit(re, child);
        if (max == unbounded) {
            try self.emitStar(re, child, greedy);
            return;
        }
        const opt = max - min;
        var splits: [max_repeat]usize = undefined;
        var i: usize = 0;
        while (i < opt) : (i += 1) {
            splits[i] = re.n_insts;
            try re.push(.{ .op = .split });
            try self.emit(re, child);
        }
        const end = re.n_insts;
        i = 0;
        while (i < opt) : (i += 1) setSplit(re, splits[i], splits[i] + 1, end, greedy);
    }
};

fn setSplit(re: *Regex, idx: usize, body: usize, exit: usize, greedy: bool) void {
    if (greedy) {
        re.insts[idx].a = @intCast(body);
        re.insts[idx].b = @intCast(exit);
    } else {
        re.insts[idx].a = @intCast(exit);
        re.insts[idx].b = @intCast(body);
    }
}

fn isDigit(b: u8) bool {
    return b >= '0' and b <= '9';
}

fn isWord(b: u8) bool {
    return (b >= '0' and b <= '9') or (b >= 'a' and b <= 'z') or (b >= 'A' and b <= 'Z') or b == '_';
}

fn isSpace(b: u8) bool {
    return b == ' ' or b == '\t' or b == '\n' or b == '\r' or b == 0x0c or b == 0x0b;
}

fn fillShorthand(cls: *Class, c: u8) void {
    var b: usize = 0;
    while (b <= 255) : (b += 1) {
        const ch: u8 = @intCast(b);
        const in = switch (c) {
            'd' => isDigit(ch),
            'D' => !isDigit(ch),
            'w' => isWord(ch),
            'W' => !isWord(ch),
            's' => isSpace(ch),
            'S' => !isSpace(ch),
            else => false,
        };
        if (in) cls.set(ch);
        if (b == 255) break;
    }
}

// ---- tests ----

fn expectMatch(pattern: []const u8, input: []const u8) !void {
    const re = try Regex.compile(pattern, .{});
    var caps: Captures = .{};
    try std.testing.expect(re.search(input, &caps) != null);
}

fn expectNoMatch(pattern: []const u8, input: []const u8) !void {
    const re = try Regex.compile(pattern, .{});
    var caps: Captures = .{};
    try std.testing.expect(re.search(input, &caps) == null);
}

test "literal, dot, and anchors" {
    try expectMatch("abc", "xxabcyy");
    try expectNoMatch("abc", "abx");
    try expectMatch("a.c", "azc");
    try expectNoMatch("a.c", "a\nc");
    try expectMatch("^abc", "abcdef");
    try expectNoMatch("^abc", "zabc");
    try expectMatch("abc$", "zzabc");
    try expectNoMatch("abc$", "abcz");
}

test "star, plus, quest greedy" {
    try expectMatch("ab*c", "ac");
    try expectMatch("ab*c", "abbbbc");
    try expectMatch("ab+c", "abc");
    try expectNoMatch("ab+c", "ac");
    try expectMatch("ab?c", "ac");
    try expectMatch("ab?c", "abc");
    try expectNoMatch("ab?c", "abbc");
}

test "character classes with ranges, negation, and shorthands" {
    try expectMatch("[a-f]+", "0deadbeef1");
    try expectMatch("[^0-9]", "a");
    try expectNoMatch("^[^0-9]$", "5");
    try expectMatch("\\d+", "port 8080 open");
    try expectMatch("^\\w+$", "host_name99");
    try expectNoMatch("^\\w+$", "has space");
    try expectMatch("a\\s+b", "a \t b");
}

test "alternation and grouping" {
    try expectMatch("cat|dog|bird", "i have a dog");
    try expectNoMatch("^(cat|dog)$", "fish");
    try expectMatch("^(ab)+$", "ababab");
    try expectNoMatch("^(ab)+$", "aba");
}

test "bounded repeat {n}, {n,}, {n,m}" {
    try expectMatch("^a{3}$", "aaa");
    try expectNoMatch("^a{3}$", "aa");
    try expectMatch("^a{2,}$", "aaaaa");
    try expectNoMatch("^a{2,}$", "a");
    try expectMatch("^a{2,4}$", "aaa");
    try expectNoMatch("^a{2,4}$", "aaaaa");
    try expectMatch("^\\d{1,3}\\.\\d{1,3}$", "10.255");
}

test "captures extract submatches" {
    const re = try Regex.compile("^SSH-([\\d.]+)-(\\S+)", .{});
    var caps: Captures = .{};
    const banner = "SSH-2.0-OpenSSH_9.6p1\r\n";
    try std.testing.expect(re.search(banner, &caps) != null);
    try std.testing.expectEqualStrings("2.0", caps.group(banner, 1).?);
    try std.testing.expectEqualStrings("OpenSSH_9.6p1", caps.group(banner, 2).?);
}

test "case-insensitive flag folds literals and ranges" {
    const re = try Regex.compile("server: ([a-z]+)", .{ .fold = true });
    var caps: Captures = .{};
    const hdr = "Server: Nginx";
    try std.testing.expect(re.search(hdr, &caps) != null);
    try std.testing.expectEqualStrings("Nginx", caps.group(hdr, 1).?);
}

test "dotall flag lets dot cross newlines" {
    var caps: Captures = .{};
    const plain = try Regex.compile("a.b", .{});
    try std.testing.expect(plain.search("a\nb", &caps) == null);
    const dotall = try Regex.compile("a.b", .{ .dotall = true });
    try std.testing.expect(dotall.search("a\nb", &caps) != null);
}

test "lazy quantifier stops at the first opportunity" {
    const re = try Regex.compile("<(.+?)>", .{});
    var caps: Captures = .{};
    const s = "<a><b>";
    try std.testing.expect(re.search(s, &caps) != null);
    try std.testing.expectEqualStrings("a", caps.group(s, 1).?);
}

test "the step budget makes a pathological input fail closed instead of hanging" {
    const re = try Regex.compile("(a+)+$", .{});
    var caps: Captures = .{};
    const evil = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX";
    try std.testing.expect(re.search(evil, &caps) == null);
}

test "the recursion-depth cap fails closed on a match deeper than the stack allows" {
    var input: [max_depth + 100]u8 = undefined;
    @memset(&input, 'a');
    const re = try Regex.compile("^a*$", .{});
    var caps: Captures = .{};
    try std.testing.expect(re.search(&input, &caps) == null);
    try std.testing.expect(re.search("aaaa", &caps) != null);
}

test "escaped metacharacters are literal" {
    try expectMatch("^\\d+\\.\\d+$", "3.14");
    try expectNoMatch("^\\d+\\.\\d+$", "3x14");
    try expectMatch("a\\+b", "a+b");
}

test "empty pattern matches, unbalanced paren rejected" {
    try expectMatch("", "anything");
    try std.testing.expectError(error.UnbalancedParen, Regex.compile("(ab", .{}));
    try std.testing.expectError(error.QuantifierOnGroup, Regex.compile("(ab){2}", .{}));
}

test "compiles at comptime into an embeddable program" {
    const re = comptime blk: {
        @setEvalBranchQuota(20000);
        break :blk Regex.compile("^220[- ]", .{}) catch unreachable;
    };
    var caps: Captures = .{};
    try std.testing.expect(re.search("220 smtp.example.com ESMTP", &caps) != null);
    try std.testing.expect(re.search("500 error", &caps) == null);
}
