const std = @import("std");
const builtin = @import("builtin");

const posix = std.posix;
const process = std.process;
const Io = std.Io;
const math = std.math;

pub const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;

const buf_size = 4096;

const salt_length = 16;
const password_length = 1024;

pub const EnvVar = struct {
    name: []const u8,
    value: []const u8,
};

pub const Header = extern struct {
    salt: [salt_length]u8,
    nonce: [Aead.nonce_length]u8,
    tag: [Aead.tag_length]u8,
    executable_offset: usize,
};

pub const Footer = extern struct {
    pub const OffsetType = u64;
    offset: [@sizeOf(OffsetType)]u8,

    pub fn readOffset(self: *const @This()) OffsetType {
        return std.mem.readInt(OffsetType, &self.offset, .little);
    }

    pub fn writeOffset(self: *@This(), offset: OffsetType) void {
        std.mem.writeInt(OffsetType, &self.offset, offset, .little);
    }
};

pub const Payload = struct {
    const Self = @This();

    data: []u8,

    pub fn init(gpa: std.mem.Allocator, private_size: usize) std.mem.Allocator.Error!Payload {
        const data = try gpa.alloc(
            u8,
            @sizeOf(Header) + private_size + @sizeOf(Footer),
        );
        return Payload{ .data = data };
    }

    pub fn deinit(self: Self, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }

    pub fn fromData(data: []u8) Payload {
        const footer_offset = data.len - @sizeOf(Footer);
        const f = std.mem.bytesAsValue(Footer, data[footer_offset..]);
        const offset = f.readOffset();
        return Payload{ .data = data[offset..] };
    }

    pub fn header(self: *Self) *align(1) Header {
        return std.mem.bytesAsValue(Header, self.data[0..@sizeOf(Header)]);
    }

    pub fn footer(self: *Self) *align(1) Footer {
        const footer_offset = self.data.len - @sizeOf(Footer);
        return std.mem.bytesAsValue(Footer, self.data[footer_offset..]);
    }

    pub fn encryptedPayload(self: *Self) []u8 {
        const header_offset = @sizeOf(Header);
        const footer_offset = self.data.len - @sizeOf(Footer);
        return self.data[header_offset..footer_offset];
    }
};

pub const PrivatePayload = struct {
    const Self = @This();

    data: []u8,
    executable_offset: usize,

    pub const EnvIter = struct {
        payload: *Self,
        reader: Io.Reader,
        num: u32,
        idx: u32,

        pub fn next(iter: *EnvIter) ?EnvVar {
            if (iter.idx >= iter.num) return null;
            const name_len = iter.reader.takeInt(u16, .little) catch return null;
            const name = iter.reader.take(name_len) catch return null;
            const value_len = iter.reader.takeInt(u16, .little) catch return null;
            const value = iter.reader.take(value_len) catch return null;
            iter.idx += 1;
            return EnvVar{
                .name = name,
                .value = value,
            };
        }
    };

    pub fn init(
        gpa: std.mem.Allocator,
        env_map: *const process.EnvMap,
        compressed_executable: []const u8,
    ) !PrivatePayload {
        var writer = Io.Writer.Allocating.init(gpa);
        try encodeEnv(&writer.writer, env_map);
        const offset = writer.written().len;
        try writer.writer.writeAll(compressed_executable);
        return PrivatePayload{
            .data = try writer.toOwnedSlice(),
            .executable_offset = offset,
        };
    }

    pub fn deinit(self: Self, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }

    pub fn fromData(data: []u8, executable_offset: usize) PrivatePayload {
        std.debug.assert(executable_offset <= data.len);
        return PrivatePayload{
            .data = data,
            .executable_offset = executable_offset,
        };
    }

    pub fn env(self: *Self) []u8 {
        return self.data[0..self.executable_offset];
    }

    pub fn executable(self: *Self) []u8 {
        return self.data[self.executable_offset..];
    }

    pub fn envIterator(self: *Self) EnvIter {
        var reader = Io.Reader.fixed(self.env());
        const num = reader.takeInt(u32, .little) catch 0;

        return EnvIter{
            .payload = self,
            .reader = reader,
            .idx = 0,
            .num = num,
        };
    }
};

pub fn kdf(gpa: std.mem.Allocator, derived_key: []u8, password: []const u8, salt: []const u8) !void {
    const argon2 = std.crypto.pwhash.argon2;
    const params: argon2.Params = if (builtin.mode == .Debug)
        .{
            .p = 1,
            .m = 2 * 1024,
            .t = 1,
        }
    else
        .{
            .p = 8,
            .m = 2 * 1024 * 1024,
            .t = 1,
        };
    return argon2.kdf(gpa, derived_key, password, salt, params, .argon2d);
}

pub fn promptPassword(gpa: std.mem.Allocator) ![]u8 {
    var tty = std.fs.openFileAbsolute(
        "/dev/tty",
        .{ .mode = .read_write },
    ) catch |err| switch (err) {
        error.FileNotFound => return error.NotATerminal,
        else => return err,
    };

    var read_buf: [buf_size]u8 = undefined;
    var tty_reader = tty.readerStreaming(&read_buf);
    var reader = &tty_reader.interface;
    var write_buf: [buf_size]u8 = undefined;
    var tty_writer = tty.writerStreaming(&write_buf);
    var writer = &tty_writer.interface;

    const termios = try posix.tcgetattr(tty.handle);
    defer _ = posix.tcsetattr(tty.handle, posix.TCSA.NOW, termios) catch {};
    var new_termios = termios;
    new_termios.lflag.ECHO = false;
    new_termios.lflag.ICANON = false;
    try posix.tcsetattr(tty.handle, posix.TCSA.NOW, new_termios);

    _ = try writer.write("Password: ");
    try writer.flush();

    var pw_buf = try std.ArrayList(u8).initCapacity(gpa, password_length);
    while (true) {
        const ch = reader.takeByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (ch == '\r' or ch == '\n') {
            break;
        }
        if (pw_buf.items.len < pw_buf.capacity) {
            pw_buf.appendAssumeCapacity(ch);
        }
    }

    _ = try writer.write("\n");
    try writer.flush();

    if (pw_buf.items.len == pw_buf.capacity) {
        return error.PasswordTooLong;
    }

    const password = try pw_buf.toOwnedSlice(gpa);
    if (password.len == 0) {
        return error.EmptyPassword;
    }

    return password;
}

fn encodeEnv(writer: *Io.Writer, env: *const process.EnvMap) !void {
    try writer.writeInt(u32, env.count(), .little);

    var it = env.iterator();
    while (it.next()) |entry| {
        if (entry.key_ptr.len > math.maxInt(u16)) {
            return error.EnvVarTooLarge;
        }
        if (entry.value_ptr.len > math.maxInt(u16)) {
            return error.EnvVarTooLarge;
        }
        try writer.writeInt(u16, @truncate(entry.key_ptr.len), .little);
        try writer.writeAll(entry.key_ptr.*);
        try writer.writeInt(u16, @truncate(entry.value_ptr.len), .little);
        try writer.writeAll(entry.value_ptr.*);
    }
}
