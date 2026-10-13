const std = @import("std");

const posix = std.posix;

pub const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const salt_length = 16;

const buf_size = 1024;
pub const max_password_length = 1024;

pub const KdfParams = struct {
    m: u32, // memory in KB
    t: u32, // time cost (iterations)
    p: u24, // parallelism
};

pub fn kdf(io: std.Io, gpa: std.mem.Allocator, derived_key: []u8, password: []const u8, salt: []const u8, params: KdfParams) !void {
    const argon2 = std.crypto.pwhash.argon2;
    const argon2_params: argon2.Params = .{
        .m = params.m,
        .t = params.t,
        .p = params.p,
    };
    return argon2.kdf(gpa, derived_key, password, salt, argon2_params, .argon2d, io);
}

pub const Password = union(enum) {
    fixed: []const u8,
    prompt: *const fn (io: std.Io, buf: []u8) anyerror![]const u8,

    pub fn resolve(self: Password, io: std.Io, buf: []u8) ![]const u8 {
        return switch (self) {
            .fixed => |fixed| blk: {
                if (fixed.len > buf.len) return error.PasswordTooLong;
                @memcpy(buf[0..fixed.len], fixed);
                break :blk buf[0..fixed.len];
            },
            .prompt => |promptFn| promptFn(io, buf),
        };
    }
};

pub fn promptPassword(io: std.Io, buf: []u8) ![]const u8 {
    var tty = std.Io.Dir.openFileAbsolute(
        io,
        "/dev/tty",
        .{ .mode = .read_write },
    ) catch |err| switch (err) {
        error.NoDevice => return error.NotATerminal,
        else => return err,
    };
    defer tty.close(io);

    var read_buf: [buf_size]u8 = undefined;
    var tty_reader = tty.readerStreaming(io, &read_buf);
    var reader = &tty_reader.interface;
    var write_buf: [buf_size]u8 = undefined;
    var tty_writer = tty.writerStreaming(io, &write_buf);
    var writer = &tty_writer.interface;

    const termios = try posix.tcgetattr(tty.handle);
    defer _ = posix.tcsetattr(tty.handle, posix.TCSA.NOW, termios) catch {};
    var new_termios = termios;
    new_termios.lflag.ECHO = false;
    new_termios.lflag.ICANON = false;
    try posix.tcsetattr(tty.handle, posix.TCSA.NOW, new_termios);

    _ = try writer.write("Password: ");
    try writer.flush();

    var len: usize = 0;
    var too_long = false;
    while (true) {
        const ch = reader.takeByte() catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (ch == '\r' or ch == '\n') {
            break;
        }
        if (len < buf.len) {
            buf[len] = ch;
            len += 1;
        } else {
            too_long = true;
        }
    }

    _ = try writer.write("\n");
    try writer.flush();

    if (too_long) {
        return error.PasswordTooLong;
    }
    if (len == 0) {
        return error.EmptyPassword;
    }

    return buf[0..len];
}
