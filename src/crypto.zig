const std = @import("std");
const builtin = @import("builtin");

const posix = std.posix;

pub const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const salt_length = 16;

const buf_size = 4096;
const password_length = 1024;

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
        error.NoDevice => return error.NotATerminal,
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
