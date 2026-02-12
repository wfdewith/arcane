const std = @import("std");
const posix = std.posix;

const crypto = @import("crypto.zig");
const format = @import("format.zig");
const unpacker = @import("unpacker.zig");

const syscalls = struct {
    fn execveat(
        fd: posix.fd_t,
        path: [*:0]const u8,
        argv: [*:null]const ?[*:0]const u8,
        envp: [*:null]const ?[*:0]const u8,
        flags: u32,
    ) usize {
        return std.os.linux.syscall5(
            .execveat,
            @as(usize, @bitCast(@as(isize, fd))),
            @intFromPtr(path),
            @intFromPtr(argv),
            @intFromPtr(envp),
            flags,
        );
    }
};

const buf_size = 1024;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const gpa = arena.allocator();
    defer arena.deinit();

    const password = try getPassword(gpa);
    defer std.crypto.secureZero(u8, password);

    const exe = try std.fs.openFileAbsolute("/proc/self/exe", .{});

    const memfd = try posix.memfd_create("", 0);
    const memfd_file = std.fs.File{ .handle = memfd };

    var read_buf: [buf_size]u8 = undefined;
    var reader = exe.reader(&read_buf);
    var write_buf: [buf_size]u8 = undefined;
    var writer = memfd_file.writerStreaming(&write_buf);

    var private_payload = unpacker.unpack(
        gpa,
        &reader.interface,
        &writer.interface,
        password,
    ) catch |err| switch (err) {
        error.AuthenticationFailed => {
            std.log.err("Wrong password or corrupted file.", .{});
            return err;
        },
        else => return err,
    };
    try writer.end();

    if (private_payload.exe_type == .elf) {
        _ = try posix.fcntl(memfd, posix.F.SETFD, posix.FD_CLOEXEC);
    }

    var env_map = try std.process.getEnvMap(gpa);
    defer env_map.deinit();

    var env_it = private_payload.envIterator();
    while (env_it.next()) |env_var| {
        try env_map.put(env_var.name, env_var.value);
    }

    try exec(gpa, memfd_file, &env_map);
}

fn getPassword(gpa: std.mem.Allocator) ![]u8 {
    const pw = crypto.promptPassword(gpa) catch |err| switch (err) {
        error.NotATerminal => {
            std.log.err("Input is not a TTY.", .{});
            return err;
        },
        error.PasswordTooLong => {
            std.log.err("Password is too long.", .{});
            return err;
        },
        else => return err,
    };
    return pw;
}

fn exec(gpa: std.mem.Allocator, file: std.fs.File, env: *const std.process.EnvMap) !noreturn {
    const argvp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.argv.ptr));
    const envp = try std.process.createNullDelimitedEnvMap(gpa, env);
    if (syscalls.execveat(file.handle, "", argvp, envp, posix.AT.EMPTY_PATH) != 0) {
        return error.ExecFailed;
    } else unreachable;
}
