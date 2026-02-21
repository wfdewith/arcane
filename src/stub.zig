const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const crypto = @import("crypto.zig");
const format = @import("format.zig");
const unpacker = @import("unpacker.zig");

// linux/capability.h
const cap = struct {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

    const user_cap_header = extern struct {
        version: u32,
        pid: linux.pid_t,
    };

    const user_cap_data = extern struct {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    };
};

const syscalls = struct {
    fn execveat(
        fd: posix.fd_t,
        path: [*:0]const u8,
        argv: [*:null]const ?[*:0]const u8,
        envp: [*:null]const ?[*:0]const u8,
        flags: u32,
    ) usize {
        return linux.syscall5(
            .execveat,
            @as(usize, @bitCast(@as(isize, fd))),
            @intFromPtr(path),
            @intFromPtr(argv),
            @intFromPtr(envp),
            flags,
        );
    }

    fn capget(header: *cap.user_cap_header, data: *[2]cap.user_cap_data) usize {
        return linux.syscall2(.capget, @intFromPtr(header), @intFromPtr(data));
    }

    fn capset(header: *cap.user_cap_header, data: *[2]cap.user_cap_data) usize {
        return linux.syscall2(.capset, @intFromPtr(header), @intFromPtr(data));
    }
};

const buf_size = 1024;

pub fn main() void {
    run() catch |err| {
        const msg: ?[]const u8 = switch (err) {
            error.NotATerminal => "Input is not a TTY.",
            error.PasswordTooLong => "Password is too long.",
            error.EmptyPassword => "Password cannot be empty.",
            error.AuthenticationFailed => "Wrong password or corrupted file.",
            error.NotAPackedFile => "Not a valid packed file.",
            error.UnsupportedVersion => "Unsupported file format version.",
            error.CapGetFailed => "Failed to read process capabilities.",
            error.CapSetFailed => "Failed to set process capabilities.",
            error.ExecFailed => "Failed to execute unpacked binary.",
            error.OutOfMemory => "Out of memory.",
            else => null,
        };
        if (msg) |m| {
            std.log.err("{s}", .{m});
        } else {
            std.log.err("Unexpected error: {s}", .{@errorName(err)});
        }
        std.process.exit(1);
    };
}

fn run() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const gpa = arena.allocator();
    defer arena.deinit();

    const password = try crypto.promptPassword(gpa);
    defer std.crypto.secureZero(u8, password);

    const exe = try std.fs.openFileAbsolute("/proc/self/exe", .{});

    const memfd = try posix.memfd_create("", 0);
    const memfd_file = std.fs.File{ .handle = memfd };

    var read_buf: [buf_size]u8 = undefined;
    var reader = exe.reader(&read_buf);
    var write_buf: [buf_size]u8 = undefined;
    var writer = memfd_file.writerStreaming(&write_buf);

    var private_payload = try unpacker.unpack(
        gpa,
        &reader.interface,
        &writer.interface,
        password,
    );
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

fn raiseAmbientCaps() !void {
    var header = cap.user_cap_header{
        .version = cap.LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    var data: [2]cap.user_cap_data = undefined;

    if (syscalls.capget(&header, &data) != 0) return error.CapGetFailed;

    // Required before raising to ambient
    data[0].inheritable = data[0].permitted;
    data[1].inheritable = data[1].permitted;

    if (syscalls.capset(&header, &data) != 0) return error.CapSetFailed;

    for (0..2) |i| {
        const idx: u32 = @intCast(i);
        var bits = data[i].permitted;
        while (bits != 0) {
            const bit: u32 = @intCast(@ctz(bits));
            const cap_num = idx * 32 + bit;
            _ = try posix.prctl(posix.PR.CAP_AMBIENT, .{ posix.PR.CAP_AMBIENT_RAISE, cap_num, 0, 0 });
            bits &= bits - 1;
        }
    }
}

fn exec(gpa: std.mem.Allocator, file: std.fs.File, env: *const std.process.EnvMap) !noreturn {
    const argvp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.argv.ptr));
    const envp = try std.process.createNullDelimitedEnvMap(gpa, env);

    try raiseAmbientCaps();

    if (syscalls.execveat(file.handle, "", argvp, envp, posix.AT.EMPTY_PATH) != 0) {
        return error.ExecFailed;
    } else unreachable;
}
