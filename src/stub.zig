const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const crypto = @import("crypto.zig");
const format = @import("format.zig");
const posix = @import("posix.zig");
const unpacker = @import("unpacker.zig");

pub const std_options: std.Options = if (builtin.mode != .debug) .{
    .enable_segfault_handler = false,
    .signal_stack_size = null,
    .allow_stack_tracing = false,
    .networking = false,
} else .{};
pub const panic = if (builtin.mode != .debug)
    std.debug.no_panic
else
    std.debug.FullPanic(std.debug.defaultPanic);

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
        fd: std.posix.fd_t,
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

pub fn main(init: std.process.Init.Minimal) void {
    run(init) catch |err| {
        const msg: ?[]const u8 = switch (err) {
            error.NotATerminal => "input is not a TTY.",
            error.PasswordTooLong => "password is too long.",
            error.EmptyPassword => "password cannot be empty.",
            error.AuthenticationFailed => "wrong password or corrupted file.",
            error.NotAPackedFile => "not a valid packed file.",
            error.UnsupportedVersion => "unsupported file format version.",
            error.CapGetFailed => "failed to read process capabilities.",
            error.CapSetFailed => "failed to set process capabilities.",
            error.ExecFailed => "failed to execute unpacked binary.",
            error.OutOfMemory => "out of memory.",
            else => null,
        };
        if (msg) |m| {
            std.log.err("{s}", .{m});
        } else {
            std.log.err("unexpected error: {s}", .{@errorName(err)});
        }
        std.process.exit(1);
    };
}

fn run(init: std.process.Init.Minimal) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const gpa = arena.allocator();
    defer arena.deinit();

    const exe = try std.Io.Dir.openFileAbsolute(io, "/proc/self/exe", .{});

    const memfd = try std.posix.memfd_create("", 0);
    const memfd_file = std.Io.File{
        .handle = memfd,
        .flags = .{ .nonblocking = false },
    };

    var read_buf: [buf_size]u8 = undefined;
    var reader = exe.reader(io, &read_buf);
    var write_buf: [buf_size]u8 = undefined;
    var writer = memfd_file.writerStreaming(io, &write_buf);

    var private_payload = try unpacker.unpack(
        io,
        gpa,
        &reader.interface,
        &writer.interface,
        .{ .prompt = &crypto.promptPassword },
    );
    try writer.end();

    if (private_payload.exe_type == .elf) {
        _ = try posix.fcntl(memfd, std.posix.F.SETFD, std.posix.FD_CLOEXEC);
    }

    var env_map = try init.environ.createMap(gpa);
    defer env_map.deinit();

    var env_it = private_payload.envIterator();
    while (env_it.next()) |env_var| {
        try env_map.put(env_var.name, env_var.value);
    }

    try exec(gpa, init.args, memfd_file, &env_map);
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
            _ = try std.posix.prctl(
                std.posix.PR.CAP_AMBIENT,
                .{ std.posix.PR.CAP_AMBIENT_RAISE, cap_num, 0, 0 },
            );
            bits &= bits - 1;
        }
    }
}

fn exec(
    gpa: std.mem.Allocator,
    args: std.process.Args,
    file: std.Io.File,
    env: *const std.process.Environ.Map,
) !noreturn {
    const argvp = @as([*:null]const ?[*:0]const u8, @ptrCast(args.vector));
    const envp = (try env.createPosixBlock(gpa, .{})).slice;

    try raiseAmbientCaps();

    if (syscalls.execveat(file.handle, "", argvp, envp, std.posix.AT.EMPTY_PATH) != 0) {
        return error.ExecFailed;
    } else unreachable;
}
