const std = @import("std");
const posix = std.posix;

const common = @import("common.zig");

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

// based on https://github.com/facebook/zstd/blob/dev/lib/compress/clevels.h
// Using the power of two of W for the highest compression level
const zstd_window_size = 1 << 27;

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_allocator.allocator();
    defer arena_allocator.deinit();

    const password = try getPassword(arena);

    var payload = try extractPayload();
    const decrypted_payload = try decryptPayload(arena, &payload, password);

    var decrypted_payload_reader = std.Io.Reader.fixed(decrypted_payload);
    var decompress = std.compress.zstd.Decompress.init(
        &decrypted_payload_reader,
        &.{},
        .{ .window_len = zstd_window_size },
    );

    const memfd = try createMemfd(arena, &decompress.reader);
    exec(memfd);
}

fn extractPayload() !common.Payload {
    const exe = try std.fs.openFileAbsolute("/proc/self/exe", .{});
    const exe_size = (try exe.stat()).size;

    const exe_bytes = try posix.mmap(
        null,
        exe_size,
        posix.PROT.READ,
        .{ .TYPE = .SHARED },
        exe.handle,
        0,
    );

    return common.Payload.fromData(exe_bytes);
}

fn getPassword(allocator: std.mem.Allocator) ![]u8 {
    const pw = common.promptPassword(allocator) catch |err| switch (err) {
        error.NotATerminal => {
            _ = std.log.err("Input is not a TTY.", .{});
            return err;
        },
        else => return err,
    };
    return pw;
}

fn decryptPayload(allocator: std.mem.Allocator, payload: *common.Payload, password: []const u8) ![]u8 {
    const header = payload.header();
    const footer = payload.footer();

    const decrypted_payload = try allocator.alloc(u8, payload.payload().len);

    var key: [common.Aead.key_length]u8 = undefined;
    try common.kdf(allocator, &key, password, &header.salt);

    try common.Aead.decrypt(
        decrypted_payload,
        payload.payload(),
        header.tag,
        &footer.offset,
        header.nonce,
        key,
    );
    return decrypted_payload;
}

fn createMemfd(allocator: std.mem.Allocator, reader: *std.Io.Reader) !std.fs.File {
    const memfd = try std.posix.memfd_create("", std.posix.MFD.CLOEXEC);
    const memfd_file = std.fs.File{ .handle = memfd };

    const write_buf = try allocator.alloc(u8, zstd_window_size);
    var writer = memfd_file.writerStreaming(write_buf);
    _ = try reader.streamRemaining(&writer.interface);
    try writer.end();
    return memfd_file;
}

fn exec(file: std.fs.File) noreturn {
    const argvp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.argv.ptr));
    const envp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.environ.ptr));
    if (syscalls.execveat(file.handle, "", argvp, envp, posix.AT.EMPTY_PATH) != 0) {
        std.posix.exit(1);
    } else unreachable;
}
