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

const pw = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// based on https://github.com/facebook/zstd/blob/dev/lib/compress/clevels.h
// Using the power of two of W for the highest compression level
const zstd_window_size = 1 << 27;

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = arena_allocator.allocator();
    defer arena_allocator.deinit();

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

    var payload = common.Payload.fromData(exe_bytes);
    const header = payload.header();
    const footer = payload.footer();

    const decrypted_payload = try arena.alloc(u8, payload.payload().len);

    var key: [common.Aead.key_length]u8 = undefined;
    try common.kdf(arena, &key, pw, &header.salt);

    try common.Aead.decrypt(
        decrypted_payload,
        payload.payload(),
        header.tag,
        &footer.offset,
        header.nonce,
        key,
    );

    var reader = std.Io.Reader.fixed(decrypted_payload);
    var decompress = std.compress.zstd.Decompress.init(
        &reader,
        &.{},
        .{ .window_len = zstd_window_size },
    );

    const memfd = try std.posix.memfd_create("", std.posix.MFD.CLOEXEC);
    const memfd_file = std.fs.File{ .handle = memfd };

    const write_buf = try arena.alloc(u8, zstd_window_size);
    var writer = memfd_file.writerStreaming(write_buf);
    _ = try decompress.reader.streamRemaining(&writer.interface);
    try writer.end();

    const argvp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.argv.ptr));
    const envp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.environ.ptr));
    if (syscalls.execveat(memfd, "", argvp, envp, posix.AT.EMPTY_PATH) != 0) {
        std.posix.exit(1);
    }
}
