const std = @import("std");

const common = @import("common.zig");

const posix = std.posix;

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

const AesGcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

var write_buf: [std.compress.zstd.default_window_len]u8 = undefined;

pub fn main() !void {
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

    const decrypted_payload = try posix.mmap(
        null,
        payload.payload().len,
        posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );

    try AesGcm.decrypt(
        decrypted_payload,
        payload.payload(),
        header.tag,
        &footer.offset,
        header.nonce,
        key.*,
    );

    var reader = std.Io.Reader.fixed(decrypted_payload);
    var decompress = std.compress.zstd.Decompress.init(&reader, &.{}, .{});

    const memfd = try std.posix.memfd_create("", std.posix.MFD.CLOEXEC);
    const memfd_file = std.fs.File{ .handle = memfd };

    var writer = memfd_file.writerStreaming(&write_buf);
    _ = try decompress.reader.streamRemaining(&writer.interface);
    try writer.end();

    const argvp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.argv.ptr));
    const envp = @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.environ.ptr));
    if (syscalls.execveat(memfd, "", argvp, envp, posix.AT.EMPTY_PATH) != 0) {
        std.posix.exit(1);
    }
}
