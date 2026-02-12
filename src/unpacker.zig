const std = @import("std");

const crypto = @import("crypto.zig");
const format = @import("format.zig");

// based on https://github.com/facebook/zstd/blob/dev/lib/compress/clevels.h
// Using the power of two of W for the highest compression level
const zstd_window_size = 1 << 27;

const elf_magic = "\x7fELF";

pub fn unpack(
    gpa: std.mem.Allocator,
    in_file: std.fs.File,
    out_file: std.fs.File,
    password: []const u8,
) !format.PrivatePayload {
    var read_buf: [4096]u8 = undefined;
    var reader = in_file.reader(&read_buf);
    const file_size = try reader.getSize();
    const file_data = try reader.interface.readAlloc(gpa, file_size);

    var payload = try format.Payload.extract(file_data);
    var private_payload = try payload.decrypt(gpa, password);

    var compressed_reader = std.Io.Reader.fixed(private_payload.executable());
    const decompress_buf = try gpa.alloc(u8, zstd_window_size);
    var decompress = std.compress.zstd.Decompress.init(
        &compressed_reader,
        decompress_buf,
        .{ .window_len = zstd_window_size },
    );

    const is_elf = std.mem.eql(
        u8,
        try decompress.reader.peekArray(elf_magic.len),
        elf_magic,
    );
    private_payload.exe_type = if (is_elf) .elf else .script;

    var write_buf: [4096]u8 = undefined;
    var writer = out_file.writerStreaming(&write_buf);
    _ = try decompress.reader.streamRemaining(&writer.interface);
    try writer.end();

    return private_payload;
}
