const std = @import("std");
const Io = std.Io;

const crypto = @import("crypto.zig");
const format = @import("format.zig");

// based on https://github.com/facebook/zstd/blob/dev/lib/compress/clevels.h
// Using the power of two of W for the highest compression level
const zstd_window_size = 1 << 27;

const elf_magic = "\x7fELF";

pub fn unpack(
    gpa: std.mem.Allocator,
    reader: *Io.Reader,
    writer: *Io.Writer,
    password: []const u8,
) !format.PrivatePayload {
    const file_data = try reader.allocRemaining(gpa, .unlimited);

    var payload = try format.Payload.extract(file_data);
    var private_payload = try payload.decrypt(gpa, password);

    var compressed_reader = Io.Reader.fixed(private_payload.executable());
    const decompress_buf = try gpa.alloc(u8, zstd_window_size);
    defer gpa.free(decompress_buf);
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

    _ = try decompress.reader.streamRemaining(writer);

    return private_payload;
}
