const std = @import("std");

const common = @import("common.zig");

const zstd = @cImport(@cInclude("zstd.h"));

const stub linksection(".stub") = @embedFile("stub");

const key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    const arena = arena_allocator.allocator();
    defer arena_allocator.deinit();

    const out_file = try std.fs.cwd().createFile("test", .{});
    defer out_file.close();

    const in_file = try std.fs.openFileAbsolute("/usr/bin/ls", .{});
    defer in_file.close();

    var read_buf: [4096]u8 = undefined;
    var reader = in_file.reader(&read_buf);
    const payload_size = try reader.getSize();

    const payload = try reader.interface.readAlloc(arena, payload_size);

    var compressed_payload = try arena.alloc(u8, payload_size);
    const compressed_size = zstd.ZSTD_compress(
        compressed_payload.ptr,
        compressed_payload.len,
        payload.ptr,
        payload.len,
        22,
    );
    if (zstd.ZSTD_isError(compressed_size) != 0) {
        std.debug.print("libzstd: {s}\n", .{zstd.ZSTD_getErrorName(compressed_size)});
        return error.ZstdError;
    }

    compressed_payload = compressed_payload[0..compressed_size];

    const full_payload_size = @sizeOf(common.Header) + compressed_size + @sizeOf(common.Footer);
    var full_payload = try arena.alloc(u8, full_payload_size);

    const header: *common.Header = @ptrCast(
        full_payload[0..@sizeOf(common.Header)].ptr,
    );
    const footer: *common.Footer = @ptrCast(
        full_payload[@sizeOf(common.Header) + compressed_size ..][0..@sizeOf(common.Footer)].ptr,
    );
    const encrypted_payload = full_payload[@sizeOf(common.Header)..][0..compressed_size];

    std.crypto.random.bytes(&header.nonce);

    std.mem.writeInt(common.Footer.OffsetType, &footer.offset, stub.len, .little);

    common.AesGcm.encrypt(
        encrypted_payload,
        &header.tag,
        compressed_payload,
        &footer.offset,
        header.nonce,
        key.*,
    );

    var write_buf: [4096]u8 = undefined;
    var writer = out_file.writerStreaming(&write_buf);

    try writer.interface.writeAll(stub);
    try writer.interface.writeAll(full_payload);
    try writer.end();
}
