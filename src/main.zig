const std = @import("std");

const common = @import("common.zig");

const zstd = @cImport(@cInclude("zstd.h"));

const stub linksection(".stub") = @embedFile("stub");

const pw = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

    const compressed_payload = try compress(arena, payload);

    var full_payload = try common.Payload.init(arena, compressed_payload.len);
    const header: *common.Header = full_payload.header();
    const footer: *common.Footer = full_payload.footer();
    const encrypted_payload = full_payload.payload();

    std.crypto.random.bytes(&header.nonce);

    footer.writeOffset(stub.len);

    var key: [common.Aead.key_length]u8 = undefined;
    try common.kdf(arena, &key, pw, &header.salt);

    common.Aead.encrypt(
        encrypted_payload,
        &header.tag,
        compressed_payload,
        &footer.offset,
        header.nonce,
        key,
    );

    var write_buf: [4096]u8 = undefined;
    var writer = out_file.writerStreaming(&write_buf);

    try writer.interface.writeAll(stub);
    try writer.interface.writeAll(full_payload.data);
    try writer.end();
}

fn compress(allocator: std.mem.Allocator, data: []u8) ![]u8 {
    const upper_bound = zstd.ZSTD_compressBound(data.len);
    const compressed_data = try allocator.alloc(u8, upper_bound);
    const compressed_size = zstd.ZSTD_compress(
        compressed_data.ptr,
        compressed_data.len,
        data.ptr,
        data.len,
        22,
    );
    if (zstd.ZSTD_isError(compressed_size) != 0) {
        std.log.err("libzstd: {s}", .{zstd.ZSTD_getErrorName(compressed_size)});
        return error.ZstdError;
    }
    return compressed_data[0..compressed_size];
}
