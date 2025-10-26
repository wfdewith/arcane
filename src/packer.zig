const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

const zstd = @cImport(@cInclude("zstd.h"));

const common = @import("common.zig");

const stub linksection(".stub") = @embedFile("stub");

const pw = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

pub fn pack(allocator: std.mem.Allocator, in_file: std.fs.File, out_file: std.fs.File) !void {
    var read_buf: [4096]u8 = undefined;
    var reader = in_file.reader(&read_buf);
    const payload_size = try reader.getSize();

    const payload = try reader.interface.readAlloc(allocator, payload_size);

    const compressed_payload = try compress(allocator, payload);

    var full_payload = try common.Payload.init(allocator, compressed_payload.len);
    const header: *common.Header = full_payload.header();
    const footer: *common.Footer = full_payload.footer();
    const encrypted_payload = full_payload.payload();

    std.crypto.random.bytes(&header.salt);
    std.crypto.random.bytes(&header.nonce);

    footer.writeOffset(stub.len);

    var key: [common.Aead.key_length]u8 = undefined;
    try common.kdf(allocator, &key, pw, &header.salt);

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
