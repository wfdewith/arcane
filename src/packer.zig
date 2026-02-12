const std = @import("std");
const builtin = @import("builtin");

const zstd = @cImport(@cInclude("zstd.h"));

const common = @import("common.zig");

const stub linksection(".stub") = @embedFile("stub");

pub fn pack(
    gpa: std.mem.Allocator,
    in_file: std.fs.File,
    out_file: std.fs.File,
    env: *const std.process.EnvMap,
    password: []const u8,
) !void {
    var read_buf: [4096]u8 = undefined;
    var reader = in_file.reader(&read_buf);
    const executable_size = try reader.getSize();

    const executable = try reader.interface.readAlloc(gpa, executable_size);

    const compressed_executable = try compress(gpa, executable);
    defer gpa.free(compressed_executable);

    var private_payload = try common.PrivatePayload.init(gpa, env, compressed_executable);
    defer private_payload.deinit(gpa);

    var payload = try common.Payload.init(gpa, private_payload.data.len);
    defer payload.deinit(gpa);

    const header = payload.header();
    const footer = payload.footer();
    const encrypted_payload = payload.encryptedPayload();

    std.crypto.random.bytes(&header.salt);
    std.crypto.random.bytes(&header.nonce);

    header.executable_offset = private_payload.env().len;
    footer.writeOffset(stub.len);

    var key: [common.Aead.key_length]u8 = undefined;
    try common.kdf(gpa, &key, password, &header.salt);

    common.Aead.encrypt(
        encrypted_payload,
        &header.tag,
        private_payload.data,
        &footer.offset,
        header.nonce,
        key,
    );

    var write_buf: [4096]u8 = undefined;
    var writer = out_file.writerStreaming(&write_buf);

    try writer.interface.writeAll(stub);
    try writer.interface.writeAll(payload.data);
    try writer.end();
}

fn compress(gpa: std.mem.Allocator, data: []u8) ![]u8 {
    const upper_bound = zstd.ZSTD_compressBound(data.len);
    const compressed_data = try gpa.alloc(u8, upper_bound);
    const compressed_size = zstd.ZSTD_compress(
        compressed_data.ptr,
        compressed_data.len,
        data.ptr,
        data.len,
        if (builtin.mode == .Debug) 1 else 22,
    );
    if (zstd.ZSTD_isError(compressed_size) != 0) {
        std.log.err("libzstd: {s}", .{zstd.ZSTD_getErrorName(compressed_size)});
        return error.ZstdError;
    }
    return gpa.realloc(compressed_data, compressed_size);
}
