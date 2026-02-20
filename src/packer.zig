const std = @import("std");

const Io = std.Io;

const zstd = @cImport(@cInclude("zstd.h"));

const format = @import("format.zig");
const crypto = @import("crypto.zig");

const stub linksection(".stub") = @embedFile("stub");

pub fn pack(
    gpa: std.mem.Allocator,
    reader: *Io.Reader,
    writer: *Io.Writer,
    env: *const std.process.EnvMap,
    password: []const u8,
    compression_level: u8,
    kdf_params: crypto.KdfParams,
) !void {
    const executable = try reader.allocRemaining(gpa, .unlimited);

    const compressed_executable = try compress(gpa, executable, compression_level);
    defer gpa.free(compressed_executable);

    var private_payload = try format.PrivatePayload.init(gpa, env, compressed_executable);
    defer private_payload.deinit(gpa);

    const payload = try private_payload.encrypt(gpa, password, stub.len, kdf_params);
    defer payload.deinit(gpa);

    try writer.writeAll(stub);
    try writer.writeAll(payload.data);
}


fn compress(gpa: std.mem.Allocator, data: []u8, level: u8) ![]u8 {
    const upper_bound = zstd.ZSTD_compressBound(data.len);
    const compressed_data = try gpa.alloc(u8, upper_bound);
    const compressed_size = zstd.ZSTD_compress(
        compressed_data.ptr,
        compressed_data.len,
        data.ptr,
        data.len,
        level,
    );
    if (zstd.ZSTD_isError(compressed_size) != 0) {
        std.log.err("libzstd: {s}", .{zstd.ZSTD_getErrorName(compressed_size)});
        return error.ZstdError;
    }
    return gpa.realloc(compressed_data, compressed_size);
}
