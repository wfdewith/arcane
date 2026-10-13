const std = @import("std");
const Io = std.Io;

const crypto = @import("crypto.zig");
const format = @import("format.zig");

// based on https://github.com/facebook/zstd/blob/dev/lib/compress/clevels.h
// Using the power of two of W for the highest compression level
const zstd_window_size = 1 << 27;

const elf_magic = "\x7fELF";

pub const max_password_attempts: u8 = 3;

pub fn unpack(
    io: std.Io,
    gpa: std.mem.Allocator,
    reader: *Io.Reader,
    writer: *Io.Writer,
    password: crypto.Password,
) !format.PrivatePayload {
    const file_data = try reader.allocRemaining(gpa, .unlimited);
    defer gpa.free(file_data);

    var payload = try format.Payload.extract(file_data);

    const interactive = switch (password) {
        .fixed => false,
        .prompt => true,
    };

    var pw_buf: [crypto.max_password_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &pw_buf);

    var attempt: u8 = 0;
    var private_payload: format.PrivatePayload = undefined;
    while (true) {
        const pw = try password.resolve(io, &pw_buf);

        private_payload = payload.decrypt(io, gpa, pw) catch |err| {
            if (err != error.AuthenticationFailed) return err;
            attempt += 1;
            if (!interactive or attempt >= max_password_attempts) return err;
            std.log.err(
                "wrong password, try again ({d}/{d}).",
                .{ attempt + 1, max_password_attempts },
            );
            continue;
        };
        break;
    }

    var compressed_reader = Io.Reader.fixed(private_payload.executable());
    const decompress_buf = try gpa.alloc(u8, zstd_window_size + std.compress.zstd.block_size_max);
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
