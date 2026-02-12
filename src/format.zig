const std = @import("std");

const process = std.process;
const Io = std.Io;
const math = std.math;

const crypto = @import("crypto.zig");

pub const EnvVar = struct {
    name: []const u8,
    value: []const u8,
};

pub const magic = "ARCN";
pub const format_version: u8 = 1;

pub const Header = extern struct {
    pub const OffsetType = u64;

    magic: [4]u8,
    salt: [crypto.salt_length]u8,
    nonce: [crypto.Aead.nonce_length]u8,
    tag: [crypto.Aead.tag_length]u8,
    executable_offset: [@sizeOf(OffsetType)]u8,

    pub fn readOffset(self: *const @This()) OffsetType {
        return std.mem.readInt(OffsetType, &self.executable_offset, .little);
    }

    pub fn writeOffset(self: *@This(), offset: OffsetType) void {
        std.mem.writeInt(OffsetType, &self.executable_offset, offset, .little);
    }
};

pub const Footer = extern struct {
    pub const OffsetType = u64;
    magic: [4]u8,
    version: u8,
    offset: [@sizeOf(OffsetType)]u8,

    pub fn readOffset(self: *const @This()) OffsetType {
        return std.mem.readInt(OffsetType, &self.offset, .little);
    }

    pub fn writeOffset(self: *@This(), offset: OffsetType) void {
        std.mem.writeInt(OffsetType, &self.offset, offset, .little);
    }
};

pub const Payload = struct {
    const Self = @This();
    pub const size_overhead = @sizeOf(Header) + @sizeOf(Footer);

    data: []u8,

    pub fn deinit(self: Self, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }

    pub fn extract(packed_exe: []u8) !Payload {
        if (packed_exe.len < @sizeOf(Footer)) return error.NotAPackedFile;
        const footer_offset = packed_exe.len - @sizeOf(Footer);
        const f = std.mem.bytesAsValue(Footer, packed_exe[footer_offset..]);
        if (!std.mem.eql(u8, &f.magic, magic)) return error.NotAPackedFile;
        if (f.version != format_version) return error.UnsupportedVersion;
        const offset = f.readOffset();
        if (offset >= packed_exe.len) return error.NotAPackedFile;
        return Payload{ .data = packed_exe[offset..] };
    }

    pub fn header(self: *Self) *align(1) Header {
        return std.mem.bytesAsValue(Header, self.data[0..@sizeOf(Header)]);
    }

    pub fn footer(self: *Self) *align(1) Footer {
        const footer_offset = self.data.len - @sizeOf(Footer);
        return std.mem.bytesAsValue(Footer, self.data[footer_offset..]);
    }

    pub fn encryptedPayload(self: *Self) []u8 {
        const header_offset = @sizeOf(Header);
        const footer_offset = self.data.len - @sizeOf(Footer);
        return self.data[header_offset..footer_offset];
    }

    pub fn decrypt(self: *Self, gpa: std.mem.Allocator, password: []const u8) !PrivatePayload {
        const hdr = self.header();
        const ftr = self.footer();

        const decrypted = try gpa.alloc(u8, self.encryptedPayload().len);

        var key: [crypto.Aead.key_length]u8 = undefined;
        try crypto.kdf(gpa, &key, password, &hdr.salt);

        try crypto.Aead.decrypt(
            decrypted,
            self.encryptedPayload(),
            hdr.tag,
            &ftr.offset,
            hdr.nonce,
            key,
        );

        return PrivatePayload{
            .data = decrypted,
            .executable_offset = hdr.readOffset(),
        };
    }
};

pub const ExeType = enum { elf, script };

pub const PrivatePayload = struct {
    const Self = @This();

    data: []u8,
    executable_offset: usize,
    exe_type: ExeType = .elf,

    pub const EnvIter = struct {
        payload: *Self,
        reader: Io.Reader,
        num: u32,
        idx: u32,

        pub fn next(iter: *EnvIter) ?EnvVar {
            if (iter.idx >= iter.num) return null;
            const name_len = iter.reader.takeInt(u16, .little) catch return null;
            const name = iter.reader.take(name_len) catch return null;
            const value_len = iter.reader.takeInt(u16, .little) catch return null;
            const value = iter.reader.take(value_len) catch return null;
            iter.idx += 1;
            return EnvVar{
                .name = name,
                .value = value,
            };
        }
    };

    pub fn init(
        gpa: std.mem.Allocator,
        env_map: *const process.EnvMap,
        compressed_executable: []const u8,
    ) !PrivatePayload {
        var writer = Io.Writer.Allocating.init(gpa);
        try encodeEnv(&writer.writer, env_map);
        const offset = writer.written().len;
        try writer.writer.writeAll(compressed_executable);
        return PrivatePayload{
            .data = try writer.toOwnedSlice(),
            .executable_offset = offset,
        };
    }

    pub fn deinit(self: Self, gpa: std.mem.Allocator) void {
        gpa.free(self.data);
    }

    pub fn env(self: *Self) []u8 {
        return self.data[0..self.executable_offset];
    }

    pub fn executable(self: *Self) []u8 {
        return self.data[self.executable_offset..];
    }

    pub fn encrypt(self: *Self, gpa: std.mem.Allocator, password: []const u8, stub_len: usize) !Payload {
        const payload_data = try gpa.alloc(u8, Payload.size_overhead + self.data.len);
        var payload = Payload{ .data = payload_data };

        const hdr = payload.header();
        const ftr = payload.footer();
        const encrypted = payload.encryptedPayload();

        hdr.magic = magic.*;
        std.crypto.random.bytes(&hdr.salt);
        std.crypto.random.bytes(&hdr.nonce);

        hdr.writeOffset(self.env().len);
        ftr.magic = magic.*;
        ftr.version = format_version;
        ftr.writeOffset(stub_len);

        var key: [crypto.Aead.key_length]u8 = undefined;
        try crypto.kdf(gpa, &key, password, &hdr.salt);

        crypto.Aead.encrypt(
            encrypted,
            &hdr.tag,
            self.data,
            &ftr.offset,
            hdr.nonce,
            key,
        );

        return payload;
    }

    pub fn envIterator(self: *Self) EnvIter {
        var reader = Io.Reader.fixed(self.env());
        const num = reader.takeInt(u32, .little) catch 0;

        return EnvIter{
            .payload = self,
            .reader = reader,
            .idx = 0,
            .num = num,
        };
    }
};

pub fn encodeEnv(writer: *Io.Writer, env_map: *const process.EnvMap) !void {
    try writer.writeInt(u32, env_map.count(), .little);

    var it = env_map.iterator();
    while (it.next()) |entry| {
        if (entry.key_ptr.len > math.maxInt(u16)) {
            return error.EnvVarTooLarge;
        }
        if (entry.value_ptr.len > math.maxInt(u16)) {
            return error.EnvVarTooLarge;
        }
        try writer.writeInt(u16, @intCast(entry.key_ptr.len), .little);
        try writer.writeAll(entry.key_ptr.*);
        try writer.writeInt(u16, @intCast(entry.value_ptr.len), .little);
        try writer.writeAll(entry.value_ptr.*);
    }
}
