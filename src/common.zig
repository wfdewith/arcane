const std = @import("std");
const builtin = @import("builtin");
pub const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;

const salt_length = 16;

pub const Header = extern struct {
    salt: [salt_length]u8,
    nonce: [Aead.nonce_length]u8,
    tag: [Aead.tag_length]u8,
};

pub const Footer = extern struct {
    pub const OffsetType = u64;
    offset: [@sizeOf(OffsetType)]u8,

    pub fn readOffset(self: *const @This()) OffsetType {
        return std.mem.readInt(OffsetType, &self.offset, .little);
    }

    pub fn writeOffset(self: *@This(), offset: OffsetType) void {
        std.mem.writeInt(Footer.OffsetType, &self.offset, offset, .little);
    }
};

pub const Payload = struct {
    data: []u8,

    pub fn init(allocator: std.mem.Allocator, size: usize) std.mem.Allocator.Error!Payload {
        const data = try allocator.alloc(u8, @sizeOf(Header) + size + @sizeOf(Footer));
        return Payload{ .data = data };
    }

    pub fn fromData(data: []u8) Payload {
        const footer_offset = data.len - @sizeOf(Footer);
        const f: *Footer = @ptrCast(data[footer_offset..].ptr);
        const offset = f.readOffset();
        return Payload{ .data = data[offset..] };
    }

    pub fn header(self: *@This()) *Header {
        return @ptrCast(self.data[0..@sizeOf(Header)].ptr);
    }

    pub fn footer(self: *@This()) *Footer {
        const footer_offset = self.data.len - @sizeOf(Footer);
        return @ptrCast(self.data[footer_offset..].ptr);
    }

    pub fn payload(self: *@This()) []u8 {
        const footer_offset = self.data.len - @sizeOf(Footer);
        return self.data[@sizeOf(Header)..footer_offset];
    }
};

pub fn kdf(allocator: std.mem.Allocator, derived_key: []u8, password: []const u8, salt: []const u8) !void {
    const argon2 = std.crypto.pwhash.argon2;
    const params: argon2.Params = if (builtin.mode == .Debug)
        .{
            .p = 1,
            .m = 2 * 1024,
            .t = 1,
        }
    else
        .{
            .p = 8,
            .m = 2 * 1024 * 1024,
            .t = 1,
        };
    return argon2.kdf(allocator, derived_key, password, salt, params, .argon2d);
}
