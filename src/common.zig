const std = @import("std");

pub const AesGcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const Header = extern struct {
    nonce: [AesGcm.nonce_length]u8,
    tag: [AesGcm.tag_length]u8,
};

pub const Footer = extern struct {
    pub const OffsetType = u64;
    offset: [@sizeOf(OffsetType)]u8,
};
