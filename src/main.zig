const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const cli = @import("cli");

const crypto = @import("crypto.zig");
const packer = @import("packer.zig");
const unpacker = @import("unpacker.zig");

const buf_size = 1024;

var pack_config = struct {
    gpa: std.mem.Allocator = undefined,
    in_path: []const u8 = undefined,
    out_path: ?[]const u8 = null,
    password: ?[]u8 = null,
    env: []const []const u8 = undefined,
    compression_level: u8 = if (builtin.mode == .Debug) 1 else 22,
    argon2_memory: u32 = if (builtin.mode == .Debug) 2 * 1024 else 2 * 1024 * 1024,
    argon2_time: u32 = 1,
    argon2_parallelism: u24 = if (builtin.mode == .Debug) 1 else 8,
}{};

var unpack_config = struct {
    gpa: std.mem.Allocator = undefined,
    in_path: []const u8 = undefined,
    out_path: ?[]const u8 = null,
    password: ?[]u8 = null,
    env_file: ?[]const u8 = null,
}{};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    const gpa = arena.allocator();
    defer arena.deinit();

    var r = try cli.AppRunner.init(gpa);
    const app = cli.App{
        .command = cli.Command{
            .name = "arcane",
            .description = .{
                .one_line = "A simple packer for Linux executables.",
                .detailed =
                \\Arcane compresses and packs ELF executables into a self-extracting stub.
                \\This can be useful for reducing the size of executables and for distributing applications as a single file.
                ,
            },
            .target = cli.CommandTarget{
                .subcommands = try r.allocCommands(&.{
                    try packCommand(&r, gpa),
                    try unpackCommand(&r, gpa),
                }),
            },
        },
    };
    try r.run(&app);
}

fn packCommand(r: *cli.AppRunner, gpa: std.mem.Allocator) !cli.Command {
    pack_config.gpa = gpa;
    return cli.Command{
        .name = "pack",
        .description = .{ .one_line = "Pack an executable." },
        .options = try r.allocOptions(&.{
            cli.Option{
                .long_name = "output",
                .short_alias = 'o',
                .help =
                \\Write packed executable to PATH.
                \\Will be set to <INPUT>.packed if not set.
                ,
                .value_ref = r.mkRef(&pack_config.out_path),
                .value_name = "PATH",
            },
            cli.Option{
                .long_name = "password",
                .short_alias = 'p',
                .help =
                \\Set password to decrypt the packed executable.
                \\Will be prompted if not set.
                ,
                .value_ref = r.mkRef(&pack_config.password),
                .value_name = "PASSWORD",
                .envvar = "ARCANE_PASSWORD",
            },
            cli.Option{
                .long_name = "env",
                .short_alias = 'e',
                .help =
                \\Set environment variable.
                \\Can be specified multiple times.
                ,
                .value_name = "VARIABLE=VALUE",
                .value_ref = r.mkRef(&pack_config.env),
            },
            cli.Option{
                .long_name = "compression-level",
                .short_alias = 'l',
                .help = "Zstd compression level (1–22).",
                .value_ref = r.mkRef(&pack_config.compression_level),
                .value_name = "LEVEL",
            },
            cli.Option{
                .long_name = "kdf-memory",
                .help = "Argon2 memory cost in KB.",
                .value_ref = r.mkRef(&pack_config.argon2_memory),
                .value_name = "KB",
            },
            cli.Option{
                .long_name = "kdf-time",
                .help = "Argon2 time cost (iterations).",
                .value_ref = r.mkRef(&pack_config.argon2_time),
                .value_name = "ITER",
            },
            cli.Option{
                .long_name = "kdf-parallelism",
                .help = "Argon2 parallelism.",
                .value_ref = r.mkRef(&pack_config.argon2_parallelism),
                .value_name = "N",
            },
        }),
        .target = cli.CommandTarget{
            .action = cli.CommandAction{
                .positional_args = .{
                    .required = try r.allocPositionalArgs(&.{
                        cli.PositionalArg{
                            .name = "INPUT",
                            .help = "Path to the input executable to pack.",
                            .value_ref = r.mkRef(&pack_config.in_path),
                        },
                    }),
                },
                .exec = pack,
            },
        },
    };
}

fn unpackCommand(r: *cli.AppRunner, gpa: std.mem.Allocator) !cli.Command {
    unpack_config.gpa = gpa;
    return cli.Command{
        .name = "unpack",
        .description = .{ .one_line = "Unpack a packed executable." },
        .options = try r.allocOptions(&.{
            cli.Option{
                .long_name = "output",
                .short_alias = 'o',
                .help =
                \\Write unpacked executable to PATH.
                \\Will be set to <INPUT>.unpacked if not set.
                ,
                .value_ref = r.mkRef(&unpack_config.out_path),
                .value_name = "PATH",
            },
            cli.Option{
                .long_name = "password",
                .short_alias = 'p',
                .help =
                \\Set password to decrypt the packed executable.
                \\Will be prompted if not set.
                ,
                .value_ref = r.mkRef(&unpack_config.password),
                .value_name = "PASSWORD",
                .envvar = "ARCANE_PASSWORD",
            },
            cli.Option{
                .long_name = "env-file",
                .short_alias = 'e',
                .help =
                \\Write packed environment variables to PATH in KEY=VALUE format.
                \\If not set, environment variables are discarded.
                ,
                .value_ref = r.mkRef(&unpack_config.env_file),
                .value_name = "PATH",
            },
        }),
        .target = cli.CommandTarget{
            .action = cli.CommandAction{
                .positional_args = .{
                    .required = try r.allocPositionalArgs(&.{
                        cli.PositionalArg{
                            .name = "INPUT",
                            .help = "Path to the packed executable to unpack.",
                            .value_ref = r.mkRef(&unpack_config.in_path),
                        },
                    }),
                },
                .exec = unpack,
            },
        },
    };
}

fn pack() !void {
    const gpa = pack_config.gpa;
    const env = try parseEnv(gpa);

    const in_file = try std.fs.cwd().openFile(pack_config.in_path, .{});
    defer in_file.close();

    const out_path = pack_config.out_path orelse blk: {
        const p = try std.fmt.allocPrint(gpa, "{s}.packed", .{pack_config.in_path});
        break :blk std.fs.path.basename(p);
    };
    const out_file = try std.fs.cwd().createFile(
        out_path,
        .{ .mode = posix.S.IRWXU | posix.S.IRWXG | posix.S.IRWXO },
    );
    defer out_file.close();

    const password = pack_config.password orelse try getPassword(gpa);
    defer std.crypto.secureZero(u8, password);

    var read_buf: [buf_size]u8 = undefined;
    var reader = in_file.reader(&read_buf);
    var write_buf: [buf_size]u8 = undefined;
    var writer = out_file.writerStreaming(&write_buf);

    const kdf_params = crypto.KdfParams{
        .m = pack_config.argon2_memory,
        .t = pack_config.argon2_time,
        .p = pack_config.argon2_parallelism,
    };
    const compression_level = pack_config.compression_level;

    if (compression_level < 1 or compression_level > 22) {
        std.log.err("compression level must be between 1 and 22.", .{});
        return error.InvalidCompressionLevel;
    }
    if (kdf_params.p == 0) {
        std.log.err("KDF parallelism must be greater than 0.", .{});
        return error.InvalidKdfParams;
    }
    if (kdf_params.t == 0) {
        std.log.err("KDF time must be greater than 0.", .{});
        return error.InvalidKdfParams;
    }
    if (kdf_params.m < 8 * kdf_params.p) {
        std.log.err("KDF memory must be at least 8 * parallelism ({d} KB).", .{8 * kdf_params.p});
        return error.InvalidKdfParams;
    }

    try packer.pack(gpa, &reader.interface, &writer.interface, &env, password, compression_level, kdf_params);
    try writer.end();
}

fn unpack() !void {
    const gpa = unpack_config.gpa;

    const in_file = try std.fs.cwd().openFile(unpack_config.in_path, .{});
    defer in_file.close();

    const out_path = unpack_config.out_path orelse blk: {
        const p = try std.fmt.allocPrint(gpa, "{s}.unpacked", .{unpack_config.in_path});
        break :blk std.fs.path.basename(p);
    };
    const out_file = try std.fs.cwd().createFile(
        out_path,
        .{ .mode = posix.S.IRWXU | posix.S.IRWXG | posix.S.IRWXO },
    );
    defer out_file.close();

    const password = unpack_config.password orelse try getPassword(gpa);
    defer std.crypto.secureZero(u8, password);

    var read_buf: [buf_size]u8 = undefined;
    var reader = in_file.reader(&read_buf);
    var write_buf: [buf_size]u8 = undefined;
    var writer = out_file.writerStreaming(&write_buf);

    var private_payload = unpacker.unpack(
        gpa,
        &reader.interface,
        &writer.interface,
        password,
    ) catch |err| switch (err) {
        error.NotAPackedFile => {
            std.log.err("input is not a packed executable.", .{});
            return err;
        },
        error.UnsupportedVersion => {
            std.log.err("unsupported format version.", .{});
            return err;
        },
        else => return err,
    };
    try writer.end();

    if (unpack_config.env_file) |env_path| {
        const env_file = try std.fs.cwd().createFile(env_path, .{});
        defer env_file.close();
        var env_write_buf: [buf_size]u8 = undefined;
        var env_writer = env_file.writerStreaming(&env_write_buf);
        var env_it = private_payload.envIterator();
        while (env_it.next()) |env_var| {
            try env_writer.interface.writeAll(env_var.name);
            try env_writer.interface.writeAll("=");
            try env_writer.interface.writeAll(env_var.value);
            try env_writer.interface.writeAll("\n");
        }
        try env_writer.end();
    }
}

fn getPassword(gpa: std.mem.Allocator) ![]u8 {
    const pw = crypto.promptPassword(gpa) catch |err| switch (err) {
        error.EmptyPassword => {
            std.log.err("no password set.", .{});
            return error.EmptyPassword;
        },
        error.NotATerminal => {
            std.log.err("input is not a TTY, use -p or ARCANE_PASSWORD to set password.", .{});
            return err;
        },
        error.PasswordTooLong => {
            std.log.err("password is too long.", .{});
            return err;
        },
        else => return err,
    };
    return pw;
}

fn parseEnv(gpa: std.mem.Allocator) !std.process.EnvMap {
    var env_map = std.process.EnvMap.init(gpa);
    for (pack_config.env) |env_var| {
        const idx = std.mem.indexOfScalar(u8, env_var, '=') orelse {
            std.log.err("variable '{s}' has no value", .{env_var});
            return error.MalformedEnvVariable;
        };
        const name = env_var[0..idx];
        const value = env_var[idx + 1 ..];
        try env_map.put(name, value);
    }
    return env_map;
}
