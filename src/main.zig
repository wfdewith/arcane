const std = @import("std");
const posix = std.posix;

const cli = @import("cli");

const common = @import("common.zig");
const packer = @import("packer.zig");

var pack_config = struct {
    gpa: std.mem.Allocator = undefined,
    in_path: []const u8 = undefined,
    out_path: ?[]const u8 = null,
    password: ?[]const u8 = null,
    env: []const []const u8 = undefined,
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

fn pack() !void {
    const gpa = pack_config.gpa;
    const env = try parseEnv(gpa);

    const in_file = try std.fs.openFileAbsolute(pack_config.in_path, .{});
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

    try packer.pack(gpa, in_file, out_file, &env, password);
}

fn getPassword(gpa: std.mem.Allocator) ![]u8 {
    const pw = common.promptPassword(gpa) catch |err| switch (err) {
        error.EmptyPassword => {
            std.log.err("No password set.", .{});
            return error.EmptyPassword;
        },
        error.NotATerminal => {
            std.log.err("Input is not a TTY, use -p or ARCANE_PASSWORD to set password.", .{});
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
            std.log.err("Variable '{s}' has no value", .{env_var});
            return error.MalformedEnvVariable;
        };
        const name = env_var[0..idx];
        const value = env_var[idx + 1 ..];
        try env_map.put(name, value);
    }
    return env_map;
}
