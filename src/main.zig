const std = @import("std");
const posix = std.posix;

const cli = @import("cli");

const packer = @import("packer.zig");

var pack_config = struct {
    in_path: []const u8 = undefined,
    out_path: ?[]const u8 = null,
    password: ?[]const u8 = null,
}{};

var arena_allocator = std.heap.ArenaAllocator.init(std.heap.c_allocator);
const arena = arena_allocator.allocator();

pub fn main() !void {
    defer arena_allocator.deinit();

    var r = try cli.AppRunner.init(arena);
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
                    try packCommand(&r),
                }),
            },
        },
    };
    try r.run(&app);
}

fn packCommand(r: *cli.AppRunner) !cli.Command {
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
    const in_file = try std.fs.openFileAbsolute(pack_config.in_path, .{});
    defer in_file.close();

    const out_path = pack_config.out_path orelse blk: {
        const p = try std.fmt.allocPrint(arena, "{s}.packed", .{pack_config.in_path});
        break :blk std.fs.path.basename(p);
    };
    const out_file = try std.fs.cwd().createFile(
        out_path,
        .{ .mode = posix.S.IRWXU | posix.S.IRWXG | posix.S.IRWXO },
    );
    defer out_file.close();

    try packer.pack(arena, in_file, out_file);
}
