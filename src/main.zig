const std = @import("std");
const posix = std.posix;

const zli = @import("zli");

const packer = @import("packer.zig");

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    const arena = arena_allocator.allocator();
    defer arena_allocator.deinit();

    var stdout_writer = std.fs.File.stdout().writerStreaming(&.{});
    var stdout = &stdout_writer.interface;

    const buf = try arena.alloc(u8, 4096);
    var stdin_reader = std.fs.File.stdin().readerStreaming(buf);
    const stdin = &stdin_reader.interface;

    const cli = try buildCli(stdout, stdin, arena);
    try cli.execute(.{});
    try stdout.flush();
}

fn buildCli(writer: *std.Io.Writer, reader: *std.Io.Reader, allocator: std.mem.Allocator) !*zli.Command {
    const root = try zli.Command.init(writer, reader, allocator, .{
        .name = "arcane",
        .description = "A simple packer for Linux",
    }, run);

    try root.addPositionalArg(.{
        .name = "input",
        .description = "Executable to pack",
        .required = true,
    });
    try root.addFlag(.{
        .name = "output",
        .shortcut = "o",
        .description = "Output executable (defaults to '<input>.packed')",
        .type = .String,
        .default_value = .{ .String = "" },
    });
    return root;
}

fn run(ctx: zli.CommandContext) !void {
    const in_path = ctx.getArg("input").?;
    const in_file = try std.fs.openFileAbsolute(in_path, .{});
    defer in_file.close();

    const output_flag = ctx.flag("output", []const u8);
    const out_path = if (output_flag.len != 0) output_flag else blk: {
        const p = try std.fmt.allocPrint(ctx.allocator, "{s}.packed", .{in_path});
        break :blk std.fs.path.basename(p);
    };
    const out_file = try std.fs.cwd().createFile(
        out_path,
        .{ .mode = posix.S.IRWXU | posix.S.IRWXG | posix.S.IRWXO },
    );
    defer out_file.close();

    try packer.pack(ctx.allocator, in_file, out_file);
}
