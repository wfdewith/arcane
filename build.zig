const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const stub_optimize: std.builtin.OptimizeMode = if (optimize == .Debug) .Debug else .ReleaseSmall;

    const cli_dep = b.dependency("cli", .{
        .target = target,
        .optimize = optimize,
    });

    const stub_mod = b.createModule(.{
        .root_source_file = b.path("src/stub.zig"),
        .target = target,
        .optimize = stub_optimize,
    });

    const stub_exe = b.addExecutable(.{
        .name = "stub.bin",
        .root_module = stub_mod,
        .linkage = .static,
    });

    const packer_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    packer_mod.linkSystemLibrary("libzstd", .{});
    packer_mod.addAnonymousImport("stub", .{
        .root_source_file = stub_exe.getEmittedBin(),
    });
    packer_mod.addImport("cli", cli_dep.module("cli"));

    const packer_exe = b.addExecutable(.{
        .name = "arcane",
        .root_module = packer_mod,
        .linkage = .dynamic,
    });

    b.installArtifact(packer_exe);
    b.installArtifact(stub_exe);

    const run_cmd = b.addRunArtifact(packer_exe);
    const run_step = b.step("run", "Run packer");
    run_step.dependOn(&run_cmd.step);

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
}
