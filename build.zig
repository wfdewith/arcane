const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const stub_optimize: std.builtin.OptimizeMode = if (optimize == .debug) .debug else .small;

    const cli_dep = b.dependency("cli", .{
        .target = target,
        .optimize = optimize,
    });

    const zstd = b.addTranslateC(.{
        .root_source_file = b.path("src/zstd.h"),
        .target = target,
        .optimize = optimize,
    });
    zstd.linkSystemLibrary("libzstd", .{});

    const stub_mod = b.createModule(.{
        .root_source_file = b.path("src/stub.zig"),
        .target = target,
        .optimize = stub_optimize,
        .strip = optimize != .debug,
        .single_threaded = true,
        .unwind_tables = if (stub_optimize == .debug) null else .none,
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

    packer_mod.addAnonymousImport("stub", .{
        .root_source_file = stub_exe.getEmittedBin(),
    });
    packer_mod.addImport("cli", cli_dep.module("cli"));
    packer_mod.addImport("zstd", zstd.createModule());

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

    run_cmd.addPassthruArgs();

    // This is a bit of a workaround because setEnvironmentVariable does not
    // support LazyPath.
    const test_cmd = b.addSystemCommand(&.{"env"});
    test_cmd.addArtifactArg2(packer_exe, .{ .prefix = "ARCANE=", .make_absolute = true });
    test_cmd.addArgs(&.{ "bats", "tests/" });
    test_cmd.step.dependOn(b.getInstallStep());
    const test_step = b.step("test", "Run end-to-end tests");
    test_step.dependOn(&test_cmd.step);
}
