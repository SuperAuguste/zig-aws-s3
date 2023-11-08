const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // linux-only
    const lc_dep = b.dependency("aws/aws-lc", .{});
    _ = lc_dep;
    const s2n_tls_dep = b.dependency("aws/s2n-tls", .{});
    _ = s2n_tls_dep;

    // remaining
    const c_common_dep = b.dependency("awslabs/aws-c-common", .{});
    const checksums_dep = b.dependency("awslabs/aws-checksums", .{});
    const c_cal_dep = b.dependency("awslabs/aws-c-cal", .{});
    const c_io_dep = b.dependency("awslabs/aws-c-io", .{});
    const c_compression_dep = b.dependency("awslabs/aws-c-compression", .{});
    const c_http_dep = b.dependency("awslabs/aws-c-http", .{});
    const c_sdkutils_dep = b.dependency("awslabs/aws-c-sdkutils", .{});
    const c_auth_dep = b.dependency("awslabs/aws-c-auth", .{});

    // the main dependency
    const c_s3_dep = b.dependency("awslabs/aws-c-s3", .{});

    const config_header = b.addConfigHeader(.{
        .include_path = "aws/common/config.h",
        .style = .{
            .cmake = c_common_dep.path("include/aws/common/config.h.in"),
        },
    }, .{
        .AWS_HAVE_GCC_OVERFLOW_MATH_EXTENSIONS = false,
        .AWS_HAVE_GCC_INLINE_ASM = false,
        .AWS_HAVE_MSVC_INTRINSICS_X64 = false,
        .AWS_HAVE_POSIX_LARGE_FILE_SUPPORT = false,
        .AWS_HAVE_EXECINFO = false,
        .AWS_HAVE_WINAPI_DESKTOP = false,
        .AWS_HAVE_LINUX_IF_LINK_H = false,
    });

    const lib = b.addStaticLibrary(.{
        .name = "aws-s3",
        .target = target,
        // The follow files reveal an issue with not passing an optimization level to the C code:
        // - https://sourcegraph.com/github.com/ziglang/zig/-/blob/lib/libc/include/any-windows-any/_mingw.h?L103
        // - https://sourcegraph.com/github.com/ziglang/zig/-/blob/lib/libc/include/any-windows-any/winnt.h?L8069
        // which define __NO_INLINE__ and thus not define RtlSecureZeroMemory
        .optimize = switch (optimize) {
            .Debug => .ReleaseSafe,
            else => optimize,
        },
        .link_libc = true,
    });

    lib.addConfigHeader(config_header);

    var dirs_to_skip: ?[]const []const u8 = null;
    switch (target.getOsTag()) {
        .macos => {
            lib.defineCMacro("AWS_AFFINITY_METHOD", "0");
            lib.defineCMacro("PLATFORM_APPLE", null);
            lib.defineCMacro("ENABLE_COMMONCRYPTO_ENCRYPTION", null);
            lib.linkFramework("Security");
            lib.linkFramework("CoreFoundation");
            lib.defineCMacro("INTEL_NO_ITTNOTIFY_API", null);

            switch (target.getCpuArch()) {
                .aarch64 => {
                    dirs_to_skip = &.{
                        "windows",
                        "unix",
                        "s2n",
                        "linux",
                        "android",
                        "intel",
                    };
                },
                else => |arch| @panic(b.fmt("arch {s} not supported for macos", .{@tagName(arch)})),
            }
        },
        .windows => {
            lib.defineCMacro("AWS_AFFINITY_METHOD", "0");
            lib.defineCMacro("PLATFORM_WINDOWS", null);
            lib.defineCMacro("ENABLE_BCRYPT_ENCRYPTION", null);
            lib.defineCMacro("AWS_OS_WINDOWS_DESKTOP", null);

            lib.linkSystemLibrary("kernel32");
            lib.linkSystemLibrary("ws2_32");
            lib.linkSystemLibrary("shlwapi");
            lib.linkSystemLibrary("psapi");
            lib.linkSystemLibrary("bcrypt");

            switch (target.getCpuArch()) {
                .x86_64, .x86 => {
                    dirs_to_skip = &.{
                        "bsd",
                        "darwin",
                        "posix",
                        "unix",
                        "s2n",
                        "linux",
                        "android",
                        "iocp",
                        "intel",
                    };
                },
                else => |arch| @panic(b.fmt("arch {s} not supported for macos", .{@tagName(arch)})),
            }
        },
        else => |os| @panic(b.fmt("os {s} not supported", .{@tagName(os)})),
    }

    inline for (.{
        c_common_dep,
        checksums_dep,
        c_cal_dep,
        c_io_dep,
        c_compression_dep,
        c_http_dep,
        c_sdkutils_dep,
        c_auth_dep,
        c_s3_dep,
    }) |dep| {
        lib.addIncludePath(dep.path("include"));

        var iterable = std.fs.openIterableDirAbsolute(dep.path("source").getPath(b), .{}) catch @panic("failed to open source");
        defer iterable.close();

        var walker = iterable.walk(b.allocator) catch @panic("failed to init walker");

        var files = std.ArrayListUnmanaged([]const u8){};
        while (walker.next() catch @panic("failed to walk source dir")) |entry| {
            const skip = for (dirs_to_skip.?) |dir| {
                if (std.mem.indexOf(u8, entry.path, dir) != null) {
                    break true;
                }
            } else false;

            if (skip)
                continue;

            if (entry.kind == .file and std.mem.eql(u8, std.fs.path.extension(entry.basename), ".c")) {
                files.append(b.allocator, b.pathJoin(&.{ "source", entry.path })) catch @panic("OOM");
            }
        }

        lib.addCSourceFiles(.{
            .files = files.items,
            .dependency = dep,
            .flags = &.{ "-std=c99", "-Wno-implicit-function-declaration" },
        });
    }

    b.installArtifact(lib);

    const example = b.addExecutable(.{
        .name = "example",
        .root_source_file = .{ .path = "example.zig" },
        .target = target,
        .optimize = optimize,
    });
    example.linkLibrary(lib);
    example.step.dependOn(&config_header.step);
    example.include_dirs.appendSlice(lib.include_dirs.items) catch @panic("OOM");

    const example_step = b.step("example", "run the example");
    example_step.dependOn(&b.addRunArtifact(example).step);
}
