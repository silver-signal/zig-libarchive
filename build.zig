const package = "libarchive";
const package_name = package["lib".len..];

const version: std.SemanticVersion = .{
    .major = 3,
    .minor = 8,
    .patch = 1,
};
const version_string = std.fmt.comptimePrint("{}", .{version});

pub fn build(b: *Build) !void {
    const upstream = b.dependency(package, .{});
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const linkage = b.option(std.builtin.LinkMode, "linkage", "Link mode") orelse .static;
    const strip = b.option(bool, "strip", "Omit debug information");
    const pic = b.option(bool, "pic", "Produce Position Independent Code");
    const sanitize_c = b.option(bool, "sanitize_c", "Enable C sanitizer") orelse false; // TODO: Switch to default true

    const minimal = b.option(bool, "minimal", "Build minimal artifacts. Dependencies are all set to default=false. (default=false)") orelse false;

    // Provide a helpful error message if a user tries to compile on an unsupported platform.
    switch (target.result.os.tag) {
        .linux => {},
        else => |tag| @panic(b.fmt("ERROR: zig-libarchive does not support this OS: {}\n", .{tag})),
    }

    _ = b.step("check", "Check that build.zig compiles. Used for analysis by zls.");
    const test_step = b.step("test", "Run all of the tests.");

    const config_h = getConfigHeader(b, upstream, target);
    configXAttr(config_h);

    const flags_default: []const []const u8 = &.{
        // CFLAGS
        "-Wall",
        "-Wformat",
        "-Wformat-security",
        "-ffunction-sections",
        "-fdata-sections",

        // DEFS
        "-DHAVE_CONFIG_H=1",

        // DEAD_CODE_REMOVAL
        "-Wl,--gc-sections",

        // zig cc supports visibility annotations
        "-D__LIBARCHIVE_ENABLE_VISIBILITY",
        "-fvisibility=hidden",
    };

    var flags_list = try std.ArrayList([]const u8).initCapacity(b.allocator, flags_default.len);
    try flags_list.appendSlice(flags_default);
    if (linkage == .static) try flags_list.append("-DLIBARCHIVE_STATIC");
    const flags: []const []const u8 = try flags_list.toOwnedSlice();

    // The core libarchive module. All other binaries depend on this.
    const libarchive_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = strip,
        .pic = pic,
        .sanitize_c = sanitize_c,
    });
    libarchive_module.addConfigHeader(config_h);
    libarchive_module.addIncludePath(upstream.path(""));
    libarchive_module.addCSourceFiles(.{
        .root = upstream.path("libarchive"),
        .files = libarchive_src,
        .flags = flags,
    });
    configAcl(b, config_h, libarchive_module, .{ .minimal = minimal });
    configB2(b, config_h, libarchive_module, .{ .minimal = minimal });
    configBzip2(b, config_h, libarchive_module, .{ .minimal = minimal });
    configExpat(b, config_h, libarchive_module, .{ .minimal = minimal });
    configIconv(b, config_h, libarchive_module, .{ .minimal = minimal });
    configLz4(b, config_h, libarchive_module, .{ .minimal = minimal });
    configLzma(b, config_h, libarchive_module, .{ .minimal = minimal });
    configLzo2(b, config_h, libarchive_module, .{ .minimal = minimal });
    configRegex(b, config_h, libarchive_module, .{ .minimal = minimal });
    configXml2(b, config_h, libarchive_module, .{ .minimal = minimal });
    configZlib(b, config_h, libarchive_module, .{ .minimal = minimal });
    configZstd(b, config_h, libarchive_module, .{ .minimal = minimal });

    // TODO: The configure script does some specialized things for the crypto libraries.
    // For now, we'll just configure as normal, but we'll need to add special steps in the future.
    configCng(b, config_h, libarchive_module, .{ .minimal = minimal });
    configMbedTls(b, config_h, libarchive_module, .{ .minimal = minimal });
    configNettle(b, config_h, libarchive_module, .{ .minimal = minimal });
    configOpenSsl(b, config_h, libarchive_module, .{ .minimal = minimal });

    const libarchive = b.addLibrary(.{
        .name = package_name,
        .root_module = libarchive_module,
        .linkage = linkage,
    });
    libarchive.installHeadersDirectory(upstream.path("libarchive"), "", .{
        .include_extensions = &.{
            "archive.h",
            "archive_entry.h",
        },
    });
    b.installArtifact(libarchive);

    // Common frontend code used in all of the executables (bsdcat, bsdtar, etc.)
    const libarchive_fe_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = strip,
        .pic = pic,
        .sanitize_c = sanitize_c,
    });
    libarchive_fe_module.addCSourceFiles(.{
        .root = upstream.path("libarchive_fe"),
        .files = libarchive_fe_src,
        .flags = flags,
    });
    libarchive_fe_module.addIncludePath(upstream.path(""));
    libarchive_fe_module.addConfigHeader(config_h);

    const libarchive_fe = b.addLibrary(.{
        .name = "libarchive_fe",
        .root_module = libarchive_fe_module,
        .linkage = .static,
    });

    const module_names: []const []const u8 = &.{ "cat", "cpio", "tar", "unzip" };
    for (module_names) |mod_name| {
        const enable_module_arg = b.fmt("enable-bsd{s}", .{mod_name});
        const enable_module_msg = b.fmt("enable build of bsd{s} (default=true)", .{mod_name});
        const enable_module = b.option(bool, enable_module_arg, enable_module_msg) orelse true;
        if (!enable_module) continue;

        // Compile the executables
        const exe_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .strip = strip,
            .pic = pic,
            .sanitize_c = sanitize_c,
        });
        exe_module.addConfigHeader(config_h);
        exe_module.addIncludePath(upstream.path(""));
        exe_module.addCSourceFiles(.{
            .root = upstream.path(mod_name),
            .files = src_map.get(mod_name) orelse unreachable,
            .flags = flags,
        });
        exe_module.addCSourceFiles(.{
            .root = upstream.path(mod_name),
            .files = main_src_map.get(mod_name) orelse unreachable,
            .flags = flags,
        });
        exe_module.addIncludePath(upstream.path("libarchive"));
        exe_module.linkLibrary(libarchive);
        exe_module.addIncludePath(upstream.path("libarchive_fe"));
        exe_module.linkLibrary(libarchive_fe);

        const exe = b.addExecutable(.{
            .name = b.fmt("bsd{s}", .{mod_name}),
            .root_module = exe_module,
        });
        b.installArtifact(exe);

        // Compile the executable tests, create a top-level step for them,
        // and add them to the test step.
        const test_step_name = b.fmt("bsd{s}_test", .{mod_name});
        const exe_test_step = b.step(test_step_name, b.fmt("Run the tests for bsd{s}", .{mod_name}));
        test_step.dependOn(exe_test_step);

        const test_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .strip = strip,
            .pic = pic,
            .sanitize_c = sanitize_c,
        });
        test_module.addCSourceFiles(.{
            .root = upstream.path(mod_name),
            .files = test_src_map.get(mod_name) orelse unreachable,
            .flags = flags,
        });
        test_module.addCSourceFiles(.{
            .root = b.path(b.fmt("disabled_tests/{s}", .{mod_name})),
            .files = disabled_test_src_map.get(mod_name) orelse unreachable,
            .flags = flags,
        });
        test_module.addCSourceFiles(.{
            .root = upstream.path("test_utils"),
            .files = test_utils_src,
            .flags = flags,
        });
        test_module.addConfigHeader(config_h);
        test_module.addIncludePath(upstream.path(""));
        test_module.addIncludePath(upstream.path("test_utils"));
        test_module.addIncludePath(upstream.path("libarchive"));
        test_module.linkLibrary(libarchive);
        test_module.addIncludePath(upstream.path(mod_name));
        test_module.addIncludePath(upstream.path(b.fmt("{s}/test", .{mod_name})));
        test_module.addIncludePath(upstream.path("libarchive_fe"));
        test_module.linkLibrary(libarchive_fe);

        const exe_test = b.addExecutable(.{
            .name = test_step_name,
            .root_module = test_module,
        });
        const exe_test_run = b.addRunArtifact(exe_test);
        exe_test_run.setCwd(upstream.path(""));
        exe_test_run.addArg("-p");
        exe_test_run.addArtifactArg(exe);
        exe_test_step.dependOn(&exe_test_run.step);
    }

    const libarchive_test_step = b.step("libarchive_test", "Run the tests for libarchive.");
    test_step.dependOn(libarchive_test_step);
    const libarchive_test_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    libarchive_test_module.addCSourceFiles(.{
        .root = upstream.path("libarchive/test"),
        .files = libarchive_test_src,
        .flags = flags,
    });
    libarchive_test_module.addCSourceFiles(.{
        .root = upstream.path("test_utils"),
        .files = test_utils_src,
        .flags = flags,
    });
    libarchive_test_module.addCSourceFiles(.{
        .root = b.path("disabled_tests/libarchive"),
        .files = libarchive_test_disabled_src,
        .flags = flags,
    });
    libarchive_test_module.addConfigHeader(config_h);
    libarchive_test_module.addIncludePath(upstream.path(""));
    libarchive_test_module.addIncludePath(upstream.path("test_utils"));
    libarchive_test_module.addIncludePath(upstream.path("libarchive"));
    libarchive_test_module.addIncludePath(upstream.path("libarchive/test"));
    libarchive_test_module.linkLibrary(libarchive);

    const libarchive_test = b.addExecutable(.{
        .name = "libarchive_test",
        .root_module = libarchive_test_module,
    });
    const libarchive_test_run = b.addRunArtifact(libarchive_test);
    libarchive_test_run.setCwd(upstream.path(""));
    libarchive_test_run.addArg("-v");
    libarchive_test_run.addArg("-d");
    libarchive_test_step.dependOn(&libarchive_test_run.step);
}

fn configXAttr(config_h: *Step.ConfigHeader) void {
    // TODO:
    // const enable_xattr = b.option(bool, enable-xattr, "Enable xattr support (default=true)");
    config_h.addValues(.{
        .HAVE_ATTR_XATTR_H = null,
        .HAVE_SYS_XATTR_H = null,
        .ARCHIVE_XATTR_AIX = null,
        .ARCHIVE_XATTR_DARWIN = null,
        .ARCHIVE_XATTR_FREEBSD = null,
        .ARCHIVE_XATTR_LINUX = null,
        .LIBATTR_PKGCONFIG_VERSION = null,
        .HAVE_DECL_XATTR_NOFOLLOW = null,
        .HAVE_GETXATTR = null,
        .HAVE_SETXATTR = null,
        .HAVE_LISTXATTR = null,
        .HAVE_FGETXATTR = null,
        .HAVE_FSETXATTR = null,
        .HAVE_FLISTXATTR = null,
        .HAVE_LGETXATTR = null,
        .HAVE_LSETXATTR = null,
        .HAVE_LLISTXATTR = null,
        .HAVE_EXTATTR_GET_FD = null,
        .HAVE_EXTATTR_GET_FILE = null,
        .HAVE_EXTATTR_GET_LINK = null,
        .HAVE_EXTATTR_LIST_FD = null,
        .HAVE_EXTATTR_LIST_FILE = null,
        .HAVE_EXTATTR_LIST_LINK = null,
        .HAVE_EXTATTR_SET_FD = null,
        .HAVE_EXTATTR_SET_LINK = null,
        .HAVE_DECL_EXTATTR_NAMESPACE_USER = false,
        .HAVE_SYS_EXTATTR_H = null,
    });
}

const ConfigOptions = struct {
    minimal: bool,
};

fn configAcl(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO:
    // const enable_acl = b.option(bool, enable-acl, "Enable acl support (default=true)") orelse !options.minimal;
    _ = b;
    _ = module;
    _ = options;
    config_h.addValues(.{
        .ARCHIVE_ACL_DARWIN = null,
        .ARCHIVE_ACL_FREEBSD = null,
        .ARCHIVE_ACL_FREEBSD_NFS4 = null,
        .ARCHIVE_ACL_LIBACL = null,
        .ARCHIVE_ACL_LIBRICHACL = null,
        .ARCHIVE_ACL_SUNOS = null,
        .ARCHIVE_ACL_SUNOS_NFS4 = null,
        .HAVE_ACL = null,
        .HAVE_FACL = null,
        .HAVE_LIBACL = null,
        .HAVE_LIBRICHACL = null,
        .HAVE_RICHACL_ALLOC = null,
        .HAVE_RICHACL_EQUIV_MODE = null,
        .HAVE_RICHACL_FREE = null,
        .HAVE_RICHACL_GET_FD = null,
        .HAVE_RICHACL_GET_FILE = null,
        .HAVE_RICHACL_SET_FD = null,
        .HAVE_RICHACL_SET_FILE = null,
        .HAVE_STRUCT_RICHACE = null,
        .HAVE_STRUCT_RICHACL = null,
        .HAVE_ACE_T = null,
        .HAVE_ACLENT_T = null,
        .HAVE_ACL_ADD_FLAG_NP = null,
        .HAVE_ACL_ADD_PERM = null,
        .HAVE_ACL_CLEAR_FLAGS_NP = null,
        .HAVE_ACL_CLEAR_PERMS = null,
        .HAVE_ACL_CREATE_ENTRY = null,
        .HAVE_ACL_DELETE_DEF_FILE = null,
        .HAVE_ACL_ENTRY_T = null,
        .HAVE_ACL_FREE = null,
        .HAVE_ACL_GET_BRAND_NP = null,
        .HAVE_ACL_GET_ENTRY = null,
        .HAVE_ACL_GET_ENTRY_TYPE_NP = null,
        .HAVE_ACL_GET_FD = null,
        .HAVE_ACL_GET_FD_NP = null,
        .HAVE_ACL_GET_FILE = null,
        .HAVE_ACL_GET_FLAGSET_NP = null,
        .HAVE_ACL_GET_FLAG_NP = null,
        .HAVE_ACL_GET_LINK_NP = null,
        .HAVE_ACL_GET_PERM = null,
        .HAVE_ACL_GET_PERMSET = null,
        .HAVE_ACL_GET_PERM_NP = null,
        .HAVE_ACL_GET_QUALIFIER = null,
        .HAVE_ACL_GET_TAG_TYPE = null,
        .HAVE_ACL_INIT = null,
        .HAVE_ACL_IS_TRIVIAL_NP = null,
        .HAVE_ACL_LIBACL_H = null,
        .HAVE_SYS_ACL_H = null,
        .HAVE_SYS_RICHACL_H = null,
        .HAVE_ACL_PERMSET_T = null,
        .HAVE_ACL_SET_ENTRY_TYPE_NP = null,
        .HAVE_ACL_SET_FD = null,
        .HAVE_ACL_SET_FD_NP = null,
        .HAVE_ACL_SET_FILE = null,
        .HAVE_ACL_SET_LINK_NP = null,
        .HAVE_ACL_SET_QUALIFIER = null,
        .HAVE_ACL_SET_TAG_TYPE = null,
        .HAVE_ACL_T = null,
        .HAVE_ACL_TAG_T = null,
        .HAVE_DECL_ACE_GETACL = null,
        .HAVE_DECL_ACE_GETACLCNT = null,
        .HAVE_DECL_ACE_SETACL = null,
        .HAVE_DECL_ACL_SYNCHRONIZE = null,
        .HAVE_DECL_ACL_TYPE_EXTENDED = null,
        .HAVE_DECL_ACL_TYPE_NFS4 = null,
        .HAVE_DECL_ACL_USER = null,
        .HAVE_DECL_GETACL = null,
        .HAVE_DECL_SETACL = null,
        .HAVE_DECL_GETACLCNT = null,
        .LIBACL_PKGCONFIG_VERSION = null,
        .LIBRICHACL_PKGCONFIG_VERSION = null,
    });
}

fn configB2(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO: Add libb2 support.
    _ = b;
    _ = module;
    _ = options;
    config_h.addValues(.{
        .HAVE_BLAKE2_H = null,
        .HAVE_LIBB2 = null,
        .LIBB2_PKGCONFIG_VERSION = null,
    });
}

fn configBzip2(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    if (b.option(bool, "enable-bzip2", "Build support for bzip2 through libbz2 (default=true)") orelse !options.minimal) {
        config_h.addValues(.{
            .HAVE_BZLIB_H = true,
            .HAVE_LIBBZ2 = true,
        });
        if (b.lazyDependency("bzip2", .{ .target = module.resolved_target.?, .optimize = module.optimize.? })) |bzip2| {
            module.linkLibrary(bzip2.artifact("bz2"));
        }
    } else {
        config_h.addValues(.{
            .HAVE_BZLIB_H = null,
            .HAVE_LIBBZ2 = null,
        });
    }
}

fn configCng(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO: Add CNG library support
    _ = b;
    _ = module;
    _ = options;
    config_h.addValues(.{
        .HAVE_BCRYPT_H = null,
    });
}

fn configMbedTls(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO: Add mbedtls library support
    _ = b;
    _ = module;
    _ = options;
    config_h.addValues(.{
        .HAVE_MBEDTLS_AES_H = null,
        .HAVE_MBEDTLS_MD_H = null,
        .HAVE_MBEDTLS_PKCS5_H = null,
        .HAVE_MBEDTLS_VERSION_H = null,
        .HAVE_LIBMBEDCRYPTO = null,
        .ARCHIVE_CRYPTO_MD5_MBEDTLS = null,
        .ARCHIVE_CRYPTO_RMD160_MBEDTLS = null,
        .ARCHIVE_CRYPTO_SHA1_MBEDTLS = null,
        .ARCHIVE_CRYPTO_SHA256_MBEDTLS = null,
        .ARCHIVE_CRYPTO_SHA384_MBEDTLS = null,
        .ARCHIVE_CRYPTO_SHA512_MBEDTLS = null,
    });
}

fn configExpat(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO: Add Expat library support.
    _ = b;
    _ = module;
    _ = options;
    config_h.addValues(.{
        .HAVE_EXPAT_H = null,
        .HAVE_LIBEXPAT = null,
    });
}

fn configIconv(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    config_h.addValues(.{
        .HAVE_LOCALE_CHARSET = null,
    });
    if (b.option(bool, "enable-iconv", "Enable iconv support (default=true)") orelse !options.minimal) {
        const target = module.resolved_target.?;
        const optimize = module.optimize.?;

        config_h.addValues(.{
            .HAVE_ICONV_H = true,
            .HAVE_ICONV = true,
            .ICONV_CONST = {},
        });

        const IconvImpl = enum { libc, libiconv };
        const impl: IconvImpl = b.option(
            IconvImpl,
            "iconv-impl",
            "Set the iconv implementation (default=libc)",
        ) orelse .libc;
        switch (impl) {
            .libc => {
                config_h.addValues(.{
                    .HAVE_LIBICONV = null,
                    .HAVE_LOCALCHARSET_H = null,
                    .HAVE_LIBCHARSET = null,
                });
            },
            .libiconv => {
                config_h.addValues(.{
                    .HAVE_LIBICONV = true,
                    .HAVE_LOCALCHARSET_H = true,
                    .HAVE_LIBCHARSET = true,
                });

                if (b.lazyDependency("libiconv", .{ .target = target, .optimize = optimize })) |libiconv| {
                    module.linkLibrary(libiconv.artifact("iconv"));
                    module.linkLibrary(libiconv.artifact("charset"));
                }
            },
        }
    } else {
        config_h.addValues(.{
            .HAVE_ICONV_H = null,
            .HAVE_ICONV = null,
            .HAVE_LIBICONV = null,
            .ICONV_CONST = null,
            .HAVE_LOCALCHARSET_H = null,
            .HAVE_LIBCHARSET = null,
        });
    }
}

fn configLz4(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    if (b.option(bool, "enable-lz4", "Build support for lz4 through liblz4 (default=true)") orelse !options.minimal) {
        config_h.addValues(.{
            .HAVE_LIBLZ4 = true,
            .HAVE_LZ4HC_H = true,
            .HAVE_LZ4_H = true,
        });
        if (b.lazyDependency("lz4", .{ .target = module.resolved_target.?, .optimize = module.optimize.? })) |lz4| {
            module.linkLibrary(lz4.artifact("lz4"));
        }
    } else {
        config_h.addValues(.{
            .HAVE_LIBLZ4 = null,
            .HAVE_LZ4HC_H = null,
            .HAVE_LZ4_H = null,
        });
    }
}

fn configLzma(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO: Add LZMA library
    _ = b;
    _ = module;
    _ = options;
    config_h.addValues(.{
        .HAVE_LIBLZMA = null,
        .HAVE_LZMA_H = null,
        .HAVE_LZMA_STREAM_ENCODER_MT = null,
    });
}

fn configLzo2(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO: Add LZO2 library
    _ = b;
    _ = module;
    _ = options;
    config_h.addValues(.{
        .HAVE_LIBLZO2 = null,
        .HAVE_LZO_LZO1X_H = null,
        .HAVE_LZO_LZOCONF_H = null,
    });
}

fn configNettle(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO: Add Nettle library
    _ = b;
    _ = module;
    _ = options;
    config_h.addValues(.{
        .ARCHIVE_CRYPTO_MD5_NETTLE = null,
        .ARCHIVE_CRYPTO_RMD160_NETTLE = null,
        .ARCHIVE_CRYPTO_SHA1_NETTLE = null,
        .ARCHIVE_CRYPTO_SHA256_NETTLE = null,
        .ARCHIVE_CRYPTO_SHA384_NETTLE = null,
        .ARCHIVE_CRYPTO_SHA512_NETTLE = null,
        .HAVE_LIBNETTLE = null,
        .HAVE_NETTLE_AES_H = null,
        .HAVE_NETTLE_HMAC_H = null,
        .HAVE_NETTLE_MD5_H = null,
        .HAVE_NETTLE_PBKDF2_H = null,
        .HAVE_NETTLE_RIPEMD160_H = null,
        .HAVE_NETTLE_SHA_H = null,
        .HAVE_NETTLE_VERSION_H = null,
    });
}

fn configOpenSsl(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    // TODO: add support for OpenSSL libcrypto
    config_h.addValues(.{
        .HAVE_LIBCRYPTO = null,
    });

    if (b.option(bool, "enable-openssl", "Build support for mtree and xar hashes through openssl (default=true)") orelse !options.minimal) {
        config_h.addValues(.{
            .HAVE_OPENSSL_EVP_H = true,
            .HAVE_OPENSSL_OPENSSLV_H = true,
            .ARCHIVE_CRYPTO_MD5_OPENSSL = true,
            .ARCHIVE_CRYPTO_RMD160_OPENSSL = true,
            .ARCHIVE_CRYPTO_SHA1_OPENSSL = true,
            .ARCHIVE_CRYPTO_SHA256_OPENSSL = true,
            .ARCHIVE_CRYPTO_SHA384_OPENSSL = true,
            .ARCHIVE_CRYPTO_SHA512_OPENSSL = true,
        });
        if (b.lazyDependency("openssl", .{ .target = module.resolved_target.?, .optimize = module.optimize.? })) |openssl| {
            module.linkLibrary(openssl.artifact("openssl"));
        }
    } else {
        config_h.addValues(.{
            .HAVE_OPENSSL_EVP_H = null,
            .HAVE_OPENSSL_OPENSSLV_H = null,
            .ARCHIVE_CRYPTO_MD5_OPENSSL = null,
            .ARCHIVE_CRYPTO_RMD160_OPENSSL = null,
            .ARCHIVE_CRYPTO_SHA1_OPENSSL = null,
            .ARCHIVE_CRYPTO_SHA256_OPENSSL = null,
            .ARCHIVE_CRYPTO_SHA384_OPENSSL = null,
            .ARCHIVE_CRYPTO_SHA512_OPENSSL = null,
        });
    }
    // TODO: Add support for configuring libmd (BSD Message Digest library)
    config_h.addValues(.{
        .HAVE_MD5_H = null,
        .HAVE_RIPEMD_H = null,
        .HAVE_SHA256_H = null,
        .HAVE_SHA512_H = null,
        .HAVE_SHA_H = null,
        .ARCHIVE_CRYPTO_MD5_LIBMD = null,
        .ARCHIVE_CRYPTO_RMD160_LIBMD = null,
        .ARCHIVE_CRYPTO_SHA1_LIBMD = null,
        .ARCHIVE_CRYPTO_SHA256_LIBMD = null,
        .ARCHIVE_CRYPTO_SHA512_LIBMD = null,
        .HAVE_LIBMD = null,
    });
}

fn configRegex(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    _ = b;
    _ = module;
    _ = options;
    // TODO: Configure regex expression support.
    config_h.addValues(.{
        .HAVE_REGEX_H = null,
        .HAVE_LIBREGEX = null,
        .HAVE_LIBPCRE = null,
        .HAVE_LIBPCRE2 = null,
        .HAVE_LIBPCRE2_POSIX = null,
        .HAVE_LIBPCREPOSIX = null,
        .HAVE_PCRE2POSIX_H = null,
        .HAVE_PCREPOSIX_H = null,
        .PCRE2_STATIC = null,
        .PCRE_STATIC = null,
    });
}

fn configXml2(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    if (b.option(bool, "enable-xml2", "Build support for xar through libxml2 (default=true)") orelse !options.minimal) {
        config_h.addValues(.{
            .HAVE_LIBXML2 = true,
            .HAVE_LIBXML_XMLREADER_H = true,
            .HAVE_LIBXML_XMLWRITER_H = true,
            .HAVE_LIBXML_XMLVERSION_H = true,
        });
        if (b.lazyDependency("libxml2", .{ .target = module.resolved_target.?, .optimize = module.optimize.? })) |libxml2| {
            module.linkLibrary(libxml2.artifact("xml"));
        }
    } else {
        config_h.addValues(.{
            .HAVE_LIBXML2 = null,
            .HAVE_LIBXML_XMLREADER_H = null,
            .HAVE_LIBXML_XMLWRITER_H = null,
            .HAVE_LIBXML_XMLVERSION_H = null,
        });
    }
}

fn configZlib(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    if (b.option(bool, "enable-zlib", "Build support for gzip through zlib (default=true)") orelse !options.minimal) {
        config_h.addValues(.{
            .HAVE_ZLIB_H = true,
            .HAVE_LIBZ = true,
        });
        if (b.lazyDependency("zlib", .{ .target = module.resolved_target.?, .optimize = module.optimize.? })) |zlib| {
            module.linkLibrary(zlib.artifact("z"));
        }
    } else {
        config_h.addValues(.{
            .HAVE_ZLIB_H = null,
            .HAVE_LIBZ = null,
        });
    }
}

fn configZstd(b: *Build, config_h: *Step.ConfigHeader, module: *Build.Module, options: ConfigOptions) void {
    if (b.option(bool, "enable-zstd", "Build support for zstd through libzstd (default=true)") orelse !options.minimal) {
        config_h.addValues(.{
            .HAVE_LIBZSTD = true,
            .HAVE_ZSTD_H = true,
            .HAVE_ZSTD_compressStream = true,
            .HAVE_ZSTD_minCLevel = true,
        });
        if (b.lazyDependency("zstd", .{ .target = module.resolved_target.?, .optimize = module.optimize.? })) |zstd| {
            module.linkLibrary(zstd.artifact("zstd"));
        }
    } else {
        config_h.addValues(.{
            .HAVE_LIBZSTD = null,
            .HAVE_ZSTD_H = null,
            .HAVE_ZSTD_compressStream = null,
            .HAVE_ZSTD_minCLevel = null,
        });
    }
}

fn getConfigHeader(b: *Build, upstream: *Build.Dependency, target: Build.ResolvedTarget) *Step.ConfigHeader {
    const linux_version_range = target.result.os.versionRange();
    const glibc_version = linux_version_range.gnuLibCVersion().?;
    const config_h = b.addConfigHeader(.{ .style = .{ .autoconf = upstream.path("config.h.in") } }, .{});

    // Package info
    config_h.addValues(.{
        .PACKAGE = package,
        .PACKAGE_BUGREPORT = package ++ "-discuss@googlegroups.com",
        .PACKAGE_NAME = package,
        .PACKAGE_STRING = b.fmt("{s} {}", .{ package, version }),
        .PACKAGE_TARNAME = package,
        .PACKAGE_URL = "",
        .PACKAGE_VERSION = version_string,
        .VERSION = version_string,
        .LIBARCHIVE_VERSION_NUMBER = std.fmt.comptimePrint("{d}{d:0>3}{d:0>3}", .{
            version.major, version.minor, version.patch,
        }),
        .LIBARCHIVE_VERSION_STRING = version_string,
        .BSDCAT_VERSION_STRING = version_string,
        .BSDCPIO_VERSION_STRING = version_string,
        .BSDTAR_VERSION_STRING = version_string,
        .BSDUNZIP_VERSION_STRING = version_string,
    });

    // C type definitions
    config_h.addValues(.{
        .HAVE_DECL_INT32_MAX = true,
        .HAVE_DECL_INT32_MIN = true,
        .HAVE_DECL_INT64_MAX = true,
        .HAVE_DECL_INT64_MIN = true,
        .HAVE_DECL_INTMAX_MAX = true,
        .HAVE_DECL_INTMAX_MIN = true,
        .HAVE_DECL_SIZE_MAX = true,
        .HAVE_DECL_SSIZE_MAX = true,
        .HAVE_DECL_STRERROR_R = true,
        .HAVE_DECL_UINT32_MAX = true,
        .HAVE_DECL_UINT64_MAX = true,
        .HAVE_DECL_UINTMAX_MAX = true,
        .HAVE_INTMAX_T = true,
        .HAVE_LONG_LONG_INT = true,
        .HAVE_UINTMAX_T = true,
        .HAVE_UNSIGNED_LONG_LONG = true,
        .HAVE_UNSIGNED_LONG_LONG_INT = true,
        .HAVE_WCHAR_T = true,
        .SIZEOF_INT = target.result.cTypeByteSize(.int),
        .SIZEOF_LONG = target.result.cTypeByteSize(.long),
        .SIZEOF_WCHAR_T = @as(u3, switch (target.result.os.tag) {
            .windows => 2,
            else => 4,
        }),
        .@"const" = null,
        .gid_t = null,
        .id_t = null,
        .int16_t = null,
        .int32_t = null,
        .int64_t = null,
        .intmax_t = null,
        .mode_t = null,
        .off_t = null,
        .size_t = null,
        .uid_t = null,
        .uint16_t = null,
        .uint32_t = null,
        .uint64_t = null,
        .uint8_t = null,
        .uintmax_t = null,
        .uintptr_t = null,
        ._UINT32_T = null,
        ._UINT64_T = null,
        ._UINT8_T = null,
    });

    // C standard library headers
    config_h.addValues(.{
        .HAVE_CTYPE_H = true,
        .HAVE_ERRNO_H = true,
        .HAVE_INTTYPES_H = true,
        .HAVE_LIMITS_H = true,
        .HAVE_LOCALE_H = true,
        .HAVE_SIGNAL_H = true,
        .HAVE_STDARG_H = true,
        .HAVE_STDINT_H = true,
        .HAVE_STDIO_H = true,
        .HAVE_STDLIB_H = true,
        .HAVE_STRINGS_H = true,
        .HAVE_STRING_H = true,
        .HAVE_TIME_H = true,
        .HAVE_WCHAR_H = true,
        .HAVE_WCTYPE_H = true,
        .STDC_HEADERS = true,
    });

    // System headers
    config_h.addValues(.{
        .HAVE_COPYFILE_H = null,
        .HAVE_DIRENT_H = true,
        .HAVE_DLFCN_H = true,
        .HAVE_EXT2FS_EXT2_FS_H = null,
        .HAVE_FCNTL_H = true,
        .HAVE_FNMATCH_H = true,
        .HAVE_GRP_H = true,
        .HAVE_IO_H = null,
        .HAVE_LANGINFO_H = true,
        .HAVE_LINUX_FIEMAP_H = true,
        .HAVE_LINUX_FS_H = true,
        .HAVE_LINUX_MAGIC_H = true,
        .HAVE_LINUX_TYPES_H = true,
        .HAVE_MEMBERSHIP_H = null,
        .HAVE_MINIX_CONFIG_H = null,
        .HAVE_NDIR_H = null,
        .HAVE_PATHS_H = true,
        .HAVE_POLL_H = true,
        .HAVE_PTHREAD_H = true,
        .HAVE_PWD_H = true,
        .HAVE_READPASSPHRASE_H = null,
        .HAVE_SPAWN_H = true,
        .HAVE_SYS_CDEFS_H = true,
        .HAVE_SYS_DIR_H = null,
        .HAVE_SYS_EA_H = null,
        .HAVE_SYS_IOCTL_H = true,
        .HAVE_SYS_MKDEV_H = null,
        .HAVE_SYS_MOUNT_H = true,
        .HAVE_SYS_NDIR_H = null,
        .HAVE_SYS_PARAM_H = true,
        .HAVE_SYS_POLL_H = true,
        .HAVE_SYS_SELECT_H = true,
        .HAVE_SYS_STATFS_H = true,
        .HAVE_SYS_STATVFS_H = true,
        .HAVE_SYS_STAT_H = true,
        .HAVE_SYS_SYSMACROS_H = true,
        .HAVE_SYS_TIME_H = true,
        .HAVE_SYS_TYPES_H = true,
        .HAVE_SYS_UTIME_H = null,
        .HAVE_SYS_UTSNAME_H = true,
        .HAVE_SYS_VFS_H = true,
        .HAVE_SYS_WAIT_H = true,
        .HAVE_UNISTD_H = true,
        .HAVE_UTIME_H = true,
        .HAVE_WINCRYPT_H = null,
        .HAVE_WINDOWS_H = null,
        .HAVE_WINIOCTL_H = null,
    });

    // System crypto support.
    // TODO: Move these when reorganizing the crypto libraries.
    config_h.addValues(.{
        .ARCHIVE_CRYPTO_MD5_LIBC = null,
        .ARCHIVE_CRYPTO_MD5_LIBSYSTEM = null,
        .ARCHIVE_CRYPTO_MD5_WIN = null,
        .ARCHIVE_CRYPTO_RMD160_LIBC = null,
        .ARCHIVE_CRYPTO_SHA1_LIBC = null,
        .ARCHIVE_CRYPTO_SHA1_LIBSYSTEM = null,
        .ARCHIVE_CRYPTO_SHA1_WIN = null,
        .ARCHIVE_CRYPTO_SHA256_LIBC = null,
        .ARCHIVE_CRYPTO_SHA256_LIBC2 = null,
        .ARCHIVE_CRYPTO_SHA256_LIBC3 = null,
        .ARCHIVE_CRYPTO_SHA256_LIBSYSTEM = null,
        .ARCHIVE_CRYPTO_SHA256_WIN = null,
        .ARCHIVE_CRYPTO_SHA384_LIBC = null,
        .ARCHIVE_CRYPTO_SHA384_LIBC2 = null,
        .ARCHIVE_CRYPTO_SHA384_LIBC3 = null,
        .ARCHIVE_CRYPTO_SHA384_LIBSYSTEM = null,
        .ARCHIVE_CRYPTO_SHA384_WIN = null,
        .ARCHIVE_CRYPTO_SHA512_LIBC = null,
        .ARCHIVE_CRYPTO_SHA512_LIBC2 = null,
        .ARCHIVE_CRYPTO_SHA512_LIBC3 = null,
        .ARCHIVE_CRYPTO_SHA512_LIBSYSTEM = null,
        .ARCHIVE_CRYPTO_SHA512_WIN = null,
    });

    // System Extensions
    config_h.addValues(.{
        ._ALL_SOURCE = true,
        ._DARWIN_C_SOURCE = true,
        .__EXTENSIONS__ = true,
        ._GNU_SOURCE = true,
        ._HPUX_ALT_XOPEN_SOCKET_API = true,
        ._MINIX = null,
        ._NETBSD_SOURCE = true,
        ._OPENBSD_SOURCE = true,
        ._POSIX_SOURCE = null,
        ._POSIX_1_SOURCE = null,
        ._POSIX_PTHREAD_SEMANTICS = true,
        .__STDC_WANT_IEC_60559_ATTRIBS_EXT__ = true,
        .__STDC_WANT_IEC_60559_BFP_EXT__ = true,
        .__STDC_WANT_IEC_60559_DFP_EXT__ = true,
        .__STDC_WANT_IEC_60559_FUNCS_EXT__ = true,
        .__STDC_WANT_IEC_60559_TYPES_EXT__ = true,
        .__STDC_WANT_LIB_EXT2__ = true,
        .__STDC_WANT_MATH_SPEC_FUNCS__ = true,
        ._TANDEM_SOURCE = true,
        ._XOPEN_SOURCE = null,
        .WINVER = null,
        ._FILE_OFFSET_BITS = null,
        ._LARGEFILE_SOURCE = null,
        ._LARGE_FILES = null,
        ._WIN32_WINNT = null,
    });

    // syscalls.
    // All Linux syscalls are supported by at least version 2.6.22.
    config_h.addValues(.{
        .HAVE_CHFLAGS = null, // MacOS
        .HAVE_CHOWN = true,
        .HAVE_CHROOT = true,
        .HAVE_CMTIME_S = null, // MacOS
        .HAVE_FCHDIR = true,
        .HAVE_FCHMOD = true,
        .HAVE_FCHOWN = true,
        .HAVE_FCNTL = true,
        .HAVE_FORK = true,
        .HAVE_FSTAT = true,
        .HAVE_FSTATAT = true,
        .HAVE_FSTATFS = true,
        .HAVE_FTRUNCATE = true,
        .HAVE_FUTIMESAT = true,
        .HAVE_GETEUID = true,
        .HAVE_GETPID = true,
        .HAVE_LCHOWN = true,
        .HAVE_LINK = true,
        .HAVE_LINKAT = true,
        .HAVE_LSTAT = true,
        .HAVE_MKDIR = true,
        .HAVE_MKNOD = true,
        .HAVE_OPENAT = true,
        .HAVE_PIPE = true,
        .HAVE_POLL = true,
        .HAVE_READLINK = true,
        .HAVE_READLINKAT = true,
        .HAVE_SELECT = true,
        .HAVE_SIGACTION = true,
        .HAVE_STATFS = true,
        .HAVE_SYMLINK = true,
        .HAVE_UNLINKAT = true,
        .HAVE_UTIME = true,
        .HAVE_UTIMES = true,
        .HAVE_UTIMENSAT = true,
        .HAVE_VFORK = true,
    });

    // linux glibc functions. values marked true have been supported since at least glibc version 2.2.5
    // (the earliest glibc version that zig cc supports).
    config_h.addValues(.{
        .HAVE_ARC4RANDOM_BUF = glibc_version.order(.{ .major = 2, .minor = 36, .patch = 0 }).compare(.gte),
        .HAVE_CTIME_R = true,
        .HAVE_DIRFD = true,
        .HAVE_FDOPENDIR = true,
        .HAVE_FNMATCH = true,
        .HAVE_FSEEKO = true,
        .HAVE_FSTATVFS = true,
        .HAVE_FUTIMENS = true,
        .HAVE_FUTIMES = true,
        .HAVE_GETGRGID_R = true,
        .HAVE_GETGRNAM_R = true,
        .HAVE_GETLINE = true,
        .HAVE_GETPWNAM_R = true,
        .HAVE_GETPWUID_R = true,
        .HAVE_GMTIME_R = true,
        .HAVE_LCHMOD = true,
        .HAVE_LOCALTIME_R = true,
        .HAVE_LUTIMES = true,
        .HAVE_MBRTOWC = true,
        .HAVE_MEMMOVE = true,
        .HAVE_MEMSET = true,
        .HAVE_MKFIFO = true,
        .HAVE_MKSTEMP = true,
        .HAVE_NL_LANGINFO = true,
        .HAVE_POSIX_SPAWNP = true,
        .HAVE_READDIR_R = true,
        .HAVE_SETENV = true,
        .HAVE_SETLOCALE = true,
        .HAVE_STATVFS = true,
        .HAVE_STRCHR = true,
        .HAVE_STRDUP = true,
        .HAVE_STRERROR = true,
        .HAVE_STRERROR_R = true,
        .HAVE_STRFTIME = true,
        .HAVE_STRNCPY_S = null,
        .HAVE_STRNLEN = true,
        .HAVE_STRRCHR = true,
        .HAVE_SYSCONF = true,
        .HAVE_TCGETATTR = true,
        .HAVE_TCSETATTR = true,
        .HAVE_TIMEGM = true,
        .HAVE_TZSET = true,
        .HAVE_UNSETENV = true,
        .HAVE_VPRINTF = true,
        .HAVE_WCRTOMB = true,
        .HAVE_WCSCMP = true,
        .HAVE_WCSCPY = true,
        .HAVE_WCSLEN = true,
        .HAVE_WCTOMB = true,
        .HAVE_WMEMCMP = true,
        .HAVE_WMEMCPY = true,
        .HAVE_WMEMMOVE = true,
    });

    // TODO: Organize these remaining values.
    config_h.addValues(.{
        .HAVE_EFTYPE = null,
        .HAVE_EILSEQ = true,
        .HAVE_FCHFLAGS = null,
        .HAVE_FGETEA = null,
        .HAVE_FLISTEA = null,
        .HAVE_FSETEA = null,
        .HAVE_GETEA = null,
        .HAVE_GETVFSBYNAME = null,
        .HAVE_GMTIME_S = null,
        .HAVE_LCHFLAGS = null,
        .HAVE_LGETEA = null,
        .HAVE_LISTEA = null,
        .HAVE_LLISTEA = null,
        .HAVE_LOCALTIME_S = null,
        .HAVE_LSETEA = null,
        .HAVE_MBR_GID_TO_UUID = null,
        .HAVE_MBR_UID_TO_UUID = null,
        .HAVE_MBR_UUID_TO_ID = null,
        .HAVE_PKCS5_PBKDF2_HMAC_SHA1 = null,
        .HAVE_READPASSPHRASE = null,
        .HAVE_STRUCT_STATFS = null,
        .HAVE_STRUCT_STATFS_F_IOSIZE = null,
        .HAVE_STRUCT_STATFS_F_NAMEMAX = null,
        .HAVE_STRUCT_STATVFS_F_IOSIZE = null,
        .HAVE_STRUCT_STAT_ST_BIRTHTIME = null,
        .HAVE_STRUCT_STAT_ST_BIRTHTIMESPEC_TV_NSEC = null,
        .HAVE_STRUCT_STAT_ST_BLKSIZE = true,
        .HAVE_STRUCT_STAT_ST_FLAGS = null,
        .HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC = null,
        .HAVE_STRUCT_STAT_ST_MTIME_N = null,
        .HAVE_STRUCT_STAT_ST_MTIME_USEC = null,
        .HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC = true,
        .HAVE_STRUCT_STAT_ST_UMTIME = null,
        .HAVE_STRUCT_TM_TM_GMTOFF = true,
        .HAVE_STRUCT_TM___TM_GMTOFF = null,
        .HAVE_STRUCT_VFSCONF = null,
        .HAVE_STRUCT_XVFSCONF = null,
        .HAVE_WORKING_EXT2_IOC_GETFLAGS = true,
        .HAVE_WORKING_FS_IOC_GETFLAGS = true,
        .HAVE__FSEEKI64 = null,
        .HAVE__GET_TIMEZONE = null,
        .HAVE__MKGMTIME = null,
        .MAJOR_IN_MKDEV = null,
        .MAJOR_IN_SYSMACROS = true,
        .STRERROR_R_CHAR_P = true,
    });

    // Misc settings
    config_h.addValues(.{
        .HAVE_CYGWIN_CONV_PATH = null, // Cygwin environments
        .HAVE_D_MD_ORDER = null, // Item value for nl_langinfo
        .HAVE_DOPRNT = null, // Only set if vprintf isn't available, which isn't possible for `zig cc`
        .NTDDI_VERSION = null, // Used for Windows Server 2003, which is not supported by Zig
        .LSTAT_FOLLOWS_SLASHED_SYMLINK = true, // Always true for modern lstat implementations
        .LT_OBJDIR = ".libs/", // Libtool setting
        .HAVE_LSTAT_EMPTY_STRING_BUG = null, // Never true for current systems
        .HAVE_STAT_EMPTY_STRING_BUG = null, // Never true for current systems
        .__LIBARCHIVE_CONFIG_H_INCLUDED = true, // libarchive sanity check. Always true for this build.
    });

    return config_h;
}

const main_src_map = StaticStringMap([]const []const u8).initComptime(.{
    .{ "cat", bsdcat_main },
    .{ "cpio", bsdcpio_main },
    .{ "tar", bsdtar_main },
    .{ "unzip", bsdunzip_main },
});

const src_map = StaticStringMap([]const []const u8).initComptime(.{
    .{ "cat", bsdcat_src },
    .{ "cpio", bsdcpio_src },
    .{ "tar", bsdtar_src },
    .{ "unzip", bsdunzip_src },
});

const bsdcat_main: []const []const u8 = &.{
    "bsdcat.c",
};

const bsdcat_src: []const []const u8 = &.{
    "cmdline.c",
};

const bsdcpio_main: []const []const u8 = &.{
    "cpio.c",
};

const bsdcpio_src: []const []const u8 = &.{
    "cmdline.c",
    "cpio_windows.c",
};

const libarchive_fe_src: []const []const u8 = &.{
    "err.c",
    "line_reader.c",
    "passphrase.c",
};

const bsdtar_main: []const []const u8 = &.{
    "bsdtar.c",
};

const bsdtar_src: []const []const u8 = &.{
    "bsdtar_windows.c",
    "cmdline.c",
    "creation_set.c",
    "read.c",
    "subst.c",
    "util.c",
    "write.c",
};

const bsdunzip_main: []const []const u8 = &.{
    "bsdunzip.c",
};

const bsdunzip_src: []const []const u8 = &.{
    "cmdline.c",
    "la_getline.c",
};

const libarchive_src: []const []const u8 = &.{
    "archive_acl.c",
    "archive_blake2s_ref.c",
    "archive_blake2sp_ref.c",
    "archive_check_magic.c",
    "archive_cmdline.c",
    "archive_cryptor.c",
    "archive_digest.c",
    "archive_disk_acl_darwin.c",
    "archive_disk_acl_freebsd.c",
    "archive_disk_acl_linux.c",
    "archive_disk_acl_sunos.c",
    "archive_entry.c",
    "archive_entry_copy_bhfi.c",
    "archive_entry_copy_stat.c",
    "archive_entry_link_resolver.c",
    "archive_entry_sparse.c",
    "archive_entry_stat.c",
    "archive_entry_strmode.c",
    "archive_entry_xattr.c",
    "archive_getdate.c",
    "archive_hmac.c",
    "archive_match.c",
    "archive_options.c",
    "archive_pack_dev.c",
    "archive_pathmatch.c",
    "archive_ppmd7.c",
    "archive_ppmd8.c",
    "archive_random.c",
    "archive_rb.c",
    "archive_read.c",
    "archive_read_add_passphrase.c",
    "archive_read_append_filter.c",
    "archive_read_data_into_fd.c",
    "archive_read_disk_entry_from_file.c",
    "archive_read_disk_posix.c",
    "archive_read_disk_set_standard_lookup.c",
    "archive_read_disk_windows.c",
    "archive_read_extract.c",
    "archive_read_extract2.c",
    "archive_read_open_fd.c",
    "archive_read_open_file.c",
    "archive_read_open_filename.c",
    "archive_read_open_memory.c",
    "archive_read_set_format.c",
    "archive_read_set_options.c",
    "archive_read_support_filter_all.c",
    "archive_read_support_filter_by_code.c",
    "archive_read_support_filter_bzip2.c",
    "archive_read_support_filter_compress.c",
    "archive_read_support_filter_gzip.c",
    "archive_read_support_filter_grzip.c",
    "archive_read_support_filter_lrzip.c",
    "archive_read_support_filter_lz4.c",
    "archive_read_support_filter_lzop.c",
    "archive_read_support_filter_none.c",
    "archive_read_support_filter_program.c",
    "archive_read_support_filter_rpm.c",
    "archive_read_support_filter_uu.c",
    "archive_read_support_filter_xz.c",
    "archive_read_support_filter_zstd.c",
    "archive_read_support_format_7zip.c",
    "archive_read_support_format_all.c",
    "archive_read_support_format_ar.c",
    "archive_read_support_format_by_code.c",
    "archive_read_support_format_cab.c",
    "archive_read_support_format_cpio.c",
    "archive_read_support_format_empty.c",
    "archive_read_support_format_iso9660.c",
    "archive_read_support_format_lha.c",
    "archive_read_support_format_mtree.c",
    "archive_read_support_format_rar.c",
    "archive_read_support_format_rar5.c",
    "archive_read_support_format_raw.c",
    "archive_read_support_format_tar.c",
    "archive_read_support_format_warc.c",
    "archive_read_support_format_xar.c",
    "archive_read_support_format_zip.c",
    "archive_string.c",
    "archive_string_sprintf.c",
    "archive_util.c",
    "archive_version_details.c",
    "archive_virtual.c",
    "archive_windows.c",
    "archive_write.c",
    "archive_write_add_filter.c",
    "archive_write_add_filter_b64encode.c",
    "archive_write_add_filter_by_name.c",
    "archive_write_add_filter_bzip2.c",
    "archive_write_add_filter_compress.c",
    "archive_write_add_filter_grzip.c",
    "archive_write_add_filter_gzip.c",
    "archive_write_add_filter_lrzip.c",
    "archive_write_add_filter_lz4.c",
    "archive_write_add_filter_lzop.c",
    "archive_write_add_filter_none.c",
    "archive_write_add_filter_program.c",
    "archive_write_add_filter_uuencode.c",
    "archive_write_add_filter_xz.c",
    "archive_write_add_filter_zstd.c",
    "archive_write_disk_posix.c",
    "archive_write_disk_set_standard_lookup.c",
    "archive_write_disk_windows.c",
    "archive_write_open_fd.c",
    "archive_write_open_file.c",
    "archive_write_open_filename.c",
    "archive_write_open_memory.c",
    "archive_write_set_format.c",
    "archive_write_set_format_7zip.c",
    "archive_write_set_format_ar.c",
    "archive_write_set_format_by_name.c",
    "archive_write_set_format_cpio.c",
    "archive_write_set_format_cpio_binary.c",
    "archive_write_set_format_cpio_newc.c",
    "archive_write_set_format_cpio_odc.c",
    "archive_write_set_format_filter_by_ext.c",
    "archive_write_set_format_gnutar.c",
    "archive_write_set_format_iso9660.c",
    "archive_write_set_format_mtree.c",
    "archive_write_set_format_pax.c",
    "archive_write_set_format_raw.c",
    "archive_write_set_format_shar.c",
    "archive_write_set_format_ustar.c",
    "archive_write_set_format_v7tar.c",
    "archive_write_set_format_warc.c",
    "archive_write_set_format_xar.c",
    "archive_write_set_format_zip.c",
    "archive_write_set_options.c",
    "archive_write_set_passphrase.c",
    "filter_fork_posix.c",
    "filter_fork_windows.c",
    "xxhash.c",
};

const test_utils_src: []const []const u8 = &.{
    "test_main.c",
    "test_utils.c",
};

const libarchive_test_src: []const []const u8 = &.{
    "read_open_memory.c",
    "test_7zip_filename_encoding.c",
    "test_acl_nfs4.c",
    "test_acl_pax.c",
    "test_acl_platform_nfs4.c",
    "test_acl_platform_posix1e.c",
    "test_acl_posix1e.c",
    "test_acl_text.c",
    "test_archive_api_feature.c",
    "test_archive_clear_error.c",
    "test_archive_cmdline.c",
    "test_archive_digest.c",
    "test_archive_getdate.c",
    "test_archive_match_owner.c",
    "test_archive_match_path.c",
    "test_archive_match_time.c",
    "test_archive_pathmatch.c",
    "test_archive_read_add_passphrase.c",
    "test_archive_read.c",
    "test_archive_read_close_twice.c",
    "test_archive_read_close_twice_open_fd.c",
    "test_archive_read_close_twice_open_filename.c",
    "test_archive_read_multiple_data_objects.c",
    "test_archive_read_next_header_empty.c",
    "test_archive_read_next_header_raw.c",
    "test_archive_read_open2.c",
    "test_archive_read_set_filter_option.c",
    "test_archive_read_set_format_option.c",
    "test_archive_read_set_option.c",
    "test_archive_read_set_options.c",
    "test_archive_read_support.c",
    "test_archive_set_error.c",
    "test_archive_string.c",
    "test_archive_string_conversion.c",
    "test_archive_write_add_filter_by_name.c",
    "test_archive_write_set_filter_option.c",
    "test_archive_write_set_format_by_name.c",
    "test_archive_write_set_format_filter_by_ext.c",
    "test_archive_write_set_format_option.c",
    "test_archive_write_set_option.c",
    "test_archive_write_set_options.c",
    "test_archive_write_set_passphrase.c",
    "test_ar_mode.c",
    "test_bad_fd.c",
    "test_compat_bzip2.c",
    "test_compat_cpio.c",
    "test_compat_gtar.c",
    "test_compat_gtar_large.c",
    "test_compat_gzip.c",
    "test_compat_lz4.c",
    "test_compat_lzip.c",
    "test_compat_lzma.c",
    "test_compat_lzop.c",
    "test_compat_mac.c",
    "test_compat_perl_archive_tar.c",
    "test_compat_plexus_archiver_tar.c",
    "test_compat_solaris_pax_sparse.c",
    "test_compat_solaris_tar_acl.c",
    "test_compat_star_acl.c",
    "test_compat_tar_directory.c",
    "test_compat_tar_hardlink.c",
    "test_compat_uudecode.c",
    "test_compat_uudecode_large.c",
    "test_compat_xz.c",
    "test_compat_zip.c",
    "test_compat_zstd.c",
    "test_empty_write.c",
    "test_entry.c",
    "test_entry_strmode.c",
    "test_extattr_freebsd.c",
    "test_filter_count.c",
    "test_fuzz.c",
    "test_gnutar_filename_encoding.c",
    "test_link_resolver.c",
    "test_open_failure.c",
    "test_open_fd.c",
    "test_open_file.c",
    "test_open_filename.c",
    "test_pax_filename_encoding.c",
    "test_pax_xattr_header.c",
    "test_read_data_large.c",
    "test_read_disk.c",
    "test_read_disk_directory_traversals.c",
    "test_read_disk_entry_from_file.c",
    "test_read_extract.c",
    "test_read_file_nonexistent.c",
    "test_read_filter_compress.c",
    "test_read_filter_grzip.c",
    "test_read_filter_gzip_recursive.c",
    "test_read_filter_lrzip.c",
    "test_read_filter_lzop.c",
    "test_read_filter_lzop_multiple_parts.c",
    "test_read_filter_program.c",
    "test_read_filter_program_signature.c",
    "test_read_filter_uudecode.c",
    "test_read_filter_uudecode_raw.c",
    "test_read_format_7zip.c",
    "test_read_format_7zip_encryption_data.c",
    "test_read_format_7zip_encryption_header.c",
    "test_read_format_7zip_encryption_partially.c",
    "test_read_format_7zip_malformed.c",
    "test_read_format_7zip_packinfo_digests.c",
    "test_read_format_ar.c",
    "test_read_format_cab.c",
    "test_read_format_cab_filename.c",
    "test_read_format_cpio_afio.c",
    "test_read_format_cpio_bin_be.c",
    "test_read_format_cpio_bin_bz2.c",
    "test_read_format_cpio_bin.c",
    "test_read_format_cpio_bin_gz.c",
    "test_read_format_cpio_bin_le.c",
    "test_read_format_cpio_bin_lzip.c",
    "test_read_format_cpio_bin_lzma.c",
    "test_read_format_cpio_bin_xz.c",
    "test_read_format_cpio_bin_Z.c",
    "test_read_format_cpio_filename.c",
    "test_read_format_cpio_odc.c",
    "test_read_format_cpio_svr4_bzip2_rpm.c",
    "test_read_format_cpio_svr4c_Z.c",
    "test_read_format_cpio_svr4_gzip.c",
    "test_read_format_cpio_svr4_gzip_rpm.c",
    "test_read_format_empty.c",
    "test_read_format_gtar_filename.c",
    "test_read_format_gtar_gz.c",
    "test_read_format_gtar_lzma.c",
    "test_read_format_gtar_sparse.c",
    "test_read_format_gtar_sparse_length.c",
    "test_read_format_gtar_sparse_skip_entry.c",
    "test_read_format_huge_rpm.c",
    "test_read_format_isojoliet_bz2.c",
    "test_read_format_isojoliet_long.c",
    "test_read_format_isojoliet_rr.c",
    "test_read_format_isojoliet_versioned.c",
    "test_read_format_iso_multi_extent.c",
    "test_read_format_isorr_bz2.c",
    "test_read_format_isorr_ce.c",
    "test_read_format_isorr_new_bz2.c",
    "test_read_format_isorr_rr_moved.c",
    "test_read_format_iso_xorriso.c",
    "test_read_format_iso_Z.c",
    "test_read_format_isozisofs_bz2.c",
    "test_read_format_lha_bugfix_0.c",
    "test_read_format_lha.c",
    "test_read_format_lha_filename.c",
    "test_read_format_lha_filename_utf16.c",
    "test_read_format_mtree.c",
    "test_read_format_mtree_crash747.c",
    "test_read_format_pax_bz2.c",
    "test_read_format_rar5.c",
    "test_read_format_rar.c",
    "test_read_format_rar_encryption.c",
    "test_read_format_rar_encryption_data.c",
    "test_read_format_rar_encryption_header.c",
    "test_read_format_rar_encryption_partially.c",
    "test_read_format_rar_filter.c",
    "test_read_format_rar_invalid1.c",
    "test_read_format_raw.c",
    "test_read_format_tar.c",
    "test_read_format_tar_concatenated.c",
    "test_read_format_tar_empty_filename.c",
    "test_read_format_tar_empty_pax.c",
    "test_read_format_tar_empty_with_gnulabel.c",
    "test_read_format_tar_filename.c",
    "test_read_format_tar_invalid_pax_size.c",
    "test_read_format_tar_pax_large_attr.c",
    "test_read_format_tbz.c",
    "test_read_format_tgz.c",
    "test_read_format_tlz.c",
    "test_read_format_txz.c",
    "test_read_format_tz.c",
    "test_read_format_ustar_filename.c",
    "test_read_format_warc.c",
    "test_read_format_xar.c",
    "test_read_format_xar_doublelink.c",
    "test_read_format_zip_7075_utf8_paths.c",
    "test_read_format_zip.c",
    "test_read_format_zip_comment_stored.c",
    "test_read_format_zip_encryption_data.c",
    "test_read_format_zip_encryption_header.c",
    "test_read_format_zip_encryption_partially.c",
    "test_read_format_zip_extra_padding.c",
    "test_read_format_zip_filename.c",
    "test_read_format_zip_high_compression.c",
    "test_read_format_zip_jar.c",
    "test_read_format_zip_mac_metadata.c",
    "test_read_format_zip_malformed.c",
    "test_read_format_zip_msdos.c",
    "test_read_format_zip_nested.c",
    "test_read_format_zip_nofiletype.c",
    "test_read_format_zip_padded.c",
    "test_read_format_zip_sfx.c",
    "test_read_format_zip_traditional_encryption_data.c",
    "test_read_format_zip_winzip_aes.c",
    "test_read_format_zip_winzip_aes_large.c",
    "test_read_format_zip_with_invalid_traditional_eocd.c",
    "test_read_format_zip_zip64.c",
    "test_read_large.c",
    "test_read_pax_truncated.c",
    "test_read_pax_xattr_rht_security_selinux.c",
    "test_read_pax_xattr_schily.c",
    "test_read_position.c",
    "test_read_set_format.c",
    "test_read_too_many_filters.c",
    "test_read_truncated.c",
    "test_read_truncated_filter.c",
    "test_short_writes.c",
    //"test_sparse_basic.c", SKIP: triggers UBSAN
    "test_tar_filenames.c",
    "test_tar_large.c",
    "test_ustar_filename_encoding.c",
    "test_ustar_filenames.c",
    "test_warn_missing_hardlink_target.c",
    "test_write_disk_appledouble.c",
    "test_write_disk.c",
    "test_write_disk_failures.c",
    "test_write_disk_fixup.c",
    "test_write_disk_hardlink.c",
    "test_write_disk_hfs_compression.c",
    "test_write_disk_lookup.c",
    "test_write_disk_mac_metadata.c",
    "test_write_disk_no_hfs_compression.c",
    "test_write_disk_perms.c",
    "test_write_disk_secure744.c",
    "test_write_disk_secure745.c",
    "test_write_disk_secure746.c",
    "test_write_disk_secure.c",
    "test_write_disk_secure_noabsolutepaths.c",
    "test_write_disk_sparse.c",
    "test_write_disk_symlink.c",
    "test_write_disk_times.c",
    "test_write_filter_b64encode.c",
    "test_write_filter_bzip2.c",
    "test_write_filter_compress.c",
    "test_write_filter_gzip.c",
    "test_write_filter_gzip_timestamp.c",
    "test_write_filter_lrzip.c",
    "test_write_filter_lz4.c",
    "test_write_filter_lzip.c",
    "test_write_filter_lzma.c",
    "test_write_filter_lzop.c",
    "test_write_filter_program.c",
    "test_write_filter_uuencode.c",
    "test_write_filter_xz.c",
    "test_write_filter_zstd.c",
    "test_write_format_7zip.c",
    "test_write_format_7zip_empty.c",
    "test_write_format_7zip_large.c",
    "test_write_format_ar.c",
    "test_write_format_cpio.c",
    "test_write_format_cpio_empty.c",
    "test_write_format_cpio_newc.c",
    "test_write_format_cpio_odc.c",
    "test_write_format_gnutar.c",
    "test_write_format_gnutar_filenames.c",
    "test_write_format_iso9660_boot.c",
    "test_write_format_iso9660.c",
    "test_write_format_iso9660_empty.c",
    "test_write_format_iso9660_filename.c",
    "test_write_format_iso9660_zisofs.c",
    "test_write_format_mtree_absolute_path.c",
    "test_write_format_mtree.c",
    "test_write_format_mtree_classic.c",
    "test_write_format_mtree_classic_indent.c",
    "test_write_format_mtree_fflags.c",
    "test_write_format_mtree_no_separator.c",
    "test_write_format_mtree_quoted_filename.c",
    "test_write_format_pax.c",
    "test_write_format_raw_b64.c",
    "test_write_format_raw.c",
    "test_write_format_shar_empty.c",
    "test_write_format_tar.c",
    "test_write_format_tar_empty.c",
    "test_write_format_tar_sparse.c",
    "test_write_format_tar_ustar.c",
    "test_write_format_tar_v7tar.c",
    "test_write_format_warc.c",
    "test_write_format_warc_empty.c",
    "test_write_format_xar.c",
    "test_write_format_xar_empty.c",
    "test_write_format_zip64_stream.c",
    "test_write_format_zip.c",
    "test_write_format_zip_compression_store.c",
    "test_write_format_zip_empty.c",
    "test_write_format_zip_empty_zip64.c",
    "test_write_format_zip_entry_size_unset.c",
    "test_write_format_zip_file.c",
    "test_write_format_zip_file_zip64.c",
    //"test_write_format_zip_large.c", SKIP: triggers UBSAN
    "test_write_format_zip_stream.c",
    "test_write_format_zip_windows_path.c",
    "test_write_format_zip_zip64.c",
    "test_write_open_memory.c",
    "test_write_read_format_zip.c",
    "test_xattr_platform.c",
    "test_zip_filename_encoding.c",
};

const libarchive_test_disabled_src: []const []const u8 = &.{
    "test_sparse_basic.c",
    "test_write_format_zip_large.c",
};

const test_src_map = StaticStringMap([]const []const u8).initComptime(.{
    .{ "cat", bsdcat_src ++ bsdcat_test_src },
    .{ "cpio", bsdcpio_src ++ bsdcpio_test_src },
    .{ "tar", bsdtar_test_src },
    .{ "unzip", bsdunzip_test_src },
});

const disabled_test_src_map = StaticStringMap([]const []const u8).initComptime(.{
    .{ "cat", bsdcat_disabled_test_src },
    .{ "cpio", bsdcpio_disabled_test_src },
    .{ "tar", bsdtar_disabled_test_src },
    .{ "unzip", bsdunzip_disabled_test_src },
});

const bsdcat_test_src: []const []const u8 = &.{
    "test/test_0.c",
    "test/test_empty_gz.c",
    "test/test_empty_lz4.c",
    "test/test_empty_xz.c",
    "test/test_empty_zstd.c",
    "test/test_error.c",
    "test/test_error_mixed.c",
    "test/test_expand_Z.c",
    "test/test_expand_bz2.c",
    "test/test_expand_gz.c",
    "test/test_expand_lz4.c",
    "test/test_expand_mixed.c",
    "test/test_expand_plain.c",
    "test/test_expand_xz.c",
    "test/test_expand_zstd.c",
    "test/test_help.c",
    "test/test_stdin.c",
    "test/test_version.c",
};

const bsdcat_disabled_test_src: []const []const u8 = &.{};

const bsdcpio_test_src: []const []const u8 = &.{
    "test/test_0.c",
    "test/test_basic.c",
    "test/test_cmdline.c",
    "test/test_extract_cpio_Z.c",
    "test/test_extract_cpio_absolute_paths.c",
    "test/test_extract_cpio_bz2.c",
    "test/test_extract_cpio_grz.c",
    "test/test_extract_cpio_gz.c",
    "test/test_extract_cpio_lrz.c",
    "test/test_extract_cpio_lz.c",
    "test/test_extract_cpio_lz4.c",
    "test/test_extract_cpio_lzma.c",
    "test/test_extract_cpio_lzo.c",
    "test/test_extract_cpio_xz.c",
    "test/test_extract_cpio_zstd.c",
    "test/test_format_newc.c",
    "test/test_gcpio_compat.c",
    "test/test_missing_file.c",
    "test/test_option_0.c",
    "test/test_option_B_upper.c",
    "test/test_option_C_upper.c",
    "test/test_option_J_upper.c",
    "test/test_option_L_upper.c",
    "test/test_option_Z_upper.c",
    "test/test_option_a.c",
    "test/test_option_b64encode.c",
    "test/test_option_c.c",
    "test/test_option_d.c",
    "test/test_option_f.c",
    "test/test_option_grzip.c",
    "test/test_option_help.c",
    "test/test_option_l.c",
    "test/test_option_lrzip.c",
    "test/test_option_lz4.c",
    "test/test_option_lzma.c",
    "test/test_option_lzop.c",
    "test/test_option_m.c",
    "test/test_option_passphrase.c",
    "test/test_option_t.c",
    "test/test_option_u.c",
    "test/test_option_uuencode.c",
    "test/test_option_version.c",
    "test/test_option_xz.c",
    "test/test_option_y.c",
    "test/test_option_z.c",
    "test/test_option_zstd.c",
    "test/test_owner_parse.c",
    "test/test_passthrough_dotdot.c",
    "test/test_passthrough_reverse.c",
};

const bsdcpio_disabled_test_src: []const []const u8 = &.{};

const bsdtar_test_src: []const []const u8 = &.{
    "test/test_0.c",
    "test/test_basic.c",
    "test/test_copy.c",
    "test/test_empty_mtree.c",
    "test/test_extract_tar_Z.c",
    "test/test_extract_tar_bz2.c",
    "test/test_extract_tar_grz.c",
    "test/test_extract_tar_gz.c",
    "test/test_extract_tar_lrz.c",
    "test/test_extract_tar_lz.c",
    "test/test_extract_tar_lz4.c",
    "test/test_extract_tar_lzma.c",
    "test/test_extract_tar_lzo.c",
    "test/test_extract_tar_xz.c",
    "test/test_extract_tar_zstd.c",
    "test/test_format_newc.c",
    "test/test_help.c",
    "test/test_leading_slash.c",
    "test/test_list_item.c",
    "test/test_missing_file.c",
    "test/test_option_C_mtree.c",
    "test/test_option_C_upper.c",
    "test/test_option_H_upper.c",
    "test/test_option_L_upper.c",
    "test/test_option_O_upper.c",
    "test/test_option_P_upper.c",
    "test/test_option_T_upper.c",
    "test/test_option_U_upper.c",
    "test/test_option_X_upper.c",
    "test/test_option_a.c",
    "test/test_option_acls.c",
    "test/test_option_b.c",
    "test/test_option_b64encode.c",
    "test/test_option_exclude.c",
    "test/test_option_exclude_vcs.c",
    "test/test_option_fflags.c",
    "test/test_option_gid_gname.c",
    "test/test_option_group.c",
    "test/test_option_grzip.c",
    "test/test_option_ignore_zeros.c",
    "test/test_option_j.c",
    "test/test_option_k.c",
    "test/test_option_keep_newer_files.c",
    "test/test_option_lrzip.c",
    "test/test_option_lz4.c",
    "test/test_option_lzma.c",
    "test/test_option_lzop.c",
    "test/test_option_n.c",
    "test/test_option_newer_than.c",
    "test/test_option_nodump.c",
    "test/test_option_older_than.c",
    "test/test_option_owner.c",
    "test/test_option_passphrase.c",
    "test/test_option_q.c",
    "test/test_option_r.c",
    "test/test_option_s.c",
    "test/test_option_safe_writes.c",
    "test/test_option_uid_uname.c",
    "test/test_option_uuencode.c",
    "test/test_option_xattrs.c",
    "test/test_option_xz.c",
    "test/test_option_z.c",
    "test/test_option_zstd.c",
    "test/test_patterns.c",
    "test/test_print_longpath.c",
    "test/test_stdio.c",
    "test/test_strip_components.c",
    "test/test_symlink_dir.c",
    "test/test_version.c",
    "test/test_windows.c",
};

const bsdtar_disabled_test_src: []const []const u8 = &.{};

const bsdunzip_test_src: []const []const u8 = &.{
    "test/test_0.c",
    "test/test_C.c",
    "test/test_I.c",
    "test/test_L.c",
    //"test/test_P_encryption.c", SKIPPED due to test failures
    "test/test_Z1.c",
    "test/test_basic.c",
    "test/test_d.c",
    "test/test_doubledash.c",
    "test/test_glob.c",
    "test/test_j.c",
    "test/test_n.c",
    "test/test_not_exist.c",
    "test/test_o.c",
    "test/test_p.c",
    "test/test_q.c",
    "test/test_singlefile.c",
    "test/test_t.c",
    "test/test_t_bad.c",
    "test/test_version.c",
    "test/test_x.c",
};

const bsdunzip_disabled_test_src: []const []const u8 = &.{
    "test_P_encryption.c",
};

const std = @import("std");

const mem = std.mem;

const StaticStringMap = std.StaticStringMap;

const Build = std.Build;
const Step = Build.Step;
