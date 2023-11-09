const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // linux-only
    const boringssl_dep = b.dependency("google/boringssl", .{});
    const s2n_tls_dep = b.dependency("aws/s2n-tls", .{});

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
        // (this applies only to windows)
        .optimize = if (target.getOsTag() == .windows and optimize == .Debug)
            .ReleaseSmall
        else
            optimize,
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
        .linux => {
            // TODO: https://sourcegraph.com/github.com/awslabs/aws-c-common/-/blob/cmake/AwsThreadAffinity.cmake?L38:15
            lib.defineCMacro("AWS_AFFINITY_METHOD", "2");
            lib.defineCMacro("PLATFORM_LINUX", null);
            lib.defineCMacro("ENABLE_OPENSSL_ENCRYPTION", null);

            lib.linkLibCpp();
            lib.defineCMacro("_BORINGSSL_LIBPKI_", null);
            lib.addIncludePath(boringssl_dep.path("include"));
            lib.addCSourceFiles(.{
                .files = boring_sources,
                .dependency = boringssl_dep,
            });

            lib.addIncludePath(s2n_tls_dep.path("."));
            lib.addIncludePath(s2n_tls_dep.path("api"));
            lib.addCSourceFiles(.{
                .files = s2n_sources,
                .dependency = s2n_tls_dep,
                .flags = &.{ "-std=c99", "-Wno-implicit-function-declaration" },
            });
            switch (target.getCpuArch()) {
                .x86_64, .x86 => {
                    dirs_to_skip = &.{
                        "windows",
                        "bsd",
                        "darwin",
                        "s2n",
                        "android",
                        "iocp",
                        "intel",
                        "huffman_generator",
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
            .flags = &.{ "-Wall", "-Wstrict-prototypes" },
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

const boring_sources = &.{
    "pki/cert_error_id.cc",
    "pki/cert_error_params.cc",
    "pki/cert_errors.cc",
    "pki/cert_issuer_source_static.cc",
    "pki/certificate_policies.cc",
    "pki/common_cert_errors.cc",
    "pki/crl.cc",
    "pki/encode_values.cc",
    "pki/extended_key_usage.cc",
    "pki/fillins/base64.cc",
    "pki/fillins/ip_address.cc",
    "pki/fillins/openssl_util.cc",
    "pki/fillins/string_util.cc",
    "pki/fillins/utf_string_conversions.cc",
    "pki/general_names.cc",
    "pki/input.cc",
    "pki/name_constraints.cc",
    "pki/parse_certificate.cc",
    "pki/parse_name.cc",
    "pki/parse_values.cc",
    "pki/parsed_certificate.cc",
    "pki/parser.cc",
    "pki/path_builder.cc",
    "pki/pem.cc",
    "pki/revocation_util.cc",
    "pki/signature_algorithm.cc",
    "pki/simple_path_builder_delegate.cc",
    "pki/string_util.cc",
    "pki/tag.cc",
    "pki/trust_store_collection.cc",
    "pki/trust_store_in_memory.cc",
    "pki/trust_store.cc",
    "pki/verify_certificate_chain.cc",
    "pki/verify_name_match.cc",
    "pki/verify_signed_data.cc",

    "ssl/bio_ssl.cc",
    "ssl/d1_both.cc",
    "ssl/d1_lib.cc",
    "ssl/d1_pkt.cc",
    "ssl/d1_srtp.cc",
    "ssl/dtls_method.cc",
    "ssl/dtls_record.cc",
    "ssl/encrypted_client_hello.cc",
    "ssl/extensions.cc",
    "ssl/handoff.cc",
    "ssl/handshake.cc",
    "ssl/handshake_client.cc",
    "ssl/handshake_server.cc",
    "ssl/s3_both.cc",
    "ssl/s3_lib.cc",
    "ssl/s3_pkt.cc",
    "ssl/ssl_aead_ctx.cc",
    "ssl/ssl_asn1.cc",
    "ssl/ssl_buffer.cc",
    "ssl/ssl_cert.cc",
    "ssl/ssl_cipher.cc",
    "ssl/ssl_file.cc",
    "ssl/ssl_key_share.cc",
    "ssl/ssl_lib.cc",
    "ssl/ssl_privkey.cc",
    "ssl/ssl_session.cc",
    "ssl/ssl_stat.cc",
    "ssl/ssl_transcript.cc",
    "ssl/ssl_versions.cc",
    "ssl/ssl_x509.cc",
    "ssl/t1_enc.cc",
    "ssl/tls_method.cc",
    "ssl/tls_record.cc",
    "ssl/tls13_both.cc",
    "ssl/tls13_client.cc",
    "ssl/tls13_enc.cc",
    "ssl/tls13_server.cc",

    "crypto/curve25519/asm/x25519-asm-arm.S",
    "crypto/hrss/asm/poly_rq_mul.S",
    "crypto/poly1305/poly1305_arm_asm.S",
    "third_party/fiat/asm/fiat_curve25519_adx_mul.S",
    "third_party/fiat/asm/fiat_curve25519_adx_square.S",

    "crypto/asn1/a_bitstr.c",
    "crypto/asn1/a_bool.c",
    "crypto/asn1/a_d2i_fp.c",
    "crypto/asn1/a_dup.c",
    "crypto/asn1/a_gentm.c",
    "crypto/asn1/a_i2d_fp.c",
    "crypto/asn1/a_int.c",
    "crypto/asn1/a_mbstr.c",
    "crypto/asn1/a_object.c",
    "crypto/asn1/a_octet.c",
    "crypto/asn1/a_strex.c",
    "crypto/asn1/a_strnid.c",
    "crypto/asn1/a_time.c",
    "crypto/asn1/a_type.c",
    "crypto/asn1/a_utctm.c",
    "crypto/asn1/asn1_lib.c",
    "crypto/asn1/asn1_par.c",
    "crypto/asn1/asn_pack.c",
    "crypto/asn1/f_int.c",
    "crypto/asn1/f_string.c",
    "crypto/asn1/tasn_dec.c",
    "crypto/asn1/tasn_enc.c",
    "crypto/asn1/tasn_fre.c",
    "crypto/asn1/tasn_new.c",
    "crypto/asn1/tasn_typ.c",
    "crypto/asn1/tasn_utl.c",
    "crypto/asn1/posix_time.c",
    "crypto/base64/base64.c",
    "crypto/bio/bio.c",
    "crypto/bio/bio_mem.c",
    "crypto/bio/connect.c",
    "crypto/bio/errno.c",
    "crypto/bio/fd.c",
    "crypto/bio/file.c",
    "crypto/bio/hexdump.c",
    "crypto/bio/pair.c",
    "crypto/bio/printf.c",
    "crypto/bio/socket.c",
    "crypto/bio/socket_helper.c",
    "crypto/blake2/blake2.c",
    "crypto/bn_extra/bn_asn1.c",
    "crypto/bn_extra/convert.c",
    "crypto/buf/buf.c",
    "crypto/bytestring/asn1_compat.c",
    "crypto/bytestring/ber.c",
    "crypto/bytestring/cbb.c",
    "crypto/bytestring/cbs.c",
    "crypto/bytestring/unicode.c",
    "crypto/chacha/chacha.c",
    "crypto/cipher_extra/cipher_extra.c",
    "crypto/cipher_extra/derive_key.c",
    "crypto/cipher_extra/e_aesctrhmac.c",
    "crypto/cipher_extra/e_aesgcmsiv.c",
    "crypto/cipher_extra/e_chacha20poly1305.c",
    "crypto/cipher_extra/e_des.c",
    "crypto/cipher_extra/e_null.c",
    "crypto/cipher_extra/e_rc2.c",
    "crypto/cipher_extra/e_rc4.c",
    "crypto/cipher_extra/e_tls.c",
    "crypto/cipher_extra/tls_cbc.c",
    "crypto/conf/conf.c",
    "crypto/cpu_aarch64_apple.c",
    "crypto/cpu_aarch64_openbsd.c",
    "crypto/cpu_aarch64_fuchsia.c",
    "crypto/cpu_aarch64_linux.c",
    "crypto/cpu_aarch64_sysreg.c",
    "crypto/cpu_aarch64_win.c",
    "crypto/cpu_arm_freebsd.c",
    "crypto/cpu_arm_linux.c",
    "crypto/cpu_arm.c",
    "crypto/cpu_intel.c",
    "crypto/crypto.c",
    "crypto/curve25519/curve25519.c",
    "crypto/curve25519/curve25519_64_adx.c",
    "crypto/curve25519/spake25519.c",
    "crypto/des/des.c",
    "crypto/dh_extra/params.c",
    "crypto/dh_extra/dh_asn1.c",
    "crypto/digest_extra/digest_extra.c",
    "crypto/dsa/dsa.c",
    "crypto/dsa/dsa_asn1.c",
    "crypto/ecdh_extra/ecdh_extra.c",
    "crypto/ecdsa_extra/ecdsa_asn1.c",
    "crypto/ec_extra/ec_asn1.c",
    "crypto/ec_extra/ec_derive.c",
    "crypto/ec_extra/hash_to_curve.c",
    "crypto/err/err.c",
    // "crypto/err_data.c",
    "crypto/engine/engine.c",
    "crypto/evp/evp.c",
    "crypto/evp/evp_asn1.c",
    "crypto/evp/evp_ctx.c",
    "crypto/evp/p_dsa_asn1.c",
    "crypto/evp/p_ec.c",
    "crypto/evp/p_ec_asn1.c",
    "crypto/evp/p_ed25519.c",
    "crypto/evp/p_ed25519_asn1.c",
    "crypto/evp/p_hkdf.c",
    "crypto/evp/p_rsa.c",
    "crypto/evp/p_rsa_asn1.c",
    "crypto/evp/p_x25519.c",
    "crypto/evp/p_x25519_asn1.c",
    "crypto/evp/pbkdf.c",
    "crypto/evp/print.c",
    "crypto/evp/scrypt.c",
    "crypto/evp/sign.c",
    "crypto/ex_data.c",
    "crypto/hpke/hpke.c",
    "crypto/hrss/hrss.c",
    "crypto/kyber/keccak.c",
    "crypto/kyber/kyber.c",
    "crypto/lhash/lhash.c",
    "crypto/mem.c",
    "crypto/obj/obj.c",
    "crypto/obj/obj_xref.c",
    "crypto/pem/pem_all.c",
    "crypto/pem/pem_info.c",
    "crypto/pem/pem_lib.c",
    "crypto/pem/pem_oth.c",
    "crypto/pem/pem_pk8.c",
    "crypto/pem/pem_pkey.c",
    "crypto/pem/pem_x509.c",
    "crypto/pem/pem_xaux.c",
    "crypto/pkcs7/pkcs7.c",
    "crypto/pkcs7/pkcs7_x509.c",
    "crypto/pkcs8/pkcs8.c",
    "crypto/pkcs8/pkcs8_x509.c",
    "crypto/pkcs8/p5_pbev2.c",
    "crypto/poly1305/poly1305.c",
    "crypto/poly1305/poly1305_arm.c",
    "crypto/poly1305/poly1305_vec.c",
    "crypto/pool/pool.c",
    "crypto/rand_extra/deterministic.c",
    "crypto/rand_extra/forkunsafe.c",
    "crypto/rand_extra/getentropy.c",
    "crypto/rand_extra/ios.c",
    "crypto/rand_extra/passive.c",
    "crypto/rand_extra/rand_extra.c",
    "crypto/rand_extra/trusty.c",
    "crypto/rand_extra/windows.c",
    "crypto/rc4/rc4.c",
    "crypto/refcount.c",
    "crypto/rsa_extra/rsa_asn1.c",
    "crypto/rsa_extra/rsa_crypt.c",
    "crypto/rsa_extra/rsa_print.c",
    "crypto/stack/stack.c",
    "crypto/siphash/siphash.c",
    "crypto/thread.c",
    "crypto/thread_none.c",
    "crypto/thread_pthread.c",
    "crypto/thread_win.c",
    "crypto/trust_token/pmbtoken.c",
    "crypto/trust_token/trust_token.c",
    "crypto/trust_token/voprf.c",
    "crypto/x509/a_digest.c",
    "crypto/x509/a_sign.c",
    "crypto/x509/a_verify.c",
    "crypto/x509/algorithm.c",
    "crypto/x509/asn1_gen.c",
    "crypto/x509/by_dir.c",
    "crypto/x509/by_file.c",
    "crypto/x509/i2d_pr.c",
    "crypto/x509/name_print.c",
    "crypto/x509/policy.c",
    "crypto/x509/rsa_pss.c",
    "crypto/x509/t_crl.c",
    "crypto/x509/t_req.c",
    "crypto/x509/t_x509.c",
    "crypto/x509/t_x509a.c",
    "crypto/x509/x509.c",
    "crypto/x509/x509_att.c",
    "crypto/x509/x509_cmp.c",
    "crypto/x509/x509_d2.c",
    "crypto/x509/x509_def.c",
    "crypto/x509/x509_ext.c",
    "crypto/x509/x509_lu.c",
    "crypto/x509/x509_obj.c",
    "crypto/x509/x509_req.c",
    "crypto/x509/x509_set.c",
    "crypto/x509/x509_trs.c",
    "crypto/x509/x509_txt.c",
    "crypto/x509/x509_v3.c",
    "crypto/x509/x509_vfy.c",
    "crypto/x509/x509_vpm.c",
    "crypto/x509/x509cset.c",
    "crypto/x509/x509name.c",
    "crypto/x509/x509rset.c",
    "crypto/x509/x509spki.c",
    "crypto/x509/x_algor.c",
    "crypto/x509/x_all.c",
    "crypto/x509/x_attrib.c",
    "crypto/x509/x_crl.c",
    "crypto/x509/x_exten.c",
    "crypto/x509/x_info.c",
    "crypto/x509/x_name.c",
    "crypto/x509/x_pkey.c",
    "crypto/x509/x_pubkey.c",
    "crypto/x509/x_req.c",
    "crypto/x509/x_sig.c",
    "crypto/x509/x_spki.c",
    "crypto/x509/x_val.c",
    "crypto/x509/x_x509.c",
    "crypto/x509/x_x509a.c",
    "crypto/x509v3/v3_akey.c",
    "crypto/x509v3/v3_akeya.c",
    "crypto/x509v3/v3_alt.c",
    "crypto/x509v3/v3_bcons.c",
    "crypto/x509v3/v3_bitst.c",
    "crypto/x509v3/v3_conf.c",
    "crypto/x509v3/v3_cpols.c",
    "crypto/x509v3/v3_crld.c",
    "crypto/x509v3/v3_enum.c",
    "crypto/x509v3/v3_extku.c",
    "crypto/x509v3/v3_genn.c",
    "crypto/x509v3/v3_ia5.c",
    "crypto/x509v3/v3_info.c",
    "crypto/x509v3/v3_int.c",
    "crypto/x509v3/v3_lib.c",
    "crypto/x509v3/v3_ncons.c",
    "crypto/x509v3/v3_ocsp.c",
    "crypto/x509v3/v3_pcons.c",
    "crypto/x509v3/v3_pmaps.c",
    "crypto/x509v3/v3_prn.c",
    "crypto/x509v3/v3_purp.c",
    "crypto/x509v3/v3_skey.c",
    "crypto/x509v3/v3_utl.c",

    "decrepit/bio/base64_bio.c",
    "decrepit/blowfish/blowfish.c",
    "decrepit/cast/cast.c",
    "decrepit/cast/cast_tables.c",
    "decrepit/cfb/cfb.c",
    "decrepit/des/cfb64ede.c",
    "decrepit/dh/dh_decrepit.c",
    "decrepit/dsa/dsa_decrepit.c",
    "decrepit/evp/dss1.c",
    "decrepit/evp/evp_do_all.c",
    "decrepit/obj/obj_decrepit.c",
    "decrepit/rc4/rc4_decrepit.c",
    "decrepit/ripemd/ripemd.c",
    "decrepit/rsa/rsa_decrepit.c",
    "decrepit/ssl/ssl_decrepit.c",
    "decrepit/x509/x509_decrepit.c",
    "decrepit/xts/xts.c",

    "crypto/fipsmodule/bcm.c",
    "crypto/fipsmodule/fips_shared_support.c",
};

const s2n_sources = &.{
    "crypto/s2n_aead_cipher_aes_gcm.c",
    "crypto/s2n_aead_cipher_chacha20_poly1305.c",
    "crypto/s2n_cbc_cipher_3des.c",
    "crypto/s2n_cbc_cipher_aes.c",
    "crypto/s2n_certificate.c",
    "crypto/s2n_cipher.c",
    "crypto/s2n_composite_cipher_aes_sha.c",
    "crypto/s2n_crypto.c",
    "crypto/s2n_dhe.c",
    "crypto/s2n_drbg.c",
    "crypto/s2n_ecc_evp.c",
    "crypto/s2n_ecdsa.c",
    "crypto/s2n_evp_signing.c",
    "crypto/s2n_evp.c",
    "crypto/s2n_fips.c",
    "crypto/s2n_hash.c",
    "crypto/s2n_hkdf.c",
    "crypto/s2n_hmac.c",
    "crypto/s2n_libcrypto.c",
    "crypto/s2n_locking.c",
    "crypto/s2n_openssl_x509.c",
    "crypto/s2n_pkey.c",
    "crypto/s2n_rsa_pss.c",
    "crypto/s2n_rsa_signing.c",
    "crypto/s2n_rsa.c",
    "crypto/s2n_sequence.c",
    "crypto/s2n_stream_cipher_null.c",
    "crypto/s2n_stream_cipher_rc4.c",
    "crypto/s2n_tls13_keys.c",

    "pq-crypto/kyber_r3/KeccakP-1600-times4-SIMD256_avx2.c",
    "pq-crypto/kyber_r3/kyber512r3_cbd_avx2.c",
    "pq-crypto/kyber_r3/kyber512r3_cbd.c",
    "pq-crypto/kyber_r3/kyber512r3_consts_avx2.c",
    "pq-crypto/kyber_r3/kyber512r3_fips202.c",
    "pq-crypto/kyber_r3/kyber512r3_fips202x4_avx2.c",
    "pq-crypto/kyber_r3/kyber512r3_indcpa_avx2.c",
    "pq-crypto/kyber_r3/kyber512r3_indcpa.c",
    "pq-crypto/kyber_r3/kyber512r3_kem.c",
    "pq-crypto/kyber_r3/kyber512r3_ntt.c",
    "pq-crypto/kyber_r3/kyber512r3_poly_avx2.c",
    "pq-crypto/kyber_r3/kyber512r3_poly.c",
    "pq-crypto/kyber_r3/kyber512r3_polyvec_avx2.c",
    "pq-crypto/kyber_r3/kyber512r3_polyvec.c",
    "pq-crypto/kyber_r3/kyber512r3_reduce.c",
    "pq-crypto/kyber_r3/kyber512r3_rejsample_avx2.c",
    "pq-crypto/kyber_r3/kyber512r3_symmetric-shake.c",
    "pq-crypto/s2n_kyber_evp.c",
    "pq-crypto/s2n_pq_random.c",
    "pq-crypto/s2n_pq.c",

    "utils/s2n_array.c",
    "utils/s2n_atomic.c",
    "utils/s2n_blob.c",
    "utils/s2n_ensure.c",
    "utils/s2n_fork_detection.c",
    "utils/s2n_init.c",
    "utils/s2n_io.c",
    "utils/s2n_map.c",
    "utils/s2n_mem.c",
    "utils/s2n_random.c",
    "utils/s2n_result.c",
    "utils/s2n_rfc5952.c",
    "utils/s2n_safety.c",
    "utils/s2n_set.c",
    "utils/s2n_socket.c",
    "utils/s2n_timer.c",
};
