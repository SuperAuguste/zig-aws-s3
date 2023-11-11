const std = @import("std");
const c = @cImport({
    @cInclude("aws/common/condition_variable.h");
    @cInclude("aws/common/mutex.h");
    @cInclude("aws/s3/s3.h");
    @cInclude("aws/s3/s3_client.h");
    @cInclude("aws/auth/credentials.h");
    @cInclude("aws/common/command_line_parser.h");
    @cInclude("aws/common/condition_variable.h");
    @cInclude("aws/common/mutex.h");
    @cInclude("aws/common/zero.h");
    @cInclude("aws/io/channel_bootstrap.h");
    @cInclude("aws/io/event_loop.h");
    @cInclude("aws/io/logging.h");
    @cInclude("aws/io/uri.h");
    @cInclude("aws/s3/private/s3_list_objects.h");
});

const SigningConfig = extern struct {
    // https://github.com/ziglang/zig/issues/1499
    const Flags = extern struct {
        use_double_uri_encode: u32,
        should_normalize_uri_path: u32,
        omit_session_token: u32,
    };

    config_type: c.enum_aws_signing_config_type = @import("std").mem.zeroes(c.enum_aws_signing_config_type),
    algorithm: c.enum_aws_signing_algorithm = @import("std").mem.zeroes(c.enum_aws_signing_algorithm),
    signature_type: c.enum_aws_signature_type = @import("std").mem.zeroes(c.enum_aws_signature_type),
    region: c.struct_aws_byte_cursor = @import("std").mem.zeroes(c.struct_aws_byte_cursor),
    service: c.struct_aws_byte_cursor = @import("std").mem.zeroes(c.struct_aws_byte_cursor),
    date: c.struct_aws_date_time = @import("std").mem.zeroes(c.struct_aws_date_time),
    should_sign_header: ?*const c.aws_should_sign_header_fn = @import("std").mem.zeroes(?*const c.aws_should_sign_header_fn),
    should_sign_header_ud: ?*anyopaque = @import("std").mem.zeroes(?*anyopaque),
    flags: Flags = @import("std").mem.zeroes(Flags),
    signed_body_value: c.struct_aws_byte_cursor = @import("std").mem.zeroes(c.struct_aws_byte_cursor),
    signed_body_header: c.enum_aws_signed_body_header_type = @import("std").mem.zeroes(c.enum_aws_signed_body_header_type),
    credentials: ?*const c.struct_aws_credentials = @import("std").mem.zeroes(?*const c.struct_aws_credentials),
    credentials_provider: [*c]c.struct_aws_credentials_provider = @import("std").mem.zeroes([*c]c.struct_aws_credentials_provider),
    expiration_in_seconds: u64 = @import("std").mem.zeroes(u64),
};

pub const ClientConfig = extern struct {
    max_active_connections_override: u32 = @import("std").mem.zeroes(u32),
    region: c.struct_aws_byte_cursor = @import("std").mem.zeroes(c.struct_aws_byte_cursor),
    client_bootstrap: [*c]c.struct_aws_client_bootstrap = @import("std").mem.zeroes([*c]c.struct_aws_client_bootstrap),
    tls_mode: c.enum_aws_s3_meta_request_tls_mode = @import("std").mem.zeroes(c.enum_aws_s3_meta_request_tls_mode),
    tls_connection_options: ?*c.struct_aws_tls_connection_options = @import("std").mem.zeroes(?*c.struct_aws_tls_connection_options),
    signing_config: ?*SigningConfig = @import("std").mem.zeroes(?*SigningConfig),
    part_size: u64 = @import("std").mem.zeroes(u64),
    max_part_size: u64 = @import("std").mem.zeroes(u64),
    multipart_upload_threshold: u64 = @import("std").mem.zeroes(u64),
    throughput_target_gbps: f64 = @import("std").mem.zeroes(f64),
    retry_strategy: [*c]c.struct_aws_retry_strategy = @import("std").mem.zeroes([*c]c.struct_aws_retry_strategy),
    compute_content_md5: c.enum_aws_s3_meta_request_compute_content_md5 = @import("std").mem.zeroes(c.enum_aws_s3_meta_request_compute_content_md5),
    shutdown_callback: ?*const c.aws_s3_client_shutdown_complete_callback_fn = @import("std").mem.zeroes(?*const c.aws_s3_client_shutdown_complete_callback_fn),
    shutdown_callback_user_data: ?*anyopaque = @import("std").mem.zeroes(?*anyopaque),
    proxy_options: ?*c.struct_aws_http_proxy_options_11 = @import("std").mem.zeroes(?*c.struct_aws_http_proxy_options_11),
    proxy_ev_settings: ?*c.struct_proxy_env_var_settings_12 = @import("std").mem.zeroes(?*c.struct_proxy_env_var_settings_12),
    connect_timeout_ms: u32 = @import("std").mem.zeroes(u32),
    tcp_keep_alive_options: [*c]c.struct_aws_s3_tcp_keep_alive_options = @import("std").mem.zeroes([*c]c.struct_aws_s3_tcp_keep_alive_options),
    monitoring_options: ?*c.struct_aws_http_connection_monitoring_options_13 = @import("std").mem.zeroes(?*c.struct_aws_http_connection_monitoring_options_13),
    enable_read_backpressure: bool = @import("std").mem.zeroes(bool),
    initial_read_window: usize = @import("std").mem.zeroes(usize),
};

pub extern fn aws_s3_paginator_continue(
    paginator: ?*c.struct_aws_s3_paginator,
    signing_config: ?*const SigningConfig,
) c_int;

pub extern fn aws_s3_init_default_signing_config(
    signing_config: ?*SigningConfig,
    region: c.struct_aws_byte_cursor,
    credentials_provider: [*c]c.struct_aws_credentials_provider,
) void;

pub extern fn aws_s3_client_new(
    allocator: [*c]c.struct_aws_allocator,
    client_config: [*c]const ClientConfig,
) ?*c.struct_aws_s3_client;

const Context = extern struct {
    allocator: *c.aws_allocator,
    client: ?*c.aws_s3_client,
    credentials_provider: *c.aws_credentials_provider,
    client_bootstrap: ?*c.aws_client_bootstrap,
    logger: c.aws_logger,
    mutex: c.aws_mutex,
    c_var: c.aws_condition_variable,
    execution_completed: bool,
    signing_config: SigningConfig,
    region: [*:0]const u8,
};

fn sliceToByteCursor(slice: []const u8) c.struct_aws_byte_cursor {
    return c.aws_byte_cursor_from_array(slice.ptr, slice.len);
}

fn onObject(info: [*c]const c.aws_s3_object_info, user_data: ?*anyopaque) callconv(.C) c_int {
    _ = user_data;
    std.log.info("object: {s}", .{info.*.key.ptr[0..info.*.key.len]});
    return 0;
}

fn onListFinished(paginator: ?*c.aws_s3_paginator, error_code: c_int, user_data: ?*anyopaque) callconv(.C) void {
    const ctx: *Context = @alignCast(@ptrCast(user_data.?));

    if (error_code == 0) {
        const has_more_results = c.aws_s3_paginator_has_more_results(paginator);
        if (has_more_results) {
            const result = aws_s3_paginator_continue(paginator, &ctx.signing_config);
            if (result != 0) {
                std.log.err("returned by aws_s3_paginator_continue from s_on_list_finished: {d}", .{result});
            }
            return;
        }
    } else {
        std.log.err("Failure while listing objects. Please check if you have valid credentials and s3 path is correct. {s}", .{c.aws_error_debug_str(error_code)});
    }

    _ = c.aws_mutex_lock(&ctx.mutex);
    ctx.execution_completed = true;
    _ = c.aws_mutex_unlock(&ctx.mutex);
    _ = c.aws_condition_variable_notify_one(&ctx.c_var);
}

fn appCompletionPredicate(user_data: ?*anyopaque) callconv(.C) bool {
    const ctx: *Context = @alignCast(@ptrCast(user_data.?));
    return ctx.execution_completed;
}

pub fn main() u8 {
    const allocator = c.aws_default_allocator();
    c.aws_s3_library_init(allocator);

    var ctx = std.mem.zeroes(Context);

    ctx.allocator = allocator;
    _ = c.aws_mutex_init(&ctx.mutex);
    _ = c.aws_condition_variable_init(&ctx.c_var);
    ctx.execution_completed = false;
    ctx.region = "us-east-3";

    // event loop
    const event_loop_group = c.aws_event_loop_group_new_default(allocator, 0, null);

    // resolver
    const resolver_options = c.aws_host_resolver_default_options{
        .el_group = event_loop_group,
        .max_entries = 8,
    };
    const resolver = c.aws_host_resolver_new_default(allocator, &resolver_options);

    // client bootstrap
    const bootstrap_options = c.aws_client_bootstrap_options{
        .event_loop_group = event_loop_group,
        .host_resolver = resolver,
    };
    ctx.client_bootstrap = c.aws_client_bootstrap_new(allocator, &bootstrap_options);
    if (ctx.client_bootstrap == null) {
        std.log.err("failed to initialize client bootstrap", .{});
        return 1;
    }

    var credentials_provider_options = std.mem.zeroes(c.aws_credentials_provider_chain_default_options);
    credentials_provider_options.bootstrap = ctx.client_bootstrap;
    ctx.credentials_provider = c.aws_credentials_provider_new_chain_default(allocator, &credentials_provider_options);

    var logger_options = c.aws_logger_standard_options{
        .level = c.AWS_LOG_LEVEL_TRACE,
        // .file = std.os.STDERR_FILENO,
        .filename = "log",
    };
    if (c.aws_logger_init_standard(&ctx.logger, allocator, &logger_options) != 0) {
        std.log.err("failed to initialize logger", .{});
        return 1;
    }
    c.aws_logger_set(&ctx.logger);

    aws_s3_init_default_signing_config(&ctx.signing_config, sliceToByteCursor("nyc3"), ctx.credentials_provider);
    ctx.signing_config.flags.use_double_uri_encode = 0;

    var client_config = std.mem.zeroes(ClientConfig);
    client_config.client_bootstrap = ctx.client_bootstrap;
    client_config.region = sliceToByteCursor("nyc3");
    client_config.signing_config = &ctx.signing_config;
    ctx.client = aws_s3_client_new(allocator, &client_config);

    var params = c.aws_s3_list_objects_params{
        .client = ctx.client,
        .bucket_name = sliceToByteCursor("fuzzing-output"),
        .endpoint = sliceToByteCursor("nyc3.digitaloceanspaces.com"),
        .on_object = &onObject,
        .on_list_finished = &onListFinished,
        .user_data = &ctx,
    };

    std.log.info("listing:", .{});

    var paginator = c.aws_s3_initiate_list_objects(allocator, &params);
    if (aws_s3_paginator_continue(paginator, &ctx.signing_config) != 0) {
        std.log.err("failed initial call to aws_s3_paginator_continue", .{});
        return 1;
    }

    c.aws_s3_paginator_release(paginator);

    // wait completion of last page
    _ = c.aws_mutex_lock(&ctx.mutex);
    _ = c.aws_condition_variable_wait_pred(&ctx.c_var, &ctx.mutex, &appCompletionPredicate, &ctx);
    _ = c.aws_mutex_unlock(&ctx.mutex);

    return 0;
}
