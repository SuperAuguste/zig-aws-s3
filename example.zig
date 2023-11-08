const c = @cImport({
    @cInclude("aws/s3/s3.h");
    @cInclude("aws/auth/credentials.h");
    @cInclude("aws/common/command_line_parser.h");
    @cInclude("aws/common/condition_variable.h");
    @cInclude("aws/common/mutex.h");
    @cInclude("aws/common/zero.h");
    @cInclude("aws/io/channel_bootstrap.h");
    @cInclude("aws/io/event_loop.h");
    @cInclude("aws/io/logging.h");
    @cInclude("aws/io/uri.h");
});

pub fn main() void {
    _ = c.aws_s3_library_init;
}
