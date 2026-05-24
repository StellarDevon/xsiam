cmake_minimum_required(VERSION 3.12)

# out_xsiam_log — XLOG binary framing + zstd TSV uploader
set(src out_xsiam_log.c)

FLB_PLUGIN(out_xsiam_log "${src}" "")

# Link against the zstd bundled with Fluent Bit
target_link_libraries(flb-plugin-out_xsiam_log libzstd_static)
