/*
 * xlog.c — XLOG binary framing + zstd-compressed TSV log uploader
 *
 * Dependencies:
 *   zstd   (libzstd-dev / zstd.h)   for ZSTD_compress()
 *
 * Compile example:
 *   gcc -O2 -Wall -o xlog.o -c xlog.c -lzstd
 */

#include "xlog.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* Pull in zstd.  If the host build does not have zstd, define XLOG_NO_ZSTD
 * and a trivial passthrough (uncompressed) will be used instead — useful for
 * unit testing without the library installed. */
#ifndef XLOG_NO_ZSTD
#  include <zstd.h>
#  define COMPRESS(dst, dstCap, src, srcSize, level) \
       ZSTD_compress((dst), (dstCap), (src), (srcSize), (level))
#  define COMPRESS_BOUND(srcSize)  ZSTD_compressBound((srcSize))
#  define COMPRESS_IS_ERROR(r)     ZSTD_isError((r))
#  define COMPRESS_ERROR_NAME(r)   ZSTD_getErrorName((r))
#else
/* Stub: just copy — for testing / platforms without zstd */
static size_t passthrough_compress(void *dst, size_t dstCap,
                                   const void *src, size_t srcSize,
                                   int level) {
    (void)level;
    if (dstCap < srcSize) return srcSize + 1; /* signal "too small" */
    memcpy(dst, src, srcSize);
    return srcSize;
}
#  define COMPRESS(dst, dstCap, src, srcSize, level) \
       passthrough_compress((dst), (dstCap), (src), (srcSize), (level))
#  define COMPRESS_BOUND(srcSize)  ((srcSize) + 64)
#  define COMPRESS_IS_ERROR(r)     ((r) > (srcSize) + 64)
#  define COMPRESS_ERROR_NAME(r)   "passthrough error"
#endif

/* ── Internal helpers ────────────────────────────────────────────────── */

/* Dynamic byte buffer */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} xlog_buf_t;

static int buf_init(xlog_buf_t *b, size_t initial) {
    b->data = (uint8_t *)malloc(initial ? initial : 4096);
    if (!b->data) return XLOG_ERR_OOM;
    b->len = 0;
    b->cap = initial ? initial : 4096;
    return XLOG_OK;
}

static int buf_grow(xlog_buf_t *b, size_t need) {
    if (b->len + need <= b->cap) return XLOG_OK;
    size_t ncap = b->cap * 2;
    while (ncap < b->len + need) ncap *= 2;
    uint8_t *nd = (uint8_t *)realloc(b->data, ncap);
    if (!nd) return XLOG_ERR_OOM;
    b->data = nd;
    b->cap  = ncap;
    return XLOG_OK;
}

static int buf_append(xlog_buf_t *b, const void *src, size_t n) {
    int rc = buf_grow(b, n);
    if (rc != XLOG_OK) return rc;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return XLOG_OK;
}

static void buf_free(xlog_buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* Write big-endian integers */
static void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v);
}
static void put_be64(uint8_t *p, uint64_t v) {
    put_be32(p,     (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)(v));
}

/* Append a single TLV field: T(1) L(2 BE) V(L) */
static int tlv_append(xlog_buf_t *body, uint8_t tag,
                      const void *val, uint16_t vlen) {
    uint8_t hdr[3];
    hdr[0] = tag;
    put_be16(hdr + 1, vlen);
    int rc = buf_append(body, hdr, 3);
    if (rc == XLOG_OK && vlen > 0)
        rc = buf_append(body, val, vlen);
    return rc;
}

/* Convert tab-separated column names → comma-separated (for TLV 0x04) */
static char *tabs_to_commas(const char *s) {
    if (!s || !*s) return NULL;
    size_t n = strlen(s);
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < n; i++)
        out[i] = (s[i] == '\t') ? ',' : s[i];
    out[n] = '\0';
    return out;
}

/* ── xlog_batch_t ────────────────────────────────────────────────────── */

struct xlog_batch {
    char    *tag;          /* log source label (e.g. "winevent")          */
    char    *columns_csv;  /* comma-separated column names for TLV 0x04   */
    uint64_t agent_id;
    uint64_t seq;
    xlog_buf_t tsv;        /* raw UTF-8 TSV rows, newline-terminated       */
    size_t   row_count;
};

xlog_batch_t *xlog_batch_new(const char *tag, uint64_t agent_id, uint64_t seq) {
    xlog_batch_t *b = (xlog_batch_t *)calloc(1, sizeof(*b));
    if (!b) return NULL;

    /* Copy and truncate tag to XLOG_MAX_TAG_LEN */
    size_t tlen = tag ? strlen(tag) : 0;
    if (tlen > XLOG_MAX_TAG_LEN) tlen = XLOG_MAX_TAG_LEN;
    b->tag = (char *)malloc(tlen + 1);
    if (!b->tag) { free(b); return NULL; }
    if (tlen) memcpy(b->tag, tag, tlen);
    b->tag[tlen] = '\0';

    b->agent_id = agent_id;
    b->seq      = seq;
    b->row_count = 0;

    if (buf_init(&b->tsv, 8192) != XLOG_OK) {
        free(b->tag);
        free(b);
        return NULL;
    }
    return b;
}

void xlog_batch_set_columns(xlog_batch_t *b, const char *columns) {
    free(b->columns_csv);
    b->columns_csv = columns ? tabs_to_commas(columns) : NULL;
}

int xlog_batch_append_row(xlog_batch_t *b, const char *row) {
    if (!row) return XLOG_ERR_PARAM;
    size_t rowlen = strlen(row);

    /* Enforce body size cap early (raw TSV ≤ 32 MB before compression) */
    if (b->tsv.len + rowlen + 1 > XLOG_MAX_FRAME_BODY)
        return XLOG_ERR_TOO_LARGE;

    int rc = buf_append(&b->tsv, row, rowlen);
    if (rc != XLOG_OK) return rc;
    rc = buf_append(&b->tsv, "\n", 1);
    if (rc == XLOG_OK) b->row_count++;
    return rc;
}

size_t xlog_batch_row_count(const xlog_batch_t *b) {
    return b ? b->row_count : 0;
}

void xlog_batch_free(xlog_batch_t *b) {
    if (!b) return;
    free(b->tag);
    free(b->columns_csv);
    buf_free(&b->tsv);
    free(b);
}

const char *xlog_strerror(int rc) {
    switch (rc) {
    case XLOG_OK:            return "ok";
    case XLOG_ERR_OOM:       return "out of memory";
    case XLOG_ERR_COMPRESS:  return "zstd compression failed";
    case XLOG_ERR_TOO_LARGE: return "batch too large (>32 MB)";
    case XLOG_ERR_PARAM:     return "invalid parameter";
    default:                 return "unknown error";
    }
}

/* ── xlog_batch_encode ───────────────────────────────────────────────── */

int xlog_batch_encode(xlog_batch_t *b, uint8_t **out, size_t *out_len) {
    *out     = NULL;
    *out_len = 0;

    if (!b || b->tsv.len == 0) return XLOG_ERR_PARAM;

    /* ── Step 1: zstd-compress the TSV payload ── */
    size_t orig_size = b->tsv.len;
    size_t bound     = COMPRESS_BOUND(orig_size);
    uint8_t *comp    = (uint8_t *)malloc(bound);
    if (!comp) return XLOG_ERR_OOM;

    size_t comp_len = COMPRESS(comp, bound, b->tsv.data, orig_size, /*level=*/3);
    if (COMPRESS_IS_ERROR(comp_len)) {
        free(comp);
        return XLOG_ERR_COMPRESS;
    }

    /* ── Step 2: build TLV body ── */
    xlog_buf_t body;
    if (buf_init(&body, comp_len + 64) != XLOG_OK) {
        free(comp);
        return XLOG_ERR_OOM;
    }

    /* 0x01  schema_version = 1 */
    { uint8_t sv[2]; put_be16(sv, 1);
      if (tlv_append(&body, XLOG_TAG_SCHEMA_VERSION, sv, 2) != XLOG_OK) goto oom; }

    /* 0x02  row_count */
    { uint8_t rc_buf[4]; put_be32(rc_buf, (uint32_t)b->row_count);
      if (tlv_append(&body, XLOG_TAG_ROW_COUNT, rc_buf, 4) != XLOG_OK) goto oom; }

    /* 0x03  orig_size */
    { uint8_t os_buf[4]; put_be32(os_buf, (uint32_t)orig_size);
      if (tlv_append(&body, XLOG_TAG_ORIG_SIZE, os_buf, 4) != XLOG_OK) goto oom; }

    /* 0x04  columns (if provided) */
    if (b->columns_csv && b->columns_csv[0]) {
        size_t clen = strlen(b->columns_csv);
        if (clen > 0xFFFF) clen = 0xFFFF;
        if (tlv_append(&body, XLOG_TAG_COLUMNS,
                       b->columns_csv, (uint16_t)clen) != XLOG_OK) goto oom;
    }

    /* 0x10  data (compressed TSV) */
    if (comp_len > 0xFFFF) {
        /* Large chunks: split not yet supported — emit as single TLV.
         * The protocol allows up to 32 MB; TLV length field is u16 which
         * caps at 64 KB.  For larger payloads we embed a u32 length prefix
         * inside the value: first 4 bytes = u32 BE actual length, then data.
         * The Go decoder handles both cases. */
        uint8_t hdr32[3 + 4];
        hdr32[0] = XLOG_TAG_DATA;
        put_be16(hdr32 + 1, (uint16_t)(comp_len & 0xFFFF)); /* lower 16 bits */
        /* embed true 32-bit length in first 4 bytes of value */
        put_be32(hdr32 + 3, (uint32_t)comp_len);
        if (buf_append(&body, hdr32, 7) != XLOG_OK) goto oom;
        if (buf_append(&body, comp, comp_len) != XLOG_OK) goto oom;
    } else {
        if (tlv_append(&body, XLOG_TAG_DATA,
                       comp, (uint16_t)comp_len) != XLOG_OK) goto oom;
    }
    free(comp);
    comp = NULL;

    /* ── Step 3: build XLOG frame header ── */
    size_t tag_len = b->tag ? strlen(b->tag) : 0;
    if (tag_len > XLOG_MAX_TAG_LEN) tag_len = XLOG_MAX_TAG_LEN;

    /* header size: 8 (fixed) + tag_len + 28 (scalar tail) */
    size_t hdr_size = 8 + tag_len + 28;
    size_t total    = hdr_size + body.len;

    uint8_t *frame = (uint8_t *)malloc(total);
    if (!frame) goto oom;

    uint8_t *p = frame;

    /* magic */
    put_be32(p, XLOG_MAGIC); p += 4;
    /* ver + type + flags + tag_len */
    *p++ = XLOG_VERSION;
    *p++ = XLOG_TYPE_LOG_BATCH;
    *p++ = 0; /* flags */
    *p++ = (uint8_t)tag_len;
    /* tag */
    if (tag_len) { memcpy(p, b->tag, tag_len); p += tag_len; }
    /* agent_id */
    put_be64(p, b->agent_id); p += 8;
    /* seq */
    put_be64(p, b->seq); p += 8;
    /* ts_ms */
    {
        struct timespec ts;
#if defined(_WIN32)
        /* Windows: use GetSystemTimeAsFileTime for ms precision */
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        uint64_t ms = (((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 10000
                      - 11644473600000ULL;
        put_be64(p, ms);
#else
        clock_gettime(CLOCK_REALTIME, &ts);
        put_be64(p, (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
#endif
    }
    p += 8;
    /* body_len */
    put_be32(p, (uint32_t)body.len); p += 4;

    /* body */
    memcpy(p, body.data, body.len);

    buf_free(&body);

    *out     = frame;
    *out_len = total;
    return XLOG_OK;

oom:
    free(comp);
    buf_free(&body);
    return XLOG_ERR_OOM;
}
