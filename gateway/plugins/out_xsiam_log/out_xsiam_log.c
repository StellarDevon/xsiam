/*
 * out_xsiam_log.c  —  Fluent Bit OUTPUT plugin
 *
 * Receives log events from in_xsiam_agent (EVENT_BATCH records) and
 * forwards them to the XSIAM ingest endpoint as XLOG binary frames.
 *
 * Each Fluent Bit chunk → one XLOG TypeLogBatch frame:
 *   • TSV rows assembled from flb_log_event fields
 *   • Compressed with zstd (level 3)
 *   • POST to <Ingest_URL>/internal/agent/log
 *     Content-Type: application/x-xlog
 *
 * Config map options:
 *   Ingest_URL    http://127.0.0.1:18090      XSIAM internal ingest base URL
 *   Ingest_Token  <empty>                      Optional Bearer token
 *   Tag_Field     tag                          Event field used as XLOG tag
 *   Compress_Level 3                           zstd level 1-19
 *   Max_Batch_Rows 8192                        Flush at this many rows
 */

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <zstd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ── Magic & wire constants (must match xlog.h / ingest/frame.go) ──── */
#define XLOG_MAGIC            0x584C4F47UL  /* "XLOG" */
#define XLOG_VERSION          1
#define XLOG_TYPE_LOG_BATCH   0x01

#define XLOG_TAG_SCHEMA_VER   0x01
#define XLOG_TAG_ROW_COUNT    0x02
#define XLOG_TAG_ORIG_SIZE    0x03
#define XLOG_TAG_COLUMNS      0x04
#define XLOG_TAG_DATA         0x10

#define XLOG_COLUMNS "agent_id\t_time\tevent_id\tkind\ttag\tlog"

static const char *XLOG_COLUMNS_CSV = "agent_id,_time,event_id,kind,tag,log";

/* ── Context ─────────────────────────────────────────────────────────── */

struct xsiam_log_ctx {
    char                   *ingest_url;
    char                   *ingest_token;
    char                   *tag_field;
    int                     compress_level;
    int                     max_batch_rows;
    struct flb_upstream    *upstream;
    struct flb_output_instance *ins;
};

/* ── Byte helpers ────────────────────────────────────────────────────── */

static void put_be16(uint8_t *p, uint16_t v) { p[0]=v>>8; p[1]=v; }
static void put_be32(uint8_t *p, uint32_t v) {
    p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v;
}
static void put_be64(uint8_t *p, uint64_t v) {
    put_be32(p, (uint32_t)(v>>32));
    put_be32(p+4, (uint32_t)v);
}

/* ── Dynamic buffer ──────────────────────────────────────────────────── */

typedef struct { uint8_t *d; size_t len, cap; } dbuf_t;

static int dbuf_init(dbuf_t *b, size_t init) {
    b->d = flb_malloc(init ? init : 4096);
    if (!b->d) return -1;
    b->len = 0; b->cap = init ? init : 4096;
    return 0;
}
static int dbuf_grow(dbuf_t *b, size_t need) {
    if (b->len + need <= b->cap) return 0;
    size_t nc = b->cap * 2;
    while (nc < b->len + need) nc *= 2;
    uint8_t *nd = flb_realloc(b->d, nc);
    if (!nd) return -1;
    b->d = nd; b->cap = nc;
    return 0;
}
static int dbuf_append(dbuf_t *b, const void *src, size_t n) {
    if (dbuf_grow(b, n)) return -1;
    memcpy(b->d + b->len, src, n);
    b->len += n;
    return 0;
}
static void dbuf_free(dbuf_t *b) { flb_free(b->d); b->d=NULL; b->len=b->cap=0; }

/* ── TLV append ──────────────────────────────────────────────────────── */

static int tlv_append(dbuf_t *body, uint8_t tag, const void *val, uint16_t vlen) {
    uint8_t h[3]; h[0]=tag; put_be16(h+1, vlen);
    if (dbuf_append(body, h, 3)) return -1;
    if (vlen && dbuf_append(body, val, vlen)) return -1;
    return 0;
}

/* ── Build and send one XLOG frame ───────────────────────────────────── */

static int send_xlog_frame(struct xsiam_log_ctx *ctx,
                           uint64_t agent_id,
                           const char *tag_label,
                           dbuf_t *tsv,
                           uint32_t row_count)
{
    if (tsv->len == 0) return FLB_OK;

    /* ── zstd compress ── */
    size_t bound    = ZSTD_compressBound(tsv->len);
    uint8_t *comp   = flb_malloc(bound);
    if (!comp) return FLB_RETRY;

    size_t comp_len = ZSTD_compress(comp, bound,
                                    tsv->d, tsv->len,
                                    ctx->compress_level);
    if (ZSTD_isError(comp_len)) {
        flb_plg_error(ctx->ins, "zstd compress failed: %s",
                      ZSTD_getErrorName(comp_len));
        flb_free(comp);
        return FLB_ERROR;
    }

    /* ── TLV body ── */
    dbuf_t body;
    if (dbuf_init(&body, comp_len + 128)) {
        flb_free(comp);
        return FLB_RETRY;
    }

    { uint8_t v[2]; put_be16(v, 1);
      tlv_append(&body, XLOG_TAG_SCHEMA_VER, v, 2); }
    { uint8_t v[4]; put_be32(v, row_count);
      tlv_append(&body, XLOG_TAG_ROW_COUNT, v, 4); }
    { uint8_t v[4]; put_be32(v, (uint32_t)tsv->len);
      tlv_append(&body, XLOG_TAG_ORIG_SIZE, v, 4); }
    { size_t clen = strlen(XLOG_COLUMNS_CSV);
      tlv_append(&body, XLOG_TAG_COLUMNS,
                 XLOG_COLUMNS_CSV, (uint16_t)clen); }
    if (comp_len <= 0xFFFF) {
        tlv_append(&body, XLOG_TAG_DATA, comp, (uint16_t)comp_len);
    } else {
        /* large: embed u32 len in first 4 bytes of value */
        uint8_t hdr32[3+4];
        hdr32[0] = XLOG_TAG_DATA;
        put_be16(hdr32+1, (uint16_t)(comp_len & 0xFFFF));
        put_be32(hdr32+3, (uint32_t)comp_len);
        dbuf_append(&body, hdr32, 7);
        dbuf_append(&body, comp, comp_len);
    }
    flb_free(comp);

    /* ── XLOG frame header ── */
    const char *tag = tag_label ? tag_label : "agent_log";
    size_t tlen = strlen(tag);
    if (tlen > 255) tlen = 255;

    size_t hdr_size = 8 + tlen + 28;
    size_t total    = hdr_size + body.len;
    uint8_t *frame  = flb_malloc(total);
    if (!frame) { dbuf_free(&body); return FLB_RETRY; }

    uint8_t *p = frame;
    put_be32(p, XLOG_MAGIC);       p += 4;
    *p++ = XLOG_VERSION;
    *p++ = XLOG_TYPE_LOG_BATCH;
    *p++ = 0;                       /* flags */
    *p++ = (uint8_t)tlen;
    memcpy(p, tag, tlen);           p += tlen;
    put_be64(p, agent_id);          p += 8;
    put_be64(p, (uint64_t)time(NULL)); p += 8;  /* seq: timestamp as proxy */
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        put_be64(p, (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    }                               p += 8;
    put_be32(p, (uint32_t)body.len); p += 4;
    memcpy(p, body.d, body.len);

    dbuf_free(&body);

    /* ── HTTP POST ── */
    struct flb_connection *u_conn = flb_upstream_conn_get(ctx->upstream);
    if (!u_conn) {
        flb_free(frame);
        return FLB_RETRY;
    }

    size_t b_sent = 0;
    char path[256];
    snprintf(path, sizeof(path), "/internal/agent/log");

    struct flb_http_client *c = flb_http_client(u_conn, FLB_HTTP_POST, path,
                                                (char *)frame, total,
                                                NULL, 0, NULL, 0);
    if (!c) {
        flb_upstream_conn_release(u_conn);
        flb_free(frame);
        return FLB_RETRY;
    }

    flb_http_add_header(c, "Content-Type", 12,
                        "application/x-xlog", 18);
    if (ctx->ingest_token && ctx->ingest_token[0]) {
        char auth[512];
        snprintf(auth, sizeof(auth), "Bearer %s", ctx->ingest_token);
        flb_http_add_header(c, "Authorization", 13, auth, strlen(auth));
    }

    int ret = flb_http_do(c, &b_sent);
    int status = c->resp.status;
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    flb_free(frame);

    if (ret != 0 || status != 204) {
        flb_plg_warn(ctx->ins,
                     "xlog post failed ret=%d status=%d rows=%u comp=%zu",
                     ret, status, row_count, comp_len);
        return FLB_RETRY;
    }

    flb_plg_debug(ctx->ins,
                  "xlog posted agent_id=%llu rows=%u orig=%zu comp=%zu",
                  (unsigned long long)agent_id, row_count, tsv->len, comp_len);
    return FLB_OK;
}

/* ── Plugin callbacks ────────────────────────────────────────────────── */

static int cb_init(struct flb_output_instance *ins,
                   struct flb_config *config, void *data)
{
    struct xsiam_log_ctx *ctx = flb_calloc(1, sizeof(*ctx));
    if (!ctx) return -1;

    ctx->ins = ins;

    if (flb_output_config_map_set(ins, (void *)ctx) < 0) {
        flb_free(ctx);
        return -1;
    }

    /* Parse Ingest_URL into host/port for flb_upstream */
    const char *url = ctx->ingest_url ? ctx->ingest_url : "http://127.0.0.1:18090";

    /* Strip scheme */
    const char *host_start = url;
    if (strncmp(url, "http://", 7) == 0) host_start = url + 7;
    else if (strncmp(url, "https://", 8) == 0) host_start = url + 8;

    char host[256] = "127.0.0.1";
    int  port       = 18090;
    const char *colon = strchr(host_start, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - host_start);
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, host_start, hlen);
        host[hlen] = '\0';
        port = atoi(colon + 1);
    } else {
        size_t hlen = strlen(host_start);
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, host_start, hlen);
        host[hlen] = '\0';
    }
    /* Remove any path suffix */
    char *slash = strchr(host, '/');
    if (slash) *slash = '\0';

    ctx->upstream = flb_upstream_create(config, host, port,
                                        FLB_IO_TCP, NULL);
    if (!ctx->upstream) {
        flb_plg_error(ins, "could not create upstream %s:%d", host, port);
        flb_free(ctx);
        return -1;
    }

    /* Associate upstream with this output instance (required for worker threads) */
    flb_output_upstream_set(ctx->upstream, ins);

    flb_output_set_context(ins, ctx);
    flb_plg_info(ins, "xsiam_log output → %s:%d (zstd level %d, max %d rows)",
                 host, port,
                 ctx->compress_level > 0 ? ctx->compress_level : 3,
                 ctx->max_batch_rows  > 0 ? ctx->max_batch_rows  : 8192);
    return 0;
}

static void cb_flush(struct flb_event_chunk *event_chunk,
                     struct flb_output_flush *out_flush,
                     struct flb_input_instance *i_ins,
                     void *out_context,
                     struct flb_config *config)
{
    (void)out_flush; (void)i_ins; (void)config;

    struct xsiam_log_ctx *ctx = out_context;
    struct flb_log_event_decoder dec;
    struct flb_log_event ev;
    int ret;

    ret = flb_log_event_decoder_init(&dec,
                                     (char *)event_chunk->data,
                                     event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    dbuf_t tsv;
    if (dbuf_init(&tsv, 65536)) {
        flb_log_event_decoder_destroy(&dec);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    uint32_t row_count = 0;
    uint64_t cur_agent_id = 0;
    char cur_tag[128] = "agent_log";
    int max_rows = ctx->max_batch_rows > 0 ? ctx->max_batch_rows : 8192;

    while ((ret = flb_log_event_decoder_next(&dec, &ev))
           == FLB_EVENT_DECODER_SUCCESS) {

        /* Extract fields from msgpack map */
        uint64_t agent_id   = 0;
        uint64_t event_id   = 0;
        uint8_t  kind       = 0;
        const char *log_str = "";
        size_t   log_len    = 0;
        const char *tag_str = cur_tag;

        msgpack_object *body_map = ev.body;
        if (body_map && body_map->type == MSGPACK_OBJECT_MAP) {
            for (uint32_t i = 0; i < body_map->via.map.size; i++) {
                msgpack_object_kv *kv = &body_map->via.map.ptr[i];
                if (kv->key.type != MSGPACK_OBJECT_STR) continue;
                const char *k = kv->key.via.str.ptr;
                size_t      kl = kv->key.via.str.size;
#define KEY_EQ(s) (kl == sizeof(s)-1 && memcmp(k, (s), kl) == 0)
                if (KEY_EQ("agent_id")) {
                    if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER)
                        agent_id = kv->val.via.u64;
                } else if (KEY_EQ("event_id")) {
                    if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER)
                        event_id = kv->val.via.u64;
                } else if (KEY_EQ("kind")) {
                    if (kv->val.type == MSGPACK_OBJECT_POSITIVE_INTEGER)
                        kind = (uint8_t)kv->val.via.u64;
                } else if (KEY_EQ("log")) {
                    if (kv->val.type == MSGPACK_OBJECT_STR) {
                        log_str = kv->val.via.str.ptr;
                        log_len = kv->val.via.str.size;
                    }
                } else if (KEY_EQ("session_protocol")) {
                    if (kv->val.type == MSGPACK_OBJECT_STR) {
                        size_t tl = kv->val.via.str.size;
                        if (tl >= sizeof(cur_tag)) tl = sizeof(cur_tag)-1;
                        memcpy(cur_tag, kv->val.via.str.ptr, tl);
                        cur_tag[tl] = '\0';
                        tag_str = cur_tag;
                    }
                }
#undef KEY_EQ
            }
        }

        /* Timestamp as RFC 3339 */
        char ts_buf[32];
        struct tm tm_val;
        time_t ts_sec = (time_t)(ev.timestamp.tm.tv_sec);
#if defined(_WIN32)
        gmtime_s(&tm_val, &ts_sec);
#else
        gmtime_r(&ts_sec, &tm_val);
#endif
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_val);

        /* TSV row: agent_id \t _time \t event_id \t kind \t tag \t log */
        char row[4096];
        int rlen = snprintf(row, sizeof(row),
                            "%llu\t%s\t%llu\t%u\t%s\t",
                            (unsigned long long)agent_id,
                            ts_buf,
                            (unsigned long long)event_id,
                            (unsigned int)kind,
                            tag_str);
        if (rlen < 0 || (size_t)rlen >= sizeof(row) - log_len - 2)
            rlen = (int)(sizeof(row) - log_len - 2);

        dbuf_append(&tsv, row, (size_t)rlen);
        /* append log payload (may contain tabs/newlines — leave as-is) */
        if (log_len > 0) dbuf_append(&tsv, log_str, log_len);
        dbuf_append(&tsv, "\n", 1);

        cur_agent_id = agent_id;
        row_count++;

        /* Flush sub-batch if max_rows reached */
        if ((int)row_count >= max_rows) {
            int sr = send_xlog_frame(ctx, cur_agent_id, tag_str,
                                     &tsv, row_count);
            if (sr != FLB_OK) {
                dbuf_free(&tsv);
                flb_log_event_decoder_destroy(&dec);
                FLB_OUTPUT_RETURN(sr);
            }
            tsv.len = 0;
            row_count = 0;
        }
    }

    flb_log_event_decoder_destroy(&dec);

    int final_ret = FLB_OK;
    if (row_count > 0)
        final_ret = send_xlog_frame(ctx, cur_agent_id, cur_tag,
                                    &tsv, row_count);
    dbuf_free(&tsv);

    FLB_OUTPUT_RETURN(final_ret);
}

static int cb_exit(void *data, struct flb_config *config)
{
    (void)config;
    struct xsiam_log_ctx *ctx = data;
    if (!ctx) return 0;
    if (ctx->upstream) flb_upstream_destroy(ctx->upstream);
    flb_free(ctx);
    return 0;
}

/* ── Config map ──────────────────────────────────────────────────────── */

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "ingest_url", "http://127.0.0.1:18090",
     0, FLB_TRUE, offsetof(struct xsiam_log_ctx, ingest_url),
     "XSIAM ingest base URL (internal port)"
    },
    {
     FLB_CONFIG_MAP_STR, "ingest_token", "",
     0, FLB_TRUE, offsetof(struct xsiam_log_ctx, ingest_token),
     "Optional Bearer token for ingest auth"
    },
    {
     FLB_CONFIG_MAP_STR, "tag_field", "session_protocol",
     0, FLB_TRUE, offsetof(struct xsiam_log_ctx, tag_field),
     "Event field to use as the XLOG source tag"
    },
    {
     FLB_CONFIG_MAP_INT, "compress_level", "3",
     0, FLB_TRUE, offsetof(struct xsiam_log_ctx, compress_level),
     "zstd compression level (1=fast … 19=best)"
    },
    {
     FLB_CONFIG_MAP_INT, "max_batch_rows", "8192",
     0, FLB_TRUE, offsetof(struct xsiam_log_ctx, max_batch_rows),
     "Flush after this many rows within one Fluent Bit chunk"
    },
    {0}
};

/* ── Plugin registration ─────────────────────────────────────────────── */

struct flb_output_plugin out_xsiam_log_plugin = {
    .name        = "xsiam_log",
    .description = "XSIAM XLOG compressed TSV log uploader",
    .cb_init     = cb_init,
    .cb_flush    = cb_flush,
    .cb_exit     = cb_exit,
    .config_map  = config_map,
    .flags       = 0,
};
