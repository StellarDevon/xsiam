/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "xsiam_agent_conn.h"
#include "xsiam_agent_state.h"   /* agent_state_mark_* */

#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_mem.h>

#include <string.h>
#include <stdio.h>

/* ── Wire helpers (private) ────────────────────────────────────────────── */

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000u) +
           ((uint64_t)ts.tv_nsec / 1000000u);
}

static int write_all(struct flb_connection *connection,
                     const void *buf, size_t len)
{
    size_t sent = 0;
    size_t out_len = 0;
    int ret;

    while (sent < len) {
        ret = flb_io_net_write(connection,
                               (const char *)buf + sent,
                               len - sent, &out_len);
        if (ret < 0 || out_len == 0) {
            return -1;
        }
        sent += out_len;
    }
    return 0;
}

static int heartbeat_random_interval(struct xsiam_agent_ctx *ctx)
{
    int range = ctx->heartbeat_max - ctx->heartbeat_min + 1;

    if (range <= 1) {
        return ctx->heartbeat_min;
    }
    return ctx->heartbeat_min + (rand_r(&ctx->rand_state) % range);
}

static void schedule_next_heartbeat(struct xsiam_agent_conn *conn)
{
    conn->next_heartbeat = time(NULL) +
                           heartbeat_random_interval(conn->ctx);
}

/* ── Frame I/O ──────────────────────────────────────────────────────────── */

static int send_frame(struct xsiam_agent_conn *conn,
                      uint8_t msg_type, uint32_t agent_id, uint64_t seq,
                      const unsigned char *body, uint32_t body_len)
{
    unsigned char len_buf[4];
    unsigned char hdr[WZCP_HEADER_SIZE];
    uint32_t frame_len = WZCP_HEADER_SIZE + body_len;

    put_be32(len_buf, frame_len);
    put_be32(hdr,      WZCP_MAGIC);
    hdr[4] = WZCP_VERSION;
    hdr[5] = WZCP_HEADER_SIZE;
    hdr[6] = 0;
    hdr[7] = msg_type;
    put_be32(hdr + 8,  agent_id);
    put_be64(hdr + 12, seq);
    put_be64(hdr + 20, now_ms());
    put_be32(hdr + 28, body_len);

    if (write_all(conn->connection, len_buf, sizeof(len_buf)) ||
        write_all(conn->connection, hdr,     sizeof(hdr))) {
        return -1;
    }
    if (body_len > 0 && body) {
        return write_all(conn->connection, body, body_len);
    }
    return 0;
}

static int send_ack(struct xsiam_agent_conn *conn, uint64_t seq)
{
    unsigned char body[8];

    put_be64(body, seq);
    return send_frame(conn, WZCP_MSG_ACK, 0, seq, body, sizeof(body));
}

/* ── Header unpacking ───────────────────────────────────────────────────── */

static int unpack_header(const unsigned char *in, struct wzcp_header *h)
{
    h->magic       = get_be32(in);
    h->version     = in[4];
    h->header_len  = in[5];
    h->flags       = in[6];
    h->msg_type    = in[7];
    h->agent_id    = get_be32(in + 8);
    h->seq         = get_be64(in + 12);
    h->timestamp_ms = get_be64(in + 20);
    h->body_len    = get_be32(in + 28);

    if (h->magic      != WZCP_MAGIC      ||
        h->version    != WZCP_VERSION    ||
        h->header_len != WZCP_HEADER_SIZE ||
        h->body_len   >  WZCP_MAX_FRAME) {
        return -1;
    }
    return 0;
}

/* ── Protocol detection ─────────────────────────────────────────────────── */

static int looks_like_wzcp(const char *buf, int len)
{
    uint32_t frame_len;

    if (len < 4 + WZCP_HEADER_SIZE) {
        return FLB_FALSE;
    }
    frame_len = get_be32((const unsigned char *)buf);
    if (frame_len < WZCP_HEADER_SIZE || frame_len > WZCP_MAX_FRAME) {
        return FLB_FALSE;
    }
    return get_be32((const unsigned char *)buf + 4) == WZCP_MAGIC;
}

static int looks_like_syslog(const char *buf, int len)
{
    int i;

    if (len <= 0) {
        return FLB_FALSE;
    }
    if (buf[0] == '<' && len > 2 && buf[1] >= '0' && buf[1] <= '9') {
        return FLB_TRUE;
    }
    for (i = 0; i < len && i < 128; i++) {
        unsigned char c = (unsigned char)buf[i];

        if (c == '\n') {
            return FLB_TRUE;
        }
        if (c == '\0' || (c < 0x09) || (c > 0x0d && c < 0x20)) {
            return FLB_FALSE;
        }
    }
    return FLB_FALSE;
}

/* ── Connection classification ──────────────────────────────────────────── */

static void conn_set_classification(struct xsiam_agent_conn *conn,
                                    const char *protocol_tag,
                                    const char *client_group)
{
    if (!conn) {
        return;
    }
    if (protocol_tag &&
        (!conn->protocol_tag ||
         strcmp(conn->protocol_tag, protocol_tag) != 0)) {
        replace_str(&conn->protocol_tag, protocol_tag);
    }
    if (client_group &&
        (!conn->client_group ||
         strcmp(conn->client_group, client_group) != 0)) {
        replace_str(&conn->client_group, client_group);
    }
}

/* ── String/binary parsing helpers ─────────────────────────────────────── */

static int read_string(const unsigned char *body, uint32_t body_len,
                       uint32_t *off, char *out, size_t out_size)
{
    uint16_t len;

    if (*off + 2 > body_len || out_size == 0) {
        return -1;
    }
    len = get_be16(body + *off);
    *off += 2;
    if (*off + len > body_len || len >= out_size) {
        return -1;
    }
    memcpy(out, body + *off, len);
    out[len] = '\0';
    *off += len;
    return 0;
}

static void json_escape_append(flb_sds_t *s, const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    char tmp[8];

    while (*p) {
        switch (*p) {
        case '\\': *s = flb_sds_cat(*s, "\\\\", 2); break;
        case '"':  *s = flb_sds_cat(*s, "\\\"", 2); break;
        case '\n': *s = flb_sds_cat(*s, "\\n",  2); break;
        case '\r': *s = flb_sds_cat(*s, "\\r",  2); break;
        case '\t': *s = flb_sds_cat(*s, "\\t",  2); break;
        default:
            if (*p < 0x20) {
                snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
                *s = flb_sds_cat(*s, tmp, strlen(tmp));
            }
            else {
                *s = flb_sds_cat(*s, (const char *)p, 1);
            }
            break;
        }
        p++;
    }
}

/* ── Log record emitters ────────────────────────────────────────────────── */

static int append_record(struct xsiam_agent_conn *conn,
                         const struct wzcp_header *h,
                         uint8_t kind, uint64_t event_id,
                         const char *payload, uint16_t payload_len)
{
    int ret;
    struct xsiam_agent_ctx *ctx = conn->ctx;

    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
            ctx->log_encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("protocol"),
            FLB_LOG_EVENT_CSTRING_VALUE("wzcp"),
            FLB_LOG_EVENT_CSTRING_VALUE("session_id"),
            FLB_LOG_EVENT_CSTRING_VALUE(conn->session_id),
            FLB_LOG_EVENT_CSTRING_VALUE("session_protocol"),
            FLB_LOG_EVENT_CSTRING_VALUE(conn->protocol_tag
                                        ? conn->protocol_tag
                                        : SESSION_PROTO_AGENT_WZCP),
            FLB_LOG_EVENT_CSTRING_VALUE("client_group"),
            FLB_LOG_EVENT_CSTRING_VALUE(conn->client_group
                                        ? conn->client_group
                                        : SESSION_GROUP_AGENT),
            FLB_LOG_EVENT_CSTRING_VALUE("agent_id"),
            FLB_LOG_EVENT_UINT64_VALUE(h->agent_id),
            FLB_LOG_EVENT_CSTRING_VALUE("frame_seq"),
            FLB_LOG_EVENT_UINT64_VALUE(h->seq),
            FLB_LOG_EVENT_CSTRING_VALUE("event_id"),
            FLB_LOG_EVENT_UINT64_VALUE(event_id),
            FLB_LOG_EVENT_CSTRING_VALUE("kind"),
            FLB_LOG_EVENT_UINT64_VALUE(kind),
            FLB_LOG_EVENT_CSTRING_VALUE("log"),
            FLB_LOG_EVENT_STRING_VALUE(payload, payload_len));
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }
    return ret == FLB_EVENT_ENCODER_SUCCESS ? 0 : -1;
}

static int append_syslog_record(struct xsiam_agent_conn *conn,
                                const char *payload, uint16_t payload_len)
{
    int ret;
    struct xsiam_agent_ctx *ctx = conn->ctx;

    ret = flb_log_event_encoder_begin_record(ctx->log_encoder);
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(ctx->log_encoder);
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_append_body_values(
            ctx->log_encoder,
            FLB_LOG_EVENT_CSTRING_VALUE("protocol"),
            FLB_LOG_EVENT_CSTRING_VALUE("syslog"),
            FLB_LOG_EVENT_CSTRING_VALUE("session_id"),
            FLB_LOG_EVENT_CSTRING_VALUE(conn->session_id),
            FLB_LOG_EVENT_CSTRING_VALUE("session_protocol"),
            FLB_LOG_EVENT_CSTRING_VALUE(conn->protocol_tag
                                        ? conn->protocol_tag
                                        : SESSION_PROTO_SYSLOG),
            FLB_LOG_EVENT_CSTRING_VALUE("client_group"),
            FLB_LOG_EVENT_CSTRING_VALUE(conn->client_group
                                        ? conn->client_group
                                        : SESSION_GROUP_DEVICE),
            FLB_LOG_EVENT_CSTRING_VALUE("log"),
            FLB_LOG_EVENT_STRING_VALUE(payload, payload_len));
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }
    return ret == FLB_EVENT_ENCODER_SUCCESS ? 0 : -1;
}

/* ── WZCP message handlers ──────────────────────────────────────────────── */

static int process_hello(struct xsiam_agent_conn *conn,
                         const struct wzcp_header *h,
                         const unsigned char *body)
{
    uint32_t off = 4;
    uint16_t schema_version;
    char agent_id[128]     = {0};
    char agent_name[256]   = {0};
    char agent_version[64] = {0};
    char host_type[16]     = {0};
    flb_sds_t mac_addresses_json = NULL;

    if (h->body_len < 4) {
        return -1;
    }
    schema_version = get_be16(body);
    if (schema_version < 1) {
        return -1;
    }

    if (read_string(body, h->body_len, &off, agent_id,      sizeof(agent_id))      < 0 ||
        read_string(body, h->body_len, &off, agent_name,    sizeof(agent_name))    < 0 ||
        read_string(body, h->body_len, &off, agent_version, sizeof(agent_version)) < 0) {
        return -1;
    }

    if (schema_version >= 2) {
        uint16_t mac_count;
        uint16_t i;

        if (read_string(body, h->body_len, &off, host_type, sizeof(host_type)) < 0 ||
            off + 2u > h->body_len) {
            return -1;
        }
        mac_count = get_be16(body + off);
        off += 2;
        mac_addresses_json = flb_sds_create("[");
        if (!mac_addresses_json) {
            return -1;
        }
        for (i = 0; i < mac_count; i++) {
            char mac[32] = {0};

            if (read_string(body, h->body_len, &off, mac, sizeof(mac)) < 0) {
                flb_sds_destroy(mac_addresses_json);
                return -1;
            }
            if (i > 0) {
                mac_addresses_json = flb_sds_cat(mac_addresses_json, ",", 1);
            }
            mac_addresses_json = flb_sds_cat(mac_addresses_json, "\"", 1);
            json_escape_append(&mac_addresses_json, mac);
            mac_addresses_json = flb_sds_cat(mac_addresses_json, "\"", 1);
        }
        mac_addresses_json = flb_sds_cat(mac_addresses_json, "]", 1);
    }

    agent_state_mark_seen(conn->ctx, agent_id, agent_name, agent_version,
                          host_type[0] ? host_type : NULL,
                          mac_addresses_json, conn);
    conn_set_classification(conn, SESSION_PROTO_AGENT_WZCP, SESSION_GROUP_AGENT);

    if (mac_addresses_json) {
        flb_sds_destroy(mac_addresses_json);
    }
    return send_ack(conn, h->seq);
}

static int process_event_batch(struct xsiam_agent_conn *conn,
                               const struct wzcp_header *h,
                               const unsigned char *body)
{
    uint16_t count;
    uint32_t off = 2;
    uint32_t i;
    uint8_t  kind;
    uint64_t event_id;
    uint16_t payload_len;

    if (h->body_len < 2) {
        return -1;
    }
    count = get_be16(body);
    flb_log_event_encoder_reset(conn->ctx->log_encoder);

    for (i = 0; i < count; i++) {
        if (off + 20 > h->body_len) {
            return -1;
        }
        kind        = body[off];
        event_id    = get_be64(body + off + 10);
        payload_len = get_be16(body + off + 18);
        off        += 20;

        if (off + payload_len > h->body_len) {
            return -1;
        }
        if (append_record(conn, h, kind, event_id,
                          (const char *)body + off, payload_len) < 0) {
            return -1;
        }
        off += payload_len;
    }

    if (conn->ctx->log_encoder->output_length > 0) {
        flb_input_log_append(conn->ctx->ins, NULL, 0,
                             conn->ctx->log_encoder->output_buffer,
                             conn->ctx->log_encoder->output_length);
    }
    return send_ack(conn, h->seq);
}

/* ── Syslog handler ─────────────────────────────────────────────────────── */

static ssize_t process_syslog_lines(struct xsiam_agent_conn *conn)
{
    int    i;
    int    line_start = 0;
    int    line_len;
    size_t consumed   = 0;

    flb_log_event_encoder_reset(conn->ctx->log_encoder);

    for (i = 0; i < conn->buf_len; i++) {
        if (conn->buf_data[i] != '\n') {
            continue;
        }
        line_len = i - line_start;
        if (line_len > 0 &&
            conn->buf_data[line_start + line_len - 1] == '\r') {
            line_len--;
        }
        if (line_len > 0 &&
            append_syslog_record(conn, conn->buf_data + line_start,
                                 (uint16_t)line_len) < 0) {
            return -1;
        }
        consumed   = (size_t)i + 1;
        line_start = i + 1;
    }

    if (conn->ctx->log_encoder->output_length > 0) {
        flb_input_log_append(conn->ctx->ins, NULL, 0,
                             conn->ctx->log_encoder->output_buffer,
                             conn->ctx->log_encoder->output_length);
    }
    return (ssize_t)consumed;
}

/* ── WZCP frame dispatcher ──────────────────────────────────────────────── */

static ssize_t process_frames(struct xsiam_agent_conn *conn)
{
    uint32_t frame_len;
    struct wzcp_header h;
    unsigned char *body;
    size_t consumed = 0;
    int    ret;

    conn_set_classification(conn, SESSION_PROTO_AGENT_WZCP, SESSION_GROUP_AGENT);

    while ((size_t)conn->buf_len - consumed >= 4 + WZCP_HEADER_SIZE) {
        frame_len = get_be32((unsigned char *)conn->buf_data + consumed);
        if (frame_len < WZCP_HEADER_SIZE || frame_len > WZCP_MAX_FRAME) {
            return -1;
        }
        if ((size_t)conn->buf_len - consumed < 4 + frame_len) {
            break;
        }
        if (unpack_header((unsigned char *)conn->buf_data + consumed + 4, &h) < 0 ||
            h.body_len != frame_len - WZCP_HEADER_SIZE) {
            return -1;
        }
        body = (unsigned char *)conn->buf_data + consumed + 4 + WZCP_HEADER_SIZE;

        if (h.msg_type == WZCP_MSG_HELLO) {
            ret = process_hello(conn, &h, body);
        }
        else if (h.msg_type == WZCP_MSG_HEARTBEAT) {
            if (conn->agent_key) {
                agent_state_mark_heartbeat(conn->ctx, conn->agent_key);
            }
            ret = send_ack(conn, h.seq);
        }
        else if (h.msg_type == WZCP_MSG_EVENT_BATCH) {
            if (conn->agent_key) {
                agent_state_mark_heartbeat(conn->ctx, conn->agent_key);
            }
            ret = process_event_batch(conn, &h, body);
        }
        else {
            ret = 0;
        }

        if (ret < 0) {
            return -1;
        }
        consumed += 4 + frame_len;
    }
    return (ssize_t)consumed;
}

/* ── Buffer dispatch ────────────────────────────────────────────────────── */

static ssize_t process_buffer(struct xsiam_agent_conn *conn)
{
    if (looks_like_wzcp(conn->buf_data, conn->buf_len)) {
        return process_frames(conn);
    }
    if (looks_like_syslog(conn->buf_data, conn->buf_len)) {
        conn_set_classification(conn, SESSION_PROTO_SYSLOG, SESSION_GROUP_DEVICE);
        return process_syslog_lines(conn);
    }
    if (conn->buf_len >= 4 + WZCP_HEADER_SIZE) {
        return -1;   /* unrecognised protocol — drop */
    }
    return 0;        /* not enough data yet */
}

static void consume_bytes(char *buf, size_t bytes, size_t length)
{
    if (bytes > 0 && bytes <= length) {
        memmove(buf, buf + bytes, length - bytes);
    }
}

/* ── Public API ─────────────────────────────────────────────────────────── */

struct xsiam_agent_conn *conn_add(struct flb_connection *connection,
                                  struct xsiam_agent_ctx *ctx)
{
    int ret;
    struct xsiam_agent_conn *conn;

    conn = flb_calloc(1, sizeof(struct xsiam_agent_conn));
    if (!conn) {
        flb_errno();
        return NULL;
    }

    conn->connection = connection;
    conn->ctx        = ctx;
    snprintf(conn->session_id, sizeof(conn->session_id),
             "session-%llu", (unsigned long long)++ctx->session_seq);
    conn->buf_size = (int)ctx->chunk_size;
    conn->buf_data = flb_malloc(conn->buf_size);
    if (!conn->buf_data) {
        flb_free(conn);
        return NULL;
    }
    conn->protocol_tag = xstrdup(SESSION_PROTO_UNKNOWN);
    conn->client_group = xstrdup(SESSION_GROUP_UNKNOWN);
    if (!conn->protocol_tag || !conn->client_group) {
        flb_free(conn->protocol_tag);
        flb_free(conn->client_group);
        flb_free(conn->buf_data);
        flb_free(conn);
        return NULL;
    }

    schedule_next_heartbeat(conn);

    MK_EVENT_NEW(&connection->event);
    connection->user_data    = conn;
    connection->event.type    = FLB_ENGINE_EV_CUSTOM;
    connection->event.handler = conn_event;

    ret = mk_event_add(flb_engine_evl_get(), connection->fd,
                       FLB_ENGINE_EV_CUSTOM, MK_EVENT_READ,
                       &connection->event);
    if (ret == -1) {
        flb_free(conn->buf_data);
        flb_free(conn);
        return NULL;
    }

    mk_list_add(&conn->_head, &ctx->connections);
    return conn;
}

int conn_del(struct xsiam_agent_conn *conn)
{
    if (conn->agent_key) {
        agent_state_mark_disconnected(conn->ctx, conn->agent_key);
    }
    flb_downstream_conn_release(conn->connection);
    mk_list_del(&conn->_head);
    flb_free(conn->buf_data);
    flb_free(conn->agent_key);
    flb_free(conn->protocol_tag);
    flb_free(conn->client_group);
    flb_free(conn);
    return 0;
}

int conn_event(void *data)
{
    int    bytes;
    int    available;
    int    size;
    char  *tmp;
    ssize_t processed;
    struct flb_connection   *connection = data;
    struct xsiam_agent_conn *conn       = connection->user_data;
    struct xsiam_agent_ctx  *ctx        = conn->ctx;
    struct mk_event         *event      = &connection->event;

    conn->busy = FLB_TRUE;

    if (event->mask & MK_EVENT_READ) {
        available = conn->buf_size - conn->buf_len;
        if (available < 1) {
            if ((size_t)conn->buf_size + ctx->chunk_size > ctx->buffer_size) {
                conn->busy = FLB_FALSE;
                conn_del(conn);
                return -1;
            }
            size = conn->buf_size + (int)ctx->chunk_size;
            tmp  = flb_realloc(conn->buf_data, size);
            if (!tmp) {
                conn->busy = FLB_FALSE;
                return -1;
            }
            conn->buf_data = tmp;
            conn->buf_size = size;
            available      = conn->buf_size - conn->buf_len;
        }

        bytes = flb_io_net_read(connection,
                                conn->buf_data + conn->buf_len, available);
        if (bytes <= 0) {
            conn->busy = FLB_FALSE;
            conn_del(conn);
            return -1;
        }

        conn->buf_len += bytes;
        processed = process_buffer(conn);
        if (processed < 0) {
            conn->busy = FLB_FALSE;
            conn_del(conn);
            return -1;
        }
        consume_bytes(conn->buf_data, (size_t)processed,
                      (size_t)conn->buf_len);
        conn->buf_len -= processed;
    }

    if (event->mask & MK_EVENT_CLOSE) {
        conn->busy = FLB_FALSE;
        conn_del(conn);
        return -1;
    }

    conn->busy = FLB_FALSE;
    if (conn->pending_close) {
        conn_del(conn);
        return -1;
    }
    return 0;
}

/* ── Collector callbacks ────────────────────────────────────────────────── */

int collect(struct flb_input_instance *in,
            struct flb_config *config, void *in_context)
{
    struct flb_connection  *connection;
    struct xsiam_agent_ctx *ctx = in_context;

    (void)config;

    connection = flb_downstream_conn_get(ctx->downstream);
    if (!connection) {
        return 0;
    }
    if (!conn_add(connection, ctx)) {
        flb_downstream_conn_release(connection);
        return -1;
    }
    return 0;
}

int heartbeat_collect(struct flb_input_instance *in,
                      struct flb_config *config, void *in_context)
{
    struct mk_list         *tmp;
    struct mk_list         *head;
    struct xsiam_agent_conn *conn;
    struct xsiam_agent_ctx  *ctx = in_context;
    time_t now;

    (void)in;
    (void)config;

    now = time(NULL);
    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct xsiam_agent_conn, _head);
        if (!conn->protocol_tag ||
            strcmp(conn->protocol_tag, SESSION_PROTO_AGENT_WZCP) != 0) {
            continue;
        }
        if (now < conn->next_heartbeat) {
            continue;
        }
        if (send_frame(conn, WZCP_MSG_HEARTBEAT, 0,
                       ++ctx->gateway_seq, NULL, 0) != 0) {
            conn_del(conn);
        }
        else {
            schedule_next_heartbeat(conn);
        }
    }
    return 0;
}
