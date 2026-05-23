/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_input_log.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_utils.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#define WZCP_MAGIC 0x575A4350u
#define WZCP_VERSION 1
#define WZCP_HEADER_SIZE 32
#define WZCP_MAX_FRAME (1024u * 1024u)

#define WZCP_MSG_HELLO 1
#define WZCP_MSG_EVENT_BATCH 2
#define WZCP_MSG_ACK 3
#define WZCP_MSG_HEARTBEAT 4
#define WZCP_MSG_CONTROL 5
#define WZCP_MSG_ERROR 6

#define XSIAM_DB_HOST "127.0.0.1"
#define XSIAM_DB_PORT 8529
#define XSIAM_DB_USER "root"
#define XSIAM_DB_PASS "changeme"
#define XSIAM_DB_NAME "xsiamdb"
#define XSIAM_DB_FLUSH_INTERVAL 5
#define XSIAM_DB_HEARTBEAT_FLUSH_INTERVAL 180

#define SESSION_PROTO_UNKNOWN "unknown"
#define SESSION_PROTO_AGENT_WZCP "agent_wzcp"
#define SESSION_PROTO_SYSLOG "syslog"
#define SESSION_GROUP_UNKNOWN "unknown"
#define SESSION_GROUP_AGENT "agent"
#define SESSION_GROUP_DEVICE "device"

struct wzcp_header {
    uint32_t magic;
    uint8_t version;
    uint8_t header_len;
    uint8_t flags;
    uint8_t msg_type;
    uint32_t agent_id;
    uint64_t seq;
    uint64_t timestamp_ms;
    uint32_t body_len;
};

struct xsiam_agent_ctx {
    char *listen;
    char *tcp_port;
    char *arango_host;
    char *arango_user;
    char *arango_pass;
    char *arango_database;
    flb_sds_t chunk_size_str;
    flb_sds_t buffer_size_str;
    size_t chunk_size;
    size_t buffer_size;
    int collector_id;
    int heartbeat_collector_id;
    int db_collector_id;
    int heartbeat_min;
    int heartbeat_max;
    int db_sync;
    int arango_port;
    int db_flush_interval;
    int heartbeat_flush_interval;
    uint64_t gateway_seq;
    uint64_t session_seq;
    unsigned int rand_state;
    struct flb_downstream *downstream;
    struct flb_upstream *arango_upstream;
    struct mk_list connections;
    struct mk_list agents;
    struct flb_input_instance *ins;
    struct flb_log_event_encoder *log_encoder;
};

struct xsiam_agent_conn {
    struct flb_connection *connection;
    struct xsiam_agent_ctx *ctx;
    char *buf_data;
    int buf_len;
    int buf_size;
    int busy;
    int pending_close;
    time_t next_heartbeat;
    char *agent_key;
    char *protocol_tag;
    char *client_group;
    char session_id[64];
    struct mk_list _head;
};

struct xsiam_agent_state {
    char *agent_id;
    char *tenant_id;
    char *hostname;
    char *host_type;
    char *agent_version;
    char *agent_status;
    char *gateway_id;
    char *ip;
    flb_sds_t mac_addresses_json;
    int is_connected;
    time_t installed_at;
    time_t connected_at;
    time_t last_heartbeat;
    time_t last_seen;
    time_t created_at;
    time_t updated_at;
    time_t last_db_flush;
    int dirty;
    struct mk_list _head;
};

static uint16_t get_be16(const unsigned char *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t get_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t get_be64(const unsigned char *p)
{
    return ((uint64_t)get_be32(p) << 32) | get_be32(p + 4);
}

static char *xstrdup(const char *s)
{
    char *out;

    if (!s) {
        s = "";
    }
    out = flb_strdup(s);
    return out;
}

static void replace_str(char **dst, const char *src)
{
    char *tmp = xstrdup(src);

    if (!tmp) {
        return;
    }
    flb_free(*dst);
    *dst = tmp;
}

static time_t now_sec(void)
{
    return time(NULL);
}

static void iso_time(time_t ts, char *out, size_t out_size)
{
    struct tm tm;

    gmtime_r(&ts, &tm);
    strftime(out, out_size, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

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

static void conn_set_classification(struct xsiam_agent_conn *conn,
                                    const char *protocol_tag,
                                    const char *client_group)
{
    if (!conn) {
        return;
    }

    if (protocol_tag && (!conn->protocol_tag ||
                         strcmp(conn->protocol_tag, protocol_tag) != 0)) {
        replace_str(&conn->protocol_tag, protocol_tag);
    }

    if (client_group && (!conn->client_group ||
                         strcmp(conn->client_group, client_group) != 0)) {
        replace_str(&conn->client_group, client_group);
    }
}

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

static void json_escape_append(flb_sds_t *s, const char *value)
{
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    char tmp[8];

    while (*p) {
        switch (*p) {
        case '\\':
            *s = flb_sds_cat(*s, "\\\\", 2);
            break;
        case '"':
            *s = flb_sds_cat(*s, "\\\"", 2);
            break;
        case '\n':
            *s = flb_sds_cat(*s, "\\n", 2);
            break;
        case '\r':
            *s = flb_sds_cat(*s, "\\r", 2);
            break;
        case '\t':
            *s = flb_sds_cat(*s, "\\t", 2);
            break;
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

static void put_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static void put_be64(unsigned char *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

static int unpack_header(const unsigned char *in, struct wzcp_header *h)
{
    h->magic = get_be32(in);
    h->version = in[4];
    h->header_len = in[5];
    h->flags = in[6];
    h->msg_type = in[7];
    h->agent_id = get_be32(in + 8);
    h->seq = get_be64(in + 12);
    h->timestamp_ms = get_be64(in + 20);
    h->body_len = get_be32(in + 28);

    if (h->magic != WZCP_MAGIC ||
        h->version != WZCP_VERSION ||
        h->header_len != WZCP_HEADER_SIZE ||
        h->body_len > WZCP_MAX_FRAME) {
        return -1;
    }

    return 0;
}

static int write_all(struct flb_connection *connection, const void *buf, size_t len)
{
    size_t sent = 0;
    size_t out_len = 0;
    int ret;

    while (sent < len) {
        ret = flb_io_net_write(connection, (const char *)buf + sent,
                               len - sent, &out_len);
        if (ret < 0 || out_len == 0) {
            return -1;
        }
        sent += out_len;
    }

    return 0;
}

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000u) + ((uint64_t)ts.tv_nsec / 1000000u);
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
    conn->next_heartbeat = time(NULL) + heartbeat_random_interval(conn->ctx);
}

static int send_frame(struct xsiam_agent_conn *conn, uint8_t msg_type,
                      uint32_t agent_id, uint64_t seq,
                      const unsigned char *body, uint32_t body_len)
{
    unsigned char len_buf[4];
    unsigned char hdr[WZCP_HEADER_SIZE];
    uint32_t frame_len = WZCP_HEADER_SIZE + body_len;

    put_be32(len_buf, frame_len);
    put_be32(hdr, WZCP_MAGIC);
    hdr[4] = WZCP_VERSION;
    hdr[5] = WZCP_HEADER_SIZE;
    hdr[6] = 0;
    hdr[7] = msg_type;
    put_be32(hdr + 8, agent_id);
    put_be64(hdr + 12, seq);
    put_be64(hdr + 20, now_ms());
    put_be32(hdr + 28, body_len);

    if (write_all(conn->connection, len_buf, sizeof(len_buf)) ||
        write_all(conn->connection, hdr, sizeof(hdr))) {
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

static struct xsiam_agent_state *agent_state_get(struct xsiam_agent_ctx *ctx,
                                                 const char *agent_id,
                                                 int create)
{
    struct mk_list *head;
    struct xsiam_agent_state *st;
    time_t now = now_sec();

    mk_list_foreach(head, &ctx->agents) {
        st = mk_list_entry(head, struct xsiam_agent_state, _head);
        if (strcmp(st->agent_id, agent_id) == 0) {
            return st;
        }
    }

    if (!create) {
        return NULL;
    }

    st = flb_calloc(1, sizeof(struct xsiam_agent_state));
    if (!st) {
        return NULL;
    }

    st->agent_id = xstrdup(agent_id);
    st->tenant_id = xstrdup("tenant-default");
    st->hostname = xstrdup(agent_id);
    st->host_type = xstrdup("pc");
    st->agent_version = xstrdup("unknown");
    st->agent_status = xstrdup("online");
    st->gateway_id = xstrdup("gateway-local-001");
    st->ip = xstrdup("");
    st->mac_addresses_json = flb_sds_create("[]");
    st->installed_at = now;
    st->created_at = now;
    st->updated_at = now;
    st->last_seen = now;
    st->last_heartbeat = now;
    st->dirty = FLB_TRUE;
    mk_list_add(&st->_head, &ctx->agents);
    return st;
}

static void agent_state_destroy(struct xsiam_agent_state *st)
{
    flb_free(st->agent_id);
    flb_free(st->tenant_id);
    flb_free(st->hostname);
    flb_free(st->host_type);
    flb_free(st->agent_version);
    flb_free(st->agent_status);
    flb_free(st->gateway_id);
    flb_free(st->ip);
    flb_sds_destroy(st->mac_addresses_json);
    flb_free(st);
}

static void agent_state_mark_seen(struct xsiam_agent_ctx *ctx, const char *agent_id,
                                  const char *agent_name, const char *agent_version,
                                  const char *host_type, flb_sds_t mac_addresses_json,
                                  struct xsiam_agent_conn *conn)
{
    struct xsiam_agent_state *st;
    time_t now = now_sec();

    if (!agent_id || agent_id[0] == '\0') {
        return;
    }

    st = agent_state_get(ctx, agent_id, FLB_TRUE);
    if (!st) {
        return;
    }

    replace_str(&st->hostname, agent_name && agent_name[0] ? agent_name : agent_id);
    replace_str(&st->agent_version, agent_version && agent_version[0] ? agent_version : "unknown");
    if (host_type && (strcmp(host_type, "server") == 0 || strcmp(host_type, "pc") == 0)) {
        replace_str(&st->host_type, host_type);
    }
    if (mac_addresses_json) {
        flb_sds_destroy(st->mac_addresses_json);
        st->mac_addresses_json = flb_sds_create_len(mac_addresses_json,
                                                    flb_sds_len(mac_addresses_json));
        if (!st->mac_addresses_json) {
            st->mac_addresses_json = flb_sds_create("[]");
        }
    }
    replace_str(&st->agent_status, "online");
    st->is_connected = FLB_TRUE;
    st->connected_at = now;
    st->last_seen = now;
    st->last_heartbeat = now;
    st->updated_at = now;
    st->dirty = FLB_TRUE;

    if (conn) {
        replace_str(&conn->agent_key, agent_id);
    }
}

static void agent_state_mark_heartbeat(struct xsiam_agent_ctx *ctx, const char *agent_id)
{
    struct xsiam_agent_state *st;
    time_t now = now_sec();

    st = agent_state_get(ctx, agent_id, FLB_FALSE);
    if (!st) {
        return;
    }
    st->last_heartbeat = now;
    st->last_seen = now;
    st->updated_at = now;
    if (now - st->last_db_flush >= ctx->heartbeat_flush_interval) {
        st->dirty = FLB_TRUE;
    }
}

static void agent_state_mark_disconnected(struct xsiam_agent_ctx *ctx, const char *agent_id)
{
    struct xsiam_agent_state *st;
    time_t now = now_sec();

    st = agent_state_get(ctx, agent_id, FLB_FALSE);
    if (!st) {
        return;
    }
    if (st->is_connected) {
        st->is_connected = FLB_FALSE;
        replace_str(&st->agent_status, "offline");
        st->last_seen = now;
        st->updated_at = now;
        st->dirty = FLB_TRUE;
    }
}

static int process_hello(struct xsiam_agent_conn *conn,
                         const struct wzcp_header *h,
                         const unsigned char *body)
{
    uint32_t off = 4;
    uint16_t schema_version;
    char agent_id[128] = {0};
    char agent_name[256] = {0};
    char agent_version[64] = {0};
    char host_type[16] = {0};
    flb_sds_t mac_addresses_json = NULL;

    if (h->body_len < 4) {
        return -1;
    }

    schema_version = get_be16(body);
    if (schema_version < 1) {
        return -1;
    }

    if (read_string(body, h->body_len, &off, agent_id, sizeof(agent_id)) < 0 ||
        read_string(body, h->body_len, &off, agent_name, sizeof(agent_name)) < 0 ||
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
                          host_type[0] ? host_type : NULL, mac_addresses_json, conn);
    conn_set_classification(conn, SESSION_PROTO_AGENT_WZCP, SESSION_GROUP_AGENT);
    if (mac_addresses_json) {
        flb_sds_destroy(mac_addresses_json);
    }
    return send_ack(conn, h->seq);
}

static void append_json_string_field(flb_sds_t *s, const char *name, const char *value)
{
    *s = flb_sds_cat(*s, "\"", 1);
    *s = flb_sds_cat(*s, name, strlen(name));
    *s = flb_sds_cat(*s, "\":\"", 3);
    json_escape_append(s, value);
    *s = flb_sds_cat(*s, "\"", 1);
}

static void append_json_time_field(flb_sds_t *s, const char *name, time_t value)
{
    char buf[32];

    iso_time(value, buf, sizeof(buf));
    append_json_string_field(s, name, buf);
}

static void append_agent_doc(flb_sds_t *s, struct xsiam_agent_state *st)
{
    const char *connected_json;
    flb_sds_t device_key;

    device_key = flb_sds_create("device-");
    if (device_key) {
        device_key = flb_sds_cat(device_key, st->agent_id, strlen(st->agent_id));
    }
    *s = flb_sds_cat(*s, "{", 1);
    append_json_string_field(s, "_key", device_key ? device_key : st->agent_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "device_id", device_key ? device_key : st->agent_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "tenant_id", st->tenant_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "agent_id", st->agent_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "gateway_id", st->gateway_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "hostname", st->hostname);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "host_type", st->host_type);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "ip", st->ip);
    *s = flb_sds_cat(*s, ",\"ip_addresses\":[],\"mac_addresses\":",
                     strlen(",\"ip_addresses\":[],\"mac_addresses\":"));
    *s = flb_sds_cat(*s, st->mac_addresses_json, flb_sds_len(st->mac_addresses_json));
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "os_type", "windows");
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "os_version", "");
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "agent_version", st->agent_version);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "agent_status", st->agent_status);
    connected_json = st->is_connected ? ",\"is_connected\":true," : ",\"is_connected\":false,";
    *s = flb_sds_cat(*s, connected_json, strlen(connected_json));
    append_json_string_field(s, "protocol", "wzcp");
    *s = flb_sds_cat(*s, ",\"protocol_version\":1,",
                     strlen(",\"protocol_version\":1,"));
    append_json_time_field(s, "installed_at", st->installed_at);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "enrolled_at", st->installed_at);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "last_heartbeat", st->last_heartbeat);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "last_seen", st->last_seen);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "created_at", st->created_at);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "updated_at", st->updated_at);
    *s = flb_sds_cat(*s, "}", 1);
    flb_sds_destroy(device_key);
}

static flb_sds_t build_arango_payload(struct xsiam_agent_ctx *ctx, int *doc_count)
{
    struct mk_list *head;
    struct xsiam_agent_state *st;
    flb_sds_t s;
    int count = 0;

    s = flb_sds_create_size(4096);
    if (!s) {
        return NULL;
    }

    s = flb_sds_cat(s,
                    "{\"query\":\"FOR doc IN @devices UPSERT {agent_id: doc.agent_id} INSERT doc UPDATE MERGE(OLD, UNSET(doc, '_key')) IN devices\",\"bindVars\":{\"devices\":[",
                    strlen("{\"query\":\"FOR doc IN @devices UPSERT {agent_id: doc.agent_id} INSERT doc UPDATE MERGE(OLD, UNSET(doc, '_key')) IN devices\",\"bindVars\":{\"devices\":["));
    mk_list_foreach(head, &ctx->agents) {
        st = mk_list_entry(head, struct xsiam_agent_state, _head);
        if (!st->dirty) {
            continue;
        }
        if (count > 0) {
            s = flb_sds_cat(s, ",", 1);
        }
        append_agent_doc(&s, st);
        count++;
    }
    s = flb_sds_cat(s, "]}}", 3);
    *doc_count = count;
    return s;
}

static int arango_flush_dirty_agents(struct xsiam_agent_ctx *ctx)
{
    int ret;
    int count = 0;
    size_t b_sent = 0;
    char uri[256];
    flb_sds_t payload;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct mk_list *head;
    struct xsiam_agent_state *st;

    if (!ctx->db_sync || !ctx->arango_upstream) {
        return 0;
    }

    payload = build_arango_payload(ctx, &count);
    if (!payload || count == 0) {
        flb_sds_destroy(payload);
        return 0;
    }

    u_conn = flb_upstream_conn_get(ctx->arango_upstream);
    if (!u_conn) {
        flb_sds_destroy(payload);
        return -1;
    }

    snprintf(uri, sizeof(uri), "/_db/%s/_api/cursor", ctx->arango_database);
    c = flb_http_client(u_conn, FLB_HTTP_POST, uri,
                        payload, flb_sds_len(payload),
                        NULL, 0, NULL, 0);
    if (!c) {
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(payload);
        return -1;
    }

    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    flb_http_basic_auth(c, ctx->arango_user, ctx->arango_pass);
    ret = flb_http_do(c, &b_sent);
    if (ret == 0 && c->resp.status >= 200 && c->resp.status < 300) {
        mk_list_foreach(head, &ctx->agents) {
            st = mk_list_entry(head, struct xsiam_agent_state, _head);
            if (st->dirty) {
                st->dirty = FLB_FALSE;
                st->last_db_flush = now_sec();
            }
        }
    }
    else {
        flb_plg_warn(ctx->ins, "failed to flush %d agent states to ArangoDB status=%d",
                     count, c->resp.status);
        ret = -1;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    flb_sds_destroy(payload);
    return ret;
}

static void consume_bytes(char *buf, size_t bytes, size_t length)
{
    if (bytes > 0 && bytes <= length) {
        memmove(buf, buf + bytes, length - bytes);
    }
}

static int append_record(struct xsiam_agent_conn *conn, const struct wzcp_header *h,
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
            FLB_LOG_EVENT_CSTRING_VALUE(conn->protocol_tag ? conn->protocol_tag : SESSION_PROTO_AGENT_WZCP),
            FLB_LOG_EVENT_CSTRING_VALUE("client_group"),
            FLB_LOG_EVENT_CSTRING_VALUE(conn->client_group ? conn->client_group : SESSION_GROUP_AGENT),
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
            FLB_LOG_EVENT_CSTRING_VALUE(conn->protocol_tag ? conn->protocol_tag : SESSION_PROTO_SYSLOG),
            FLB_LOG_EVENT_CSTRING_VALUE("client_group"),
            FLB_LOG_EVENT_CSTRING_VALUE(conn->client_group ? conn->client_group : SESSION_GROUP_DEVICE),
            FLB_LOG_EVENT_CSTRING_VALUE("log"),
            FLB_LOG_EVENT_STRING_VALUE(payload, payload_len));
    }
    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(ctx->log_encoder);
    }

    return ret == FLB_EVENT_ENCODER_SUCCESS ? 0 : -1;
}

static int process_event_batch(struct xsiam_agent_conn *conn,
                               const struct wzcp_header *h,
                               const unsigned char *body)
{
    uint16_t count;
    uint16_t payload_len;
    uint64_t event_id;
    uint32_t off = 2;
    uint32_t i;
    uint8_t kind;

    if (h->body_len < 2) {
        return -1;
    }

    count = get_be16(body);
    flb_log_event_encoder_reset(conn->ctx->log_encoder);

    for (i = 0; i < count; i++) {
        if (off + 20 > h->body_len) {
            return -1;
        }

        kind = body[off];
        event_id = get_be64(body + off + 10);
        payload_len = get_be16(body + off + 18);
        off += 20;

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

static ssize_t process_syslog_lines(struct xsiam_agent_conn *conn)
{
    int i;
    int line_start = 0;
    int line_len;
    size_t consumed = 0;

    flb_log_event_encoder_reset(conn->ctx->log_encoder);
    for (i = 0; i < conn->buf_len; i++) {
        if (conn->buf_data[i] != '\n') {
            continue;
        }

        line_len = i - line_start;
        if (line_len > 0 && conn->buf_data[line_start + line_len - 1] == '\r') {
            line_len--;
        }

        if (line_len > 0 &&
            append_syslog_record(conn, conn->buf_data + line_start,
                                 (uint16_t)line_len) < 0) {
            return -1;
        }

        consumed = (size_t)i + 1;
        line_start = i + 1;
    }

    if (conn->ctx->log_encoder->output_length > 0) {
        flb_input_log_append(conn->ctx->ins, NULL, 0,
                             conn->ctx->log_encoder->output_buffer,
                             conn->ctx->log_encoder->output_length);
    }

    return (ssize_t)consumed;
}

static ssize_t process_frames(struct xsiam_agent_conn *conn)
{
    uint32_t frame_len;
    struct wzcp_header h;
    unsigned char *body;
    size_t consumed = 0;
    int ret;

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
        return -1;
    }

    return 0;
}

static int conn_event(void *data);

static struct xsiam_agent_conn *conn_add(struct flb_connection *connection,
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
    conn->ctx = ctx;
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
    connection->user_data = conn;
    connection->event.type = FLB_ENGINE_EV_CUSTOM;
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

static int conn_del(struct xsiam_agent_conn *conn)
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

static int conn_event(void *data)
{
    int bytes;
    int available;
    int size;
    char *tmp;
    ssize_t processed;
    struct flb_connection *connection = data;
    struct xsiam_agent_conn *conn = connection->user_data;
    struct xsiam_agent_ctx *ctx = conn->ctx;
    struct mk_event *event = &connection->event;

    conn->busy = FLB_TRUE;

    if (event->mask & MK_EVENT_READ) {
        available = (conn->buf_size - conn->buf_len);
        if (available < 1) {
            if ((size_t)conn->buf_size + ctx->chunk_size > ctx->buffer_size) {
                conn->busy = FLB_FALSE;
                conn_del(conn);
                return -1;
            }
            size = conn->buf_size + (int)ctx->chunk_size;
            tmp = flb_realloc(conn->buf_data, size);
            if (!tmp) {
                conn->busy = FLB_FALSE;
                return -1;
            }
            conn->buf_data = tmp;
            conn->buf_size = size;
            available = conn->buf_size - conn->buf_len;
        }

        bytes = flb_io_net_read(connection, conn->buf_data + conn->buf_len,
                                available);
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

        consume_bytes(conn->buf_data, (size_t)processed, (size_t)conn->buf_len);
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

static int collect(struct flb_input_instance *in,
                   struct flb_config *config, void *in_context)
{
    struct flb_connection *connection;
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

static int heartbeat_collect(struct flb_input_instance *in,
                             struct flb_config *config, void *in_context)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct xsiam_agent_conn *conn;
    struct xsiam_agent_ctx *ctx = in_context;
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
        if (send_frame(conn, WZCP_MSG_HEARTBEAT, 0, ++ctx->gateway_seq, NULL, 0) != 0) {
            conn_del(conn);
        }
        else {
            schedule_next_heartbeat(conn);
        }
    }

    return 0;
}

static int db_collect(struct flb_input_instance *in,
                      struct flb_config *config, void *in_context)
{
    struct xsiam_agent_ctx *ctx = in_context;

    (void)in;
    (void)config;

    arango_flush_dirty_agents(ctx);
    return 0;
}

static int init(struct flb_input_instance *in,
                struct flb_config *config, void *data)
{
    int ret;
    char port[16];
    unsigned short int port_num;
    struct xsiam_agent_ctx *ctx;

    (void)data;

    ctx = flb_calloc(1, sizeof(struct xsiam_agent_ctx));
    if (!ctx) {
        return -1;
    }

    ctx->ins = in;
    ctx->collector_id = -1;
    ctx->heartbeat_collector_id = -1;
    ctx->db_collector_id = -1;
    ctx->gateway_seq = 0;
    ctx->session_seq = 0;
    ctx->rand_state = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)ctx;
    mk_list_init(&ctx->connections);
    mk_list_init(&ctx->agents);

    ret = flb_input_config_map_set(in, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    flb_input_net_default_listener("0.0.0.0", 1514, in);
    ctx->listen = in->host.listen;
    snprintf(port, sizeof(port) - 1, "%d", in->host.port);
    ctx->tcp_port = flb_strdup(port);
    port_num = (unsigned short int)strtoul(ctx->tcp_port, NULL, 10);

    ctx->chunk_size = ctx->chunk_size_str ? atoi(ctx->chunk_size_str) * 1024 : 32768;
    ctx->buffer_size = ctx->buffer_size_str ? atoi(ctx->buffer_size_str) * 1024 : ctx->chunk_size * 8;
    if (ctx->db_sync != FLB_FALSE) {
        ctx->db_sync = FLB_TRUE;
    }
    if (!ctx->arango_host) {
        ctx->arango_host = flb_strdup(XSIAM_DB_HOST);
    }
    if (!ctx->arango_user) {
        ctx->arango_user = flb_strdup(XSIAM_DB_USER);
    }
    if (!ctx->arango_pass) {
        ctx->arango_pass = flb_strdup(XSIAM_DB_PASS);
    }
    if (!ctx->arango_database) {
        ctx->arango_database = flb_strdup(XSIAM_DB_NAME);
    }
    if (ctx->arango_port <= 0) {
        ctx->arango_port = XSIAM_DB_PORT;
    }
    if (ctx->db_flush_interval <= 0) {
        ctx->db_flush_interval = XSIAM_DB_FLUSH_INTERVAL;
    }
    if (ctx->heartbeat_flush_interval <= 0) {
        ctx->heartbeat_flush_interval = XSIAM_DB_HEARTBEAT_FLUSH_INTERVAL;
    }
    if (ctx->heartbeat_min <= 0) {
        ctx->heartbeat_min = 60;
    }
    if (ctx->heartbeat_max <= 0) {
        ctx->heartbeat_max = 180;
    }
    if (ctx->heartbeat_max < ctx->heartbeat_min) {
        ctx->heartbeat_max = ctx->heartbeat_min;
    }

    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->log_encoder) {
        flb_free(ctx->tcp_port);
        flb_free(ctx);
        return -1;
    }

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                            in->flags,
                                            ctx->listen,
                                            port_num,
                                            in->tls,
                                            config,
                                            &in->net_setup);
    if (!ctx->downstream) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx->tcp_port);
        flb_free(ctx);
        return -1;
    }

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    ret = flb_input_set_collector_socket(in, collect,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_downstream_destroy(ctx->downstream);
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx->tcp_port);
        flb_free(ctx);
        return -1;
    }

    ctx->collector_id = ret;
    ret = flb_input_set_collector_time(in, heartbeat_collect, 1, 0, config);
    if (ret == -1) {
        flb_input_collector_delete(ctx->collector_id, ctx->ins);
        flb_downstream_destroy(ctx->downstream);
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx->tcp_port);
        flb_free(ctx);
        return -1;
    }

    ctx->heartbeat_collector_id = ret;
    if (ctx->db_sync) {
        ctx->arango_upstream = flb_upstream_create(config, ctx->arango_host,
                                                   ctx->arango_port,
                                                   FLB_IO_TCP | FLB_IO_TCP_KA,
                                                   NULL);
        if (!ctx->arango_upstream) {
            flb_input_collector_delete(ctx->heartbeat_collector_id, ctx->ins);
            flb_input_collector_delete(ctx->collector_id, ctx->ins);
            flb_downstream_destroy(ctx->downstream);
            flb_log_event_encoder_destroy(ctx->log_encoder);
            flb_free(ctx->tcp_port);
            flb_free(ctx);
            return -1;
        }

        ret = flb_input_set_collector_time(in, db_collect,
                                           ctx->db_flush_interval, 0,
                                           config);
        if (ret == -1) {
            flb_upstream_destroy(ctx->arango_upstream);
            flb_input_collector_delete(ctx->heartbeat_collector_id, ctx->ins);
            flb_input_collector_delete(ctx->collector_id, ctx->ins);
            flb_downstream_destroy(ctx->downstream);
            flb_log_event_encoder_destroy(ctx->log_encoder);
            flb_free(ctx->tcp_port);
            flb_free(ctx);
            return -1;
        }
        ctx->db_collector_id = ret;
    }
    flb_input_set_context(in, ctx);
    return 0;
}

static int exit_cb(void *data, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct xsiam_agent_conn *conn;
    struct xsiam_agent_state *st;
    struct xsiam_agent_ctx *ctx = data;

    (void)config;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct xsiam_agent_conn, _head);
        conn_del(conn);
    }

    if (ctx->collector_id != -1) {
        flb_input_collector_delete(ctx->collector_id, ctx->ins);
    }
    if (ctx->heartbeat_collector_id != -1) {
        flb_input_collector_delete(ctx->heartbeat_collector_id, ctx->ins);
    }
    if (ctx->db_collector_id != -1) {
        flb_input_collector_delete(ctx->db_collector_id, ctx->ins);
    }
    if (ctx->downstream) {
        flb_downstream_destroy(ctx->downstream);
    }
    if (ctx->arango_upstream) {
        arango_flush_dirty_agents(ctx);
        flb_upstream_destroy(ctx->arango_upstream);
    }
    if (ctx->log_encoder) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }
    mk_list_foreach_safe(head, tmp, &ctx->agents) {
        st = mk_list_entry(head, struct xsiam_agent_state, _head);
        mk_list_del(&st->_head);
        agent_state_destroy(st);
    }
    flb_free(ctx->tcp_port);
    flb_free(ctx->arango_host);
    flb_free(ctx->arango_user);
    flb_free(ctx->arango_pass);
    flb_free(ctx->arango_database);
    flb_free(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "chunk_size", (char *)NULL,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, chunk_size_str),
     "Set the chunk size in KB"
    },
    {
     FLB_CONFIG_MAP_STR, "buffer_size", (char *)NULL,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, buffer_size_str),
     "Set the per-connection buffer size in KB"
    },
    {
     FLB_CONFIG_MAP_INT, "heartbeat_min", "60",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, heartbeat_min),
     "Set minimum gateway-to-agent heartbeat interval in seconds"
    },
    {
     FLB_CONFIG_MAP_INT, "heartbeat_max", "180",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, heartbeat_max),
     "Set maximum gateway-to-agent heartbeat interval in seconds"
    },
    {
     FLB_CONFIG_MAP_BOOL, "db_sync", "true",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, db_sync),
     "Enable batched ArangoDB agent state synchronization"
    },
    {
     FLB_CONFIG_MAP_STR, "arango_host", XSIAM_DB_HOST,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_host),
     "Set ArangoDB host"
    },
    {
     FLB_CONFIG_MAP_INT, "arango_port", "8529",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_port),
     "Set ArangoDB port"
    },
    {
     FLB_CONFIG_MAP_STR, "arango_user", XSIAM_DB_USER,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_user),
     "Set ArangoDB username"
    },
    {
     FLB_CONFIG_MAP_STR, "arango_pass", XSIAM_DB_PASS,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_pass),
     "Set ArangoDB password"
    },
    {
     FLB_CONFIG_MAP_STR, "arango_database", XSIAM_DB_NAME,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_database),
     "Set ArangoDB database"
    },
    {
     FLB_CONFIG_MAP_INT, "db_flush_interval", "5",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, db_flush_interval),
     "Set dirty agent state flush interval in seconds"
    },
    {
     FLB_CONFIG_MAP_INT, "heartbeat_flush_interval", "180",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, heartbeat_flush_interval),
     "Set minimum interval for heartbeat-only database updates per agent"
    },
    {0}
};

struct flb_input_plugin in_xsiam_agent_plugin = {
    .name         = "xsiam_agent",
    .description  = "XSIAM WZCP agent gateway",
    .cb_init      = init,
    .cb_pre_run   = NULL,
    .cb_collect   = collect,
    .cb_flush_buf = NULL,
    .cb_pause     = NULL,
    .cb_resume    = NULL,
    .cb_exit      = exit_cb,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
