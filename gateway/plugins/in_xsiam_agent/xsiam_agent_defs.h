/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * xsiam_agent_defs.h — shared constants, structs, and inline utilities
 *
 * All other translation units in in_xsiam_agent include this header.
 * Nothing from fluent-bit internals is exposed here except the types
 * that must be visible in struct members.
 */

#ifndef XSIAM_AGENT_DEFS_H
#define XSIAM_AGENT_DEFS_H

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_io.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_sds.h>

#include <stdint.h>
#include <time.h>

/* ── WZCP wire protocol ────────────────────────────────────────────────── */

#define WZCP_MAGIC        0x575A4350u
#define WZCP_VERSION      1
#define WZCP_HEADER_SIZE  32
#define WZCP_MAX_FRAME    (1024u * 1024u)

#define WZCP_MSG_HELLO       1
#define WZCP_MSG_EVENT_BATCH 2
#define WZCP_MSG_ACK         3
#define WZCP_MSG_HEARTBEAT   4
#define WZCP_MSG_CONTROL     5
#define WZCP_MSG_ERROR       6

/* ── WZCP header struct ────────────────────────────────────────────────── */

/*
 * Unpacked representation of a WZCP frame header (32 bytes on the wire).
 * Used by unpack_header() in xsiam_agent_conn.c.
 */
struct wzcp_header {
    uint32_t magic;
    uint8_t  version;
    uint8_t  header_len;
    uint8_t  flags;
    uint8_t  msg_type;
    uint32_t agent_id;
    uint64_t seq;
    uint64_t timestamp_ms;
    uint32_t body_len;
};

/* ── ArangoDB defaults ─────────────────────────────────────────────────── */

#define XSIAM_DB_HOST                    "127.0.0.1"
#define XSIAM_DB_PORT                    8529
#define XSIAM_DB_USER                    "root"
#define XSIAM_DB_PASS                    "changeme"
#define XSIAM_DB_NAME                    "xsiamdb"
#define XSIAM_DB_FLUSH_INTERVAL          5
#define XSIAM_DB_HEARTBEAT_FLUSH_INTERVAL 180

/* ── xsiam internal-API defaults ───────────────────────────────────────── */

#define XSIAM_EVENT_HOST        "127.0.0.1"
#define XSIAM_EVENT_PORT        18090
#define XSIAM_EVENT_PATH        "/internal/agent/event"
#define XSIAM_FB_LEASE_INTERVAL 10   /* renew fb lease every 10 s */

/* ── Session classification tags ──────────────────────────────────────── */

#define SESSION_PROTO_UNKNOWN    "unknown"
#define SESSION_PROTO_AGENT_WZCP "agent_wzcp"
#define SESSION_PROTO_SYSLOG     "syslog"
#define SESSION_GROUP_UNKNOWN    "unknown"
#define SESSION_GROUP_AGENT      "agent"
#define SESSION_GROUP_DEVICE     "device"

/* ── Core structs ──────────────────────────────────────────────────────── */

/*
 * Plugin-wide context: one per INPUT instance.
 * Owns all configuration, upstreams, and the agent / connection lists.
 */
struct xsiam_agent_ctx {
    /* Network listener (set by flb_input_net_default_listener) */
    char *listen;
    char *tcp_port;

    /* ArangoDB connection */
    char *arango_host;
    char *arango_user;
    char *arango_pass;
    char *arango_database;
    int   arango_port;
    int   db_sync;
    int   db_flush_interval;
    int   heartbeat_flush_interval;

    /* xsiam internal API — agent lifecycle events + fb lease */
    char *event_host;
    int   event_port;
    int   event_enabled;       /* FLB_TRUE only when event_host is set */
    char  fb_instance_id[37];  /* UUID v4 generated at init */

    /* Tenant routing */
    char *tenant_id;

    /* Buffer sizing (from config map, stored as strings then parsed) */
    flb_sds_t chunk_size_str;
    flb_sds_t buffer_size_str;
    size_t    chunk_size;
    size_t    buffer_size;

    /* Gateway-side heartbeat cadence */
    int heartbeat_min;
    int heartbeat_max;

    /* Fluent-bit collector IDs (-1 = not registered) */
    int collector_id;
    int heartbeat_collector_id;
    int db_collector_id;
    int fb_lease_collector_id;

    /* Sequence counters */
    uint64_t gateway_seq;
    uint64_t session_seq;
    unsigned int rand_state;

    /* Fluent-bit objects */
    struct flb_downstream        *downstream;
    struct flb_upstream          *arango_upstream;
    struct flb_upstream          *event_upstream;
    struct flb_input_instance    *ins;
    struct flb_log_event_encoder *log_encoder;

    /* Runtime lists */
    struct mk_list connections;   /* xsiam_agent_conn */
    struct mk_list agents;        /* xsiam_agent_state */
};

/*
 * Per-TCP-connection state.
 * Created in conn_add(), destroyed in conn_del().
 */
struct xsiam_agent_conn {
    struct flb_connection    *connection;
    struct xsiam_agent_ctx   *ctx;
    char   *buf_data;
    int     buf_len;
    int     buf_size;
    int     busy;
    int     pending_close;
    time_t  next_heartbeat;
    char   *agent_key;      /* set after a successful HELLO */
    char   *protocol_tag;   /* e.g. SESSION_PROTO_AGENT_WZCP */
    char   *client_group;   /* e.g. SESSION_GROUP_AGENT */
    char    session_id[64]; /* "session-N" */
    struct mk_list _head;
};

/*
 * In-memory agent state cache.
 * One entry per unique agent_id seen on this fluent-bit instance.
 * Flushed to ArangoDB in batches by arango_flush_dirty_agents().
 */
struct xsiam_agent_state {
    char     *agent_id;
    char     *tenant_id;
    char     *hostname;
    char     *host_type;
    char     *agent_version;
    char     *agent_status;
    char     *gateway_id;
    char     *ip;
    flb_sds_t mac_addresses_json;
    int       is_connected;
    time_t    installed_at;
    time_t    connected_at;
    time_t    last_heartbeat;
    time_t    last_seen;
    time_t    created_at;
    time_t    updated_at;
    time_t    last_db_flush;
    int       dirty;          /* needs ArangoDB write */
    struct mk_list _head;
};

/* ── Inline wire helpers (used across multiple .c files) ───────────────── */

static inline uint16_t get_be16(const unsigned char *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static inline uint32_t get_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static inline uint64_t get_be64(const unsigned char *p)
{
    return ((uint64_t)get_be32(p) << 32) | get_be32(p + 4);
}

static inline void put_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static inline void put_be64(unsigned char *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

/* ── String helpers (header-only, used by multiple .c files) ───────────── */

#include <fluent-bit/flb_mem.h>   /* flb_strdup / flb_free / flb_calloc */
#include <string.h>

static inline char *xstrdup(const char *s)
{
    return flb_strdup(s ? s : "");
}

static inline void replace_str(char **dst, const char *src)
{
    char *tmp = xstrdup(src);
    if (tmp) {
        flb_free(*dst);
        *dst = tmp;
    }
}

static inline time_t now_sec(void)
{
    return time(NULL);
}

#endif /* XSIAM_AGENT_DEFS_H */
