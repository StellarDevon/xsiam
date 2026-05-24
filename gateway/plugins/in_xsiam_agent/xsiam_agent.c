/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * in_xsiam_agent — fluent-bit INPUT plugin
 *
 * Accepts WZCP (proprietary XSIAM agent protocol) and syslog over TCP.
 * Maintains an in-memory agent state cache, flushed to ArangoDB in batches.
 * Posts lifecycle events (connect / heartbeat / disconnect) to the xsiam
 * internal API for real-time distributed presence tracking.
 *
 * Source layout
 * ─────────────
 *   xsiam_agent_defs.h   — constants, structs, inline wire helpers
 *   xsiam_agent_state.*  — agent in-memory state machine
 *   xsiam_agent_conn.*   — TCP connection management + WZCP/syslog dispatch
 *   xsiam_agent_arango.* — ArangoDB batched upsert
 *   xsiam_agent_event.*  — UUID, POST /internal/agent/event, fb lease
 *   xsiam_agent.c        — plugin entry: cb_init, cb_exit, config_map (this file)
 */

#include "xsiam_agent_defs.h"
#include "xsiam_agent_conn.h"
#include "xsiam_agent_arango.h"
#include "xsiam_agent_event.h"
#include "xsiam_agent_state.h"

#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_mem.h>

#include <stddef.h>   /* offsetof */
#include <string.h>

/* ── cb_init ────────────────────────────────────────────────────────────── */

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

    ctx->ins                    = in;
    ctx->collector_id           = -1;
    ctx->heartbeat_collector_id = -1;
    ctx->db_collector_id        = -1;
    ctx->fb_lease_collector_id  = -1;
    ctx->rand_state = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)ctx;
    mk_list_init(&ctx->connections);
    mk_list_init(&ctx->agents);

    /* Apply config_map values from .conf file */
    ret = flb_input_config_map_set(in, ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Resolve listening address */
    flb_input_net_default_listener("0.0.0.0", 1514, in);
    ctx->listen = in->host.listen;
    snprintf(port, sizeof(port) - 1, "%d", in->host.port);
    ctx->tcp_port = flb_strdup(port);
    port_num = (unsigned short int)strtoul(ctx->tcp_port, NULL, 10);

    /* Buffer sizing */
    ctx->chunk_size  = ctx->chunk_size_str
                       ? (size_t)atoi(ctx->chunk_size_str)  * 1024 : 32768;
    ctx->buffer_size = ctx->buffer_size_str
                       ? (size_t)atoi(ctx->buffer_size_str) * 1024
                       : ctx->chunk_size * 8;

    /* ArangoDB defaults */
    if (ctx->db_sync != FLB_FALSE) {
        ctx->db_sync = FLB_TRUE;
    }
    if (!ctx->arango_host)     { ctx->arango_host     = flb_strdup(XSIAM_DB_HOST); }
    if (!ctx->arango_user)     { ctx->arango_user     = flb_strdup(XSIAM_DB_USER); }
    if (!ctx->arango_pass)     { ctx->arango_pass     = flb_strdup(XSIAM_DB_PASS); }
    if (!ctx->arango_database) { ctx->arango_database = flb_strdup(XSIAM_DB_NAME); }
    if (ctx->arango_port          <= 0) { ctx->arango_port          = XSIAM_DB_PORT; }
    if (ctx->db_flush_interval    <= 0) { ctx->db_flush_interval    = XSIAM_DB_FLUSH_INTERVAL; }
    if (ctx->heartbeat_flush_interval <= 0) {
        ctx->heartbeat_flush_interval = XSIAM_DB_HEARTBEAT_FLUSH_INTERVAL;
    }

    /* Heartbeat jitter */
    if (ctx->heartbeat_min <= 0) { ctx->heartbeat_min = 60; }
    if (ctx->heartbeat_max <= 0) { ctx->heartbeat_max = 180; }
    if (ctx->heartbeat_max < ctx->heartbeat_min) {
        ctx->heartbeat_max = ctx->heartbeat_min;
    }

    /* Generate stable fb_instance_id for this process lifetime */
    gen_uuid_v4(ctx->fb_instance_id, &ctx->rand_state);
    flb_plg_info(ctx->ins, "fb_instance_id=%s", ctx->fb_instance_id);

    /* Event endpoint — only enabled when event_host is explicitly set */
    if (ctx->event_host && ctx->event_host[0]) {
        if (ctx->event_port <= 0) {
            ctx->event_port = XSIAM_EVENT_PORT;
        }
        ctx->event_enabled = FLB_TRUE;
    }

    /* Log encoder */
    ctx->log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (!ctx->log_encoder) {
        flb_free(ctx->tcp_port);
        flb_free(ctx);
        return -1;
    }

    /* TCP downstream (listen socket) */
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

    /* Collector: accept new connections */
    ret = flb_input_set_collector_socket(in, collect,
                                         ctx->downstream->server_fd, config);
    if (ret == -1) {
        flb_downstream_destroy(ctx->downstream);
        flb_log_event_encoder_destroy(ctx->log_encoder);
        flb_free(ctx->tcp_port);
        flb_free(ctx);
        return -1;
    }
    ctx->collector_id = ret;

    /* Collector: gateway heartbeat (every 1 s) */
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

    /* Collector: ArangoDB flush (every db_flush_interval s) */
    if (ctx->db_sync) {
        ctx->arango_upstream = flb_upstream_create(config,
                                                   ctx->arango_host,
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
                                           ctx->db_flush_interval, 0, config);
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

    /* Event upstream + fb lease collector */
    if (ctx->event_enabled) {
        ctx->event_upstream = flb_upstream_create(config,
                                                  ctx->event_host,
                                                  ctx->event_port,
                                                  FLB_IO_TCP,
                                                  NULL);
        if (!ctx->event_upstream) {
            flb_plg_warn(ctx->ins,
                         "failed to create event upstream %s:%d"
                         " — presence disabled",
                         ctx->event_host, ctx->event_port);
            ctx->event_enabled = FLB_FALSE;
        }
        else {
            flb_input_upstream_set(ctx->event_upstream, ctx->ins);

            ret = flb_input_set_collector_time(in, fb_lease_collect,
                                               XSIAM_FB_LEASE_INTERVAL, 0,
                                               config);
            if (ret == -1) {
                flb_plg_warn(ctx->ins, "failed to register fb_lease collector");
            }
            else {
                ctx->fb_lease_collector_id = ret;
            }
            flb_plg_info(ctx->ins, "event upstream ready %s:%d",
                         ctx->event_host, ctx->event_port);
        }
    }

    flb_input_set_context(in, ctx);
    return 0;
}

/* ── cb_exit ────────────────────────────────────────────────────────────── */

static int exit_cb(void *data, struct flb_config *config)
{
    struct mk_list         *tmp;
    struct mk_list         *head;
    struct xsiam_agent_conn  *conn;
    struct xsiam_agent_state *st;
    struct xsiam_agent_ctx   *ctx = data;

    (void)config;

    /* Close all active connections (triggers disconnect events) */
    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct xsiam_agent_conn, _head);
        conn_del(conn);
    }

    /* Deregister collectors */
    if (ctx->collector_id           != -1) { flb_input_collector_delete(ctx->collector_id,           ctx->ins); }
    if (ctx->heartbeat_collector_id != -1) { flb_input_collector_delete(ctx->heartbeat_collector_id, ctx->ins); }
    if (ctx->db_collector_id        != -1) { flb_input_collector_delete(ctx->db_collector_id,        ctx->ins); }
    if (ctx->fb_lease_collector_id  != -1) { flb_input_collector_delete(ctx->fb_lease_collector_id,  ctx->ins); }

    /* Destroy downstream / upstreams */
    if (ctx->downstream) {
        flb_downstream_destroy(ctx->downstream);
    }
    if (ctx->arango_upstream) {
        arango_flush_dirty_agents(ctx);   /* last flush before shutdown */
        flb_upstream_destroy(ctx->arango_upstream);
    }
    if (ctx->event_upstream) {
        flb_upstream_destroy(ctx->event_upstream);
    }

    /* Destroy log encoder */
    if (ctx->log_encoder) {
        flb_log_event_encoder_destroy(ctx->log_encoder);
    }

    /* Free agent state list */
    mk_list_foreach_safe(head, tmp, &ctx->agents) {
        st = mk_list_entry(head, struct xsiam_agent_state, _head);
        mk_list_del(&st->_head);
        agent_state_destroy(st);
    }

    /* Free config strings */
    flb_free(ctx->tcp_port);
    flb_free(ctx->arango_host);
    flb_free(ctx->arango_user);
    flb_free(ctx->arango_pass);
    flb_free(ctx->arango_database);
    flb_free(ctx->tenant_id);
    flb_free(ctx->event_host);
    flb_free(ctx);
    return 0;
}

/* ── config_map ─────────────────────────────────────────────────────────── */

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR,  "chunk_size",  (char *)NULL,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, chunk_size_str),
     "Per-connection read buffer chunk size in KB"
    },
    {
     FLB_CONFIG_MAP_STR,  "buffer_size", (char *)NULL,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, buffer_size_str),
     "Maximum per-connection buffer size in KB"
    },
    {
     FLB_CONFIG_MAP_INT,  "heartbeat_min", "60",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, heartbeat_min),
     "Minimum gateway→agent heartbeat interval (seconds)"
    },
    {
     FLB_CONFIG_MAP_INT,  "heartbeat_max", "180",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, heartbeat_max),
     "Maximum gateway→agent heartbeat interval (seconds)"
    },
    {
     FLB_CONFIG_MAP_BOOL, "db_sync", "true",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, db_sync),
     "Enable batched ArangoDB agent-state sync"
    },
    {
     FLB_CONFIG_MAP_STR,  "arango_host", XSIAM_DB_HOST,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_host),
     "ArangoDB host"
    },
    {
     FLB_CONFIG_MAP_INT,  "arango_port", "8529",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_port),
     "ArangoDB port"
    },
    {
     FLB_CONFIG_MAP_STR,  "arango_user", XSIAM_DB_USER,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_user),
     "ArangoDB username"
    },
    {
     FLB_CONFIG_MAP_STR,  "arango_pass", XSIAM_DB_PASS,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_pass),
     "ArangoDB password"
    },
    {
     FLB_CONFIG_MAP_STR,  "arango_database", XSIAM_DB_NAME,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, arango_database),
     "ArangoDB database"
    },
    {
     FLB_CONFIG_MAP_INT,  "db_flush_interval", "5",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, db_flush_interval),
     "Dirty-state flush interval to ArangoDB (seconds)"
    },
    {
     FLB_CONFIG_MAP_INT,  "heartbeat_flush_interval", "180",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, heartbeat_flush_interval),
     "Minimum interval for heartbeat-only ArangoDB updates per agent (seconds)"
    },
    {
     FLB_CONFIG_MAP_STR,  "tenant_id", "tenant-default",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, tenant_id),
     "Tenant ID written to every agent document"
    },
    {
     FLB_CONFIG_MAP_STR,  "event_host", (char *)NULL,
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, event_host),
     "xsiam internal-API host for agent lifecycle events (empty = disabled)"
    },
    {
     FLB_CONFIG_MAP_INT,  "event_port", "18090",
     0, FLB_TRUE, offsetof(struct xsiam_agent_ctx, event_port),
     "xsiam internal-API port for agent lifecycle events"
    },
    {0}
};

/* ── Plugin descriptor ──────────────────────────────────────────────────── */

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
