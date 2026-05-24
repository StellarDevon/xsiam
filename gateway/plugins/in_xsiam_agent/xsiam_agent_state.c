/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "xsiam_agent_state.h"
#include "xsiam_agent_event.h"   /* post_agent_event */

#include <fluent-bit/flb_mem.h>
#include <string.h>

/* ── Internal lookup / create ─────────────────────────────────────────── */

struct xsiam_agent_state *agent_state_get(struct xsiam_agent_ctx *ctx,
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

    st->agent_id         = xstrdup(agent_id);
    st->tenant_id        = xstrdup(ctx->tenant_id && ctx->tenant_id[0]
                                   ? ctx->tenant_id : "tenant-default");
    st->hostname         = xstrdup(agent_id);
    st->host_type        = xstrdup("pc");
    st->agent_version    = xstrdup("unknown");
    st->agent_status     = xstrdup("online");
    st->gateway_id       = xstrdup("gateway-local-001");
    st->ip               = xstrdup("");
    st->mac_addresses_json = flb_sds_create("[]");
    st->installed_at     = now;
    st->created_at       = now;
    st->updated_at       = now;
    st->last_seen        = now;
    st->last_heartbeat   = now;
    st->dirty            = FLB_TRUE;
    mk_list_add(&st->_head, &ctx->agents);
    return st;
}

/* ── Destroy ──────────────────────────────────────────────────────────── */

void agent_state_destroy(struct xsiam_agent_state *st)
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

/* ── State transitions ────────────────────────────────────────────────── */

void agent_state_mark_seen(struct xsiam_agent_ctx *ctx,
                           const char *agent_id,
                           const char *agent_name,
                           const char *agent_version,
                           const char *host_type,
                           flb_sds_t   mac_addresses_json,
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

    replace_str(&st->hostname,
                agent_name && agent_name[0] ? agent_name : agent_id);
    replace_str(&st->agent_version,
                agent_version && agent_version[0] ? agent_version : "unknown");

    if (host_type &&
        (strcmp(host_type, "server") == 0 || strcmp(host_type, "pc") == 0)) {
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
    st->is_connected   = FLB_TRUE;
    st->connected_at   = now;
    st->last_seen      = now;
    st->last_heartbeat = now;
    st->updated_at     = now;
    st->dirty          = FLB_TRUE;

    if (conn) {
        replace_str(&conn->agent_key, agent_id);
    }

    /* Notify xsiam: real-time presence connect */
    post_agent_event(ctx, "connect", agent_id);
}

void agent_state_mark_heartbeat(struct xsiam_agent_ctx *ctx,
                                const char *agent_id)
{
    struct xsiam_agent_state *st;
    time_t now = now_sec();

    st = agent_state_get(ctx, agent_id, FLB_FALSE);
    if (!st) {
        return;
    }

    st->last_heartbeat = now;
    st->last_seen      = now;
    st->updated_at     = now;
    if (now - st->last_db_flush >= ctx->heartbeat_flush_interval) {
        st->dirty = FLB_TRUE;
    }

    /* Notify xsiam: presence TTL refresh */
    post_agent_event(ctx, "heartbeat", agent_id);
}

void agent_state_mark_disconnected(struct xsiam_agent_ctx *ctx,
                                   const char *agent_id)
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
        st->last_seen  = now;
        st->updated_at = now;
        st->dirty      = FLB_TRUE;

        /* Notify xsiam: presence removal */
        post_agent_event(ctx, "disconnect", agent_id);
    }
}
