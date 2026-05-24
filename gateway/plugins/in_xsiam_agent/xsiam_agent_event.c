/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "xsiam_agent_event.h"

#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <stdio.h>
#include <string.h>

/* ── UUID v4 ──────────────────────────────────────────────────────────── */

void gen_uuid_v4(char *out, unsigned int *rand_state)
{
    unsigned char b[16];
    int i;

    for (i = 0; i < 16; i++) {
        /* Simple LCG — avoids pulling in extra randomness dependencies */
        *rand_state = *rand_state * 1664525u + 1013904223u;
        b[i] = (unsigned char)(*rand_state >> 16);
    }
    /* Version 4 and RFC 4122 variant bits */
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;

    snprintf(out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x%02x%02x%02x%02x",
             b[0],  b[1],  b[2],  b[3],
             b[4],  b[5],
             b[6],  b[7],
             b[8],  b[9],
             b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* ── Event posting ────────────────────────────────────────────────────── */

void post_agent_event(struct xsiam_agent_ctx *ctx,
                      const char *event,
                      const char *agent_id)
{
    flb_sds_t body;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    size_t b_sent = 0;
    const char *tenant;

    if (!ctx->event_enabled || !ctx->event_upstream) {
        return;
    }

    tenant = ctx->tenant_id && ctx->tenant_id[0]
             ? ctx->tenant_id : "tenant-default";

    /* Build compact JSON body */
    body = flb_sds_create_size(256);
    if (!body) {
        return;
    }
    body = flb_sds_cat(body, "{\"event\":\"",         10);
    body = flb_sds_cat(body, event, strlen(event));
    body = flb_sds_cat(body, "\",\"fb_instance_id\":\"", 20);
    body = flb_sds_cat(body, ctx->fb_instance_id,
                       strlen(ctx->fb_instance_id));
    body = flb_sds_cat(body, "\",\"tenant_id\":\"",    15);
    body = flb_sds_cat(body, tenant, strlen(tenant));
    if (agent_id && agent_id[0]) {
        body = flb_sds_cat(body, "\",\"agent_id\":\"",  14);
        body = flb_sds_cat(body, agent_id, strlen(agent_id));
    }
    body = flb_sds_cat(body, "\"}", 2);

    u_conn = flb_upstream_conn_get(ctx->event_upstream);
    if (!u_conn) {
        flb_sds_destroy(body);
        return;
    }

    c = flb_http_client(u_conn, FLB_HTTP_POST, XSIAM_EVENT_PATH,
                        body, flb_sds_len(body),
                        NULL, 0, NULL, 0);
    if (!c) {
        flb_upstream_conn_release(u_conn);
        flb_sds_destroy(body);
        return;
    }

    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    flb_http_do(c, &b_sent);

    if (c->resp.status != 0 &&
        c->resp.status != 200 &&
        c->resp.status != 204) {
        flb_plg_debug(ctx->ins,
                      "agent event '%s' status=%d", event, c->resp.status);
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    flb_sds_destroy(body);
}

/* ── fb lease collector ───────────────────────────────────────────────── */

int fb_lease_collect(struct flb_input_instance *in,
                     struct flb_config *config,
                     void *in_context)
{
    struct xsiam_agent_ctx *ctx = in_context;

    (void)in;
    (void)config;

    post_agent_event(ctx, "fb_heartbeat", NULL);
    return 0;
}
