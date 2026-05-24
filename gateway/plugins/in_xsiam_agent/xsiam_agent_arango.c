/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "xsiam_agent_arango.h"

#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <stdio.h>
#include <string.h>

/* ── JSON serialisation helpers (private to this file) ─────────────────── */

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

static void append_json_string_field(flb_sds_t *s,
                                     const char *name,
                                     const char *value)
{
    *s = flb_sds_cat(*s, "\"",   1);
    *s = flb_sds_cat(*s, name,   strlen(name));
    *s = flb_sds_cat(*s, "\":\"", 3);
    json_escape_append(s, value);
    *s = flb_sds_cat(*s, "\"",   1);
}

static void append_json_time_field(flb_sds_t *s,
                                   const char *name,
                                   time_t value)
{
    char buf[32];
    struct tm tm;

    gmtime_r(&value, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    append_json_string_field(s, name, buf);
}

/* ── Document builder ────────────────────────────────────────────────── */

static void append_agent_doc(flb_sds_t *s, struct xsiam_agent_state *st)
{
    const char *connected_json;
    flb_sds_t device_key;

    device_key = flb_sds_create("device-");
    if (device_key) {
        device_key = flb_sds_cat(device_key, st->agent_id, strlen(st->agent_id));
    }

    *s = flb_sds_cat(*s, "{", 1);
    append_json_string_field(s, "_key",      device_key ? device_key : st->agent_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "device_id", device_key ? device_key : st->agent_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "tenant_id",     st->tenant_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "agent_id",      st->agent_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "gateway_id",    st->gateway_id);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "hostname",      st->hostname);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "host_type",     st->host_type);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "ip",            st->ip);
    *s = flb_sds_cat(*s, ",\"ip_addresses\":[],\"mac_addresses\":",
                     strlen(",\"ip_addresses\":[],\"mac_addresses\":"));
    *s = flb_sds_cat(*s, st->mac_addresses_json,
                     flb_sds_len(st->mac_addresses_json));
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "os_type",       "windows");
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "os_version",    "");
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "agent_version", st->agent_version);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_string_field(s, "agent_status",  st->agent_status);

    connected_json = st->is_connected
                     ? ",\"is_connected\":true,"
                     : ",\"is_connected\":false,";
    *s = flb_sds_cat(*s, connected_json, strlen(connected_json));

    append_json_string_field(s, "protocol", "wzcp");
    *s = flb_sds_cat(*s, ",\"protocol_version\":1,",
                     strlen(",\"protocol_version\":1,"));
    append_json_time_field(s, "installed_at",   st->installed_at);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "enrolled_at",    st->installed_at);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "last_heartbeat", st->last_heartbeat);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "last_seen",      st->last_seen);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "created_at",     st->created_at);
    *s = flb_sds_cat(*s, ",", 1);
    append_json_time_field(s, "updated_at",     st->updated_at);
    *s = flb_sds_cat(*s, "}", 1);

    flb_sds_destroy(device_key);
}

/* ── Payload builder ─────────────────────────────────────────────────── */

static flb_sds_t build_arango_payload(struct xsiam_agent_ctx *ctx,
                                      int *doc_count)
{
    struct mk_list *head;
    struct xsiam_agent_state *st;
    flb_sds_t s;
    int count = 0;

    s = flb_sds_create_size(4096);
    if (!s) {
        return NULL;
    }

    /* AQL UPSERT: insert new doc or merge fields into existing one */
    s = flb_sds_cat(s,
        "{\"query\":\"FOR doc IN @devices "
        "UPSERT {agent_id: doc.agent_id} "
        "INSERT doc "
        "UPDATE MERGE(OLD, UNSET(doc, '_key')) IN devices\","
        "\"bindVars\":{\"devices\":[",
        strlen("{\"query\":\"FOR doc IN @devices "
               "UPSERT {agent_id: doc.agent_id} "
               "INSERT doc "
               "UPDATE MERGE(OLD, UNSET(doc, '_key')) IN devices\","
               "\"bindVars\":{\"devices\":["));

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

/* ── Public flush ────────────────────────────────────────────────────── */

int arango_flush_dirty_agents(struct xsiam_agent_ctx *ctx)
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
                st->dirty       = FLB_FALSE;
                st->last_db_flush = now_sec();
            }
        }
    }
    else {
        flb_plg_warn(ctx->ins,
                     "arango flush: %d agent(s) failed status=%d",
                     count, c->resp.status);
        ret = -1;
    }

    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);
    flb_sds_destroy(payload);
    return ret;
}

/* ── Collector callback ──────────────────────────────────────────────── */

int db_collect(struct flb_input_instance *in,
               struct flb_config *config,
               void *in_context)
{
    struct xsiam_agent_ctx *ctx = in_context;

    (void)in;
    (void)config;

    arango_flush_dirty_agents(ctx);
    return 0;
}
