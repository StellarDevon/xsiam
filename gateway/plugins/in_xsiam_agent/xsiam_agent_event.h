/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * xsiam_agent_event.h — UUID generation, agent lifecycle event posting,
 *                        and fluent-bit instance lease renewal.
 *
 * These functions implement the real-time distributed presence protocol:
 *   - connect / heartbeat / disconnect events → POST /internal/agent/event
 *   - fb_heartbeat (no agent_id) every XSIAM_FB_LEASE_INTERVAL seconds
 *     keeps the Redis lease key alive so the GC knows this fb is running.
 */

#ifndef XSIAM_AGENT_EVENT_H
#define XSIAM_AGENT_EVENT_H

#include "xsiam_agent_defs.h"

/*
 * Generate a UUID v4 string into out[37].
 * Uses rand_state (LCG) — no external dep required.
 */
void gen_uuid_v4(char *out, unsigned int *rand_state);

/*
 * Fire-and-forget POST /internal/agent/event.
 *
 *   event    — "connect" | "heartbeat" | "disconnect" | "fb_heartbeat"
 *   agent_id — agent identifier; may be NULL for "fb_heartbeat"
 *
 * No-op when ctx->event_enabled is false or event_upstream is NULL.
 * HTTP errors are logged at debug level and silently ignored.
 */
void post_agent_event(struct xsiam_agent_ctx *ctx,
                      const char *event,
                      const char *agent_id);

/*
 * Fluent-bit input collector callback — runs every XSIAM_FB_LEASE_INTERVAL.
 * Posts a "fb_heartbeat" event so the Go server can renew the Redis lease
 * key for this fb instance.  When this stops arriving (process died),
 * the Go GC sweep will mark all agents for this fb instance offline.
 */
int fb_lease_collect(struct flb_input_instance *in,
                     struct flb_config *config,
                     void *in_context);

#endif /* XSIAM_AGENT_EVENT_H */
