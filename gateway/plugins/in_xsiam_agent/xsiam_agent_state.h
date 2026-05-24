/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * xsiam_agent_state.h — agent in-memory state machine
 *
 * Tracks per-agent state (hostname, version, online/offline, heartbeat
 * timestamps) in an mk_list hung off xsiam_agent_ctx.agents.
 * Dirty entries are flushed to ArangoDB by xsiam_agent_arango.
 */

#ifndef XSIAM_AGENT_STATE_H
#define XSIAM_AGENT_STATE_H

#include "xsiam_agent_defs.h"

/*
 * Look up (or optionally create) the state entry for agent_id.
 * Returns NULL on allocation failure.
 */
struct xsiam_agent_state *agent_state_get(struct xsiam_agent_ctx *ctx,
                                          const char *agent_id,
                                          int create);

/* Free all memory owned by st (does NOT remove from list). */
void agent_state_destroy(struct xsiam_agent_state *st);

/*
 * Called on WZCP HELLO: registers the agent as online, updates
 * hostname / version / MACs, sets conn->agent_key, posts "connect"
 * event to xsiam.
 */
void agent_state_mark_seen(struct xsiam_agent_ctx *ctx,
                           const char *agent_id,
                           const char *agent_name,
                           const char *agent_version,
                           const char *host_type,
                           flb_sds_t   mac_addresses_json,
                           struct xsiam_agent_conn *conn);

/*
 * Called on WZCP HEARTBEAT or EVENT_BATCH: refreshes last_seen /
 * last_heartbeat, posts "heartbeat" event to xsiam.
 */
void agent_state_mark_heartbeat(struct xsiam_agent_ctx *ctx,
                                const char *agent_id);

/*
 * Called when TCP connection closes: flips status→offline, posts
 * "disconnect" event to xsiam.
 */
void agent_state_mark_disconnected(struct xsiam_agent_ctx *ctx,
                                   const char *agent_id);

#endif /* XSIAM_AGENT_STATE_H */
