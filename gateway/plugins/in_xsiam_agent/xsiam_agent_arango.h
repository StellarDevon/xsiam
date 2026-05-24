/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * xsiam_agent_arango.h — batched ArangoDB agent-state upsert
 *
 * Dirty agent-state entries are flushed to ArangoDB every
 * db_flush_interval seconds via the db_collect() fluent-bit collector.
 * Uses AQL UPSERT through the /_api/cursor HTTP endpoint.
 */

#ifndef XSIAM_AGENT_ARANGO_H
#define XSIAM_AGENT_ARANGO_H

#include "xsiam_agent_defs.h"

/*
 * Flush all dirty xsiam_agent_state entries to ArangoDB.
 * No-op if db_sync is disabled or arango_upstream is NULL.
 * Clears the dirty flag on success.
 * Returns 0 on success (or nothing to flush), -1 on error.
 */
int arango_flush_dirty_agents(struct xsiam_agent_ctx *ctx);

/*
 * Fluent-bit input collector callback — called every db_flush_interval.
 */
int db_collect(struct flb_input_instance *in,
               struct flb_config *config,
               void *in_context);

#endif /* XSIAM_AGENT_ARANGO_H */
