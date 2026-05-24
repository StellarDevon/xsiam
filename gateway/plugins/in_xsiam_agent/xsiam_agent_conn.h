/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * xsiam_agent_conn.h — TCP connection management + protocol dispatch
 *
 * conn_add() / conn_del() manage xsiam_agent_conn lifecycle.
 * conn_event() is the mk_event callback registered for each connection fd;
 * it dispatches to process_frames() (WZCP) or process_syslog_lines().
 *
 * Two fluent-bit input collector callbacks live here:
 *   collect()           — accept new TCP connections from the downstream fd
 *   heartbeat_collect() — send gateway-initiated WZCP heartbeats
 */

#ifndef XSIAM_AGENT_CONN_H
#define XSIAM_AGENT_CONN_H

#include "xsiam_agent_defs.h"

/* Create and register a new connection for an accepted fd. */
struct xsiam_agent_conn *conn_add(struct flb_connection *connection,
                                  struct xsiam_agent_ctx *ctx);

/* Tear down a connection, marking the agent offline if needed. */
int conn_del(struct xsiam_agent_conn *conn);

/* mk_event handler — read data, dispatch to protocol handler. */
int conn_event(void *data);

/* Fluent-bit collector: accept new TCP connections. */
int collect(struct flb_input_instance *in,
            struct flb_config *config,
            void *in_context);

/* Fluent-bit collector: send gateway heartbeats to connected WZCP agents. */
int heartbeat_collect(struct flb_input_instance *in,
                      struct flb_config *config,
                      void *in_context);

#endif /* XSIAM_AGENT_CONN_H */
