set(src
  xsiam_agent.c
  xsiam_agent_state.c
  xsiam_agent_conn.c
  xsiam_agent_arango.c
  xsiam_agent_event.c)

FLB_PLUGIN(in_xsiam_agent "${src}" "")
