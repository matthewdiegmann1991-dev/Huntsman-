- The MCP `research_mission` tool: the bounded, durable depth-1 passive scan of one supported
  identifier that `POST /api/research/mission` starts, kept as a saved scan. The tool waits up
  to 150 seconds for the mission to end, as a lookup waits, and answers with the scan's id and
  status, so an LLM client runs an investigation on the phone and reads it with `scan_read`;
  the same identifier asked again while it runs joins it, and a phrase is refused as a discovery
  seed. The mission's start and answer are library functions the route and the tool share.
