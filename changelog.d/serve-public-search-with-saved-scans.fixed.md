- `GET /api/lookup` with a public-search kind (`news`, `notices`, `web`, `dossier`) answered 400
  `unknown scan kind` whenever the server kept saved scans, which it does for any `HOME`: every
  lookup was routed through the scan planner, which has no such kind. A public search now runs
  live through the installed handler, as every lookup runs without saved scans, and is not kept;
  typed lookups are kept as before. The MCP `lookup` tool, which runs the handler directly, was
  unaffected.
