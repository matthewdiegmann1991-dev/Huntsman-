- The MCP `lookup` tool keeps each typed lookup as a saved scan on a machine that keeps them
  (any `HOME`), as `GET /api/lookup` does: the report names the scan and its status, `scans_list`
  lists it and `scan_read` reads it again, the web UI shows it under Scans, and a lookup still
  running after 150 seconds is refused naming its scan, which runs on. The saved-scan lookup is
  one library function the HTTP route and the tool share. A public search runs live and is not
  kept. The scan planner's refusal of a target now reads as English for every kind
  (`not a valid email scan target`).
