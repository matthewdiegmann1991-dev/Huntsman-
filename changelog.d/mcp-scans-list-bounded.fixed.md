- The MCP `scans_list` tool refused a machine with more saved scans than fit the 512 KiB view
  bound, with guidance meant for `scan_read`. It now lists the newest 200 scans and says how many
  there are (`count`, `listed`, `truncated`); `scan_read` keeps its bound. The README points an
  LLM user at the MCP server.
