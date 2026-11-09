//! `huntsman-recon mcp`: the Model Context Protocol server over stdio. The protocol lives in
//! the library ([`huntsman_recon::mcp`]); this file connects its tools to the very adapters
//! `serve` installs for `/api/lookup`, `/api/people/discover` and `/api/research`.

use std::io::{BufReader, Write};
use std::process::ExitCode;

use huntsman_recon::exit::{EX_IOERR, EX_USAGE};
use huntsman_recon::mcp::{Server, ToolError, Tools};
use huntsman_recon::people_discovery::Region;
use huntsman_recon::web_server::{LookupError, LookupQuery, lookup_json};
use serde_json::Value;

use super::fail;

pub const HELP: &str = "mcp\nServe the Model Context Protocol over standard input and output, \
so an MCP client (Claude Desktop, Claude Code, Cursor and other LLM applications) can run this \
binary as a tool. One JSON-RPC message per line in each direction; nothing else is written to \
standard output. Tools: lookup (every typed lookup and the public news, notices, web and \
dossier searches), people_discover and research, each running exactly as serve's JSON API runs \
it, with the same keys and the same public-only egress. Register it with a client by its \
absolute path, for example: claude mcp add huntsman -- /path/to/huntsman-recon mcp. Makes \
network requests when a tool is called; none at start-up.";

/// The live tools: `serve`'s own lookup, discovery and research adapters.
struct Live;

fn refusal(error: LookupError) -> ToolError {
    error.message
}

impl Tools for Live {
    fn lookup(&self, kind: &str, selector: &str) -> Result<Value, ToolError> {
        let report = super::service::web_lookup(&LookupQuery {
            kind: kind.to_owned(),
            selector: selector.to_owned(),
        })
        .map_err(refusal)?;
        lookup_json(&report).map_err(|error| format!("report could not be encoded: {error}"))
    }

    fn people_discover(&self, name: &str, region: Region) -> Result<Value, ToolError> {
        super::service::web_people_discover(name, region).map_err(refusal)
    }

    fn research(&self, query: &str) -> Result<Value, ToolError> {
        super::service::web_research(query).map_err(refusal)
    }
}

pub(super) fn mcp_cmd(args: &[String]) -> ExitCode {
    if !args.is_empty() {
        eprintln!("usage: huntsman-recon mcp");
        return ExitCode::from(EX_USAGE);
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    let served = Server::new(&Live, env!("CARGO_PKG_VERSION"))
        .serve(BufReader::new(stdin.lock()), &mut output);
    match served.and_then(|()| output.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        // The client closing its end while an answer is written is how a session ends.
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => fail(EX_IOERR, &format!("mcp: {error}")),
    }
}
