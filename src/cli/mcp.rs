//! `huntsman-recon mcp`: the Model Context Protocol server over stdio. The protocol lives in
//! the library ([`huntsman_recon::mcp`]); this file connects its tools to the very adapters
//! `serve` installs for `/api/lookup`, `/api/people/discover` and `/api/research`.

use std::io::{BufReader, Write};
use std::process::ExitCode;

use huntsman_recon::exit::{EX_IOERR, EX_USAGE};
use huntsman_recon::mcp::{ScanView, Server, ToolError, Tools};
use huntsman_recon::people_discovery::Region;
use huntsman_recon::web_server::{LookupError, LookupQuery, lookup_json};
use serde_json::Value;

use super::fail;

pub const HELP: &str = "mcp\nServe the Model Context Protocol over standard input and output, \
so an MCP client (Claude Desktop, Claude Code, Cursor and other LLM applications) can run this \
binary as a tool. One JSON-RPC message per line in each direction; nothing else is written to \
standard output. Tools: lookup (every typed lookup and the public news, notices, web and \
dossier searches), people_discover and research, each running exactly as serve's JSON API runs \
it, with the same keys and the same public-only egress; investigate (the selectors in a text), \
investigate_file (the selectors and embedded metadata in one local file, by its path, as \
investigate --file reads it), analyze (the offline multi-hop analysis of up to 16 seeds), \
scans_list and scan_read (the scans serve and scan saved on this machine, as scans list and \
show|summary|elements|correlations|log|analyze read them) and ble_decode (the bytes of a \
Bluetooth LE advertisement a scanner showed), which make no request; and radar_wifi, \
radar_cells and radar_track, which read this device's OS-cached radio sightings through \
Termux:API as radar does, on an Android phone only. Register it with a client by its absolute \
path, for example: claude mcp add huntsman -- /path/to/huntsman-recon mcp. Makes network \
requests when a live tool is called; none at start-up.";

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

    fn investigate(&self, text: &str) -> Result<Value, ToolError> {
        let report = super::service::web_investigate(text).map_err(refusal)?;
        serde_json::to_value(report)
            .map_err(|error| format!("report could not be encoded: {error}"))
    }

    fn investigate_file(&self, path: &str) -> Result<Value, ToolError> {
        encode(super::service::web_investigate_file(path).map_err(refusal)?)
    }

    fn analyze(&self, seeds: &[String]) -> Result<Value, ToolError> {
        // No saved-scan history: `serve --history DIR` bridges one, this server has no directory.
        super::service::web_analyze(seeds, None).map_err(refusal)
    }

    fn scans_list(&self) -> Result<Value, ToolError> {
        super::service::web_scans_list().map_err(refusal)
    }

    fn scan_read(&self, id: &str, view: ScanView, kind: Option<&str>) -> Result<Value, ToolError> {
        super::service::web_scan_read(id, view, kind).map_err(refusal)
    }

    fn radar_wifi(&self) -> Result<Value, ToolError> {
        encode(super::service::web_radar().map_err(refusal)?)
    }

    fn radar_cells(&self) -> Result<Value, ToolError> {
        encode(super::service::web_cells().map_err(refusal)?)
    }

    fn radar_track(&self) -> Result<Value, ToolError> {
        encode(super::service::web_track().map_err(refusal)?)
    }
}

/// A radar report as the JSON the tool returns.
fn encode<T: serde::Serialize>(report: T) -> Result<Value, ToolError> {
    serde_json::to_value(report).map_err(|error| format!("report could not be encoded: {error}"))
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
