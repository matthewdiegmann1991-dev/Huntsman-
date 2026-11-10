//! `huntsman-recon mcp`: the Model Context Protocol server over stdio. The protocol lives in
//! the library ([`huntsman_recon::mcp`]); this file connects its tools to the very adapters
//! `serve` installs for `/api/lookup`, `/api/people/discover` and `/api/research`.

use std::io::{BufReader, Write};
use std::process::ExitCode;
use std::sync::{Arc, OnceLock};

use huntsman_recon::exit::{EX_IOERR, EX_USAGE};
use huntsman_recon::mcp::{ScanView, Server, ToolError, Tools};
use huntsman_recon::people_discovery::Region;
use huntsman_recon::scan_api::ScanApi;
use huntsman_recon::web_server::{LookupError, LookupQuery, lookup_json};
use serde_json::Value;

use super::fail;

pub const HELP: &str = "mcp\nServe the Model Context Protocol over standard input and output, \
so an MCP client (Claude Desktop, Claude Code, Cursor and other LLM applications) can run this \
binary as a tool. One JSON-RPC message per line in each direction; nothing else is written to \
standard output. Tools: lookup (every typed lookup and the public news, notices, web and \
dossier searches), people_discover, research and research_mission (the bounded, durable depth-1 passive scan of one supported identifier that POST /api/research/mission starts, kept as a saved scan), each running exactly as serve's JSON API runs \
it, with the same keys and the same public-only egress, and, on a machine that keeps saved \
scans (any HOME), each lookup kept as a saved scan that scan_read reads back, as serve keeps \
its own; investigate (the selectors in a text), \
investigate_file (the selectors and embedded metadata in one local file, by its path, as \
investigate --file reads it), analyze (the offline multi-hop analysis of up to 16 seeds), \
scans_list and scan_read (the scans serve and scan saved on this machine, as scans list and \
show|summary|elements|correlations|log|analyze read them) and ble_decode (the bytes of a \
Bluetooth LE advertisement a scanner showed), which make no request; and radar_wifi, \
radar_cells and radar_track, which read this device's OS-cached radio sightings through \
Termux:API as radar does, on an Android phone only. Register it with a client by its absolute \
path, for example: claude mcp add huntsman -- /path/to/huntsman-recon mcp. Makes network \
requests when a live tool is called; none at start-up.";

/// The live tools: `serve`'s own lookup, discovery and research adapters, over the saved scans
/// this machine keeps, opened once on first use as `serve` opens them at start.
struct Live {
    scans: OnceLock<Result<Arc<ScanApi>, String>>,
}

impl Live {
    /// The saved scans this machine keeps, or why it keeps none (no `HOME`, a store that cannot
    /// be opened), decided once; said once on standard error, as `serve` says it, never on
    /// standard output, which carries the protocol alone.
    fn scans(&self) -> Result<&Arc<ScanApi>, &str> {
        self.scans
            .get_or_init(|| match super::service::saved_scans() {
                Ok(api) => Ok(Arc::new(api)),
                Err(error) => {
                    eprintln!("mcp: saved scans are off: {}", error.message);
                    Err(error.message)
                }
            })
            .as_ref()
            .map_err(String::as_str)
    }
}

fn refusal(error: LookupError) -> ToolError {
    error.message
}

impl Tools for Live {
    fn lookup(&self, kind: &str, selector: &str) -> Result<Value, ToolError> {
        let query = LookupQuery {
            kind: kind.to_owned(),
            selector: selector.to_owned(),
        };
        // Kept as a saved scan where there is somewhere to keep it, as `/api/lookup` is.
        let report = match self.scans() {
            Ok(api) => super::service::web_lookup_kept(api, &query),
            Err(_) => super::service::web_lookup(&query),
        }
        .map_err(refusal)?;
        lookup_json(&report).map_err(|error| format!("report could not be encoded: {error}"))
    }

    fn people_discover(&self, name: &str, region: Region) -> Result<Value, ToolError> {
        super::service::web_people_discover(name, region).map_err(refusal)
    }

    fn research(&self, query: &str) -> Result<Value, ToolError> {
        super::service::web_research(query).map_err(refusal)
    }

    fn research_mission(&self, selector: &str) -> Result<Value, ToolError> {
        let api = self
            .scans()
            .map_err(|why| format!("a research mission is kept as a saved scan, and {why}"))?;
        super::service::web_research_mission(api, selector).map_err(refusal)
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
        let api = self.scans().map_err(str::to_owned)?;
        super::service::web_scans_list(api).map_err(refusal)
    }

    fn scan_read(&self, id: &str, view: ScanView, kind: Option<&str>) -> Result<Value, ToolError> {
        let api = self.scans().map_err(str::to_owned)?;
        super::service::web_scan_read(api, id, view, kind).map_err(refusal)
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
    let live = Live {
        scans: OnceLock::new(),
    };
    let served = Server::new(&live, env!("CARGO_PKG_VERSION"))
        .serve(BufReader::new(stdin.lock()), &mut output);
    match served.and_then(|()| output.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        // The client closing its end while an answer is written is how a session ends.
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => fail(EX_IOERR, &format!("mcp: {error}")),
    }
}
