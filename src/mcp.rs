//! A Model Context Protocol server over standard input and output, so any MCP client (Claude
//! Desktop, Claude Code, and the other LLM applications that speak MCP) can run this binary as a
//! tool: `huntsman-recon mcp`.
//!
//! The transport is the protocol's stdio transport: one JSON-RPC 2.0 message per line in each
//! direction, nothing else on standard output, diagnostics on standard error. The server is
//! sequential and blocking, like the rest of the crate: no async runtime, nothing to install on
//! Termux beyond the binary itself.
//!
//! This module owns the protocol and the tool contracts: version negotiation, message framing,
//! request routing, argument validation and result shapes. It performs no I/O of its own beyond
//! the reader and writer it is given, and no network request: the binary supplies a [`Tools`]
//! implementation that runs each call through the same lookup, people-discovery and research
//! functions as `serve`'s JSON API, so the two front ends cannot drift apart.

use std::io::{BufRead, Read, Write};

use serde_json::{Map, Value, json};

use crate::people_discovery::Region;
use crate::public_osint::Source;
use crate::scan_route::ScanKind;

/// The protocol revisions this server speaks, newest first. A client that asks for one of them
/// gets it back; any other request is answered with the newest, as the protocol specifies, and
/// the client decides whether to continue. The server uses tools alone, whose shape these
/// revisions share; `structuredContent` is additional in revisions that predate it.
pub const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// The largest message line read. Every argument this server accepts is a few hundred bytes; a
/// longer line is refused, its remainder discarded, without being held in memory.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// The longest selector, name, query or seed accepted, the bound `serve`'s JSON API applies.
pub const MAX_ARGUMENT_BYTES: usize = 512;

/// The most seeds one offline analysis takes, as `/api/analyze` takes them.
pub const MAX_ANALYZE_SEEDS: usize = 16;

/// The longest text `investigate` reads from a call: far more than a model pastes, well within
/// the message bound, and a quarter of what the command reads from a file in Termux.
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
/// The longest saved-scan answer `scan_read` returns (512 KiB): a whole scan's elements can run
/// to megabytes, which no model reads; past this the tool says so and names the narrower views.
pub const MAX_SCAN_VIEW_BYTES: usize = 512 * 1024;
/// The most saved scans `scans_list` returns, newest first; the answer counts the rest.
pub const MAX_LISTED_SCANS: usize = 200;

/// What `scan_read` reads of one saved scan: each the answer of the scan API route `serve`
/// serves and the `scans` subcommand prints, over the same saved files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanView {
    /// The scan's row, its sources' outcomes and its report text: `scans show`.
    Status,
    /// The element counts by type: `scans summary`.
    Summary,
    /// The elements, each a typed finding with its source and parent: `scans elements`.
    Elements,
    /// The correlations the rules found: `scans correlations`.
    Correlations,
    /// The scan's log: `scans log`.
    Log,
    /// The offline multi-hop analysis of the scan's entities: `scans analyze`.
    Analyze,
}

impl ScanView {
    /// Every view, in the order the tool's schema lists them.
    pub const ALL: [Self; 6] = [
        Self::Status,
        Self::Summary,
        Self::Elements,
        Self::Correlations,
        Self::Log,
        Self::Analyze,
    ];

    /// The view's name in the tool's `view` argument.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Summary => "summary",
            Self::Elements => "elements",
            Self::Correlations => "correlations",
            Self::Log => "log",
            Self::Analyze => "analyze",
        }
    }

    /// The scan API path of the view for scan `id`.
    #[must_use]
    pub fn path(self, id: &str) -> String {
        match self {
            Self::Status => format!("/api/scans/{id}"),
            other => format!("/api/scans/{id}/{}", other.name()),
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|view| view.name() == name)
    }
}

/// The serialized size of the entities a summary lookup shows: about twelve thousand tokens, room
/// for a model to reason over while the full report (megabytes for a busy IP address) stays one
/// `detail: full` call away.
pub const SUMMARY_ENTITY_BYTES: usize = 48 * 1024;

/// Per entity in a summary: the evidence records, attributes per record and characters per
/// attribute value shown. What is cut is counted, never silently dropped.
const SUMMARY_EVIDENCE: usize = 6;
const SUMMARY_ATTRIBUTES: usize = 24;
const SUMMARY_VALUE_CHARS: usize = 240;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// What one tool call failed with: a message for the model to read, returned as a tool result
/// with `isError` so the model can correct itself, never as a protocol error.
pub type ToolError = String;

/// The live implementations of the tools. The binary implements this over its network
/// transport; tests implement it offline.
pub trait Tools {
    /// One typed lookup. `kind` is one of [`lookup_kinds`]: `auto`, a typed route's command, or
    /// a public search's name; `selector` is trimmed, nonempty and bounded.
    ///
    /// # Errors
    /// The lookup's refusal or failure, in words.
    fn lookup(&self, kind: &str, selector: &str) -> Result<Value, ToolError>;

    /// Source-scoped public-index discovery for one full name.
    ///
    /// # Errors
    /// The discovery's refusal or failure, in words.
    fn people_discover(&self, name: &str, region: Region) -> Result<Value, ToolError>;

    /// Keyless adaptive web research for free text.
    ///
    /// # Errors
    /// The search's refusal or failure, in words.
    fn research(&self, query: &str) -> Result<Value, ToolError>;

    /// A bounded, durable autonomous research mission over one exact, supported identifier: the
    /// depth-1 passive scan `POST /api/research/mission` starts, kept as a saved scan, started
    /// or joined; the answer names the scan, which `scan_read` follows.
    ///
    /// # Errors
    /// A phrase (a discovery seed, never a scan target), a term the router refuses, or a
    /// machine that keeps no saved scans, in words.
    fn research_mission(&self, selector: &str) -> Result<Value, ToolError>;

    /// The actionable entities in a text, offline: no request, no key.
    ///
    /// # Errors
    /// A text the classifier cannot read, in words.
    fn investigate(&self, text: &str) -> Result<Value, ToolError>;

    /// The actionable entities in one local file, by its path on the machine the server runs
    /// on, as `investigate --file` reads it: a text file for the selectors in it and its
    /// embedded metadata, any other file (a photo, a PDF, a document) for its embedded metadata.
    /// Offline: no request, no key; the file is never modified.
    ///
    /// # Errors
    /// A file that cannot be read (missing, a symlink, over the bound) or decoded, in words.
    fn investigate_file(&self, path: &str) -> Result<Value, ToolError>;

    /// The offline multi-hop analysis of up to [`MAX_ANALYZE_SEEDS`] seeds: the links derived
    /// between them, the next pivots, correlations, gaps and the sources the planner would ask.
    ///
    /// # Errors
    /// Seeds the spine refuses, in words.
    fn analyze(&self, seeds: &[String]) -> Result<Value, ToolError>;

    /// The scans saved on this machine, as `scans list` and `GET /api/scans` list them: the
    /// rows, newest first. Offline: no request, no key.
    ///
    /// # Errors
    /// Why the saved scans could not be read (no scan directory, a store failure), in words.
    fn scans_list(&self) -> Result<Value, ToolError>;

    /// One saved scan's `view`, as the scan API answers it; `kind` narrows the elements view to
    /// one Spiderfoot element type. Offline: no request, no key.
    ///
    /// # Errors
    /// An unknown scan, a view too long to return, or a store failure, in words.
    fn scan_read(&self, id: &str, view: ScanView, kind: Option<&str>) -> Result<Value, ToolError>;

    /// This device's OS-cached nearby Wi-Fi sightings, as `radar wifi` reads them through
    /// Termux:API; no scan is triggered and no request is made.
    ///
    /// # Errors
    /// Why the cache could not be read (no Termux:API, no permission), in words.
    fn radar_wifi(&self) -> Result<Value, ToolError>;

    /// This device's OS-cached cell identities, as `radar cells` reads them.
    ///
    /// # Errors
    /// Why the cells could not be read, in words.
    fn radar_cells(&self) -> Result<Value, ToolError>;

    /// One tracking sweep recorded into the device's private sweep log, as `radar track` does:
    /// recurring and following devices across the places the device has been.
    ///
    /// # Errors
    /// Why the sweep could not be taken or kept, in words.
    fn radar_track(&self) -> Result<Value, ToolError>;
}

/// One server: the tools it runs and the identity it reports.
pub struct Server<'a, T: Tools + ?Sized> {
    tools: &'a T,
    version: &'a str,
}

impl<'a, T: Tools + ?Sized> Server<'a, T> {
    /// A server that runs `tools` and reports `version` (the package version) in `initialize`.
    #[must_use]
    pub const fn new(tools: &'a T, version: &'a str) -> Self {
        Self { tools, version }
    }

    /// Serve until `input` ends: read one message per line, write one answer per request line.
    /// Notifications and responses from the client get no answer.
    ///
    /// # Errors
    /// Only a failure to read input or to write an answer; malformed messages are answered.
    pub fn serve<R: BufRead, W: Write>(&self, mut input: R, mut output: W) -> std::io::Result<()> {
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = input
                .by_ref()
                .take(MAX_MESSAGE_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)?;
            if read == 0 {
                return Ok(());
            }
            let answer = if line.len() > MAX_MESSAGE_BYTES && line.last() != Some(&b'\n') {
                discard_rest_of_line(&mut input)?;
                Some(error(Value::Null, INVALID_REQUEST, "message is too large"))
            } else {
                self.handle_line(&line)
            };
            if let Some(answer) = answer {
                serde_json::to_writer(&mut output, &answer)?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
    }

    /// The answer to one line, or `None` when it needs none. **Pure** apart from the tools.
    #[must_use]
    pub fn handle_line(&self, line: &[u8]) -> Option<Value> {
        let text = String::from_utf8_lossy(line);
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        match serde_json::from_str::<Value>(text) {
            Ok(message) => self.handle_message(&message),
            Err(_) => Some(error(Value::Null, PARSE_ERROR, "message is not JSON")),
        }
    }

    /// The answer to one parsed message or batch, or `None` when it needs none.
    #[must_use]
    pub fn handle_message(&self, message: &Value) -> Option<Value> {
        match message {
            // Batches were part of the 2025-03-26 revision; answering them costs nothing.
            Value::Array(batch) if batch.is_empty() => {
                Some(error(Value::Null, INVALID_REQUEST, "empty batch"))
            }
            Value::Array(batch) => {
                let answers: Vec<Value> = batch
                    .iter()
                    .filter_map(|one| self.handle_one(one))
                    .collect();
                (!answers.is_empty()).then_some(Value::Array(answers))
            }
            one => self.handle_one(one),
        }
    }

    fn handle_one(&self, message: &Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(error(
                Value::Null,
                INVALID_REQUEST,
                "message is not an object",
            ));
        };
        let id = object.get("id").cloned();
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            // A response to a request this server never sends, or junk: neither is answered,
            // except junk that names an id, which is told what is wrong with it.
            let is_response = object.contains_key("result") || object.contains_key("error");
            return match id {
                Some(id) if !is_response => {
                    Some(error(id, INVALID_REQUEST, "request has no method"))
                }
                _ => None,
            };
        };
        // A notification (initialized, cancelled, progress) needs nothing back.
        let id = id?;
        if !matches!(id, Value::String(_) | Value::Number(_)) {
            return Some(error(
                Value::Null,
                INVALID_REQUEST,
                "id must be a string or number",
            ));
        }
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        Some(match method {
            "initialize" => success(id, self.initialize(&params)),
            "ping" => success(id, json!({})),
            "tools/list" => success(id, json!({ "tools": tool_definitions() })),
            "tools/call" => match self.call(&params) {
                Ok(result) => success(id, result),
                Err(message) => error(id, INVALID_PARAMS, &message),
            },
            other => error(
                id,
                METHOD_NOT_FOUND,
                &format!("method {other} is not supported"),
            ),
        })
    }

    fn initialize(&self, params: &Value) -> Value {
        let asked = params.get("protocolVersion").and_then(Value::as_str);
        let version = asked
            .and_then(|asked| PROTOCOL_VERSIONS.iter().find(|known| **known == asked))
            .unwrap_or(&PROTOCOL_VERSIONS[0]);
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": {
                "name": "huntsman-recon",
                "title": "Huntsman OSINT Engine",
                "version": self.version,
            },
            "instructions": INSTRUCTIONS,
        })
    }

    /// One `tools/call`. `Err` is a protocol error (no such tool, no arguments object); a call
    /// whose arguments are wrong or whose lookup fails is an `Ok` tool result with `isError`.
    fn call(&self, params: &Value) -> Result<Value, String> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or("tools/call needs a tool name")?;
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(arguments)) => arguments,
            Some(_) => return Err("tool arguments must be an object".into()),
        };
        let outcome = match name {
            "lookup" => lookup_arguments(arguments).and_then(|(kind, selector, full)| {
                let report = self.tools.lookup(&kind, &selector)?;
                Ok(if full {
                    report
                } else {
                    summarize_lookup(&report)
                })
            }),
            "people_discover" => discover_arguments(arguments)
                .and_then(|(name, region)| self.tools.people_discover(&name, region)),
            "research" => text_argument(arguments, "query", MAX_ARGUMENT_BYTES)
                .and_then(|query| self.tools.research(&query)),
            "research_mission" => refuse_unknown(arguments, &["selector"])
                .and_then(|()| text_argument(arguments, "selector", MAX_ARGUMENT_BYTES))
                .and_then(|selector| self.tools.research_mission(&selector)),
            "investigate" => refuse_unknown(arguments, &["text"])
                .and_then(|()| text_argument(arguments, "text", MAX_TEXT_BYTES))
                .and_then(|text| self.tools.investigate(&text)),
            "investigate_file" => refuse_unknown(arguments, &["path"])
                .and_then(|()| text_argument(arguments, "path", MAX_ARGUMENT_BYTES))
                .and_then(|path| self.tools.investigate_file(&path)),
            "analyze" => analyze_arguments(arguments).and_then(|seeds| self.tools.analyze(&seeds)),
            "scans_list" => refuse_unknown(arguments, &[])
                .and_then(|()| self.tools.scans_list())
                .map(|scans| {
                    // The store lists newest first; a phone with years of scans is not read
                    // whole, the answer says how many there are and how many it holds.
                    let mut rows = match scans {
                        Value::Array(rows) => rows,
                        other => vec![other],
                    };
                    let count = rows.len();
                    rows.truncate(MAX_LISTED_SCANS);
                    json!({
                        "count": count,
                        "listed": rows.len(),
                        "truncated": count > rows.len(),
                        "scans": rows,
                    })
                }),
            "scan_read" => scan_read_arguments(arguments).and_then(|(id, view, kind)| {
                let report = self.tools.scan_read(&id, view, kind.as_deref())?;
                Ok(json!({ "id": id, "view": view.name(), "report": report }))
            }),
            "radar_wifi" => refuse_unknown(arguments, &[]).and_then(|()| self.tools.radar_wifi()),
            "radar_cells" => refuse_unknown(arguments, &[]).and_then(|()| self.tools.radar_cells()),
            "radar_track" => refuse_unknown(arguments, &[]).and_then(|()| self.tools.radar_track()),
            "ble_decode" => {
                ble_decode_arguments(arguments).and_then(|request| ble_decode(&request))
            }
            other => return Err(format!("no tool named {other}")),
        };
        Ok(match outcome {
            Ok(report) => tool_result(report),
            Err(message) => json!({
                "content": [{ "type": "text", "text": message }],
                "isError": true,
            }),
        })
    }
}

const INSTRUCTIONS: &str = "Huntsman OSINT Engine: live, source-attributed open-source \
intelligence lookups. Every result carries its sources' typed outcomes (success, valid_zero, \
blocked, not_configured, upstream errors) beside the entities found. A source that did not \
answer is not evidence of absence, and a name match, an indexed page or several engines \
returning one URL does not prove identity. Report candidates as candidates. investigate, \
investigate_file, analyze and ble_decode are offline (no request, no key): extract selectors \
from a text with investigate, or from a local file (a photo, a PDF, a document, a text; its \
embedded metadata too) with investigate_file by its path on this machine, look the interesting \
ones up, then analyze the set for the links between them; ble_decode reads the bytes of a \
Bluetooth LE advertisement a scanner showed. scans_list and scan_read read, offline, the scans \
serve and scan saved on this machine: list them, then read one's summary, elements (of one type \
where a scan is large), correlations, log or offline analysis; research_mission starts a \
depth-1 passive scan of one supported identifier, kept as a saved scan, which scan_read then \
follows. radar_wifi, \
radar_cells and radar_track read this device's own OS-cached radio sightings through Termux:API \
when the server runs on an Android phone; elsewhere they say why they cannot.";

/// A successful tool result: the report as structured content, and as JSON text for clients
/// that read only text content.
fn tool_result(report: Value) -> Value {
    let text = serde_json::to_string(&report).unwrap_or_default();
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false,
    });
    // Structured content must be an object; every report this server returns is one.
    if report.is_object() {
        result["structuredContent"] = report;
    }
    result
}

/// Every lookup kind the `lookup` tool accepts, in the order its schema lists them.
#[must_use]
pub fn lookup_kinds() -> Vec<&'static str> {
    std::iter::once("auto")
        .chain(ScanKind::ALL.iter().map(|kind| kind.command()))
        .chain(Source::NAMED.iter().map(|(name, _)| *name))
        .collect()
}

/// Behaviour hints for a tool that reads public sources: it changes nothing on this device or
/// elsewhere, and asks the open world, so it may answer differently each time.
fn live_hints(title: &str) -> Value {
    json!({
        "title": title,
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": false,
        "openWorldHint": true,
    })
}

/// Behaviour hints for a tool that reads only its arguments: the same call gives the same answer.
fn offline_hints(title: &str) -> Value {
    json!({
        "title": title,
        "readOnlyHint": true,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": false,
    })
}

/// The `tools/list` definitions: name, title, description, input schema and behaviour hints.
#[must_use]
pub fn tool_definitions() -> Vec<Value> {
    vec![
        lookup_tool(),
        people_discover_tool(),
        research_tool(),
        research_mission_tool(),
        investigate_tool(),
        investigate_file_tool(),
        analyze_tool(),
        scans_list_tool(),
        scan_read_tool(),
        ble_decode_tool(),
        radar_wifi_tool(),
        radar_cells_tool(),
        radar_track_tool(),
    ]
}

/// Behaviour hints for a tool that reads this device (its OS caches, its own log): not the open
/// world, and not the same answer twice.
fn device_hints(title: &str, read_only: bool) -> Value {
    json!({
        "title": title,
        "readOnlyHint": read_only,
        "destructiveHint": false,
        "idempotentHint": false,
        "openWorldHint": false,
    })
}

/// The `ble_decode` tool.
fn ble_decode_tool() -> Value {
    json!({
        "name": "ble_decode",
        "title": "Offline Bluetooth LE advertisement decode",
        "description": "Offline: no request, no key. Decode the bytes of a Bluetooth LE \
    advertisement and scan response a scanner app showed: flags, service UUIDs (named where \
    well known), the local name (a label the owner typed, never an identity), TX power, the \
    appearance category, service data and manufacturer-specific data with its company named from \
    the Bluetooth SIG list (who made the advertising firmware or the app, never who owns the \
    device). Payloads are reported by length unless raw is set. With address, the device address \
    is read as a Bluetooth LE address (public, static random, resolvable private or \
    non-resolvable private) and what that means for recognising the device later.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bytes": {
                    "type": "array",
                    "items": { "type": "string", "minLength": 1, "maxLength": MAX_ARGUMENT_BYTES },
                    "minItems": 1,
                    "maxItems": crate::ble_adv::MAX_DECODE_TOKENS,
                    "description": "Hex strings in order: whole payloads (length, type, data \
    structures) or TYPE:DATA fragments as scanner apps list them, such as ff:7500... ; a \
    data-less fragment is its type alone, such as 02: .",
                },
                "address": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                    "description": "The device address the scanner showed, to read its type.",
                },
                "raw": {
                    "type": "boolean",
                    "default": false,
                    "description": "Include manufacturer and service payload bytes in hex.",
                },
            },
            "required": ["bytes"],
            "additionalProperties": false,
        },
        "annotations": offline_hints("Offline Bluetooth LE advertisement decode"),
    })
}

/// The `radar_wifi` tool.
fn radar_wifi_tool() -> Value {
    json!({
        "name": "radar_wifi",
        "title": "This device's cached Wi-Fi sightings",
        "description": "Read this device's OS-cached nearby Wi-Fi results through Termux:API, \
    as radar wifi does: each BSSID with SSID, signal, band and cache age; no scan is triggered, \
    no position or time is inferred, and no request is made. Only on an Android phone running \
    this server in Termux with Termux:API installed; elsewhere the tool says why it cannot read \
    the cache. An empty cache is not evidence that there are no networks.",
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        "annotations": device_hints("This device's cached Wi-Fi sightings", true),
    })
}

/// The `radar_cells` tool.
fn radar_cells_tool() -> Value {
    json!({
        "name": "radar_cells",
        "title": "This device's cached cell identities",
        "description": "Read this device's OS-cached GSM, WCDMA, LTE, 5G NR and CDMA cell \
    identities through Termux:API, as radar cells does: the serving cell and neighbours with \
    their identities, bands and anomaly indicators, which are never detections. No location or \
    time is inferred and no request is made. Only on an Android phone running this server in \
    Termux with Termux:API; elsewhere the tool says why it cannot. An empty read is inconclusive.",
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        "annotations": device_hints("This device's cached cell identities", true),
    })
}

/// The `radar_track` tool.
fn radar_track_tool() -> Value {
    json!({
        "name": "radar_track",
        "title": "One tracking sweep on this device",
        "description": "Take one tracking sweep on this device, as radar track does: read the \
    cached Wi-Fi sightings and the serving cell, add the sweep to the device's private sweep log, \
    and report every stable BSSID heard in two or more sweeps (recurring) and every one heard in \
    at least three distinct cells over at least ten minutes (follower), a personal-safety signal \
    that something travelled with the device, never an identification of its owner. Appends to \
    the log; no position is recorded and no request is made. Only on an Android phone running \
    this server in Termux with Termux:API; elsewhere the tool says why it cannot.",
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        "annotations": device_hints("One tracking sweep on this device", false),
    })
}

/// The `ble_decode` arguments as one request: the hex strings, the address if given, and
/// whether payload bytes are wanted, each checked for its type here and for its bounds by the
/// decoder.
fn ble_decode_arguments(
    arguments: &Map<String, Value>,
) -> Result<crate::ble_adv::DecodeRequest, ToolError> {
    refuse_unknown(arguments, &["bytes", "address", "raw"])?;
    let bytes = match arguments.get("bytes") {
        Some(Value::Array(items)) => items,
        Some(_) => return Err("bytes must be an array of strings".into()),
        None => return Err("bytes is required".into()),
    };
    let mut strings = Vec::with_capacity(bytes.len());
    for item in bytes {
        let Some(text) = item.as_str() else {
            return Err("bytes must be an array of strings".into());
        };
        strings.push(text.to_owned());
    }
    let address = match arguments.get("address") {
        None | Some(Value::Null) => None,
        Some(Value::String(address)) => Some(address.clone()),
        Some(_) => return Err("address must be a string".into()),
    };
    let raw = match arguments.get("raw") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(raw)) => *raw,
        Some(_) => return Err("raw must be a boolean".into()),
    };
    Ok(crate::ble_adv::DecodeRequest {
        bytes: strings,
        address,
        raw,
    })
}

/// The offline decode behind the `ble_decode` tool: the same decoder as `radar ble-adv` and
/// `POST /api/ble/decode`.
fn ble_decode(request: &crate::ble_adv::DecodeRequest) -> Result<Value, ToolError> {
    let report = crate::ble_adv::decode_request(request)?;
    serde_json::to_value(report).map_err(|error| format!("report could not be encoded: {error}"))
}

/// The `lookup` tool.
fn lookup_tool() -> Value {
    json!({
        "name": "lookup",
        "title": "OSINT lookup",
        "description": format!(
            "Run one live OSINT lookup through every source for its kind and return the \
    entities found with each source's typed outcome. Kinds: auto (infer from the selector), \
    people (full name: registers, sanctions, offshore leaks), email, exposure (breach evidence \
    for an email or handle), username, phone, domain (certificate transparency, DNS, threat \
    feeds), ip, netblock (CIDR), asn, network (BSSID, ssid:NAME or LAT,LON), crypto (bitcoin, \
    eth:0x…, base:0x…, sol:…), geocode (place or LAT,LON), and the public news, notices, web \
    and dossier searches. Keyed sources run only when their key is configured. Each entity \
    carries a confidence from 0 to 1 and tags: {floor} and above is a link a recursive scan \
    follows; a value tagged {incidental} (a page that loaded a resource from the subject, a site \
    that redirected into it) or {shared} (one of more than {cap} names on one address) merely \
    co-occurred with the subject, sits below that floor, and is not a link to it however many \
    sources name it. On a machine that keeps saved scans (any HOME), a typed lookup runs as a \
    saved scan, as the JSON API's does: the report names it in scan and status, scans_list \
    lists it and scan_read reads it again; one still running after {wait} seconds is refused \
    naming its scan, which runs on. A public search runs live and is not kept.",
            floor = crate::gap::EXPAND_FLOOR,
            wait = crate::web_server::LOOKUP_WAIT.as_secs(),
            incidental = crate::tags::INCIDENTAL,
            shared = crate::tags::SHARED_HOSTING,
            cap = crate::ip_cli::MAX_COHOSTS,
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": lookup_kinds(),
                    "default": "auto",
                    "description": "What the selector is; auto infers it.",
                },
                "selector": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_ARGUMENT_BYTES,
                    "description": "The value to look up, such as an email address, \
    domain, IP address, handle, phone number or full name.",
                },
                "detail": {
                    "type": "string",
                    "enum": ["summary", "full"],
                    "default": "summary",
                    "description": "summary: every source outcome, entity counts by kind \
    and the most confident entities of every kind with their evidence (one kind at a time in \
    rounds, so a kind with hundreds of values cannot hide the others), sized for a model to \
    read. full: the complete report, which can be megabytes.",
                },
            },
            "required": ["selector"],
            "additionalProperties": false,
        },
        "annotations": live_hints("OSINT lookup"),
    })
}

/// The `people_discover` tool.
fn people_discover_tool() -> Value {
    json!({
        "name": "people_discover",
        "title": "People discovery",
        "description": "Search public indexes for leads on one person by full name: \
    LinkedIn, GitHub, ORCID and the region's official register (ASIC for au, SEC for us, DFSA for \
    ae), plus Open Library authors. Results whose title and address never name the person are \
    dropped. Every result is an unverified lead, not an identification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_ARGUMENT_BYTES,
                    "description": "The person's full name, at least two words.",
                },
                "region": {
                    "type": "string",
                    "enum": ["au", "us", "ae"],
                    "default": "au",
                    "description": "Which official register to search.",
                },
            },
            "required": ["name"],
            "additionalProperties": false,
        },
        "annotations": live_hints("People discovery"),
    })
}

/// The `research` tool.
fn research_tool() -> Value {
    json!({
        "name": "research",
        "title": "Web research",
        "description": "Keyless adaptive web search for any text: up to three \
    feedback-directed rounds across Bing, Brave and Mojeek, with every URL attributed to the \
    engines that returned it and each engine's typed outcome.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_ARGUMENT_BYTES,
                    "description": "What to search for.",
                },
            },
            "required": ["query"],
            "additionalProperties": false,
        },
        "annotations": live_hints("Web research"),
    })
}

/// The `research_mission` tool.
fn research_mission_tool() -> Value {
    json!({
        "name": "research_mission",
        "title": "Start a research mission",
        "description": format!(
            "Start a bounded, durable autonomous research mission over one exact, \
    supported identifier (an email, handle, phone, domain, IP address, address block, AS number, \
    BSSID or LAT,LON): a depth-1 passive scan through the saved scan service, as POST \
    /api/research/mission starts one, kept as a saved scan. The target's own lookup runs, then \
    one lookup of each selector it found; keyed sources run where their key is configured. It \
    waits up to {wait} seconds for the mission to end and answers with the scan's id and its \
    status, FINISHED as a rule; one still running then goes on while this session lasts, and \
    ends ABORTED with it: read it with scan_read (status, then summary, elements and \
    correlations). The same identifier asked again while it runs joins that mission. A phrase \
    or a name is a discovery seed, not a scan target: research it first and choose a supported \
    identifier. Needs a machine that keeps saved scans (any HOME).",
            wait = crate::web_server::LOOKUP_WAIT.as_secs(),
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "selector": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_ARGUMENT_BYTES,
                    "description": "The exact identifier to investigate.",
                },
            },
            "required": ["selector"],
            "additionalProperties": false,
        },
        "annotations": {
            "title": "Start a research mission",
            "readOnlyHint": false,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": true,
        },
    })
}

/// The `investigate` tool.
fn investigate_tool() -> Value {
    json!({
        "name": "investigate",
        "title": "Extract selectors from text",
        "description": "Offline: no request, no key. Extract every email address, phone \
    number, handle, domain, URL, IP address, coordinates and company number from a text (an advert, \
    a message thread, a page) as entities, each with the classifier's signal as its evidence. Use it \
    to turn pasted material into selectors for lookup.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_TEXT_BYTES,
                    "description": "The text to read.",
                },
            },
            "required": ["text"],
            "additionalProperties": false,
        },
        "annotations": offline_hints("Extract selectors from text"),
    })
}

/// The `investigate_file` tool.
fn investigate_file_tool() -> Value {
    json!({
        "name": "investigate_file",
        "title": "Extract selectors and metadata from a local file",
        "description": "Offline: no request, no key. Read one local file by its path on the \
    machine this server runs on, as investigate --file reads it: a text file (up to 1 MiB) for \
    every selector in it as investigate finds them, and for its embedded metadata when it carries \
    any; any other file (a photo, a PDF, an Office document; up to 64 MiB) for its embedded \
    metadata: the EXIF and document fields, a GPS position as coordinates, every email address, \
    link, domain, IP address or phone number written into a field people write, and every person \
    or organisation named as its author, creator or owner, each attributed to its field. A \
    symbolic link is refused; the file is never modified.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_ARGUMENT_BYTES,
                    "description": "The file's path on this machine, absolute by preference.",
                },
            },
            "required": ["path"],
            "additionalProperties": false,
        },
        "annotations": offline_hints("Extract selectors and metadata from a local file"),
    })
}

/// The `analyze` tool.
fn analyze_tool() -> Value {
    json!({
        "name": "analyze",
        "title": "Offline analysis of seeds",
        "description": "Offline: no request, no key. The multi-hop analysis of up to 16 \
    seeds (emails, domains, handles, phones, addresses): the links derived between them, the next \
    pivots ranked by how much of the graph each holds together, the correlations over those links, \
    the seeds left unlinked with what would expand them, and the sources a live lookup would ask \
    next. A link rests on the seeds given; it stays a hypothesis until a source corroborates it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "seeds": {
                    "type": "array",
                    "items": { "type": "string", "minLength": 1, "maxLength": MAX_ARGUMENT_BYTES },
                    "minItems": 1,
                    "maxItems": MAX_ANALYZE_SEEDS,
                    "description": "The selectors to analyse together.",
                },
            },
            "required": ["seeds"],
            "additionalProperties": false,
        },
        "annotations": offline_hints("Offline analysis of seeds"),
    })
}

/// The `scans_list` tool.
fn scans_list_tool() -> Value {
    json!({
        "name": "scans_list",
        "title": "List the scans saved on this machine",
        "description": format!(
            "Offline: no request, no key. The scans saved on this machine by serve, \
    scan and the JSON API, as scans list and GET /api/scans list them: each its id, name, target, \
    kind, status, times, element and correlation counts; the newest {most} of them, newest \
    first, with count saying how many there are. Read one with scan_read.",
            most = MAX_LISTED_SCANS,
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": false,
        },
        "annotations": offline_hints("List the scans saved on this machine"),
    })
}

/// The `scan_read` tool.
fn scan_read_tool() -> Value {
    let views: Vec<&str> = ScanView::ALL.iter().map(|view| view.name()).collect();
    json!({
        "name": "scan_read",
        "title": "Read one saved scan",
        "description": "Offline: no request, no key. One saved scan, by the id scans_list gave, \
    as the scan API and the scans subcommand answer it: view summary (the default) counts its \
    elements by type; status is its row, its sources' typed outcomes and its report text; \
    elements lists every element (type, data, source module, parent), narrowed to one type with \
    type, such as EMAILADDR or IP_ADDRESS, where a scan is large; correlations lists what the \
    rules found; log its log; analyze the offline multi-hop analysis of its entities. An answer \
    over 512 KiB is refused with the narrower views named.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_ARGUMENT_BYTES,
                    "description": "The scan id, as scans_list gives it.",
                },
                "view": {
                    "type": "string",
                    "enum": views,
                    "default": ScanView::Summary.name(),
                    "description": "What to read of the scan.",
                },
                "type": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_ARGUMENT_BYTES,
                    "description": "With view elements: only the elements of this Spiderfoot \
    type.",
                },
            },
            "required": ["id"],
            "additionalProperties": false,
        },
        "annotations": offline_hints("Read one saved scan"),
    })
}

/// The arguments of `scan_read`: a scan id of the store's own form, a view (summary when
/// unnamed) and, with the elements view only, an element type of letters, digits and
/// underscores, so it reaches the scan API as the one query parameter it is.
fn scan_read_arguments(
    arguments: &Map<String, Value>,
) -> Result<(String, ScanView, Option<String>), ToolError> {
    refuse_unknown(arguments, &["id", "view", "type"])?;
    let id = text_argument(arguments, "id", MAX_ARGUMENT_BYTES)?;
    if !crate::scan_store::valid_id(&id) {
        return Err("id is not a scan id: give one as scans_list gives them".into());
    }
    let view = match arguments.get("view") {
        None | Some(Value::Null) => ScanView::Summary,
        Some(Value::String(name)) => ScanView::parse(name.trim()).ok_or_else(|| {
            let names: Vec<&str> = ScanView::ALL.iter().map(|view| view.name()).collect();
            format!("view must be one of {}", names.join(", "))
        })?,
        Some(_) => return Err("view must be a string".into()),
    };
    let kind = match arguments.get("type") {
        None | Some(Value::Null) => None,
        Some(_) => {
            let kind = text_argument(arguments, "type", MAX_ARGUMENT_BYTES)?;
            if view != ScanView::Elements {
                return Err("type narrows the elements view only".into());
            }
            if !kind
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            {
                return Err("type is an element type name: letters, digits and underscores".into());
            }
            Some(kind)
        }
    };
    Ok((id, view, kind))
}

/// A required string argument, trimmed, nonempty and within `max` bytes.
fn text_argument(
    arguments: &Map<String, Value>,
    key: &str,
    max: usize,
) -> Result<String, ToolError> {
    let value = match arguments.get(key) {
        Some(Value::String(value)) => value.trim(),
        Some(_) => return Err(format!("{key} must be a string")),
        None => return Err(format!("{key} is required")),
    };
    if value.is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    if value.len() > max {
        return Err(format!("{key} is longer than {max} bytes"));
    }
    Ok(value.to_owned())
}

/// The `seeds` of an analysis: one to [`MAX_ANALYZE_SEEDS`] strings, each trimmed, nonempty and
/// within [`MAX_ARGUMENT_BYTES`].
fn analyze_arguments(arguments: &Map<String, Value>) -> Result<Vec<String>, ToolError> {
    refuse_unknown(arguments, &["seeds"])?;
    let seeds = match arguments.get("seeds") {
        Some(Value::Array(seeds)) => seeds,
        Some(_) => return Err("seeds must be an array of strings".into()),
        None => return Err("seeds is required".into()),
    };
    if seeds.is_empty() {
        return Err("seeds must hold at least one seed".into());
    }
    if seeds.len() > MAX_ANALYZE_SEEDS {
        return Err(format!("analysis takes at most {MAX_ANALYZE_SEEDS} seeds"));
    }
    seeds
        .iter()
        .enumerate()
        .map(|(index, seed)| {
            let seed = seed
                .as_str()
                .ok_or_else(|| format!("seed {index} is not a string"))?
                .trim();
            if seed.is_empty() {
                return Err(format!("seed {index} is empty"));
            }
            if seed.len() > MAX_ARGUMENT_BYTES {
                return Err(format!(
                    "seed {index} is longer than {MAX_ARGUMENT_BYTES} bytes"
                ));
            }
            Ok(seed.to_owned())
        })
        .collect()
}

/// An optional string argument, lower-cased, or `default` when absent.
fn choice_argument(
    arguments: &Map<String, Value>,
    key: &str,
    default: &str,
) -> Result<String, ToolError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(default.to_owned()),
        Some(Value::String(value)) => Ok(value.trim().to_ascii_lowercase()),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

fn refuse_unknown(arguments: &Map<String, Value>, known: &[&str]) -> Result<(), ToolError> {
    match arguments.keys().find(|key| !known.contains(&key.as_str())) {
        Some(key) => Err(format!(
            "unknown argument {key}; expected {}",
            known.join(", ")
        )),
        None => Ok(()),
    }
}

/// The lookup's kind, selector, and whether the full report was asked for.
fn lookup_arguments(arguments: &Map<String, Value>) -> Result<(String, String, bool), ToolError> {
    refuse_unknown(arguments, &["kind", "selector", "detail"])?;
    let selector = text_argument(arguments, "selector", MAX_ARGUMENT_BYTES)?;
    let kind = choice_argument(arguments, "kind", "auto")?;
    if !lookup_kinds().contains(&kind.as_str()) {
        return Err(format!(
            "unknown kind {kind}; expected one of {}",
            lookup_kinds().join(", ")
        ));
    }
    let full = match choice_argument(arguments, "detail", "summary")?.as_str() {
        "summary" => false,
        "full" => true,
        other => return Err(format!("unknown detail {other}; expected summary or full")),
    };
    Ok((kind, selector, full))
}

/// A lookup report cut to what a model can read: every source outcome, how many entities of each
/// kind were found, and the most confident entities of every kind with their evidence, within
/// [`SUMMARY_ENTITY_BYTES`]. Entities are shown one kind at a time in rounds, so a kind with
/// hundreds of confident values (an AS's netblocks, a site's addresses) cannot crowd every other
/// kind out of the budget: the first round is the best entity of each kind. The rendered text and
/// the synergy body are left out (their size is counted); every cut is reported, and
/// `detail: full` returns the report whole. **Pure.**
#[must_use]
pub fn summarize_lookup(report: &Value) -> Value {
    let entities = report
        .get("entities")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut by_kind = std::collections::BTreeMap::<String, usize>::new();
    for entity in entities {
        let kind = entity
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        *by_kind.entry(kind.to_owned()).or_default() += 1;
    }
    // Most confident first, then best corroborated; the sort is stable, so ties keep the
    // report's own order.
    let mut ranked: Vec<&Value> = entities.iter().collect();
    let score = |entity: &Value, key: &str| entity.get(key).and_then(Value::as_f64).unwrap_or(0.0);
    ranked.sort_by(|a, b| {
        score(b, "confidence")
            .total_cmp(&score(a, "confidence"))
            .then(score(b, "corroboration").total_cmp(&score(a, "corroboration")))
    });
    // One lane per kind, lanes in the order their best entity ranks, each lane in rank order.
    let mut lanes: Vec<Vec<&Value>> = Vec::new();
    let mut lane_of = std::collections::BTreeMap::<&str, usize>::new();
    for entity in ranked {
        let kind = entity
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let lane = *lane_of.entry(kind).or_insert_with(|| {
            lanes.push(Vec::new());
            lanes.len() - 1
        });
        lanes[lane].push(entity);
    }
    // Rounds across the lanes, until the budget is spent or every lane is empty.
    let mut shown = Vec::new();
    let mut used = 0;
    'rounds: for round in 0.. {
        let mut any = false;
        for lane in &lanes {
            let Some(entity) = lane.get(round) else {
                continue;
            };
            any = true;
            let compact = compact_entity(entity);
            let size = serde_json::to_string(&compact).map_or(usize::MAX, |text| text.len());
            if used + size > SUMMARY_ENTITY_BYTES {
                break 'rounds;
            }
            used += size;
            shown.push(compact);
        }
        if !any {
            break;
        }
    }
    let synergy_links = report
        .pointer("/synergy/links")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let mut summary = json!({
        "detail": "summary",
        "entity_count": entities.len(),
        "entities_by_kind": by_kind,
        "entities_shown": shown.len(),
        "entities": shown,
        "synergy_links": synergy_links,
    });
    for key in ["route", "outcomes", "scan", "status"] {
        if let Some(value) = report.get(key) {
            summary[key] = value.clone();
        }
    }
    if summary["entities_shown"] != summary["entity_count"] || synergy_links > 0 {
        summary["omitted"] = json!(
            "This is a summary: the most confident entities within a size budget, each with at \
             most six evidence records. Call lookup again with detail: full for every entity, \
             every evidence record, the synergy links and the rendered text."
        );
    }
    summary
}

/// One entity for a summary: its identity, confidence, tags, sources, and its first evidence
/// records with bounded attributes, counting whatever is cut.
fn compact_entity(entity: &Value) -> Value {
    let evidence = entity
        .get("evidence")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut sources: Vec<&str> = evidence
        .iter()
        .filter_map(|record| record.pointer("/provenance/source").and_then(Value::as_str))
        .collect();
    sources.dedup();
    sources.sort_unstable();
    sources.dedup();
    let records: Vec<Value> = evidence
        .iter()
        .take(SUMMARY_EVIDENCE)
        .map(|record| {
            let attributes = record
                .get("attributes")
                .and_then(Value::as_object)
                .map_or_else(Map::new, |attributes| {
                    let mut kept: Map<String, Value> = attributes
                        .iter()
                        .take(SUMMARY_ATTRIBUTES)
                        .map(|(key, value)| (key.clone(), bounded(value)))
                        .collect();
                    if attributes.len() > SUMMARY_ATTRIBUTES {
                        kept.insert(
                            "_attributes_omitted".into(),
                            json!(attributes.len() - SUMMARY_ATTRIBUTES),
                        );
                    }
                    kept
                });
            json!({
                "source": record.pointer("/provenance/source").cloned().unwrap_or(Value::Null),
                "summary": record.get("summary").map_or(Value::Null, bounded),
                "attributes": attributes,
            })
        })
        .collect();
    let mut compact = json!({
        "kind": entity.get("kind").cloned().unwrap_or(Value::Null),
        "value": entity.get("value").cloned().unwrap_or(Value::Null),
        "confidence": entity.get("confidence").cloned().unwrap_or(Value::Null),
        "corroboration": entity.get("corroboration").cloned().unwrap_or(Value::Null),
        "tags": entity.get("tags").cloned().unwrap_or_else(|| json!([])),
        "sources": sources,
        "evidence": records,
    });
    if evidence.len() > SUMMARY_EVIDENCE {
        compact["evidence_omitted"] = json!(evidence.len() - SUMMARY_EVIDENCE);
    }
    compact
}

/// A value with any string cut to [`SUMMARY_VALUE_CHARS`] characters, marked where cut.
fn bounded(value: &Value) -> Value {
    match value {
        Value::String(text) if text.chars().count() > SUMMARY_VALUE_CHARS => {
            let mut cut: String = text.chars().take(SUMMARY_VALUE_CHARS).collect();
            cut.push('…');
            Value::String(cut)
        }
        other => other.clone(),
    }
}

fn discover_arguments(arguments: &Map<String, Value>) -> Result<(String, Region), ToolError> {
    refuse_unknown(arguments, &["name", "region"])?;
    let name = text_argument(arguments, "name", MAX_ARGUMENT_BYTES)?;
    let region = choice_argument(arguments, "region", "au")?;
    let region = Region::parse(&region)
        .ok_or_else(|| format!("unknown region {region}; expected au, us or ae"))?;
    Ok((name, region))
}

fn envelope(id: Value, key: &str, body: Value) -> Value {
    let mut message = Map::new();
    message.insert("jsonrpc".into(), Value::from("2.0"));
    message.insert("id".into(), id);
    message.insert(key.into(), body);
    Value::Object(message)
}

fn success(id: Value, result: Value) -> Value {
    envelope(id, "result", result)
}

fn error(id: Value, code: i64, message: &str) -> Value {
    envelope(id, "error", json!({ "code": code, "message": message }))
}

fn discard_rest_of_line<R: BufRead>(input: &mut R) -> std::io::Result<()> {
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        if let Some(end) = buffer.iter().position(|byte| *byte == b'\n') {
            input.consume(end + 1);
            return Ok(());
        }
        let length = buffer.len();
        input.consume(length);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Records every call and answers from a script, offline.
    #[derive(Default)]
    struct Recorder {
        calls: RefCell<Vec<String>>,
        fail: bool,
    }

    impl Tools for Recorder {
        fn lookup(&self, kind: &str, selector: &str) -> Result<Value, ToolError> {
            self.calls
                .borrow_mut()
                .push(format!("lookup {kind} {selector}"));
            if self.fail {
                return Err("selector is not valid for this kind".into());
            }
            Ok(json!({ "route": kind, "entities": [], "outcomes": [] }))
        }

        fn people_discover(&self, name: &str, region: Region) -> Result<Value, ToolError> {
            self.calls
                .borrow_mut()
                .push(format!("discover {name} {region:?}"));
            Ok(json!({ "subject": name, "candidates": [] }))
        }

        fn research(&self, query: &str) -> Result<Value, ToolError> {
            self.calls.borrow_mut().push(format!("research {query}"));
            Ok(json!({ "route": "adaptive_web_search" }))
        }

        fn research_mission(&self, selector: &str) -> Result<Value, ToolError> {
            self.calls
                .borrow_mut()
                .push(format!("research_mission {selector}"));
            Ok(json!({ "mission_id": "0123456789abcdef", "status": "RUNNING" }))
        }

        fn investigate(&self, text: &str) -> Result<Value, ToolError> {
            self.calls.borrow_mut().push(format!("investigate {text}"));
            Ok(json!({ "route": "investigate", "entities": [] }))
        }

        fn investigate_file(&self, path: &str) -> Result<Value, ToolError> {
            self.calls
                .borrow_mut()
                .push(format!("investigate_file {path}"));
            Ok(json!({ "route": "investigate", "entities": [] }))
        }

        fn analyze(&self, seeds: &[String]) -> Result<Value, ToolError> {
            self.calls
                .borrow_mut()
                .push(format!("analyze {}", seeds.join(",")));
            Ok(json!({ "accepted": seeds, "entities": [] }))
        }

        fn scans_list(&self) -> Result<Value, ToolError> {
            self.calls.borrow_mut().push("scans_list".into());
            Ok(json!([{ "id": "0123456789abcdef", "status": "FINISHED" }]))
        }

        fn scan_read(
            &self,
            id: &str,
            view: ScanView,
            kind: Option<&str>,
        ) -> Result<Value, ToolError> {
            self.calls.borrow_mut().push(format!(
                "scan_read {id} {} {}",
                view.name(),
                kind.unwrap_or("-")
            ));
            Ok(json!({ "EMAILADDR": 2 }))
        }

        fn radar_wifi(&self) -> Result<Value, ToolError> {
            self.calls.borrow_mut().push("radar_wifi".into());
            Err("termux-wifi-scaninfo is not available on this device".into())
        }

        fn radar_cells(&self) -> Result<Value, ToolError> {
            self.calls.borrow_mut().push("radar_cells".into());
            Ok(json!({ "source": "termux-telephony-cellinfo", "cells": [] }))
        }

        fn radar_track(&self) -> Result<Value, ToolError> {
            self.calls.borrow_mut().push("radar_track".into());
            Ok(json!({ "sweeps": 1, "recurring": [], "followers": [] }))
        }
    }

    fn answer(tools: &Recorder, line: &str) -> Option<Value> {
        Server::new(tools, "test").handle_line(line.as_bytes())
    }

    fn call(tools: &Recorder, name: &str, arguments: &Value) -> Value {
        let request = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        answer(tools, &request.to_string()).expect("a request is answered")
    }

    #[test]
    fn initialize_negotiates_a_known_revision_and_falls_back_to_the_newest() {
        let tools = Recorder::default();
        for asked in PROTOCOL_VERSIONS {
            let reply = answer(
                &tools,
                &json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                        "params":{"protocolVersion":asked,"capabilities":{},
                                  "clientInfo":{"name":"t","version":"1"}}})
                .to_string(),
            )
            .unwrap();
            assert_eq!(reply["result"]["protocolVersion"], asked);
            assert_eq!(reply["result"]["serverInfo"]["name"], "huntsman-recon");
            assert_eq!(
                reply["result"]["capabilities"]["tools"]["listChanged"],
                false
            );
        }
        let reply = answer(
            &tools,
            r#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
        )
        .unwrap();
        assert_eq!(reply["id"], "a");
        assert_eq!(reply["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }

    #[test]
    fn notifications_and_client_responses_get_no_answer() {
        let tools = Recorder::default();
        for line in [
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}"#,
            r#"{"jsonrpc":"2.0","id":9,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":9,"error":{"code":1,"message":"x"}}"#,
            "",
            "   ",
        ] {
            assert_eq!(answer(&tools, line), None, "{line:?}");
        }
    }

    #[test]
    fn malformed_messages_get_the_json_rpc_error_codes() {
        let tools = Recorder::default();
        let code = |line: &str| answer(&tools, line).unwrap()["error"]["code"].clone();
        assert_eq!(code("{not json"), PARSE_ERROR);
        assert_eq!(code("[]"), INVALID_REQUEST);
        assert_eq!(code("42"), INVALID_REQUEST);
        assert_eq!(code(r#"{"jsonrpc":"2.0","id":1}"#), INVALID_REQUEST);
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#),
            INVALID_REQUEST
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","id":1,"method":"resources/list"}"#),
            METHOD_NOT_FOUND
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rm"}}"#),
            INVALID_PARAMS
        );
        let pong = answer(&tools, r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#).unwrap();
        assert_eq!(pong, json!({"jsonrpc":"2.0","id":2,"result":{}}));
    }

    #[test]
    fn a_batch_answers_its_requests_and_skips_its_notifications() {
        let tools = Recorder::default();
        let reply = answer(
            &tools,
            r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"ping"}]"#,
        )
        .unwrap();
        let ids: Vec<&Value> = reply.as_array().unwrap().iter().map(|r| &r["id"]).collect();
        assert_eq!(ids, [&json!(1), &json!(2)]);
        assert_eq!(
            answer(
                &tools,
                r#"[{"jsonrpc":"2.0","method":"notifications/initialized"}]"#
            ),
            None
        );
    }

    #[test]
    fn the_lookup_tool_tells_a_model_what_confidence_and_the_tags_mean() {
        let tools = Recorder::default();
        let reply = answer(&tools, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        let lookup = reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "lookup")
            .unwrap();
        let text = lookup["description"].as_str().unwrap();
        for needle in [
            format!("{} and above is a link", crate::gap::EXPAND_FLOOR),
            format!("tagged {}", crate::tags::INCIDENTAL),
            crate::tags::SHARED_HOSTING.to_owned(),
            format!("more than {} names", crate::ip_cli::MAX_COHOSTS),
            "not a link to it".to_owned(),
        ] {
            assert!(text.contains(&needle), "{needle}: {text}");
        }
    }

    #[test]
    fn tools_list_describes_every_tool_with_a_closed_object_schema() {
        let tools = Recorder::default();
        let reply = answer(&tools, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        let listed = reply["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = listed.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "lookup",
                "people_discover",
                "research",
                "research_mission",
                "investigate",
                "investigate_file",
                "analyze",
                "scans_list",
                "scan_read",
                "ble_decode",
                "radar_wifi",
                "radar_cells",
                "radar_track",
            ]
        );
        for tool in listed {
            let name = tool["name"].as_str().unwrap();
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{tool}");
            // Only a tracking sweep (the device's own log) and a research mission (a saved
            // scan) write anything.
            assert_eq!(
                tool["annotations"]["readOnlyHint"],
                !matches!(name, "radar_track" | "research_mission"),
                "{tool}"
            );
            assert_eq!(tool["annotations"]["destructiveHint"], false, "{tool}");
            assert!(tool["description"].as_str().unwrap().len() > 40, "{tool}");
            // The offline tools say so: a model may call them freely and expect the same answer.
            // The device tools read this phone, not the open world, and not the same twice.
            let offline = matches!(
                name,
                "investigate"
                    | "investigate_file"
                    | "analyze"
                    | "scans_list"
                    | "scan_read"
                    | "ble_decode"
            );
            let device = name.starts_with("radar_");
            assert_eq!(
                tool["annotations"]["openWorldHint"],
                !(offline || device),
                "{tool}"
            );
            // A mission asked again while it runs joins it, so it is idempotent though live.
            assert_eq!(
                tool["annotations"]["idempotentHint"],
                offline || name == "research_mission",
                "{tool}"
            );
            assert_eq!(
                tool["description"]
                    .as_str()
                    .unwrap()
                    .starts_with("Offline: no request, no key."),
                offline,
                "{tool}"
            );
        }
        // The schema's kinds are exactly the typed routes, `auto`, and the public searches.
        let kinds = &listed[0]["inputSchema"]["properties"]["kind"]["enum"];
        assert_eq!(
            kinds.as_array().unwrap().len(),
            1 + ScanKind::ALL.len() + Source::NAMED.len()
        );
        for kind in ScanKind::ALL {
            assert!(kinds.as_array().unwrap().contains(&json!(kind.command())));
        }
    }

    #[test]
    fn ble_decode_reads_a_scanner_record_offline_and_radar_tools_reach_the_device() {
        let tools = Recorder::default();
        let reply = call(
            &tools,
            "ble_decode",
            &json!({"bytes": ["01:06", "02:", "ff:7500021861B10F3C908FD6B6C2309A2F4F5604AE24545B5A363A"],
                     "address": "67:06:21:95:C1:7C"}),
        );
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        let report = &reply["result"]["structuredContent"];
        assert_eq!(report["source"], "ble-adv");
        assert_eq!(
            report["manufacturer"][0]["company"],
            "Samsung Electronics Co. Ltd."
        );
        assert_eq!(report["manufacturer"][0]["payload_bytes"], 24);
        assert!(report["manufacturer"][0].get("payload_hex").is_none());
        assert_eq!(report["address"]["kind"], "resolvable_private");
        assert!(tools.calls.borrow().is_empty(), "decoding needs no adapter");

        let raw = call(
            &tools,
            "ble_decode",
            &json!({"bytes": ["ff:750093f6"], "raw": true}),
        );
        assert_eq!(
            raw["result"]["structuredContent"]["manufacturer"][0]["payload_hex"],
            "93f6"
        );
        for bad in [
            json!({}),
            json!({"bytes": []}),
            json!({"bytes": ["zz"]}),
            json!({"bytes": ["0509414243"]}),
            json!({"bytes": ["020106"], "address": "not an address"}),
            json!({"bytes": ["020106"], "raw": "yes"}),
            json!({"bytes": ["020106"], "extra": 1}),
        ] {
            let reply = call(&tools, "ble_decode", &bad);
            assert_eq!(reply["result"]["isError"], true, "{bad}: {reply}");
        }

        let wifi = call(&tools, "radar_wifi", &json!({}));
        assert_eq!(wifi["result"]["isError"], true);
        assert_eq!(
            wifi["result"]["content"][0]["text"],
            "termux-wifi-scaninfo is not available on this device"
        );
        let cells = call(&tools, "radar_cells", &json!({}));
        assert_eq!(cells["result"]["structuredContent"]["cells"], json!([]));
        let track = call(&tools, "radar_track", &json!({}));
        assert_eq!(track["result"]["structuredContent"]["sweeps"], 1);
        let refused = call(&tools, "radar_cells", &json!({"scan": true}));
        assert_eq!(refused["result"]["isError"], true);
        assert_eq!(
            tools.calls.borrow().as_slice(),
            ["radar_wifi", "radar_cells", "radar_track"]
        );
    }

    #[test]
    fn a_call_runs_its_tool_with_validated_arguments() {
        let tools = Recorder::default();
        let reply = call(
            &tools,
            "lookup",
            &json!({"selector":"  example.com ","kind":"Domain"}),
        );
        assert_eq!(reply["result"]["isError"], false);
        assert_eq!(reply["result"]["structuredContent"]["route"], "domain");
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap()["route"],
            "domain"
        );
        call(&tools, "lookup", &json!({"selector":"8.8.8.8"}));
        call(
            &tools,
            "people_discover",
            &json!({"name":"Clara Ashwell","region":"us"}),
        );
        call(&tools, "people_discover", &json!({"name":"Clara Ashwell"}));
        call(&tools, "research", &json!({"query":"rust termux"}));
        call(
            &tools,
            "research_mission",
            &json!({"selector":" example.com "}),
        );
        call(
            &tools,
            "investigate",
            &json!({"text":"  mail a@example.com  "}),
        );
        call(
            &tools,
            "investigate_file",
            &json!({"path":" /sdcard/DCIM/IMG_0001.jpg "}),
        );
        call(
            &tools,
            "analyze",
            &json!({"seeds":[" a@example.com ", "example.com"]}),
        );
        let listed = call(&tools, "scans_list", &json!({}));
        assert_eq!(listed["result"]["structuredContent"]["count"], 1);
        assert_eq!(listed["result"]["structuredContent"]["listed"], 1);
        assert_eq!(listed["result"]["structuredContent"]["truncated"], false);
        assert_eq!(
            listed["result"]["structuredContent"]["scans"][0]["id"],
            "0123456789abcdef"
        );
        let read = call(&tools, "scan_read", &json!({"id":" 0123456789abcdef "}));
        assert_eq!(
            read["result"]["structuredContent"],
            json!({"id": "0123456789abcdef", "view": "summary", "report": {"EMAILADDR": 2}})
        );
        call(
            &tools,
            "scan_read",
            &json!({"id":"0123456789abcdef","view":"elements","type":"EMAILADDR"}),
        );
        assert_eq!(
            *tools.calls.borrow(),
            [
                "lookup domain example.com",
                "lookup auto 8.8.8.8",
                "discover Clara Ashwell Us",
                "discover Clara Ashwell Au",
                "research rust termux",
                "research_mission example.com",
                "investigate mail a@example.com",
                "investigate_file /sdcard/DCIM/IMG_0001.jpg",
                "analyze a@example.com,example.com",
                "scans_list",
                "scan_read 0123456789abcdef summary -",
                "scan_read 0123456789abcdef elements EMAILADDR",
            ]
        );
    }

    /// A machine with more saved scans than a model reads is listed newest first within
    /// [`MAX_LISTED_SCANS`], the answer counting every scan and saying it was cut; one with
    /// fewer is listed whole and says it was not.
    #[test]
    fn a_long_scan_list_is_cut_to_the_newest_and_counted() {
        struct Many(usize);
        impl Tools for Many {
            fn lookup(&self, _: &str, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn people_discover(&self, _: &str, _: Region) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn research(&self, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn research_mission(&self, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn investigate(&self, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn investigate_file(&self, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn analyze(&self, _: &[String]) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn scans_list(&self) -> Result<Value, ToolError> {
                Ok(Value::Array(
                    (0..self.0)
                        .map(|index| json!({ "id": format!("{index:016x}"), "created": self.0 - index }))
                        .collect(),
                ))
            }
            fn scan_read(&self, _: &str, _: ScanView, _: Option<&str>) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn radar_wifi(&self) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn radar_cells(&self) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn radar_track(&self) -> Result<Value, ToolError> {
                unreachable!()
            }
        }
        let list = |count: usize| {
            let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"scans_list"}});
            Server::new(&Many(count), "t")
                .handle_line(request.to_string().as_bytes())
                .unwrap()["result"]["structuredContent"]
                .clone()
        };
        let cut = list(MAX_LISTED_SCANS + 37);
        assert_eq!(cut["count"], MAX_LISTED_SCANS + 37);
        assert_eq!(cut["listed"], MAX_LISTED_SCANS);
        assert_eq!(cut["truncated"], true);
        let rows = cut["scans"].as_array().unwrap();
        assert_eq!(rows.len(), MAX_LISTED_SCANS);
        assert_eq!(rows[0]["id"], format!("{:016x}", 0), "the newest first");
        let whole = list(3);
        assert_eq!(whole["count"], 3);
        assert_eq!(whole["listed"], 3);
        assert_eq!(whole["truncated"], false);
    }

    #[test]
    fn bad_arguments_and_failed_lookups_are_tool_errors_the_model_can_read() {
        let tools = Recorder::default();
        for (name, arguments) in [
            ("lookup", json!({})),
            ("lookup", json!({"selector":""})),
            ("lookup", json!({"selector":7})),
            ("lookup", json!({"selector":"x","kind":"satellite"})),
            ("lookup", json!({"selector":"x","extra":1})),
            (
                "lookup",
                json!({"selector":"x".repeat(MAX_ARGUMENT_BYTES + 1)}),
            ),
            ("people_discover", json!({"name":"A B","region":"uk"})),
            ("research", json!({"q":"x"})),
            ("research_mission", json!({})),
            ("research_mission", json!({"selector":"  "})),
            (
                "research_mission",
                json!({"selector":"example.com","depth":2}),
            ),
            (
                "research_mission",
                json!({"selector":"x".repeat(MAX_ARGUMENT_BYTES + 1)}),
            ),
            ("investigate", json!({})),
            ("investigate", json!({"text":"   "})),
            ("investigate", json!({"text":"x","extra":1})),
            (
                "investigate",
                json!({"text":"x".repeat(MAX_TEXT_BYTES + 1)}),
            ),
            ("investigate_file", json!({})),
            ("investigate_file", json!({"path":"   "})),
            ("investigate_file", json!({"path":7})),
            ("investigate_file", json!({"path":"/tmp/a","text":"x"})),
            (
                "investigate_file",
                json!({"path":"x".repeat(MAX_ARGUMENT_BYTES + 1)}),
            ),
            ("analyze", json!({})),
            ("analyze", json!({"seeds":"a@example.com"})),
            ("analyze", json!({"seeds":[]})),
            ("analyze", json!({"seeds":["a@example.com", 7]})),
            ("analyze", json!({"seeds":["a@example.com", "  "]})),
            (
                "analyze",
                json!({"seeds": vec!["x"; MAX_ANALYZE_SEEDS + 1]}),
            ),
            ("analyze", json!({"seeds":["x"], "depth": 2})),
            ("scans_list", json!({"id":"0123456789abcdef"})),
            ("scan_read", json!({})),
            ("scan_read", json!({"id":"not-a-scan-id"})),
            ("scan_read", json!({"id":"0123456789abcdef","view":"graph"})),
            ("scan_read", json!({"id":"0123456789abcdef","view":7})),
            (
                "scan_read",
                json!({"id":"0123456789abcdef","type":"EMAILADDR"}),
            ),
            (
                "scan_read",
                json!({"id":"0123456789abcdef","view":"elements","type":"EMAIL ADDR"}),
            ),
            (
                "scan_read",
                json!({"id":"0123456789abcdef","view":"elements","unique":true}),
            ),
        ] {
            let reply = call(&tools, name, &arguments);
            assert_eq!(reply["result"]["isError"], true, "{arguments}");
            assert!(reply["result"].get("structuredContent").is_none());
        }
        assert!(
            tools.calls.borrow().is_empty(),
            "no invalid call reached a tool"
        );
        let failing = Recorder {
            fail: true,
            ..Recorder::default()
        };
        let reply = call(&failing, "lookup", &json!({"selector":"x","kind":"email"}));
        assert_eq!(reply["result"]["isError"], true);
        assert_eq!(
            reply["result"]["content"][0]["text"],
            "selector is not valid for this kind"
        );
    }

    /// A report shaped like a live lookup's: one entity with many large evidence records, and
    /// many small ones, with synergy links and rendered text.
    fn busy_report() -> Value {
        let big_evidence: Vec<Value> = (0..16)
            .map(|n| {
                let attributes: Map<String, Value> = (0..40)
                    .map(|a| (format!("a{a:02}"), json!("x".repeat(1000))))
                    .collect();
                json!({"provenance":{"source":format!("src{}", n % 3)},
                       "summary":format!("record {n}"),"attributes":attributes})
            })
            .collect();
        let mut entities = vec![json!({
            "kind":"ip_address","value":"192.0.2.1","confidence":0.9,"corroboration":3,
            "tags":["seed"],"evidence":big_evidence,
        })];
        for n in 0..3000 {
            entities.push(json!({
                "kind":"domain","value":format!("host{n}.example"),"confidence":0.5,
                "corroboration":1,"tags":[],"evidence":[{"provenance":{"source":"ct"},
                "summary":"seen","attributes":{"n":n}}],
            }));
        }
        json!({"route":"ip","text":"t".repeat(500_000),"entities":entities,
               "outcomes":[{"module":"rdap","kind":"success"}],
               "synergy":{"links":[{"a":1},{"b":2}]}})
    }

    #[test]
    fn a_summary_keeps_every_outcome_and_count_within_its_budget() {
        let report = busy_report();
        let summary = summarize_lookup(&report);
        let size = serde_json::to_string(&summary).unwrap().len();
        assert!(
            size < SUMMARY_ENTITY_BYTES + 4096,
            "summary is {size} bytes"
        );
        assert_eq!(summary["route"], "ip");
        assert_eq!(summary["outcomes"], report["outcomes"]);
        assert_eq!(summary["entity_count"], 3001);
        assert_eq!(summary["entities_by_kind"]["domain"], 3000);
        assert_eq!(summary["entities_by_kind"]["ip_address"], 1);
        assert_eq!(summary["synergy_links"], 2);
        assert!(summary.get("text").is_none() && summary.get("synergy").is_none());
        assert!(
            summary["omitted"]
                .as_str()
                .unwrap()
                .contains("detail: full")
        );
        // The most confident entity leads, with its cuts counted, not hidden.
        let first = &summary["entities"][0];
        assert_eq!(first["value"], "192.0.2.1");
        assert_eq!(first["sources"], json!(["src0", "src1", "src2"]));
        assert_eq!(
            first["evidence"].as_array().unwrap().len(),
            SUMMARY_EVIDENCE
        );
        assert_eq!(first["evidence_omitted"], 16 - SUMMARY_EVIDENCE);
        let attributes = first["evidence"][0]["attributes"].as_object().unwrap();
        assert_eq!(attributes["_attributes_omitted"], 40 - SUMMARY_ATTRIBUTES);
        assert!(attributes["a00"].as_str().unwrap().ends_with('…'));
        assert_eq!(
            summary["entities_shown"],
            summary["entities"].as_array().unwrap().len()
        );
    }

    #[test]
    fn a_summary_shows_the_best_of_every_kind_before_more_of_one() {
        // An AS lookup: thousands of confident netblocks, and the one domain, the contacts and
        // the holder that make the lookup useful, below or level with them.
        let record = |source: &str| {
            json!([{"provenance":{"source":source},"summary":"as published",
                    "attributes":{"registry":"arin","handle":"x".repeat(200)}}])
        };
        let mut entities = vec![
            json!({"kind":"asn","value":"AS64500","confidence":0.9,"corroboration":4,
                   "tags":["seed"],"evidence":record("rdap")}),
            json!({"kind":"email","value":"abuse@example.net","confidence":0.85,
                   "corroboration":1,"tags":["abuse-contact"],"evidence":record("rdap")}),
            json!({"kind":"organisation","value":"Example Net","confidence":0.85,
                   "corroboration":2,"tags":[],"evidence":record("rdap")}),
            json!({"kind":"domain","value":"example.net","confidence":0.65,
                   "corroboration":1,"tags":["peeringdb-website"],"evidence":record("peeringdb")}),
        ];
        for n in 0..3000 {
            entities.push(json!({
                "kind":"netblock","value":format!("198.51.{}.0/24", n % 256),"confidence":0.85,
                "corroboration":1,"tags":[],"evidence":record("ripestat"),
            }));
        }
        let report = json!({"route":"asn","entities":entities,"outcomes":[]});
        let summary = summarize_lookup(&report);
        let shown: Vec<(&str, &str)> = summary["entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["kind"].as_str().unwrap(), e["value"].as_str().unwrap()))
            .collect();
        assert!(
            shown.len() < 3004,
            "the budget cuts most netblocks: {}",
            shown.len()
        );
        // The first round is the best of every kind, lanes in rank order (the holder is better
        // corroborated than the contact), the seed first; the domain, the weakest single
        // entity, is shown before the second netblock.
        assert_eq!(shown[0], ("asn", "AS64500"));
        let first_round: Vec<&str> = shown.iter().take(5).map(|(kind, _)| *kind).collect();
        assert_eq!(
            first_round,
            ["asn", "organisation", "email", "netblock", "domain"]
        );
        let position = |value: &str| shown.iter().position(|(_, v)| *v == value).unwrap();
        assert!(position("example.net") < position("198.51.1.0/24"));
        assert!(shown.iter().filter(|(kind, _)| *kind == "netblock").count() > 100);
        assert_eq!(summary["entities_by_kind"]["netblock"], 3000);
    }

    #[test]
    fn a_small_report_is_shown_whole_and_says_nothing_was_cut() {
        let report = json!({"route":"email","entities":[{"kind":"email","value":"a@example.com",
            "confidence":0.99,"tags":["seed"],"evidence":[]}],"outcomes":[]});
        let summary = summarize_lookup(&report);
        assert_eq!(summary["entities_shown"], 1);
        assert!(summary.get("omitted").is_none());
    }

    #[test]
    fn lookup_summarizes_by_default_and_returns_the_whole_report_on_request() {
        struct Busy;
        impl Tools for Busy {
            fn lookup(&self, _: &str, _: &str) -> Result<Value, ToolError> {
                Ok(busy_report())
            }
            fn people_discover(&self, _: &str, _: Region) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn research(&self, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn research_mission(&self, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn investigate(&self, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn investigate_file(&self, _: &str) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn analyze(&self, _: &[String]) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn scans_list(&self) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn scan_read(&self, _: &str, _: ScanView, _: Option<&str>) -> Result<Value, ToolError> {
                unreachable!()
            }
            fn radar_wifi(&self) -> Result<Value, ToolError> {
                Err("no device".into())
            }
            fn radar_cells(&self) -> Result<Value, ToolError> {
                Err("no device".into())
            }
            fn radar_track(&self) -> Result<Value, ToolError> {
                Err("no device".into())
            }
        }
        let run = |arguments: Value| {
            let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"lookup","arguments":arguments}});
            Server::new(&Busy, "t")
                .handle_line(request.to_string().as_bytes())
                .unwrap()
        };
        let summary = run(json!({"selector":"192.0.2.1"}));
        assert_eq!(summary["result"]["structuredContent"]["detail"], "summary");
        let full = run(json!({"selector":"192.0.2.1","detail":"full"}));
        assert_eq!(full["result"]["structuredContent"], busy_report());
        let wrong = run(json!({"selector":"192.0.2.1","detail":"everything"}));
        assert_eq!(wrong["result"]["isError"], true);
    }

    #[test]
    fn serve_frames_one_answer_per_request_line_until_input_ends() {
        let tools = Recorder::default();
        let input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\r\n\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"research","arguments":{"query":"ünïcode"}}}"#,
        );
        let mut output = Vec::new();
        Server::new(&tools, "test")
            .serve(input.as_bytes(), &mut output)
            .unwrap();
        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["id"], 1);
        assert_eq!(lines[1]["id"], 2);
        assert_eq!(*tools.calls.borrow(), ["research ünïcode"]);
    }

    #[test]
    fn an_oversized_line_is_refused_and_the_next_line_still_served() {
        let tools = Recorder::default();
        let mut input = vec![b' '; MAX_MESSAGE_BYTES + 10];
        input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n");
        let mut output = Vec::new();
        Server::new(&tools, "test")
            .serve(input.as_slice(), &mut output)
            .unwrap();
        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["error"]["code"], INVALID_REQUEST);
        assert_eq!(lines[1]["id"], 3);
    }
}
