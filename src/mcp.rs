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

/// The longest selector, name or query accepted, the bound `serve`'s JSON API applies.
pub const MAX_ARGUMENT_BYTES: usize = 512;

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
            "research" => {
                text_argument(arguments, "query").and_then(|query| self.tools.research(&query))
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
returning one URL does not prove identity. Report candidates as candidates.";

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

/// The `tools/list` definitions: name, title, description, input schema and behaviour hints.
#[must_use]
pub fn tool_definitions() -> Vec<Value> {
    // Each tool reads public sources and changes nothing on this device or elsewhere.
    let hints = |title: &str| {
        json!({
            "title": title,
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": false,
            "openWorldHint": true,
        })
    };
    vec![
        json!({
            "name": "lookup",
            "title": "OSINT lookup",
            "description": "Run one live OSINT lookup through every source for its kind and \
        return the entities found with each source's typed outcome. Kinds: auto (infer from the \
        selector), people (full name: registers, sanctions, offshore leaks), email, exposure (breach \
        evidence for an email or handle), username, phone, domain (certificate transparency, DNS, \
        threat feeds), ip, netblock (CIDR), asn, network (BSSID, ssid:NAME or LAT,LON), crypto \
        (bitcoin, eth:0x…, base:0x…, sol:…), geocode (place or LAT,LON), and the public news, \
        notices, web and dossier searches. Keyed sources run only when their key is configured.",
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
        and the most confident entities with their evidence, sized for a model to read. full: the \
        complete report, which can be megabytes.",
                    },
                },
                "required": ["selector"],
                "additionalProperties": false,
            },
            "annotations": hints("OSINT lookup"),
        }),
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
            "annotations": hints("People discovery"),
        }),
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
            "annotations": hints("Web research"),
        }),
    ]
}

/// A required string argument, trimmed, nonempty and within [`MAX_ARGUMENT_BYTES`].
fn text_argument(arguments: &Map<String, Value>, key: &str) -> Result<String, ToolError> {
    let value = match arguments.get(key) {
        Some(Value::String(value)) => value.trim(),
        Some(_) => return Err(format!("{key} must be a string")),
        None => return Err(format!("{key} is required")),
    };
    if value.is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    if value.len() > MAX_ARGUMENT_BYTES {
        return Err(format!("{key} is longer than {MAX_ARGUMENT_BYTES} bytes"));
    }
    Ok(value.to_owned())
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
    let selector = text_argument(arguments, "selector")?;
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
/// kind were found, and the most confident entities with their evidence, within
/// [`SUMMARY_ENTITY_BYTES`]. The rendered text and the synergy body are left out (their size is
/// counted); every cut is reported, and `detail: full` returns the report whole. **Pure.**
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
    let mut shown = Vec::new();
    let mut used = 0;
    for entity in ranked {
        let compact = compact_entity(entity);
        let size = serde_json::to_string(&compact).map_or(usize::MAX, |text| text.len());
        if used + size > SUMMARY_ENTITY_BYTES {
            break;
        }
        used += size;
        shown.push(compact);
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
    let name = text_argument(arguments, "name")?;
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
    fn tools_list_describes_every_tool_with_a_closed_object_schema() {
        let tools = Recorder::default();
        let reply = answer(&tools, r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#).unwrap();
        let listed = reply["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = listed.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["lookup", "people_discover", "research"]);
        for tool in listed {
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{tool}");
            assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
            assert!(tool["description"].as_str().unwrap().len() > 40, "{tool}");
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
        assert_eq!(
            *tools.calls.borrow(),
            [
                "lookup domain example.com",
                "lookup auto 8.8.8.8",
                "discover Clara Ashwell Us",
                "discover Clara Ashwell Au",
                "research rust termux",
            ]
        );
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
