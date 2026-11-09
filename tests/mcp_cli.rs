//! `huntsman-recon mcp` as an MCP client runs it: the real binary, its standard input and
//! output, and only requests that need no network, so the wiring from the command to the
//! library server and on to `serve`'s own lookup adapter is held offline.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use huntsman_recon::exit::EX_USAGE;
use serde_json::{Value, json};

fn mcp(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command.arg("mcp").args(args).env(
        "HOME",
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mcp-cli-home"),
    );
    command.env_remove("HUNTSMAN_HOME");
    command
}

/// Every line the server wrote, each parsed as JSON: a line that is not JSON fails the test,
/// because a client would lose the session on it.
fn session(lines: &[Value]) -> (Vec<Value>, String, Option<i32>) {
    let mut child = mcp(&[])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for line in lines {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let answers = stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
        .collect();
    (
        answers,
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

#[test]
fn a_client_session_initializes_lists_tools_and_reads_a_refused_lookup() {
    let (answers, stderr, code) = session(&[
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"mcp_cli test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        // Refused by the lookup adapter's own selector check, before any request is made.
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"lookup","arguments":{"kind":"email","selector":"not an address"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
            "name":"people_discover","arguments":{"name":"Cher"}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"ping"}),
    ]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let ids: Vec<&Value> = answers.iter().map(|a| &a["id"]).collect();
    assert_eq!(ids, [&json!(1), &json!(2), &json!(3), &json!(4), &json!(5)]);

    assert_eq!(answers[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(answers[0]["result"]["serverInfo"]["name"], "huntsman-recon");
    assert_eq!(
        answers[0]["result"]["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    let tools: Vec<&str> = answers[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(tools, ["lookup", "people_discover", "research"]);

    // The adapter's refusal reaches the model as a readable tool error, not a protocol error.
    assert_eq!(answers[2]["result"]["isError"], true);
    assert_eq!(
        answers[2]["result"]["content"][0]["text"],
        "selector is not valid for this kind"
    );
    // A single-word name is refused by the discovery's own name check, before any request.
    assert_eq!(answers[3]["result"]["isError"], true);
    let refusal = answers[3]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(refusal.contains("two alphabetic tokens"), "{refusal}");
    assert_eq!(answers[4]["result"], json!({}));
}

#[test]
fn mcp_takes_no_arguments_and_documents_itself() {
    let out = mcp(&["--bind", "x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    let help = mcp(&["--help"]).output().unwrap();
    assert_eq!(help.status.code(), Some(0));
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("Model Context Protocol"), "{text}");
    assert!(text.contains("claude mcp add"), "{text}");
}

#[test]
fn closing_input_ends_the_server_cleanly() {
    let (answers, stderr, code) = session(&[]);
    assert_eq!(answers, Vec::<Value>::new());
    assert_eq!(code, Some(0), "{stderr}");
}
