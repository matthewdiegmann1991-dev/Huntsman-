//! `--json` on `investigate` and `research`: one JSON object on standard output, the shape the
//! JSON API and the MCP server answer, for agents that run the binary and read what it prints.
//! Held offline: `investigate` makes no request, and `research --plan` chooses its route without
//! fetching.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use huntsman_recon::exit::{EX_UNAVAILABLE, EX_USAGE};
use serde_json::{Value, json};

fn bin() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command.env(
        "HOME",
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("investigate-json-home"),
    );
    command.env_remove("HUNTSMAN_HOME");
    command
}

fn one_json_line(out: &std::process::Output) -> Value {
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout.clone()).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    serde_json::from_str(&stdout).unwrap()
}

/// The (kind, value) pairs of a report's entities, in order.
fn found(report: &Value) -> Vec<(String, String)> {
    report["entities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entity| {
            (
                entity["kind"].as_str().unwrap().to_owned(),
                entity["value"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

const TEXT: &str = "Contact alice@example.com, site https://example.com/x";

#[test]
fn investigate_json_is_the_api_report_on_one_line_wherever_the_flag_is() {
    let report = one_json_line(
        &bin()
            .args(["investigate", TEXT, "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(report["route"], "investigate");
    assert_eq!(report["outcomes"], json!([]));
    assert!(report.get("scan").is_none() && report.get("status").is_none());
    let values: Vec<String> = found(&report).into_iter().map(|(_, value)| value).collect();
    assert!(
        values.contains(&"alice@example.com".to_owned()),
        "{values:?}"
    );
    assert!(
        values.contains(&"https://example.com/x".to_owned()),
        "{values:?}"
    );
    assert!(
        report["text"]
            .as_str()
            .unwrap()
            .contains("alice@example.com"),
        "{report}"
    );
    // Each entity keeps the classifier's evidence, as the rows do.
    assert!(
        report["entities"][0]["evidence"]
            .as_array()
            .is_some_and(|evidence| !evidence.is_empty()),
        "{report}"
    );

    // The flag is taken from wherever it was typed, never read as text; a second is refused.
    let first = one_json_line(
        &bin()
            .args(["investigate", "--json", TEXT])
            .output()
            .unwrap(),
    );
    assert_eq!(found(&first), found(&report));
    assert!(
        !found(&first)
            .iter()
            .any(|(_, value)| value.contains("--json"))
    );
    let twice = bin()
        .args(["investigate", TEXT, "--json", "--json"])
        .output()
        .unwrap();
    assert_eq!(twice.status.code(), Some(i32::from(EX_USAGE)));
    assert_eq!(String::from_utf8_lossy(&twice.stdout), "");
    let none = bin().args(["investigate", "--json"]).output().unwrap();
    assert_eq!(none.status.code(), Some(i32::from(EX_USAGE)));

    // The MCP investigate tool returns the same report for the same text.
    let mut child = bin()
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for line in [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"investigate json test","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
                "name":"investigate","arguments":{"text":TEXT}}}),
        ] {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    let answers: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let served = &answers[1]["result"]["structuredContent"];
    assert_eq!(served["route"], report["route"]);
    assert_eq!(served["outcomes"], report["outcomes"]);
    assert_eq!(found(served), found(&report));
    assert_eq!(
        served.as_object().unwrap().keys().collect::<Vec<_>>(),
        report.as_object().unwrap().keys().collect::<Vec<_>>()
    );
}

#[test]
fn investigate_file_json_reads_the_file_into_the_same_shape() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("investigate-json-file");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("notes.txt");
    fs::write(&path, format!("{TEXT}\nphone +14155552671\n")).unwrap();
    let report = one_json_line(
        &bin()
            .args(["investigate", "--file", path.to_str().unwrap(), "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(report["route"], "investigate");
    let values: Vec<String> = found(&report).into_iter().map(|(_, value)| value).collect();
    assert!(
        values.contains(&"alice@example.com".to_owned()),
        "{values:?}"
    );
    assert!(values.contains(&"+14155552671".to_owned()), "{values:?}");
    // The same report whichever side of --file the flag is.
    let before = one_json_line(
        &bin()
            .args(["investigate", "--json", "--file", path.to_str().unwrap()])
            .output()
            .unwrap(),
    );
    assert_eq!(found(&before), found(&report));
}

#[test]
fn research_json_plans_offline_as_an_object_and_documents_itself() {
    let web = one_json_line(
        &bin()
            .args(["research", "--plan", "--json", "anything", "goes"])
            .output()
            .unwrap(),
    );
    assert_eq!(
        web,
        json!({"route": "adaptive_web_search", "keyless": true})
    );
    let all = one_json_line(
        &bin()
            .args(["research", "--plan", "--all", "--json", "anything", "goes"])
            .output()
            .unwrap(),
    );
    assert_eq!(all["engines"], "all");
    let typed = one_json_line(
        &bin()
            .args(["research", "--json", "--plan", "example.com"])
            .output()
            .unwrap(),
    );
    assert_eq!(typed, json!({"route": "scan", "kind": "domain"}));
    // The text plan is unchanged.
    let text = bin()
        .args(["research", "--plan", "anything", "goes"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(text.stdout).unwrap(),
        "route=adaptive_web_search\tkeyless=true\n"
    );
    for args in [
        &["research", "--json"][..],
        &["research", "--json", "--json", "x"][..],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{args:?}");
    }
    for command in ["research", "investigate"] {
        let help = bin().args([command, "--help"]).output().unwrap();
        let text = String::from_utf8(help.stdout).unwrap();
        assert!(text.contains("--json"), "{command}: {text}");
        assert!(text.contains("/api/"), "{command}: {text}");
    }
}

/// `query --json`, wherever the flag is typed, is checked with the engine options before any
/// request: refused alone, twice, or beside a misplaced option, with a usage that names the
/// flag, so it is never searched for as a word of the query. Its help names what it prints.
#[test]
fn query_json_flag_is_checked_before_any_request() {
    for args in [
        &["query", "--json"][..],
        &["query", "--json", "--all"][..],
        &["query", "topic", "--json", "--json"][..],
        &["query", "--exa", "--json"][..],
        &["query", "--json", "--adaptive", "--fast", "topic"][..],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{args:?}");
        assert_eq!(out.stdout, Vec::<u8>::new(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("usage: huntsman-recon query") && stderr.contains("[--json]"),
            "{args:?}: {stderr}"
        );
    }
    // Taken from wherever it was typed: with the flag, `--exa` reaches its leg, which, without a
    // key, makes no request and reports that; read as a word, it would have been refused as one.
    for args in [
        &["query", "--exa", "topic", "--json"][..],
        &["query", "--json", "--exa", "topic"][..],
    ] {
        let out = bin()
            .env_remove("HUNTSMAN_EXA_KEY")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(i32::from(EX_UNAVAILABLE)),
            "{args:?}"
        );
        assert_eq!(out.stdout, Vec::<u8>::new(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("engine=exa\toutcome=not_configured\tfound=none"),
            "{args:?}: {stderr}"
        );
    }
    let help = bin().args(["query", "--help"]).output().unwrap();
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(
        text.contains(
            "query [--adaptive] [--all] QUERY... [--json] | query --exa QUERY... [--json]"
        ),
        "{text}"
    );
    for route in [
        "route web_search",
        "route adaptive_web_search",
        "route exa_web_search",
    ] {
        assert!(text.contains(route), "{route}: {text}");
    }
}
