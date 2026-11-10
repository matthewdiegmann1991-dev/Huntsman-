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

/// The tools the server lists, in order: the live lookups first, then the offline readers, then
/// the device's own radios.
const TOOL_NAMES: [&str; 12] = [
    "lookup",
    "people_discover",
    "research",
    "investigate",
    "investigate_file",
    "analyze",
    "scans_list",
    "scan_read",
    "ble_decode",
    "radar_wifi",
    "radar_cells",
    "radar_track",
];

/// Every line the server wrote, each parsed as JSON: a line that is not JSON fails the test,
/// because a client would lose the session on it.
fn session(lines: &[Value]) -> (Vec<Value>, String, Option<i32>) {
    session_in(None, lines)
}

/// [`session`], the server keeping its state (saved scans) under `home` when one is given.
fn session_in(
    home: Option<&std::path::Path>,
    lines: &[Value],
) -> (Vec<Value>, String, Option<i32>) {
    let mut command = mcp(&[]);
    if let Some(home) = home {
        command.env("HUNTSMAN_HOME", home);
    }
    let mut child = command
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
        // Offline: the classifier and the investigation spine make no request.
        json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{
            "name":"investigate","arguments":{"text":"Contact alice@example.com, site https://example.com/x"}}}),
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
            "name":"analyze","arguments":{"seeds":["alice@example.com","example.com"]}}}),
    ]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let ids: Vec<&Value> = answers.iter().map(|a| &a["id"]).collect();
    assert_eq!(
        ids,
        [
            &json!(1),
            &json!(2),
            &json!(3),
            &json!(4),
            &json!(5),
            &json!(6),
            &json!(7)
        ]
    );

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
    assert_eq!(tools, TOOL_NAMES);

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

    // investigate found the address and the link in the text, with no source outcomes.
    let investigated = &answers[5]["result"];
    assert_eq!(investigated["isError"], false, "{investigated}");
    let report = &investigated["structuredContent"];
    assert_eq!(report["route"], "investigate");
    let values: Vec<&str> = report["entities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entity| entity["value"].as_str())
        .collect();
    assert!(values.contains(&"alice@example.com"), "{values:?}");
    assert!(values.contains(&"https://example.com/x"), "{values:?}");
    assert_eq!(report["outcomes"], json!([]));

    // analyze accepted both seeds and derived the link between them.
    let analyzed = &answers[6]["result"];
    assert_eq!(analyzed["isError"], false, "{analyzed}");
    let report = &analyzed["structuredContent"];
    let accepted: Vec<&str> = report["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|seed| seed["value"].as_str())
        .collect();
    assert_eq!(accepted, ["alice@example.com", "example.com"], "{report}");
    assert!(
        report["entities"].as_array().is_some_and(|e| e.len() >= 2),
        "{report}"
    );
    assert!(
        report["relations"]
            .as_array()
            .is_some_and(|r| !r.is_empty()),
        "{report}"
    );
}

#[test]
fn ble_decode_answers_offline_and_a_device_tool_says_why_it_cannot_here() {
    let (answers, stderr, code) = session(&[
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"mcp_cli test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        // Offline: the decoder reads the bytes a scanner showed.
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"ble_decode","arguments":{"bytes":["01:06","ff:750093F67DCFC4FF"],
            "address":"67:06:21:95:C1:7C"}}}),
        // This test host is no Android phone: the device tool says why, as a tool error.
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"radar_wifi"}}),
    ]);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    let decoded = &answers[1]["result"];
    assert_eq!(decoded["isError"], false, "{decoded}");
    let report = &decoded["structuredContent"];
    assert_eq!(
        report["manufacturer"][0]["company"],
        "Samsung Electronics Co. Ltd."
    );
    assert_eq!(report["manufacturer"][0]["payload_bytes"], 6);
    assert_eq!(report["address"]["kind"], "resolvable_private");
    let wifi = &answers[2]["result"];
    assert_eq!(wifi["isError"], true, "{wifi}");
    let why = wifi["content"][0]["text"].as_str().unwrap();
    assert!(!why.is_empty(), "{wifi}");
}

/// `investigate_file` reads a file on this machine as `investigate --file` reads it: the
/// selectors in a text file, each with its evidence, under the `investigate` route with no
/// source outcome; a path that is no readable regular file is a tool error in the command's own
/// words, never a protocol error, and a symlink is refused as the command refuses it.
#[test]
fn investigate_file_reads_a_local_file_offline_and_refuses_what_the_command_refuses() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mcp-investigate-file");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let note = dir.join("note.txt");
    std::fs::write(
        &note,
        "Seller: write to bob@example.net or see https://example.net/listing/42\n",
    )
    .unwrap();
    let missing = dir.join("missing.txt");
    #[cfg(unix)]
    let link = {
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&note, &link).unwrap();
        link
    };
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"mcp_cli test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"investigate_file","arguments":{"path":note.to_str().unwrap()}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"investigate_file","arguments":{"path":missing.to_str().unwrap()}}}),
    ];
    #[cfg(unix)]
    lines.push(
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
        "name":"investigate_file","arguments":{"path":link.to_str().unwrap()}}}),
    );
    let (answers, stderr, code) = session(&lines);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");

    let read = &answers[1]["result"];
    assert_eq!(read["isError"], false, "{read}");
    let report = &read["structuredContent"];
    assert_eq!(report["route"], "investigate");
    assert_eq!(report["outcomes"], json!([]));
    let values: Vec<&str> = report["entities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entity| entity["value"].as_str().unwrap())
        .collect();
    assert!(values.contains(&"bob@example.net"), "{values:?}");
    assert!(
        values.contains(&"https://example.net/listing/42"),
        "{values:?}"
    );
    assert!(
        report["entities"][0]["evidence"]
            .as_array()
            .is_some_and(|evidence| !evidence.is_empty()),
        "{report}"
    );
    // The text content is the same report, for a client that reads only text.
    let text: Value = serde_json::from_str(read["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(&text, report);

    let absent = &answers[2]["result"];
    assert_eq!(absent["isError"], true, "{absent}");
    let why = absent["content"][0]["text"].as_str().unwrap();
    assert!(why.contains("missing.txt"), "{why}");
    #[cfg(unix)]
    {
        let refused = &answers[3]["result"];
        assert_eq!(refused["isError"], true, "{refused}");
        let why = refused["content"][0]["text"].as_str().unwrap();
        assert!(why.contains("link.txt"), "{why}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A finished scan saved under `home`, as a lookup saves one: the row, its results and one
/// element, written through the store itself so no provider runs.
fn saved_scan(home: &std::path::Path) -> String {
    use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use huntsman_recon::scan_store::{
        FORMAT_VERSION, RiskCounts, ScanOptions, ScanRecord, ScanResults, ScanStatus, ScanStore,
        new_id,
    };
    use huntsman_recon::source_outcome::SourceExecutionOutcome;

    let store = ScanStore::open(&home.join("scans")).unwrap();
    let id = new_id("example.com", 1919, 0);
    store
        .create(&ScanRecord {
            format_version: FORMAT_VERSION,
            id: id.clone(),
            name: "mcp fixture".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions {
                usecase: "passive".into(),
                ..ScanOptions::default()
            },
            status: ScanStatus::Finished,
            created: 1919,
            started: Some(1920),
            ended: Some(1921),
            elements: 1,
            unique: 1,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: vec!["dns".into()],
            owner: None,
            owner_started: None,
        })
        .unwrap();
    let evidence = Evidence::new(EvidenceProvenance::for_scan("dns", id.as_str()), "A record")
        .with_attr("ip", "192.0.2.4");
    let entity = Entity::builder(EntityKind::Domain, "example.com", 0.9, id.as_str())
        .evidence(evidence)
        .build();
    let elements = huntsman_recon::sf_elements::elements(
        huntsman_recon::sf_elements::Target {
            value: "example.com",
            kind: "INTERNET_NAME",
        },
        std::slice::from_ref(&entity),
        1919,
    );
    store
        .save_results(&ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: id.clone(),
            text: "fixture".into(),
            entities: vec![entity],
            outcomes: vec![SourceExecutionOutcome::success("dns", 1, 1)],
            elements,
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        })
        .unwrap();
    id
}

/// `scans_list` and `scan_read` read the scans saved on this machine through the scan API
/// `serve` serves: the list carries the saved row, the summary counts its elements, the elements
/// view narrows to one type, and an unknown id is a tool error in the API's own words. Nothing
/// is fetched.
#[test]
fn saved_scans_are_listed_and_read_offline() {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mcp-saved-scans");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let id = saved_scan(&home);
    let (answers, stderr, code) = session_in(
        Some(&home),
        &[
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"mcp_cli test","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scans_list"}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
                "name":"scan_read","arguments":{"id":id}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{
                "name":"scan_read","arguments":{"id":id,"view":"elements","type":"INTERNET_NAME"}}}),
            json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{
                "name":"scan_read","arguments":{"id":id,"view":"status"}}}),
            json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{
                "name":"scan_read","arguments":{"id":"0123456789abcdef"}}}),
            json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
                "name":"scan_read","arguments":{"id":id,"view":"elements","type":"EMAILADDR"}}}),
        ],
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");

    let listed = &answers[1]["result"];
    assert_eq!(listed["isError"], false, "{listed}");
    assert_eq!(listed["structuredContent"]["count"], 1);
    let row = &listed["structuredContent"]["scans"][0];
    assert_eq!(row["id"], id);
    assert_eq!(row["target"], "example.com");
    assert_eq!(row["status"], "FINISHED");

    let summary = &answers[2]["result"]["structuredContent"];
    assert_eq!(summary["id"], id);
    assert_eq!(summary["view"], "summary");
    assert!(
        summary["report"].is_object() || summary["report"].is_array(),
        "{summary}"
    );

    let elements = &answers[3]["result"]["structuredContent"];
    assert_eq!(elements["view"], "elements");
    let rows = elements["report"].as_array().unwrap();
    assert!(!rows.is_empty(), "{elements}");
    assert!(
        rows.iter().all(|row| row["type"] == "INTERNET_NAME"),
        "{elements}"
    );

    let status = &answers[4]["result"]["structuredContent"];
    assert_eq!(status["report"]["target"], "example.com");
    assert_eq!(status["report"]["sources"][0]["module"], "dns");

    let unknown = &answers[5]["result"];
    assert_eq!(unknown["isError"], true, "{unknown}");
    assert_eq!(unknown["content"][0]["text"], "no scan 0123456789abcdef");
    // The type filter reaches the API: a type the scan has no element of answers none.
    let none = &answers[6]["result"];
    assert_eq!(none["isError"], false, "{none}");
    assert_eq!(none["structuredContent"]["report"], json!([]));
    let _ = std::fs::remove_dir_all(&home);
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
