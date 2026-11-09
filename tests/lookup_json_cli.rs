//! `--json` on the typed lookup commands: one JSON object on standard output, the shape
//! `/api/lookup` and the MCP `lookup` tool return, for agents and scripts that run the binary
//! and read what it prints. Held offline through `phone`, which asks no source without a key.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_USAGE};
use huntsman_recon::scan_route::ScanKind;
use serde_json::Value;

fn home(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("lookup-json-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The binary with no inherited key that would make `phone` ask a network source.
fn bin(home: &PathBuf) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command.env("HOME", home).env_remove("HUNTSMAN_HOME");
    for key in ["HUNTSMAN_NUMVERIFY_KEY", "HUNTSMAN_IPQS_KEY"] {
        command.env_remove(key);
    }
    command
}

#[test]
fn json_prints_one_object_with_the_api_lookup_shape() {
    let home = home("shape");
    let out = bin(&home)
        .args(["phone", "+14155552671", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["route"], "phone");
    for key in ["text", "entities", "outcomes", "synergy"] {
        assert!(report.get(key).is_some(), "no {key}: {report}");
    }
    assert!(report.get("saved").is_none());
    let outcomes = report["outcomes"].as_array().unwrap();
    assert!(
        outcomes
            .iter()
            .any(|o| o["module"] == "numverify" && o["kind"] == "not_configured"),
        "{outcomes:?}"
    );
    // The same report as the text form, not a different lookup.
    let text = bin(&home).args(["phone", "+14155552671"]).output().unwrap();
    assert_eq!(
        report["text"].as_str().unwrap(),
        String::from_utf8(text.stdout).unwrap()
    );
}

#[test]
fn json_with_save_puts_the_ledger_receipt_inside_the_object() {
    let home = home("save");
    let ledger = home.join("ledger.json");
    let out = bin(&home)
        .args(["phone", "+14155552671", "--save"])
        .arg(&ledger)
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "receipt lines leaked: {stdout}");
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["saved"]["path"], ledger.display().to_string());
    assert!(report["saved"]["entries"].as_u64().unwrap() > 0);
    assert_eq!(report["saved"]["tip"].as_str().unwrap().len(), 64);
    assert!(ledger.is_file());
}

#[test]
fn json_keeps_the_commands_argument_errors() {
    let home = home("errors");
    let twice = bin(&home)
        .args(["phone", "+14155552671", "--json", "--json"])
        .output()
        .unwrap();
    assert_eq!(twice.status.code(), Some(i32::from(EX_USAGE)));
    assert!(twice.stdout.is_empty());
    let bad = bin(&home)
        .args(["email", "not an address", "--json"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(i32::from(EX_DATAERR)));
    assert!(bad.stdout.is_empty());
}

#[test]
fn every_typed_lookup_documents_json() {
    let home = home("help");
    for kind in ScanKind::ALL {
        let out = bin(&home)
            .args([kind.command(), "--help"])
            .output()
            .unwrap();
        let help = String::from_utf8(out.stdout).unwrap();
        assert!(help.contains("[--json]"), "{}: {help}", kind.command());
        assert!(
            help.contains("--json prints the report as one JSON object"),
            "{}: {help}",
            kind.command()
        );
    }
}
