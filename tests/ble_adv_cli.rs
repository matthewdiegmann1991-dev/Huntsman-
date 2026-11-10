//! `radar ble-adv`: the real binary decodes advertisement bytes offline, as text and as JSON.

use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_USAGE};
use serde_json::Value;

fn bin() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command.env(
        "HOME",
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ble-adv-home"),
    );
    command.env_remove("HUNTSMAN_HOME");
    command
}

#[test]
fn a_scanner_record_decodes_to_json_and_rows() {
    let out = bin()
        .args([
            "radar",
            "ble-adv",
            "--address",
            "67:06:21:95:C1:7C",
            "--json",
            "01:06",
            "ff:7500021861B10F3C908FD6B6C2309A2F4F5604AE24545B5A363A",
            "0c094572696b2773205332322b",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["source"], "ble-adv");
    assert_eq!(report["local_name"], "Erik's S22+");
    assert_eq!(report["manufacturer"][0]["company_id"], "0075");
    assert_eq!(
        report["manufacturer"][0]["company"],
        "Samsung Electronics Co. Ltd."
    );
    assert_eq!(report["manufacturer"][0]["payload_bytes"], 24);
    assert!(report["manufacturer"][0].get("payload_hex").is_none());
    assert_eq!(report["address"]["kind"], "resolvable_private");
    assert_eq!(report["flags"]["set"][0], "le_general_discoverable");

    let text = bin()
        .args(["radar", "ble-adv", "--raw", "ff:750093F67DCFC4FF"])
        .output()
        .unwrap();
    assert_eq!(text.status.code(), Some(0));
    let rows = String::from_utf8(text.stdout).unwrap();
    assert!(
        rows.contains("manufacturer\t0x0075\tSamsung Electronics Co. Ltd.\tpayload_bytes=6\tpayload=93f67dcfc4ff"),
        "{rows}"
    );
}

#[test]
fn bad_input_is_refused_and_usage_holds() {
    let cut = bin()
        .args(["radar", "ble-adv", "0509414243"])
        .output()
        .unwrap();
    assert_eq!(cut.status.code(), Some(i32::from(EX_DATAERR)));
    assert!(String::from_utf8_lossy(&cut.stderr).contains("says 5 bytes"));
    for args in [
        &["radar", "ble-adv"][..],
        &["radar", "ble-adv", "--address"][..],
        &["radar", "ble-adv", "--json", "--json", "020106"][..],
        &["radar", "ble-adv", "--bogus", "020106"][..],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{args:?}");
    }
    let help = bin().args(["radar", "--help"]).output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("ble-adv"));
}
