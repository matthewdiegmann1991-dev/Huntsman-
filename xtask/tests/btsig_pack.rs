//! The committed company-identifier blob is what `xtask btsig pack` makes of its own `dump`, so
//! the blob is derivable from the Bluetooth SIG listing by one command, and the packer writes the
//! layout the product's reader searches.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BLOB: &str = "../src/bt_company.bin";

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask must run")
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("btsig-pack-{name}"));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The SIG listing a dump describes, quoted as the SIG file quotes.
fn yaml_of(listing: &str) -> String {
    let mut yaml = String::from("company_identifiers:\n");
    for line in listing.lines() {
        let (id, name) = line.split_once('\t').expect("ID<TAB>NAME");
        yaml.push_str(&format!(
            "\n  - value: 0x{id}\n    name: '{}'\n",
            name.replace('\'', "''")
        ));
    }
    yaml
}

#[test]
fn the_committed_blob_is_the_pack_of_its_own_dump() {
    let dump = xtask(&["btsig", "dump", BLOB]);
    assert!(dump.status.success(), "{dump:?}");
    let listing = String::from_utf8(dump.stdout).expect("UTF-8 listing");
    assert!(
        listing.lines().count() > 4000,
        "{} lines",
        listing.lines().count()
    );
    assert!(listing.contains("0075\tSamsung Electronics Co. Ltd.\n"));
    let dir = scratch("round-trip");
    let yaml = dir.join("company_identifiers.yaml");
    let out = dir.join("bt_company.bin");
    fs::write(&yaml, yaml_of(&listing)).unwrap();
    let pack = xtask(&[
        "btsig",
        "pack",
        yaml.to_str().unwrap(),
        out.to_str().unwrap(),
    ]);
    assert!(pack.status.success(), "{pack:?}");
    assert_eq!(
        fs::read(&out).unwrap(),
        fs::read(BLOB).unwrap(),
        "the committed blob must be the pack of its own dump"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The SIG UUID listing a dump describes, with the `uuid` key and the textual `id:` the SIG
/// adds, which the blob does not keep.
fn uuid_yaml_of(listing: &str) -> String {
    let mut yaml = String::from("uuids:\n");
    for line in listing.lines() {
        let (id, name) = line.split_once('\t').expect("ID<TAB>NAME");
        yaml.push_str(&format!(
            " - uuid: 0x{id}\n   name: '{}'\n   id: org.example.{id}\n",
            name.replace('\'', "''")
        ));
    }
    yaml
}

#[test]
fn the_committed_uuid_blob_is_the_pack_of_its_own_dump() {
    const UUIDS: &str = "../src/bt_uuid.bin";
    let dump = xtask(&["btsig", "dump", UUIDS]);
    assert!(dump.status.success(), "{dump:?}");
    let listing = String::from_utf8(dump.stdout).expect("UTF-8 listing");
    assert!(listing.contains("180F\tBattery\n"), "{listing}");
    assert!(listing.contains("FD5A\tSamsung Electronics Co., Ltd.\n"));
    let dir = scratch("uuid-round-trip");
    // Split the listing in two files, as the SIG publishes services and members apart.
    let lines: Vec<&str> = listing.lines().collect();
    let (first, second) = lines.split_at(lines.len() / 2);
    let a = dir.join("service_uuids.yaml");
    let b = dir.join("member_uuids.yaml");
    fs::write(&a, uuid_yaml_of(&first.join("\n"))).unwrap();
    fs::write(&b, uuid_yaml_of(&second.join("\n"))).unwrap();
    let out = dir.join("bt_uuid.bin");
    let pack = xtask(&[
        "btsig",
        "pack-uuids",
        out.to_str().unwrap(),
        a.to_str().unwrap(),
        b.to_str().unwrap(),
    ]);
    assert!(pack.status.success(), "{pack:?}");
    assert_eq!(fs::read(&out).unwrap(), fs::read(UUIDS).unwrap());
    // A UUID listed in both files is refused.
    let twice = xtask(&[
        "btsig",
        "pack-uuids",
        out.to_str().unwrap(),
        a.to_str().unwrap(),
        a.to_str().unwrap(),
    ]);
    assert_eq!(twice.status.code(), Some(64), "{twice:?}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn usage_and_a_malformed_listing_are_refused() {
    assert_eq!(xtask(&["btsig"]).status.code(), Some(64));
    let dir = scratch("malformed");
    let yaml = dir.join("bad.yaml");
    fs::write(
        &yaml,
        "company_identifiers:\n  - value: 0x0001\n  - value: 0x0002\n    name: 'x'\n",
    )
    .unwrap();
    let out = dir.join("out.bin");
    let pack = xtask(&[
        "btsig",
        "pack",
        yaml.to_str().unwrap(),
        out.to_str().unwrap(),
    ]);
    assert_eq!(pack.status.code(), Some(64), "{pack:?}");
    assert!(!out.exists());
    let _ = fs::remove_dir_all(&dir);
}
