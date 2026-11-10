use super::*;
use crate::test_support::RoutedTransport;

/// The archive as the AEC published it on 2026-11-10: thirteen CSV tables, each with its own
/// header; here the four a name lookup reaches first, with rows for one donor, one company and
/// one party, and the rest empty.
fn archive() -> Vec<u8> {
    let table = |file: &str, body: &str| (file.to_owned(), body.as_bytes().to_vec());
    let mut entries = vec![
        table(
            "Donor Returns.csv",
            "\u{feff}Financial Year,Name,Lodged on behalf of,Total Donations Made,Total Donations Received\r\n\
             2023-24,Clive Frederick Palmer,,\"$7,000,000\",$0\r\n\
             2023-24,Mineralogy Pty Ltd,,\"$1,500,000\",$0\r\n",
        ),
        table(
            "Donations Made.csv",
            "Financial Year,Donor Name,Donation Made To,Date,Value\r\n\
             2023-24,Mineralogy Pty Ltd,United Australia Party,14/03/2024,\"$1,500,000\"\r\n\
             2023-24,Clive Frederick Palmer,United Australia Party,02/02/2024,\"$7,000,000\"\r\n\
             2022-23,Someone Else,Another Party,01/01/2023,$10\r\n",
        ),
        table(
            "Detailed Receipts.csv",
            "Financial Year,Return Type,Recipient Name,Received From,Receipt Type,Value\r\n\
             2023-24,Political Party,United Australia Party,Mineralogy Pty Ltd,Donation Received,\"$1,500,000\"\r\n",
        ),
        table(
            "Third Party Returns.csv",
            "Financial Year,ClientFileId,Name,ABN,ACN,Total Expenditure,Electoral Expenditure Cat. 1,Electoral Expenditure Cat. 2,Electoral Expenditure Cat. 3,Electoral Expenditure Cat. 4,Electoral Expenditure Cat. 5,Total Gifts Received,ClientType\r\n\
             2023-24,55,Advance Australia Ltd,12345678901,,\"$2,000,000\",,,,,,$0,Third Party\r\n",
        ),
    ];
    for table_def in &TABLES {
        if !entries.iter().any(|(file, _)| file == table_def.file) {
            let header: Vec<&str> = table_def.kept.iter().map(|(title, _)| *title).collect();
            entries.push((
                table_def.file.to_owned(),
                format!("{}\r\n", header.join(",")).into_bytes(),
            ));
        }
    }
    crate::xlsx::stored_zip(&entries)
}

fn transport() -> RoutedTransport {
    RoutedTransport::new(&[]).with_bytes(ARCHIVE.url, 200, archive())
}

fn values(entities: &[Entity]) -> Vec<&str> {
    entities.iter().map(|e| e.raw_value.as_str()).collect()
}

#[test]
fn a_row_matches_when_a_name_column_carries_every_word_of_the_name() {
    let (entities, outcome) = check(&transport(), None, "Palmer Clive", "scan", 1).expect("asked");
    assert_eq!(outcome.kind, SourceOutcomeKind::Success, "{outcome:?}");
    assert_eq!(outcome.found, Some(2));
    assert!(
        outcome
            .detail
            .as_deref()
            .unwrap_or("")
            .starts_with("7 rows read across 13 tables; copy downloaded now"),
        "{outcome:?}"
    );
    let keys = values(&entities);
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert!(
        keys.contains(&"https://transparency.aec.gov.au/Download/AllAnnualData#donor-return/2023-24/clive-frederick-palmer"),
        "{keys:?}"
    );
    assert!(
        keys.contains(&"https://transparency.aec.gov.au/Download/AllAnnualData#donation-made/2023-24/clive-frederick-palmer/united-australia-party"),
        "{keys:?}"
    );
    let donation = entities
        .iter()
        .find(|e| e.raw_value.contains("donation-made"))
        .expect("the donation");
    assert_eq!(donation.kind, EntityKind::Document);
    assert!(donation.tags.iter().any(|t| t == "aec-return"));
    let evidence = &donation.evidence[0];
    assert_eq!(
        evidence
            .attributes
            .get("matched_column")
            .map(String::as_str),
        Some("Donor Name")
    );
    assert_eq!(
        evidence
            .attributes
            .get("donation_made_to")
            .map(String::as_str),
        Some("United Australia Party")
    );
    assert_eq!(
        evidence.attributes.get("value").map(String::as_str),
        Some("$7,000,000")
    );
    assert_eq!(
        evidence.attributes.get("date").map(String::as_str),
        Some("02/02/2024")
    );
    assert_eq!(
        evidence.attributes.get("dataset").map(String::as_str),
        Some(DATASET)
    );
    assert!(
        evidence.summary.contains("not proof"),
        "{}",
        evidence.summary
    );
}

#[test]
fn an_organisation_is_found_in_every_table_that_names_it_and_the_other_party_is_kept() {
    let (entities, outcome) =
        check(&transport(), None, "Mineralogy Pty Ltd", "scan", 1).expect("asked");
    assert_eq!(outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(outcome.found, Some(3));
    let keys = values(&entities);
    assert!(
        keys.iter()
            .any(|k| k.contains("#receipt/2023-24/mineralogy-pty-ltd/united-australia-party")),
        "{keys:?}"
    );
    let receipt = entities
        .iter()
        .find(|e| e.raw_value.contains("#receipt/"))
        .expect("receipt");
    let evidence = &receipt.evidence[0];
    assert_eq!(
        evidence
            .attributes
            .get("matched_column")
            .map(String::as_str),
        Some("Received From")
    );
    assert_eq!(
        evidence
            .attributes
            .get("recipient_name")
            .map(String::as_str),
        Some("United Australia Party")
    );
    assert_eq!(
        evidence.attributes.get("receipt_type").map(String::as_str),
        Some("Donation Received")
    );
}

#[test]
fn a_third_party_return_keeps_its_abn_and_a_name_with_one_word_asks_nothing() {
    let (entities, _) = check(&transport(), None, "Advance Australia", "scan", 1).expect("asked");
    let third = entities
        .iter()
        .find(|e| e.raw_value.contains("third-party-return"))
        .expect("third party");
    assert_eq!(
        third.evidence[0].attributes.get("abn").map(String::as_str),
        Some("12345678901")
    );
    assert_eq!(
        third.evidence[0]
            .attributes
            .get("client_type")
            .map(String::as_str),
        Some("Third Party")
    );
    assert!(check(&transport(), None, "Palmer", "scan", 1).is_none());
    let (entities, outcome) = check(&transport(), None, "Nobody Here", "scan", 1).expect("asked");
    assert!(entities.is_empty());
    assert_eq!(outcome.kind, SourceOutcomeKind::ValidZero);
}

#[test]
fn a_missing_table_or_archive_is_drift_or_failure_never_a_clean_zero() {
    let short = crate::xlsx::stored_zip(&[(
        "Donations Made.csv".to_owned(),
        b"Financial Year,Donor Name,Donation Made To,Date,Value\r\n2023-24,Clive Frederick Palmer,United Australia Party,02/02/2024,$7\r\n".to_vec(),
    )]);
    let partial = RoutedTransport::new(&[]).with_bytes(ARCHIVE.url, 200, short);
    let (entities, outcome) = check(&partial, None, "Clive Palmer", "scan", 1).expect("asked");
    assert_eq!(entities.len(), 1, "what the archive still holds is read");
    assert_eq!(
        outcome.kind,
        SourceOutcomeKind::ProtocolDrift,
        "{outcome:?}"
    );
    assert_eq!(outcome.found, Some(1));
    assert!(
        outcome
            .detail
            .as_deref()
            .unwrap_or("")
            .starts_with("the archive has no Donor Returns.csv"),
        "{outcome:?}"
    );
    let silent = RoutedTransport::new(&[]);
    let (entities, outcome) = check(&silent, None, "Clive Palmer", "scan", 1).expect("asked");
    assert!(entities.is_empty());
    assert_ne!(outcome.kind, SourceOutcomeKind::ValidZero);
    assert_ne!(outcome.kind, SourceOutcomeKind::Success);
    let page = RoutedTransport::new(&[(ARCHIVE.url, 200, "<html>maintenance</html>")]);
    let (_, outcome) = check(&page, None, "Clive Palmer", "scan", 1).expect("asked");
    assert_ne!(outcome.kind, SourceOutcomeKind::ValidZero, "{outcome:?}");
}

#[test]
fn a_kept_copy_past_its_week_answers_without_current_clearance() {
    let dir = std::env::temp_dir().join(format!(
        "hse-aec-stale-{}",
        crate::entity::scan_id("aec-test", "freshness")
    ));
    std::fs::create_dir_all(&dir).expect("test cache directory");
    let start = crate::clock::unix_now();
    let (_, first) = check(&transport(), Some(&dir), "Clive Palmer", "scan", start).expect("asked");
    assert_eq!(first.kind, SourceOutcomeKind::Success);
    let offline = RoutedTransport::new(&[]);
    let (entities, outcome) = check(
        &offline,
        Some(&dir),
        "Clive Palmer",
        "scan",
        start + ARCHIVE.max_age + 1,
    )
    .expect("asked");
    assert_eq!(entities.len(), 2, "the kept copy still answers");
    assert_eq!(outcome.kind, SourceOutcomeKind::Inconclusive, "{outcome:?}");
    assert_eq!(outcome.found, Some(2));
    std::fs::remove_dir_all(dir).expect("test cleanup");
}

#[test]
fn slugs_are_lowercase_dashed_words() {
    assert_eq!(slug("Clive Frederick Palmer"), "clive-frederick-palmer");
    assert_eq!(slug(" Mineralogy Pty. Ltd "), "mineralogy-pty-ltd");
    assert_eq!(slug("2023-24"), "2023-24");
    assert_eq!(slug("--"), "");
}
