use std::borrow::Cow;

use super::*;
use crate::test_support::RoutedTransport;

/// Rows shaped like the live OFAC export on 2026-11-07, with its trailing end-of-file byte.
const SDN: &str = "20157,\"KIM, Jong Un\",\"individual\",\"DPRK3\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"DOB 08 Jan 1984; nationality Korea, North.\"\r\n\
8279,\"BOUT, Viktor Anatolijevitch\",\"individual\",\"DRCONGO\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"DOB 13 Jan 1967; POB Dushanbe, Tajikistan.\"\r\n\
306,\"BANCO NACIONAL DE CUBA\",-0- ,\"CUBA\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"a.k.a. 'BNC'.\"\r\n\x1a";
const ALT: &str =
    "8279,1,\"aka\",\"BUTT, Victor\",-0- \r\n306,220,\"aka\",\"NATIONAL BANK OF CUBA\",-0- \r\n";
const UN_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CONSOLIDATED_LIST><INDIVIDUALS>\
<INDIVIDUAL><FIRST_NAME>ERIC</FIRST_NAME><SECOND_NAME>BADEGE</SECOND_NAME><UN_LIST_TYPE>DRC</UN_LIST_TYPE>\
<REFERENCE_NUMBER>CDi.001</REFERENCE_NUMBER><LISTED_ON>2012-12-31</LISTED_ON>\
<NATIONALITY><VALUE>Democratic Republic of the Congo</VALUE></NATIONALITY>\
<INDIVIDUAL_ALIAS><QUALITY/><ALIAS_NAME/></INDIVIDUAL_ALIAS>\
<INDIVIDUAL_DATE_OF_BIRTH><TYPE_OF_DATE>EXACT</TYPE_OF_DATE><YEAR>1971</YEAR></INDIVIDUAL_DATE_OF_BIRTH>\
</INDIVIDUAL></INDIVIDUALS><ENTITIES><ENTITY><FIRST_NAME>AL-QAIDA &amp; ASSOCIATES</FIRST_NAME>\
<REFERENCE_NUMBER>QDe.004</REFERENCE_NUMBER><ENTITY_ALIAS><ALIAS_NAME>THE BASE</ALIAS_NAME></ENTITY_ALIAS>\
</ENTITY></ENTITIES></CONSOLIDATED_LIST>";

/// Rows shaped like the live EU export on 2026-11-07: a byte-order mark, `;` separators and one
/// row per name and birth date of a subject. Eric Badege's two rows are one subject; KHARBOUTLI
/// holds the letters "bout" without the word.
const EU_CSV: &str = "\u{feff}fileGenerationDate;Entity_LogicalId;Entity_EU_ReferenceNumber;Entity_SubjectType;Entity_Regulation_Programme;NameAlias_FirstName;NameAlias_LastName;NameAlias_WholeName;BirthDate_BirthDate;Citizenship_CountryDescription\r\n\
07/11/2026;7200;EU.3606.65;P;COD;Eric;Badege;Eric Badege;1971-01-01;Democratic Republic of the Congo\r\n\
07/11/2026;7200;EU.3606.65;P;COD;;;Eric BADEGE;1971-01-01;Democratic Republic of the Congo\r\n\
07/11/2026;110142;EU.3843.7;P;SYR;;;Mohammed Zahir KHARBOUTLI;;Syria\r\n";

/// The address DFAT's page links its workbook under, as a site-relative path.
const DFAT_XLSX_PATH: &str = "/sites/default/files/regulation8_consolidated.xlsx";
/// The DFAT page, shaped as a site page: the workbook's link among others, site-relative.
const DFAT_HTML: &str = "<!DOCTYPE html><html><body><a href=\"/about-us/\">About</a>\
<a href=\"/sites/default/files/sanctions-guide.pdf\">Guide</a>\
<a href=\"/sites/default/files/regulation8_consolidated.xlsx?v=3\">Consolidated List (XLSX)</a>\
</body></html>";

/// DFAT's workbook as the publisher laid it out on 2026-11-10 (its columns, its name types, an
/// alias row's reference being the primary's with a letter), behind two title rows: Kim Jong
/// Un's three rows (a primary name, an alias, the name in its original script) are one
/// listing, the entity another.
fn dfat_workbook() -> Vec<u8> {
    let header = [
        "Reference",
        "Name of Individual or Entity",
        "Type",
        "Name Type",
        "Alias Strength",
        "Date of Birth",
        "Place of Birth",
        "Citizenship",
        "Address",
        "Additional Information",
        "Listing Information",
        "IMO Number",
        "Committees",
    ];
    let row = |cells: [&str; 13]| cells.iter().map(|c| (*c).to_owned()).collect::<Vec<_>>();
    crate::xlsx::workbook(&[crate::xlsx::Sheet {
        name: "Consolidated List".into(),
        rows: vec![
            vec!["Consolidated List".into()],
            vec![String::new()],
            header.iter().map(|c| (*c).to_owned()).collect(),
            row([
                "6219",
                "KIM Jong Un",
                "Individual",
                "Primary Name",
                "22",
                "08/01/1984",
                "Pyongyang",
                "DPRK",
                "",
                "Chairman of the State Affairs Commission",
                "Autonomous (DPRK) 2017",
                "",
                "1718",
            ]),
            row([
                "6219a",
                "KIM Jong-eun",
                "Individual",
                "Alias",
                "Strong",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ]),
            row([
                "6219b",
                "\u{AE40}\u{C815}\u{C740}",
                "Individual",
                "Original Script",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ]),
            row([
                "3101",
                "BANCO NACIONAL DE CUBA",
                "Entity",
                "Primary Name",
                "",
                "",
                "",
                "",
                "Havana, Cuba",
                "",
                "",
                "",
                "",
            ]),
        ],
    }])
}

fn dfat_routes(transport: RoutedTransport) -> RoutedTransport {
    transport.with_bytes(
        &format!("https://www.dfat.gov.au{DFAT_XLSX_PATH}"),
        200,
        dfat_workbook(),
    )
}

fn lists() -> Lists {
    Lists::new(
        Box::new(dfat_routes(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SDN),
            (OFAC_ALT.url, 200, ALT),
            (UN_SC.url, 200, UN_XML),
            (EU_FSF.url, 200, EU_CSV),
            (DFAT_PAGE, 200, DFAT_HTML),
        ]))),
        None,
    )
}

fn values(entities: &[Entity]) -> Vec<&str> {
    entities.iter().map(|e| e.raw_value.as_str()).collect()
}

#[test]
fn a_listing_matches_only_when_it_carries_every_word_of_the_name() {
    let (entities, outcomes) = check(&lists(), "Kim Jong Un", "scan", 1);
    assert_eq!(
        values(&entities),
        [
            "https://sanctionssearch.ofac.treas.gov/Details.aspx?id=20157",
            "https://www.dfat.gov.au/international-relations/security/sanctions/consolidated-list#6219",
        ]
    );
    assert_eq!(entities[0].kind, EntityKind::Document);
    let evidence = &entities[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("program").map(String::as_str),
        Some("DPRK3")
    );
    assert!(evidence.attributes["remarks"].contains("DOB 08 Jan 1984"));
    assert_eq!(outcomes.len(), 4);
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(outcomes[0].kind, SourceOutcomeKind::Success);
    assert_eq!(outcomes[1].module, UN);
    assert_eq!(outcomes[1].kind, SourceOutcomeKind::ValidZero);
    assert_eq!(outcomes[2].module, EU);
    assert_eq!(outcomes[2].kind, SourceOutcomeKind::ValidZero);
    // A namesake carrying only some of the words is never a match.
    let (none, _) = check(&lists(), "Kim Jong Il", "scan", 1);
    assert!(none.is_empty(), "{:?}", values(&none));
}

#[test]
fn an_alias_matches_and_the_whole_listing_is_kept() {
    let (entities, _) = check(&lists(), "Victor Butt", "scan", 1);
    assert_eq!(
        values(&entities),
        ["https://sanctionssearch.ofac.treas.gov/Details.aspx?id=8279"]
    );
    let evidence = &entities[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("matched_name").map(String::as_str),
        Some("BUTT, Victor")
    );
    assert!(evidence.attributes["remarks"].contains("POB Dushanbe"));
}

#[test]
fn the_un_list_is_read_with_its_name_parts_entities_and_escapes() {
    let (entities, outcomes) = check(&lists(), "Eric Badege", "scan", 1);
    let un: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.raw_value.starts_with("https://scsanctions.un.org/"))
        .collect();
    assert_eq!(
        un.iter().map(|e| e.raw_value.as_str()).collect::<Vec<_>>(),
        ["https://scsanctions.un.org/resources/xml/en/consolidated.xml#CDi.001"]
    );
    let evidence = &un[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("nationality").map(String::as_str),
        Some("Democratic Republic of the Congo")
    );
    assert_eq!(
        evidence.attributes.get("date_of_birth").map(String::as_str),
        Some("1971")
    );
    assert_eq!(outcomes[1].kind, SourceOutcomeKind::Success);
    let (entity, _) = check(&lists(), "Al-Qaida Associates", "scan", 1);
    assert_eq!(
        entity.len(),
        1,
        "&amp; is unescaped and the entity block read"
    );
    let (alias, _) = check(&lists(), "The Base", "scan", 1);
    assert_eq!(alias.len(), 1, "an entity alias matches");
}

#[test]
fn no_lists_consults_nothing_and_a_failed_download_is_never_a_clean_zero() {
    let (entities, outcomes) = check(&Lists::none(), "Kim Jong Un", "scan", 1);
    assert!(entities.is_empty() && outcomes.is_empty());

    let silent = Lists::new(Box::new(RoutedTransport::new(&[])), None);
    let (entities, outcomes) = check(&silent, "Kim Jong Un", "scan", 1);
    assert!(entities.is_empty());
    assert_eq!(outcomes.len(), 4);
    for outcome in outcomes {
        assert_ne!(outcome.kind, SourceOutcomeKind::ValidZero, "{outcome:?}");
        assert_ne!(outcome.kind, SourceOutcomeKind::Success, "{outcome:?}");
    }
}

#[test]
fn a_single_word_name_asks_nothing() {
    let (entities, outcomes) = check(&lists(), "Kim", "scan", 1);
    assert!(entities.is_empty() && outcomes.is_empty());
}

#[test]
fn the_eu_list_groups_a_subject_s_rows_and_matches_only_whole_words() {
    let (entities, outcomes) = check(&lists(), "Eric Badege", "scan", 1);
    let eu: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.raw_value.ends_with("#EU.3606.65"))
        .collect();
    assert_eq!(eu.len(), 1, "two rows of one subject are one listing");
    assert_eq!(
        eu[0].evidence.len(),
        1,
        "one record per subject, not one per row"
    );
    let evidence = &eu[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("alias").map(String::as_str),
        Some("Eric BADEGE"),
        "every name a subject's rows carry is kept on its one listing"
    );
    assert_eq!(
        evidence.attributes.get("program").map(String::as_str),
        Some("COD")
    );
    assert_eq!(
        evidence.attributes.get("date_of_birth").map(String::as_str),
        Some("1971-01-01"),
        "a value repeated across a subject's rows is kept once"
    );
    assert_eq!(outcomes[2].kind, SourceOutcomeKind::Success);
    // The fixture lists him on the UN and EU lists (the live OFAC list names him too).
    assert_eq!(
        entities.len(),
        2,
        "one listing per authority that names him"
    );
    // "Viktor Bout" carries the letters of KHARBOUTLI but not its words: never a match.
    let (bout, _) = check(&lists(), "Viktor Bout", "scan", 1);
    assert!(
        bout.iter().all(|e| !e.raw_value.contains("EU.3843.7")),
        "{:?}",
        values(&bout)
    );
}

/// Each list builds only the listings whose rows may carry the name asked, counts every
/// listing it holds, and finds for every name exactly what reading the whole list finds: a row
/// whose identifier sits behind a quoted cell, a number quoted, or a name spelled with a
/// character reference included.
#[test]
fn a_list_builds_only_the_listings_that_may_carry_the_name_and_counts_them_all() {
    fn same_as_whole(every: &[Listing], held: usize, parse: impl Fn(&[String]) -> Parsed) {
        for listing in every {
            for name in &listing.names {
                let query = crate::textnorm::name_match_keys(name);
                let parsed = parse(&query);
                assert_eq!(parsed.read, held, "{name}: every listing is counted");
                assert_eq!(parsed.unreadable, 0, "{name}: every row is readable");
                assert!(parsed.listings.contains(listing), "{name}: {parsed:?}");
                assert!(
                    parsed
                        .listings
                        .iter()
                        .all(|candidate| every.contains(candidate)),
                    "{name}: a candidate is a whole listing"
                );
            }
        }
        let nobody = ["nobody".to_owned(), "here".to_owned()];
        let none = parse(&nobody);
        assert!(none.listings.is_empty());
        assert_eq!((none.read, none.unreadable), (held, 0));
    }
    let every_eu = parse_eu(EU_CSV, &[]);
    let every_ofac = parse_ofac(SDN, ALT, &[]);
    let every_un = parse_un(UN_XML, &[]);
    assert_eq!((every_eu.listings.len(), every_eu.read), (2, 2));
    assert_eq!((every_ofac.listings.len(), every_ofac.read), (3, 3));
    assert_eq!((every_un.listings.len(), every_un.read), (2, 2));
    same_as_whole(&every_eu.listings, every_eu.read, |query| {
        parse_eu(EU_CSV, query)
    });
    same_as_whole(&every_ofac.listings, every_ofac.read, |query| {
        parse_ofac(SDN, ALT, query)
    });
    same_as_whole(&every_un.listings, every_un.read, |query| {
        parse_un(UN_XML, query)
    });

    // A quoted cell before the identifier, or a quoted identifier, sends the row to the splitter.
    let quoted_date = EU_CSV.replace("07/11/2026;7200;", "\"07/11/2026\";\"7200\";");
    assert_ne!(quoted_date, EU_CSV);
    let badege = crate::textnorm::name_match_keys("Eric Badege");
    assert_eq!(parse_eu(&quoted_date, &badege), parse_eu(EU_CSV, &badege));
    assert_eq!(parse_eu(&quoted_date, &[]), every_eu);
    let quoted_number = SDN.replace("8279,", "\"8279\",");
    let quoted_alias = ALT.replace("8279,", "\"8279\",");
    let bout = crate::textnorm::name_match_keys("Victor Butt");
    assert_eq!(
        parse_ofac(&quoted_number, &quoted_alias, &bout),
        parse_ofac(SDN, ALT, &bout)
    );
    assert_eq!(
        parse_ofac(&quoted_number, &quoted_alias, &bout)
            .listings
            .len(),
        1
    );
    assert_eq!(
        field_of("\"a;b\";7200;x", ';', 1).as_ref(),
        "7200",
        "a quoted cell holding the separator"
    );
    assert_eq!(field_of("a;b", ';', 5).as_ref(), "");
    assert!(matches!(
        field_of("a; 7200 ;x", ';', 1),
        Cow::Borrowed("7200")
    ));

    // A name spelled with a character reference is matched as the letter it spells.
    let referenced = UN_XML.replace("<FIRST_NAME>ERIC<", "<FIRST_NAME>&#201;RIC<");
    assert_ne!(referenced, UN_XML);
    let eric = crate::textnorm::name_match_keys("Éric Badege");
    let parsed = parse_un(&referenced, &eric);
    assert_eq!((parsed.read, parsed.unreadable), (2, 0));
    assert_eq!(parsed.listings.len(), 1, "{parsed:?}");
    assert_eq!(parsed.listings[0].names[0], "ÉRIC BADEGE");
    assert!(parse_un(&referenced, &badege).listings.is_empty());
}

#[test]
fn a_failed_refresh_preserves_historical_matches_without_current_clearance() {
    let dir = std::env::temp_dir().join(format!(
        "hse-sanctions-stale-{}",
        crate::entity::scan_id("sanctions-test", "freshness")
    ));
    std::fs::create_dir_all(&dir).expect("test cache directory");
    let start = crate::clock::unix_now();
    let first = Lists::new(
        Box::new(dfat_routes(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SDN),
            (OFAC_ALT.url, 200, ALT),
            (UN_SC.url, 200, UN_XML),
            (DFAT_PAGE, 200, DFAT_HTML),
        ]))),
        Some(dir.clone()),
    );
    let (_, initial) = check(&first, "Kim Jong Un", "scan", start);
    assert_eq!(initial[0].kind, SourceOutcomeKind::Success);
    assert_eq!(initial[1].kind, SourceOutcomeKind::ValidZero);
    assert_eq!(
        initial[3].kind,
        SourceOutcomeKind::Success,
        "{:?}",
        initial[3]
    );

    // Twenty-five hours later, every publisher is unreachable. The last valid copies
    // are still read, including the historical positive, but neither list is current.
    let offline = Lists::new(Box::new(RoutedTransport::new(&[])), Some(dir.clone()));
    let (previous, outcomes) = check(&offline, "Kim Jong Un", "scan", start + MAX_AGE + 1);
    assert_eq!(
        values(&previous),
        [
            "https://sanctionssearch.ofac.treas.gov/Details.aspx?id=20157",
            "https://www.dfat.gov.au/international-relations/security/sanctions/consolidated-list#6219",
        ]
    );
    assert_eq!(outcomes.len(), 4);
    // The DFAT page is unreachable too, so its kept workbook answers, not current.
    assert_eq!(
        outcomes[3].kind,
        SourceOutcomeKind::Inconclusive,
        "{:?}",
        outcomes[3]
    );
    assert_eq!(outcomes[3].found, Some(1));
    for outcome in &outcomes[..2] {
        assert_eq!(outcome.kind, SourceOutcomeKind::Inconclusive, "{outcome:?}");
        assert!(
            outcome
                .detail
                .as_deref()
                .unwrap_or("")
                .contains("could not be downloaded again"),
            "{outcome:?}"
        );
    }
    assert_eq!(outcomes[0].found, Some(1));
    assert_eq!(outcomes[1].found, Some(0));
    std::fs::remove_dir_all(dir).expect("test cleanup");
}

#[test]
fn missing_ofac_aliases_cannot_prove_absence() {
    let partial = Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SDN),
            (UN_SC.url, 200, UN_XML),
        ])),
        None,
    );
    let (entities, outcomes) = check(&partial, "Ada Lovelace", "scan", 1);
    assert!(entities.is_empty());
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(outcomes[0].kind, SourceOutcomeKind::Inconclusive);
    assert!(
        outcomes[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("aliases unavailable")
    );
    assert_eq!(outcomes[1].kind, SourceOutcomeKind::ValidZero);
}

/// DFAT's list: the workbook's link is read from the page (site-relative, with a query), the
/// title rows above the header are skipped, a listing's rows are grouped by reference with the
/// primary name first and its fields kept, an alias matches, and an entity is a listing too.
#[test]
fn the_dfat_list_is_read_from_the_workbook_the_page_links() {
    // "Jong-eun" is only the alias's spelling: the primary name does not carry that word.
    let (entities, outcomes) = check(&lists(), "Jong-eun Kim", "scan", 1);
    let dfat: Vec<&Entity> = entities
        .iter()
        .filter(|entity| entity.raw_value.contains("dfat.gov.au"))
        .collect();
    assert_eq!(dfat.len(), 1, "{:?}", values(&entities));
    let evidence = &dfat[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("matched_name").map(String::as_str),
        Some("KIM Jong-eun")
    );
    let aliases = evidence.attributes.get("alias").map_or("", String::as_str);
    assert!(aliases.contains("KIM Jong-eun"), "{aliases}");
    assert!(aliases.contains("\u{AE40}\u{C815}\u{C740}"), "{aliases}");
    assert_eq!(
        evidence.attributes.get("reference").map(String::as_str),
        Some("6219")
    );
    assert_eq!(
        evidence
            .attributes
            .get("alias_strength")
            .map(String::as_str),
        Some("22")
    );
    assert_eq!(
        evidence.attributes.get("committees").map(String::as_str),
        Some("1718")
    );
    assert_eq!(
        evidence.attributes.get("date_of_birth").map(String::as_str),
        Some("08/01/1984")
    );
    assert_eq!(
        evidence
            .attributes
            .get("listing_information")
            .map(String::as_str),
        Some("Autonomous (DPRK) 2017")
    );
    assert_eq!(
        evidence.attributes.get("type").map(String::as_str),
        Some("Individual")
    );
    assert_eq!(
        evidence.attributes.get("dataset").map(String::as_str),
        Some("DFAT Consolidated List (Australian sanctions)")
    );
    let dfat_outcome = outcomes
        .iter()
        .find(|o| o.module == DFAT)
        .expect("a DFAT outcome");
    assert_eq!(dfat_outcome.kind, SourceOutcomeKind::Success);
    assert_eq!(dfat_outcome.found, Some(1));
    assert!(
        dfat_outcome
            .detail
            .as_deref()
            .unwrap_or("")
            .starts_with("2 listings read"),
        "{dfat_outcome:?}"
    );

    let (entities, _) = check(&lists(), "Banco Nacional de Cuba", "scan", 1);
    assert!(
        values(&entities).iter().any(|v| v.ends_with("#3101")),
        "{:?}",
        values(&entities)
    );
}

/// A page without the workbook's link, or a workbook without the name column, is a drifted
/// list, reported as such, never a clean zero; the other lists are unaffected.
#[test]
fn a_dfat_page_or_workbook_that_drifted_is_reported_not_read_as_clear() {
    let no_link = Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SDN),
            (OFAC_ALT.url, 200, ALT),
            (UN_SC.url, 200, UN_XML),
            (EU_FSF.url, 200, EU_CSV),
            (
                DFAT_PAGE,
                200,
                "<html><a href=\"/sites/default/files/other.xlsx\">x</a></html>",
            ),
        ])),
        None,
    );
    let (entities, outcomes) = check(&no_link, "Kim Jong Un", "scan", 1);
    assert_eq!(values(&entities).len(), 1, "{:?}", values(&entities));
    assert_eq!(outcomes[3].module, DFAT);
    assert_eq!(
        outcomes[3].kind,
        SourceOutcomeKind::ProtocolDrift,
        "{:?}",
        outcomes[3]
    );
    assert!(
        outcomes[3]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("links no consolidated-list workbook"),
        "{:?}",
        outcomes[3]
    );

    let renamed = crate::xlsx::workbook(&[crate::xlsx::Sheet {
        name: "List".into(),
        rows: vec![
            vec!["Reference".into(), "Name".into()],
            vec!["1".into(), "KIM Jong Un".into()],
        ],
    }]);
    let drifted = Lists::new(
        Box::new(
            RoutedTransport::new(&[(DFAT_PAGE, 200, DFAT_HTML)]).with_bytes(
                &format!("https://www.dfat.gov.au{DFAT_XLSX_PATH}"),
                200,
                renamed,
            ),
        ),
        None,
    );
    let (_, outcomes) = check(&drifted, "Kim Jong Un", "scan", 1);
    assert_eq!(
        outcomes[3].kind,
        SourceOutcomeKind::ProtocolDrift,
        "{:?}",
        outcomes[3]
    );
    assert!(
        outcomes[3]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("no listing could be read in 2 rows"),
        "{:?}",
        outcomes[3]
    );
}

#[test]
fn the_workbook_link_is_the_first_consolidated_xlsx_made_absolute() {
    assert_eq!(
        workbook_link(DFAT_HTML).as_deref(),
        Some("https://www.dfat.gov.au/sites/default/files/regulation8_consolidated.xlsx?v=3")
    );
    assert_eq!(
        workbook_link("<a href='https://cdn.example/Consolidated_List.XLSX#top'>").as_deref(),
        Some("https://cdn.example/Consolidated_List.XLSX#top")
    );
    assert_eq!(
        workbook_link("<a href=\"//www.dfat.gov.au/files/consolidated.xlsx\">").as_deref(),
        Some("https://www.dfat.gov.au/files/consolidated.xlsx")
    );
    assert_eq!(workbook_link("<a href=\"/files/consolidated.csv\">"), None);
    assert_eq!(workbook_link("<a href=\"/files/other.xlsx\">"), None);
}

#[test]
fn a_match_cap_is_reported_never_a_silent_complete_success() {
    // 51 OFAC rows that all carry one name: the 50-match cap attaches 50 and the detail says one
    // more matched. A capped result is a Success that admits it was cut off, never a clean count.
    use std::fmt::Write as _;
    let mut sdn = String::new();
    for ent in 1000..1051 {
        let _ = write!(
            sdn,
            "{ent},\"COMMON, Name\",\"individual\",\"X\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- \r\n"
        );
    }
    sdn.push('\u{1a}');
    let sdn: &'static str = Box::leak(sdn.into_boxed_str());
    let capped = Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, sdn),
            (OFAC_ALT.url, 200, ""),
            (UN_SC.url, 200, UN_XML),
            (EU_FSF.url, 200, EU_CSV),
        ])),
        None,
    );
    let (entities, outcomes) = check(&capped, "Name Common", "scan", 1);
    let ofac: Vec<&Entity> = entities
        .iter()
        .filter(|e| e.raw_value.starts_with("https://sanctionssearch.ofac"))
        .collect();
    assert_eq!(ofac.len(), 50, "at most the cap is attached");
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(outcomes[0].kind, SourceOutcomeKind::Success);
    assert!(
        outcomes[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 more matching listings beyond the first 50 were not attached"),
        "{:?}",
        outcomes[0]
    );
}

#[test]
fn unreadable_rows_block_a_clean_zero() {
    // One readable listing that does not match, and one row too short to read: the subject could be
    // in the unreadable row, so the outcome is Inconclusive, never a clean valid_zero. The short row
    // is counted without being split, so a row that cannot carry the name is still counted.
    const SHORT: &str = "306,\"BANCO NACIONAL DE CUBA\",-0- ,\"CUBA\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"a.k.a. 'BNC'.\"\r\n9,\"TOO FEW COLUMNS\"\r\n\x1a";
    let partial = Lists::new(
        Box::new(RoutedTransport::new(&[
            (OFAC_SDN.url, 200, SHORT),
            (OFAC_ALT.url, 200, ""),
            (UN_SC.url, 200, UN_XML),
            (EU_FSF.url, 200, EU_CSV),
        ])),
        None,
    );
    let (_entities, outcomes) = check(&partial, "Jane Doe", "scan", 1);
    assert_eq!(outcomes[0].module, OFAC);
    assert_eq!(
        outcomes[0].kind,
        SourceOutcomeKind::Inconclusive,
        "{:?}",
        outcomes[0]
    );
    assert!(
        outcomes[0]
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("1 rows could not be read"),
        "{:?}",
        outcomes[0]
    );
    // A subject the EU file names only on a short row is not cleared either.
    let short_eu = format!("{EU_CSV}07/11/2026;999;EU.1.1;P;SYR;;;Jane Doe\r\n");
    let parsed = parse_eu(&short_eu, &crate::textnorm::name_match_keys("Jane Doe"));
    // The short row is not a subject read: it is counted among the unreadable rows alone.
    assert_eq!(
        (parsed.listings.len(), parsed.read, parsed.unreadable),
        (0, 2, 1)
    );
}
