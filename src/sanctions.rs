//! Consolidated sanctions lists, read offline from copies kept on the device: the US Treasury
//! OFAC Specially Designated Nationals list (with its alias table), the UN Security Council
//! Consolidated List, the EU Financial Sanctions consolidated list and DFAT's Consolidated List
//! of the persons and entities subject to Australian sanctions law (the autonomous sanctions and
//! the UN Security Council sanctions Australia implements).
//!
//! Each list is one keyless public download, kept in the list directory and downloaded again
//! once a day through the same download-and-keep machinery as the threat feeds
//! ([`crate::threat_feeds::load`]); a name is then matched locally, so a lookup sends nothing
//! about who is being looked up. A listing matches only when its name or one of its aliases
//! carries every word of the name asked. A match is a lead to review, never proof that the
//! person is the one designated: each is a `Document` keyed by the listing's own address, its
//! whole listing kept verbatim as evidence (remarks, dates of birth, nationality, programmes) so
//! it can be compared with what else is known.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::http::Transport;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::{xml_blocks, xml_tag_values, xml_unescape};
use crate::threat_feeds::{
    CachedList, Failure, MAX_FEED_BYTES, csv_fields, delimited_fields, load_with,
};

/// The module that selects every sanctions list.
pub const SOURCE: &str = "sanctions";
/// The OFAC Specially Designated Nationals list's outcome label.
pub const OFAC: &str = "sanctions.ofac_sdn";
/// The UN Security Council Consolidated List's outcome label.
pub const UN: &str = "sanctions.un_sc";
/// The EU Financial Sanctions consolidated list's outcome label.
pub const EU: &str = "sanctions.eu_fsf";
/// DFAT's Consolidated List's outcome label: Australia's sanctions.
pub const DFAT: &str = "sanctions.dfat";

/// A name match on a sanctions list: a strong lead, below a confirmed identity.
const LISTED_CONFIDENCE: f64 = 0.6;
/// The lists are published at least daily.
const MAX_AGE: u64 = 24 * 3_600;
/// The most matches one list reports for one name.
const MAX_MATCHES: usize = 50;

const OFAC_SDN: CachedList = CachedList {
    id: "sanctions-ofac-sdn.csv",
    source: OFAC,
    url: "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV",
    max_age: MAX_AGE,
    xml_root: None,
};
const OFAC_ALT: CachedList = CachedList {
    id: "sanctions-ofac-alt.csv",
    source: OFAC,
    url: "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ALT.CSV",
    max_age: MAX_AGE,
    xml_root: None,
};
/// The EU's consolidated list: one `;`-separated row per name, address, birth date, document and
/// citizenship of each subject, about 25 MB. Its token is a fixed public value, not a credential.
const EU_FSF: CachedList = CachedList {
    id: "sanctions-eu-fsf.csv",
    source: EU,
    url: "https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw",
    max_age: MAX_AGE,
    xml_root: None,
};
const UN_SC: CachedList = CachedList {
    id: "sanctions-un-consolidated.xml",
    source: UN,
    url: "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
    max_age: MAX_AGE,
    xml_root: Some("CONSOLIDATED_LIST"),
};
/// The page DFAT publishes its Consolidated List from. The list is a workbook the page links
/// under a path that has moved, so the link is read from the page when a download is due, and
/// the listings are keyed by their reference on this page.
const DFAT_PAGE: &str =
    "https://www.dfat.gov.au/international-relations/security/sanctions/consolidated-list";
/// DFAT's Consolidated List: one workbook row per name of each listed person, entity or vessel
/// (its primary name, each alias, its name in its original script), the rows of one listing
/// sharing the digits of their reference (`2298`, `2298a`, `2298b`).
const DFAT_LIST: CachedList = CachedList {
    id: "sanctions-dfat-consolidated.xlsx",
    source: DFAT,
    url: DFAT_PAGE,
    max_age: MAX_AGE,
    xml_root: None,
};
/// The column of DFAT's workbook that holds each name.
const DFAT_NAME: &str = "Name of Individual or Entity";
/// The column that marks a row as a primary name or an alias.
const DFAT_NAME_TYPE: &str = "Name Type";
/// The column that groups a listing's rows.
const DFAT_REFERENCE: &str = "Reference";
/// The workbook's columns kept for the evidence, by header, and the attribute each becomes; a
/// column the workbook does not carry is left out.
const DFAT_FIELDS: [(&str, &str); 13] = [
    ("Reference", "reference"),
    ("Type", "type"),
    ("Name Type", "name_type"),
    ("Alias Strength", "alias_strength"),
    ("Date of Birth", "date_of_birth"),
    ("Place of Birth", "place_of_birth"),
    ("Citizenship", "citizenship"),
    ("Address", "address"),
    ("Additional Information", "additional_information"),
    ("Listing Information", "listing_information"),
    ("IMO Number", "imo_number"),
    ("Committees", "committees"),
    ("Control Date", "control_date"),
];

/// Where the lists come from and where their copies are kept: a transport able to carry the
/// largest list, and the directory the copies live in. [`Lists::none`] consults no list.
pub struct Lists {
    transport: Option<Box<dyn Transport + Send + Sync>>,
    dir: Option<PathBuf>,
}

impl Lists {
    /// No list is consulted.
    #[must_use]
    pub fn none() -> Self {
        Self {
            transport: None,
            dir: None,
        }
    }

    /// The lists, downloaded over `transport` (it must carry a body of several MiB: see
    /// [`crate::threat_feeds::transport_config`]) and kept in `dir` (none keeps no copy).
    #[must_use]
    pub fn new(transport: Box<dyn Transport + Send + Sync>, dir: Option<PathBuf>) -> Self {
        Self {
            transport: Some(transport),
            dir,
        }
    }

    /// The transport the lists download over, which the other registers kept beside them (the
    /// AEC's returns) download over too; `None` consults no list.
    #[must_use]
    pub fn transport(&self) -> Option<&(dyn Transport + Send + Sync)> {
        self.transport.as_deref()
    }

    /// The directory the copies are kept in, or none.
    #[must_use]
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
}

/// One listing: its key, the names it is known by, and every field kept for the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listing {
    /// The listing's own address, the entity's value.
    url: String,
    /// The primary name, then every alias.
    names: Vec<String>,
    /// Every field the list holds for it, verbatim, in list order.
    fields: Vec<(&'static str, String)>,
}

/// Whether `listed` carries every word of `query`, matching across scripts: `query` is the
/// subject's transliteration-aware match keys ([`crate::textnorm::name_match_keys`]), and `listed`
/// is reduced the same way, so a Cyrillic listing and a Latin query (or the reverse) meet. **Pure.**
fn names_query(listed: &str, query: &[String]) -> bool {
    crate::textnorm::carries_every_key(listed, query)
}

/// A list as read for one name: the listings that may carry it (built from their rows), how
/// many listings the copy holds in all, and what the outcome says about the copy. A list is
/// read whole only for a name of no words.
struct ListRead {
    listings: Vec<Listing>,
    /// The listings the copy holds, matching or not.
    read: usize,
    /// The data rows the copy holds that could not be read: a row short of its columns, a
    /// numbered row without a name, a subject left with no name. An unreadable row may hold
    /// the subject, so a list with any cannot clear a name.
    unreadable: usize,
    note: Option<String>,
    current: bool,
}

/// What a list's parser read: the listings built, the listings the copy holds in all, and the
/// rows it could not read.
#[derive(Debug, Default, PartialEq, Eq)]
struct Parsed {
    listings: Vec<Listing>,
    read: usize,
    unreadable: usize,
}

impl Parsed {
    fn into_read(self, note: Option<String>, current: bool) -> ListRead {
        ListRead {
            listings: self.listings,
            read: self.read,
            unreadable: self.unreadable,
            note,
            current,
        }
    }
}

/// Field `at` of a delimited `line`, trimmed: read in place while no quote precedes the field's
/// end, else from the row split as the list's parser splits it. A row's identifier is read this
/// way before the row is parsed, so a row that is not wanted is never split. **Pure.**
fn field_of(line: &str, separator: char, at: usize) -> Cow<'_, str> {
    let mut rest = line;
    let mut index = 0;
    loop {
        let (field, after) = rest
            .split_once(separator)
            .map_or((rest, None), |(field, after)| (field, Some(after)));
        if field.contains('"') {
            break;
        }
        if index == at {
            return Cow::Borrowed(field.trim());
        }
        let Some(after) = after else {
            return Cow::Borrowed("");
        };
        rest = after;
        index += 1;
    }
    Cow::Owned(
        delimited_fields(line, separator)
            .get(at)
            .map_or_else(String::new, |field| field.trim().to_owned()),
    )
}

/// Match `name` against every consulted list: the listings that carry it, and one outcome per
/// list. A list that cannot be downloaded and has no kept copy is reported as such, never as a
/// clean zero.
#[must_use]
pub fn check(
    lists: &Lists,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> (Vec<Entity>, Vec<SourceExecutionOutcome>) {
    let Some(transport) = lists.transport.as_deref() else {
        return (Vec::new(), Vec::new());
    };
    if !transport.runs_module(SOURCE) {
        return (Vec::new(), Vec::new());
    }
    let query = crate::textnorm::name_match_keys(name);
    if query.len() < 2 {
        return (Vec::new(), Vec::new());
    }
    let dir = lists.dir.as_deref();
    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    for (label, read) in [
        (OFAC, read_ofac(transport, dir, &query, now_unix)),
        (UN, read_un(transport, dir, &query, now_unix)),
        (EU, read_eu(transport, dir, &query, now_unix)),
        (DFAT, read_dfat(transport, dir, now_unix)),
    ] {
        outcomes.push(match read {
            Ok(ListRead {
                listings,
                read,
                unreadable,
                note,
                current,
            }) => {
                let (found, matching) =
                    record_matches(&listings, &query, label, scan_id, &mut entities);
                let mut outcome = if !current {
                    // Retain every historical matching document, but neither a positive
                    // nor a negative from an outdated copy proves the present-day list.
                    SourceExecutionOutcome::observed(
                        label,
                        now_unix,
                        SourceOutcomeKind::Inconclusive,
                        None,
                        Some(found),
                        "list refresh failed or verified cache freshness expired",
                    )
                } else if found == 0 && unreadable > 0 {
                    // Rows that could not be read could hold the subject: no clean negative.
                    SourceExecutionOutcome::observed(
                        label,
                        now_unix,
                        SourceOutcomeKind::Inconclusive,
                        None,
                        Some(0),
                        "no readable listing matched, but some rows could not be read",
                    )
                } else if found == 0 {
                    SourceExecutionOutcome::valid_zero(label, now_unix)
                } else {
                    SourceExecutionOutcome::success(label, now_unix, found)
                };
                let mut detail = format!("{read} listings read");
                if unreadable > 0 {
                    let _ = write!(detail, "; {unreadable} rows could not be read");
                }
                if matching > found {
                    let _ = write!(
                        detail,
                        "; {} more matching listings beyond the first {found} were not attached",
                        matching - found
                    );
                }
                if let Some(note) = note {
                    detail.push_str("; ");
                    detail.push_str(&note);
                }
                outcome = outcome.with_detail(detail);
                outcome
            }
            Err((kind, why)) => SourceExecutionOutcome::failed(label, now_unix, kind, None, why),
        });
    }
    merge_by_uid(&mut entities);
    (entities, outcomes)
}

/// Push every listing in `listings` that names `query`, at most [`MAX_MATCHES`]: how many were
/// attached, and how many matched in all, so a cut-off is never silent. **Pure.**
fn record_matches(
    listings: &[Listing],
    query: &[String],
    label: &str,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) -> (usize, usize) {
    let mut found = 0;
    let mut matching = 0;
    for listing in listings {
        let Some(matched) = listing
            .names
            .iter()
            .find(|listed| names_query(listed, query))
        else {
            continue;
        };
        matching += 1;
        if found == MAX_MATCHES {
            continue;
        }
        found += 1;
        let primary = listing.names.first().map_or("", String::as_str);
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(label, scan_id),
            format!(
                "Listed on {} as {primary}; the name asked matches {matched}. A name match, not proof it is the same person: compare the dates of birth, nationality and remarks kept here",
                list_title(label)
            ),
        )
        .with_attr("dataset", list_title(label))
        .with_attr("matched_name", matched.as_str());
        for alias in listing.names.iter().skip(1) {
            evidence = evidence.with_attr("alias", alias.as_str());
        }
        for (key, value) in &listing.fields {
            evidence = evidence.with_attr(*key, value.as_str());
        }
        push_entity(
            entities,
            EntityKind::Document,
            &listing.url,
            LISTED_CONFIDENCE,
            scan_id,
            evidence,
            &["sanctions", "name-match-lead"],
        );
    }
    (found, matching)
}

const fn list_title(label: &str) -> &'static str {
    match label.as_bytes() {
        b"sanctions.ofac_sdn" => "OFAC Specially Designated Nationals list",
        b"sanctions.eu_fsf" => "EU Financial Sanctions consolidated list",
        b"sanctions.dfat" => "DFAT Consolidated List (Australian sanctions)",
        _ => "UN Security Council Consolidated List",
    }
}

/// A list's copy (kept or downloaded) as text, and what its outcome should say about the copy.
fn copy_of(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    list: &CachedList,
    now_unix: u64,
) -> Result<(String, Option<String>, bool), Failure> {
    let (body, note, current) =
        copy_bytes_of(transport, dir, list, now_unix, || Ok(list.url.to_owned()))?;
    // A copy that is UTF-8, as every list is, becomes text in place: nothing is copied.
    let text = String::from_utf8(body)
        .unwrap_or_else(|invalid| String::from_utf8_lossy(invalid.as_bytes()).into_owned());
    Ok((text, note, current))
}

/// A list's copy (kept, or downloaded from the address `resolve` gives) as bytes, and what its
/// outcome should say about the copy.
fn copy_bytes_of(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    list: &CachedList,
    now_unix: u64,
    resolve: impl FnOnce() -> Result<String, Failure>,
) -> Result<(Vec<u8>, Option<String>, bool), Failure> {
    let copy = load_with(transport, dir, list, now_unix, resolve)?;
    let current = copy.current_for(now_unix, list.max_age);
    let age = now_unix.saturating_sub(copy.fetched);
    let mut note = format!(
        "copy {} ({}s old)",
        if copy.downloaded {
            "downloaded now"
        } else {
            "kept"
        },
        age
    );
    if let Some(extra) = copy.note {
        note.push_str("; ");
        note.push_str(&extra);
    }
    Ok((copy.body, Some(note), current))
}

/// The address of the workbook DFAT's page links: the first `href` to an `.xlsx` whose path
/// names the consolidated list, made absolute. The page is asked for only when a download is
/// due.
fn dfat_workbook_url(
    transport: &(dyn Transport + Send + Sync),
    now_unix: u64,
) -> Result<String, Failure> {
    let request =
        crate::http::Request::get(DFAT_PAGE).with_timeout(crate::threat_feeds::FEED_TIMEOUT);
    let fetched = crate::fetch::fetch(
        transport,
        request,
        None,
        &crate::fetch::FetchOptions::default(),
        DFAT,
        now_unix,
    )
    .map_err(|error| (SourceOutcomeKind::RefusedBeforeSending, error.to_string()))?;
    let page = match fetched.response {
        Some(response) if response.status == 200 => {
            String::from_utf8_lossy(&response.body).into_owned()
        }
        Some(response) => {
            return Err((
                fetched.outcome.kind,
                format!("the list page answered HTTP {}", response.status),
            ));
        }
        None => return Err((fetched.outcome.kind, "the list page gave no answer".into())),
    };
    workbook_link(&page).ok_or_else(|| {
        (
            SourceOutcomeKind::ProtocolDrift,
            format!(
                "the DFAT page ({} bytes) links no consolidated-list workbook",
                page.len()
            ),
        )
    })
}

/// The first `href` in `page` to an `.xlsx` whose path names the consolidated list, absolute
/// against the DFAT site. **Pure.**
fn workbook_link(page: &str) -> Option<String> {
    let mut rest = page;
    while let Some(at) = rest.find("href=") {
        rest = &rest[at + 5..];
        let quote = rest.chars().next()?;
        if quote != '"' && quote != '\'' {
            continue;
        }
        let value = &rest[1..];
        let Some(end) = value.find(quote) else {
            break;
        };
        let href = xml_unescape(&value[..end]);
        rest = &value[end..];
        let path = href
            .split(['?', '#'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let workbook = std::path::Path::new(&path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("xlsx"));
        if workbook && path.contains("consolidated") {
            return Some(
                if href.starts_with("https://") || href.starts_with("http://") {
                    href
                } else if let Some(rest) = href.strip_prefix("//") {
                    format!("https://{rest}")
                } else if href.starts_with('/') {
                    format!("https://www.dfat.gov.au{href}")
                } else {
                    format!("https://www.dfat.gov.au/{href}")
                },
            );
        }
    }
    None
}

/// DFAT's listings: the workbook's rows grouped by reference.
fn read_dfat(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    now_unix: u64,
) -> Result<ListRead, Failure> {
    let (workbook, note, current) = copy_bytes_of(transport, dir, &DFAT_LIST, now_unix, || {
        dfat_workbook_url(transport, now_unix)
    })?;
    let rows = crate::workbook::rows(&workbook, MAX_FEED_BYTES).map_err(|why| {
        (
            SourceOutcomeKind::ProtocolDrift,
            format!(
                "the workbook ({} bytes) could not be read: {why}",
                workbook.len()
            ),
        )
    })?;
    let listings = parse_dfat(&rows);
    if listings.is_empty() {
        return Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("no listing could be read in {} rows", rows.len()),
        ));
    }
    Ok(ListRead {
        read: listings.len(),
        listings,
        unreadable: 0,
        note,
        current,
    })
}

/// Every listing in DFAT's workbook: its rows, which share the digits of their reference (the
/// primary name's `2298`, an alias's `2298a`), give the primary name first (the row whose name
/// type says so) and every other name (an alias, the name in its original script) as an alias,
/// and the fields of the primary row are kept for the evidence. The header row is the first
/// that names the name column, wherever any title rows above it end. **Pure.**
fn parse_dfat(rows: &[Vec<String>]) -> Vec<Listing> {
    let header_at = rows.iter().position(|row| {
        row.iter()
            .any(|cell| cell.trim().eq_ignore_ascii_case(DFAT_NAME))
    });
    let Some(header_at) = header_at else {
        return Vec::new();
    };
    let column = |title: &str| {
        rows[header_at]
            .iter()
            .position(|cell| cell.trim().eq_ignore_ascii_case(title))
    };
    let Some(name_at) = column(DFAT_NAME) else {
        return Vec::new();
    };
    let kind_at = column(DFAT_NAME_TYPE);
    let reference_at = column(DFAT_REFERENCE);
    let fields: Vec<(usize, &'static str)> = DFAT_FIELDS
        .iter()
        .filter_map(|(title, attr)| column(title).map(|at| (at, *attr)))
        .collect();
    let cell = |row: &[String], at: usize| row.get(at).map_or("", |c| c.trim()).to_owned();
    let mut order: Vec<String> = Vec::new();
    let mut listings: std::collections::BTreeMap<String, (Listing, bool)> =
        std::collections::BTreeMap::new();
    for row in &rows[header_at + 1..] {
        let name = cell(row, name_at);
        if name.is_empty() {
            continue;
        }
        let reference = reference_at
            .map(|at| cell(row, at))
            .filter(|reference| !reference.is_empty())
            .unwrap_or_else(|| name.clone());
        // `2298a` is an alias row of listing `2298`.
        let reference = reference
            .trim_end_matches(|c: char| c.is_ascii_alphabetic())
            .to_owned();
        let primary = kind_at.is_none_or(|at| {
            let kind = cell(row, at).to_ascii_lowercase();
            kind.is_empty() || kind.starts_with("primary")
        });
        let row_fields: Vec<(&'static str, String)> = fields
            .iter()
            .map(|(at, attr)| (*attr, cell(row, *at)))
            .filter(|(_, value)| !value.is_empty())
            .collect();
        let entry = listings.entry(reference.clone()).or_insert_with(|| {
            order.push(reference.clone());
            (
                Listing {
                    url: format!("{DFAT_PAGE}#{reference}"),
                    names: Vec::new(),
                    fields: Vec::new(),
                },
                false,
            )
        });
        let (listing, has_primary) = entry;
        if primary && !*has_primary {
            listing.names.insert(0, name);
            listing.fields = row_fields;
            *has_primary = true;
        } else {
            if listing.fields.is_empty() {
                listing.fields = row_fields;
            }
            listing.names.push(name);
        }
    }
    order
        .into_iter()
        .filter_map(|reference| listings.remove(&reference).map(|(listing, _)| listing))
        .collect()
}

/// OFAC's SDN rows that may carry `query`, joined with their aliases.
fn read_ofac(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    query: &[String],
    now_unix: u64,
) -> Result<ListRead, crate::threat_feeds::Failure> {
    let (sdn, note, sdn_current) = copy_of(transport, dir, &OFAC_SDN, now_unix)?;
    // A missing alias table does not invalidate observed primary names, but it prevents
    // a complete negative verdict: the queried name might occur only in an alias.
    let (alt, alt_note, alt_current) = match copy_of(transport, dir, &OFAC_ALT, now_unix) {
        Ok((alt, _, current)) => (alt, None, current),
        Err((_, why)) => (
            String::new(),
            Some(format!("aliases unavailable ({why})")),
            false,
        ),
    };
    let parsed = parse_ofac(&sdn, &alt, query);
    if parsed.read == 0 {
        return Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("no SDN row could be read in {} bytes", sdn.len()),
        ));
    }
    let note = [note, alt_note]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
    Ok(parsed.into_read(Some(note), sdn_current && alt_current))
}

/// The UN list's individuals and entities that may carry `query`.
fn read_un(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    query: &[String],
    now_unix: u64,
) -> Result<ListRead, crate::threat_feeds::Failure> {
    let (xml, note, current) = copy_of(transport, dir, &UN_SC, now_unix)?;
    let parsed = parse_un(&xml, query);
    if parsed.read == 0 {
        return Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("no listing could be read in {} bytes", xml.len()),
        ));
    }
    Ok(parsed.into_read(note, current))
}

/// The EU list's subjects that may carry `query`.
fn read_eu(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    query: &[String],
    now_unix: u64,
) -> Result<ListRead, crate::threat_feeds::Failure> {
    let (csv, note, current) = copy_of(transport, dir, &EU_FSF, now_unix)?;
    let parsed = parse_eu(&csv, query);
    if parsed.read == 0 {
        return Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("no subject could be read in {} bytes", csv.len()),
        ));
    }
    Ok(parsed.into_read(note, current))
}

/// The EU list's columns kept for the evidence, by header name, and the attribute each becomes.
const EU_FIELDS: [(&str, &str); 16] = [
    ("Entity_EU_ReferenceNumber", "reference_number"),
    ("Entity_SubjectType", "subject_type"),
    ("Entity_Remark", "remarks"),
    ("Entity_Regulation_Programme", "program"),
    ("Entity_Regulation_NumberTitle", "regulation"),
    ("Entity_Regulation_PublicationDate", "listed_on"),
    ("Entity_Regulation_PublicationUrl", "regulation_url"),
    ("NameAlias_Function", "function"),
    ("NameAlias_Title", "title"),
    ("NameAlias_Gender", "gender"),
    ("BirthDate_BirthDate", "date_of_birth"),
    ("BirthDate_Year", "birth_year"),
    ("BirthDate_City", "place_of_birth"),
    ("BirthDate_CountryDescription", "country_of_birth"),
    ("Citizenship_CountryDescription", "nationality"),
    ("Identification_Remark", "identification"),
];

/// Every subject on the EU list that may carry `query` (every subject, for a `query` of no
/// words), and how many subjects the list holds. The file holds one row per combination of a
/// subject's names, addresses, birth dates, documents and citizenships, so rows are grouped by
/// `Entity_LogicalId` and each value is kept once, in file order. A subject is built only when
/// one of its rows can carry every word of `query` ([`crate::textnorm::carries_every_key`]), so the
/// rows of every other subject are counted and never split. **Pure.**
fn parse_eu(csv: &str, query: &[String]) -> Parsed {
    let mut lines = csv.trim_start_matches('\u{feff}').lines();
    let Some(header) = lines.next() else {
        return Parsed::default();
    };
    let header = delimited_fields(header, ';');
    let column = |name: &str| header.iter().position(|h| h == name);
    let (Some(id_at), Some(whole_at)) = (column("Entity_LogicalId"), column("NameAlias_WholeName"))
    else {
        return Parsed::default();
    };
    let mut read: HashSet<Cow<'_, str>> = HashSet::new();
    let mut candidates: HashSet<Cow<'_, str>> = HashSet::new();
    let mut unreadable = 0;
    for line in lines.clone() {
        let line = line.trim_end_matches('\r');
        let id = field_of(line, ';', id_at);
        // A row without a subject, or with fewer cells than the header (counted without
        // splitting: a cell holding the separator only adds to the count), cannot be read.
        if id.is_empty() || line.matches(';').count() + 1 < header.len() {
            unreadable += 1;
            continue;
        }
        if crate::textnorm::carries_every_key(line, query) {
            candidates.insert(id.clone());
        }
        read.insert(id);
    }
    let parts_at = [
        column("NameAlias_FirstName"),
        column("NameAlias_MiddleName"),
        column("NameAlias_LastName"),
    ];
    let kept: Vec<(usize, &'static str)> = EU_FIELDS
        .iter()
        .filter_map(|(name, key)| column(name).map(|at| (at, *key)))
        .collect();
    let mut order: Vec<String> = Vec::new();
    let mut subjects: HashMap<String, Listing> = HashMap::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if !candidates.contains(field_of(line, ';', id_at).as_ref()) {
            continue;
        }
        let fields = delimited_fields(line, ';');
        if fields.len() != header.len() {
            unreadable += 1;
            continue;
        }
        let id = fields[id_at].trim();
        if id.is_empty() {
            continue;
        }
        let listing = subjects.entry(id.to_owned()).or_insert_with(|| {
            order.push(id.to_owned());
            Listing {
                url: String::new(),
                names: Vec::new(),
                fields: vec![("eu_logical_id", id.to_owned())],
            }
        });
        let whole = fields[whole_at].trim();
        let name = if whole.is_empty() {
            parts_at
                .iter()
                .filter_map(|at| at.map(|at| fields[at].trim()))
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            whole.to_owned()
        };
        if !name.is_empty() && !listing.names.contains(&name) {
            listing.names.push(name);
        }
        for (at, key) in &kept {
            let value = fields[*at].trim();
            if !value.is_empty() && !listing.fields.iter().any(|(k, v)| k == key && v == value) {
                listing.fields.push((key, value.to_owned()));
            }
        }
    }
    let listings = order
        .into_iter()
        .filter_map(|id| subjects.remove(&id))
        .filter(|listing| {
            let named = !listing.names.is_empty();
            if !named {
                unreadable += 1;
            }
            named
        })
        .map(|mut listing| {
            let reference = listing
                .fields
                .iter()
                .find(|(k, _)| *k == "reference_number")
                .map_or_else(
                    || {
                        listing
                            .fields
                            .first()
                            .map_or_else(String::new, |(_, id)| format!("id-{id}"))
                    },
                    |(_, r)| r.clone(),
                );
            listing.url = format!("https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content#{reference}");
            listing
        })
        .collect();
    Parsed {
        listings,
        read: read.len(),
        unreadable,
    }
}

/// OFAC's "no value" marker.
fn ofac_value(field: &str) -> Option<String> {
    let value = field.trim();
    (!value.is_empty() && value != "-0-").then(|| value.to_owned())
}

/// Every SDN row (`ent_num, name, type, program, title, call sign, vessel type, tonnage, GRT,
/// vessel flag, vessel owner, remarks`) that may carry `query`, itself or in the aliases
/// `ALT.CSV` lists under its number (every row, for a `query` of no words), with those aliases;
/// and how many numbered rows the file holds. A row that cannot carry the name, and the alias
/// rows of a number no row of which can, are counted and never split. A line that is not a
/// full row (the file's trailing end-of-file byte) is skipped. **Pure.**
fn parse_ofac(sdn: &str, alt: &str, query: &[String]) -> Parsed {
    let mut candidates: HashSet<Cow<'_, str>> = HashSet::new();
    for line in alt.lines() {
        let line = line.trim_end_matches('\r');
        if crate::textnorm::carries_every_key(line, query) {
            candidates.insert(field_of(line, ',', 0));
        }
    }
    let mut read = 0;
    let mut unreadable = 0;
    for line in sdn.lines() {
        let line = line.trim_end_matches('\r');
        let number = field_of(line, ',', 0);
        if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // A numbered row with fewer separators than a full row has cells cannot be read.
        if line.matches(',').count() < COLUMNS.len() - 1 {
            unreadable += 1;
            continue;
        }
        read += 1;
        if crate::textnorm::carries_every_key(line, query) {
            candidates.insert(number);
        }
    }
    let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
    for line in alt.lines() {
        let line = line.trim_end_matches('\r');
        if !candidates.contains(field_of(line, ',', 0).as_ref()) {
            continue;
        }
        let fields = csv_fields(line);
        if let (Some(number), Some(name)) = (
            fields.first().and_then(|f| ofac_value(f)),
            fields.get(3).and_then(|f| ofac_value(f)),
        ) {
            aliases.entry(number).or_default().push(name);
        }
    }
    const COLUMNS: [&str; 12] = [
        "ent_num",
        "sdn_name",
        "sdn_type",
        "program",
        "title",
        "call_sign",
        "vessel_type",
        "tonnage",
        "grt",
        "vessel_flag",
        "vessel_owner",
        "remarks",
    ];
    let mut listings = Vec::new();
    for line in sdn.lines() {
        let line = line.trim_end_matches('\r');
        if !candidates.contains(field_of(line, ',', 0).as_ref()) {
            continue;
        }
        let fields = csv_fields(line);
        if fields.len() < COLUMNS.len() {
            unreadable += 1;
            continue;
        }
        let (Some(number), Some(name)) = (ofac_value(&fields[0]), ofac_value(&fields[1])) else {
            unreadable += 1;
            continue;
        };
        if !number.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let mut names = vec![name];
        names.extend(aliases.remove(&number).unwrap_or_default());
        let kept = COLUMNS
            .iter()
            .zip(&fields)
            .filter_map(|(key, field)| ofac_value(field).map(|value| (*key, value)))
            .collect();
        listings.push(Listing {
            url: format!("https://sanctionssearch.ofac.treas.gov/Details.aspx?id={number}"),
            names,
            fields: kept,
        });
    }
    Parsed {
        listings,
        read,
        unreadable,
    }
}

/// Every individual and entity on the UN list whose block may carry `query` (every one, for a
/// `query` of no words): the name parts joined, every alias, and every field kept for the
/// evidence; and how many blocks the list holds. A block that cannot carry the name is counted
/// and never read. **Pure.**
fn parse_un(xml: &str, query: &[String]) -> Parsed {
    let mut listings = Vec::new();
    let mut read = 0;
    let mut unreadable = 0;
    for (element, kind) in [("INDIVIDUAL", "individual"), ("ENTITY", "entity")] {
        for block in xml_blocks(xml, element) {
            read += 1;
            let parts: Vec<String> = ["FIRST_NAME", "SECOND_NAME", "THIRD_NAME", "FOURTH_NAME"]
                .iter()
                .filter_map(|tag| xml_tag_values(block, tag).into_iter().next())
                .collect();
            let Some(reference) = xml_tag_values(block, "REFERENCE_NUMBER").into_iter().next()
            else {
                unreadable += 1;
                continue;
            };
            if parts.is_empty() {
                unreadable += 1;
                continue;
            }
            if !block_carries(block, query) {
                continue;
            }
            let mut names = vec![parts.join(" ")];
            names.extend(xml_tag_values(block, "ALIAS_NAME"));
            names.extend(xml_tag_values(block, "NAME_ORIGINAL_SCRIPT"));
            let mut fields: Vec<(&'static str, String)> = vec![
                ("listing_type", kind.to_owned()),
                ("reference_number", reference.clone()),
            ];
            for (key, tag) in [
                ("un_list_type", "UN_LIST_TYPE"),
                ("listed_on", "LISTED_ON"),
                ("gender", "GENDER"),
                ("comments", "COMMENTS1"),
                ("interpol_link", "INTERPOL_LINK"),
            ] {
                for value in xml_tag_values(block, tag) {
                    fields.push((key, value));
                }
            }
            for (key, container) in [
                ("nationality", "NATIONALITY"),
                ("designation", "DESIGNATION"),
                ("title", "TITLE"),
            ] {
                for inner in xml_blocks(block, container) {
                    for value in xml_tag_values(inner, "VALUE") {
                        fields.push((key, value));
                    }
                }
            }
            for birth in xml_blocks(block, "INDIVIDUAL_DATE_OF_BIRTH") {
                for tag in ["DATE", "YEAR", "FROM_YEAR", "TO_YEAR"] {
                    for value in xml_tag_values(birth, tag) {
                        fields.push(("date_of_birth", value));
                    }
                }
            }
            for place in xml_blocks(block, "INDIVIDUAL_PLACE_OF_BIRTH") {
                for tag in ["CITY", "STATE_PROVINCE", "COUNTRY"] {
                    for value in xml_tag_values(place, tag) {
                        fields.push(("place_of_birth", value));
                    }
                }
            }
            listings.push(Listing {
                url: format!("{}#{reference}", UN_SC.url),
                names,
                fields,
            });
        }
    }
    Parsed {
        listings,
        read,
        unreadable,
    }
}

/// Whether a block of the UN list may carry every word of `query`: asked of its text in place,
/// unescaped first when a character reference in it could spell a letter. **Pure.**
fn block_carries(block: &str, query: &[String]) -> bool {
    if block.contains("&#") {
        crate::textnorm::carries_every_key(&xml_unescape(block), query)
    } else {
        crate::textnorm::carries_every_key(block, query)
    }
}

#[cfg(test)]
mod tests;
