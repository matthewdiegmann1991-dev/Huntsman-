//! The Australian Electoral Commission's Transparency Register: the annual returns parties,
//! associated entities, donors, third parties, significant third parties and members of
//! parliament lodge under the Commonwealth Electoral Act, which the AEC publishes whole as one
//! keyless archive of CSV tables (donations made and received, receipts, debts, discretionary
//! benefits, capital contributions and each return's totals). The archive is downloaded through
//! the threat feeds' download-and-keep machinery ([`crate::threat_feeds::load`]), kept on the
//! device and refreshed weekly, and a name is matched locally, so a lookup sends nothing about
//! who is being looked up. A row matches when the name in one of its name columns carries every
//! word of the name asked. A match is a lead to review, never proof that the person or
//! organisation named in the return is the one looked up: each is a `Document` keyed by its
//! table, financial year and the names in the row, its whole row kept verbatim as evidence.

use std::path::Path;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::http::Transport;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::threat_feeds::{CachedList, Failure, csv_fields, load};

/// The module that selects the register.
pub const SOURCE: &str = "aec_transparency";
/// The register's archive: every annual return's tables, one keyless download.
const ARCHIVE: CachedList = CachedList {
    id: "aec-annual-returns.zip",
    source: SOURCE,
    url: "https://transparency.aec.gov.au/Download/AllAnnualData",
    max_age: 7 * 24 * 3_600,
    xml_root: None,
};
/// The register's name on the evidence.
const DATASET: &str = "AEC Transparency Register annual returns";
/// A name match in a return: a strong lead, below a confirmed identity.
const LISTED_CONFIDENCE: f64 = 0.6;
/// The most matching rows one table reports for one name.
const MAX_MATCHES: usize = 100;
/// The longest table read from the archive: the receipts table is 16 MB.
const MAX_RETURN_TABLE_BYTES: usize = 32 * 1024 * 1024;

/// One table of the archive: its file, what each row is a return of, the columns a name is
/// looked for in (the return's own name, then the other party's), and every column kept for
/// the evidence, with the attribute each becomes.
struct Table {
    file: &'static str,
    return_type: &'static str,
    names: &'static [&'static str],
    kept: &'static [(&'static str, &'static str)],
}

const TABLES: [Table; 13] = [
    Table {
        file: "Donor Returns.csv",
        return_type: "donor return",
        names: &["Name", "Lodged on behalf of"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Name", "name"),
            ("Lodged on behalf of", "lodged_on_behalf_of"),
            ("Total Donations Made", "total_donations_made"),
            ("Total Donations Received", "total_donations_received"),
        ],
    },
    Table {
        file: "Donations Made.csv",
        return_type: "donation made",
        names: &["Donor Name", "Donation Made To"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Donor Name", "donor_name"),
            ("Donation Made To", "donation_made_to"),
            ("Date", "date"),
            ("Value", "value"),
        ],
    },
    Table {
        file: "Donor Donations Received.csv",
        return_type: "donation a donor received",
        names: &["Name", "Donation Received From"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Name", "name"),
            ("Donation Received From", "donation_received_from"),
            ("Date", "date"),
            ("Value", "value"),
        ],
    },
    Table {
        file: "Detailed Receipts.csv",
        return_type: "receipt",
        names: &["Received From", "Recipient Name"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Return Type", "return_type"),
            ("Recipient Name", "recipient_name"),
            ("Received From", "received_from"),
            ("Receipt Type", "receipt_type"),
            ("Value", "value"),
        ],
    },
    Table {
        file: "Detailed Debts.csv",
        return_type: "debt",
        names: &["Name", "Creditor Name"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Return Type", "return_type"),
            ("Name", "name"),
            ("Creditor Name", "creditor_name"),
            ("Amount owed", "amount_owed"),
            ("Financial or Non-financial institution", "institution"),
        ],
    },
    Table {
        file: "Detailed Discretionary Benefits.csv",
        return_type: "discretionary benefit",
        names: &["Name", "Received From"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Return Type", "return_type"),
            ("Name", "name"),
            ("Received From", "received_from"),
            ("Date", "date"),
            ("Value", "value"),
        ],
    },
    Table {
        file: "Capital Contributions.csv",
        return_type: "capital contribution",
        names: &["Name", "Contributor"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Return Type", "return_type"),
            ("Name", "name"),
            ("Contributor", "contributor"),
            ("Value", "value"),
        ],
    },
    Table {
        file: "Party Returns.csv",
        return_type: "party return",
        names: &["Name"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Name", "name"),
            ("Party Group", "party_group"),
            ("Total Receipts", "total_receipts"),
            ("Total Payments", "total_payments"),
            ("Total Debts", "total_debts"),
            (
                "Total Discretionary Benefits",
                "total_discretionary_benefits",
            ),
        ],
    },
    Table {
        file: "Associated Entity Returns.csv",
        return_type: "associated entity return",
        names: &["Name", "Lodged on behalf of"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Name", "name"),
            ("Lodged on behalf of", "lodged_on_behalf_of"),
            ("AssociatedParties", "associated_parties"),
            ("Total Receipts", "total_receipts"),
            ("Total Payments", "total_payments"),
            ("Total Debts", "total_debts"),
        ],
    },
    Table {
        file: "Third Party Returns.csv",
        return_type: "third party return",
        names: &["Name"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Name", "name"),
            ("ABN", "abn"),
            ("ACN", "acn"),
            ("Total Expenditure", "total_expenditure"),
            ("Total Gifts Received", "total_gifts_received"),
            ("ClientType", "client_type"),
        ],
    },
    Table {
        file: "Significant Third Party Returns.csv",
        return_type: "significant third party return",
        names: &["Name", "Lodged on behalf of"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Return Type", "return_type"),
            ("Name", "name"),
            ("ABN", "abn"),
            ("ACN", "acn"),
            ("Lodged on behalf of", "lodged_on_behalf_of"),
            ("Total Receipts", "total_receipts"),
            ("Total Payments", "total_payments"),
            ("Electoral Expenditure", "electoral_expenditure"),
        ],
    },
    Table {
        file: "Third Party Donations Received.csv",
        return_type: "donation a third party received",
        names: &["Name", "Donation Received From"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Name", "name"),
            ("Donation Received From", "donation_received_from"),
            ("Date", "date"),
            ("Value", "value"),
        ],
    },
    Table {
        file: "MemberOfParliamentReturns.csv",
        return_type: "member of parliament return",
        names: &["Name"],
        kept: &[
            ("Financial Year", "financial_year"),
            ("Return Type", "return_type"),
            ("Name", "name"),
            ("Total Donations Received", "total_donations_received"),
            ("Number of Donors", "number_of_donors"),
        ],
    },
];

/// A row of a table that names `query`: the column it was found in, the name there, and every
/// kept field, verbatim.
struct Match {
    table: &'static Table,
    column: &'static str,
    name: String,
    fields: Vec<(&'static str, String)>,
}

/// Match `name` against every table of the register's archive (kept, or downloaded over
/// `transport` and kept in `dir`): the rows that name it, as `Document` leads, and the one
/// outcome. `None` when the transport does not run this module or the name has fewer than two
/// words. A table the archive no longer holds, or an archive that cannot be read and has no kept
/// copy, is reported as such, never as a clean zero.
#[must_use]
pub fn check(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    name: &str,
    scan_id: &str,
    now_unix: u64,
) -> Option<(Vec<Entity>, SourceExecutionOutcome)> {
    if !transport.runs_module(SOURCE) {
        return None;
    }
    let query = crate::textnorm::name_tokens(name);
    if query.len() < 2 {
        return None;
    }
    let copy = match load(transport, dir, &ARCHIVE, now_unix) {
        Ok(copy) => copy,
        Err((kind, why)) => {
            return Some((
                Vec::new(),
                SourceExecutionOutcome::failed(SOURCE, now_unix, kind, None, why),
            ));
        }
    };
    let current = copy.current_for(now_unix, ARCHIVE.max_age);
    let mut note = format!(
        "copy {} ({}s old)",
        if copy.downloaded {
            "downloaded now"
        } else {
            "kept"
        },
        now_unix.saturating_sub(copy.fetched)
    );
    if let Some(extra) = copy.note {
        note.push_str("; ");
        note.push_str(&note_extra(&extra));
    }
    let mut matches = Vec::new();
    let mut rows = 0usize;
    let mut missing = Vec::new();
    for table in &TABLES {
        match read_table(&copy.body, table) {
            Ok(text) => rows += match_table(&text, table, &query, &mut matches),
            Err(why) => missing.push(why),
        }
    }
    let mut entities = Vec::new();
    for found in &matches {
        record(found, scan_id, &mut entities);
    }
    merge_by_uid(&mut entities);
    let found = matches.len();
    let detail = format!(
        "{rows} rows read across {} tables; {note}",
        TABLES.len() - missing.len()
    );
    let outcome = if let Some(why) = missing.first() {
        SourceExecutionOutcome::observed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::ProtocolDrift,
            None,
            Some(found),
            format!("{}; {detail}", why.1),
        )
    } else if !current {
        SourceExecutionOutcome::observed(
            SOURCE,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            None,
            Some(found),
            "archive refresh failed or verified cache freshness expired",
        )
        .with_detail(detail)
    } else if found == 0 {
        SourceExecutionOutcome::valid_zero(SOURCE, now_unix).with_detail(detail)
    } else {
        SourceExecutionOutcome::success(SOURCE, now_unix, found).with_detail(detail)
    };
    Some((entities, outcome))
}

/// A copy's own note, as the outcome carries it.
fn note_extra(extra: &str) -> String {
    extra.to_owned()
}

/// One table of the archive as text.
fn read_table(archive: &[u8], table: &Table) -> Result<String, Failure> {
    match crate::zip_read::zip_member(archive, table.file, MAX_RETURN_TABLE_BYTES) {
        Ok(Some(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        Ok(None) => Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("the archive has no {}", table.file),
        )),
        Err(why) => Err((
            SourceOutcomeKind::ProtocolDrift,
            format!("{} could not be read: {why}", table.file),
        )),
    }
}

/// Every row of `text` (a CSV table, its header first) that names `query` in one of the table's
/// name columns, at most [`MAX_MATCHES`], pushed to `matches`; the rows read. **Pure.**
fn match_table(
    text: &str,
    table: &'static Table,
    query: &[String],
    matches: &mut Vec<Match>,
) -> usize {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.lines();
    let Some(header) = lines.next() else {
        return 0;
    };
    let header = csv_fields(header);
    let column = |title: &str| {
        header
            .iter()
            .position(|cell| cell.trim().eq_ignore_ascii_case(title))
    };
    let names: Vec<(usize, &'static str)> = table
        .names
        .iter()
        .filter_map(|title| column(title).map(|at| (at, *title)))
        .collect();
    let kept: Vec<(usize, &'static str)> = table
        .kept
        .iter()
        .filter_map(|(title, attr)| column(title).map(|at| (at, *attr)))
        .collect();
    let mut rows = 0;
    let mut found = 0;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        rows += 1;
        if found == MAX_MATCHES {
            continue;
        }
        let cells = csv_fields(line);
        let Some((column_title, name)) = names.iter().find_map(|(at, title)| {
            let value = cells.get(*at).map_or("", |cell| cell.trim());
            names_query(value, query).then(|| (*title, value.to_owned()))
        }) else {
            continue;
        };
        found += 1;
        matches.push(Match {
            table,
            column: column_title,
            name,
            fields: kept
                .iter()
                .map(|(at, attr)| {
                    (
                        *attr,
                        cells.get(*at).map_or("", |cell| cell.trim()).to_owned(),
                    )
                })
                .filter(|(_, value)| !value.is_empty())
                .collect(),
        });
    }
    rows
}

/// Whether `listed` carries every word of `query`. **Pure.**
fn names_query(listed: &str, query: &[String]) -> bool {
    let have = crate::textnorm::name_tokens(listed);
    query.iter().all(|word| have.contains(word))
}

/// `text` as a key fragment: lowercase, runs of anything but letters and digits as one `-`.
/// **Pure.**
fn slug(text: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in text.chars() {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    out.trim_end_matches('-').to_owned()
}

/// One matching row as a `Document` lead keyed by its table, financial year and names.
fn record(found: &Match, scan_id: &str, entities: &mut Vec<Entity>) {
    let field = |attr: &str| {
        found
            .fields
            .iter()
            .find(|(key, _)| *key == attr)
            .map_or("", |(_, value)| value.as_str())
    };
    let year = field("financial_year");
    let mut key = format!(
        "{}#{}/{}/{}",
        ARCHIVE.url,
        slug(found.table.return_type),
        slug(year),
        slug(&found.name)
    );
    for (attr, value) in &found.fields {
        if *attr != "financial_year"
            && !value.eq_ignore_ascii_case(&found.name)
            && field(attr) == value
            && found
                .table
                .names
                .iter()
                .any(|title| slug(title) == attr.replace('_', "-"))
        {
            key.push('/');
            key.push_str(&slug(value));
        }
    }
    let mut evidence = Evidence::new(
        EvidenceProvenance::for_scan(SOURCE, scan_id),
        format!(
            "Named in the {DATASET} as {} ({} column of a {} for {year}). A name match in a lodged return, not proof it is the same person or organisation: compare the other party, the amounts and the year kept here",
            found.name, found.column, found.table.return_type
        ),
    )
    .with_attr("dataset", DATASET)
    .with_attr("table", found.table.file)
    .with_attr("return_of", found.table.return_type)
    .with_attr("matched_column", found.column)
    .with_attr("matched_name", found.name.as_str());
    for (attr, value) in &found.fields {
        evidence = evidence.with_attr(*attr, value.as_str());
    }
    push_entity(
        entities,
        EntityKind::Document,
        &key,
        LISTED_CONFIDENCE,
        scan_id,
        evidence,
        &["aec-return", "name-match-lead"],
    );
}

#[cfg(test)]
mod tests;
