//! End-to-end front-end for `huntsman-recon company`: one organisation query -- a name, a nine-digit
//! ACN or an eleven-digit ABN -- looked up on ASIC's keyless organisation registers (companies,
//! business names, banned and disqualified organisations) and, for a name, on the GLEIF legal-entity
//! register, then screened against the registers kept on the device: a name against the
//! consolidated sanctions lists and the AEC Transparency Register's returns, a number against the
//! returns that carry an ABN or ACN. Every record is a register entry to review, never a confirmed
//! identity.

use crate::abn_lookup;
use crate::asic_orgs::{self, Query};
use crate::error::Error;
use crate::gleif;
use crate::http::Transport;
use crate::keys::Keys;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceRun};

pub const COMPANY_USAGE: &str = "usage: huntsman-recon company NAME|ACN|ABN";
pub const COMPANY_HELP: &str = "\
company NAME|ACN|ABN
Look up one Australian organisation by NAME, a nine-digit ACN or an eleven-digit ABN (spaces allowed; the number must pass its checksum). Searches ASIC's Company Dataset (every registered company, its current and former names, ACN, ABN, type, class, status and registration dates), the Business Names register (each trading name with the ABN of the entity that holds it) and the Banned and Disqualified Organisations register, all keyless on data.gov.au; a NAME is also looked up on the GLEIF legal-entity register. A name matches only a record holding every word of the query, and a number matches only a record holding exactly that number. A NAME of two or more words is also matched against the OFAC, UN, EU and DFAT (Australian) sanctions lists and the AEC Transparency Register's annual returns kept on the device, and an ABN or ACN against the AEC returns that carry one (third-party and significant third-party returns): each match a Document lead with the listing or row kept as evidence. An ABN or ACN is also looked up on the Australian Business Register (ABN Lookup) when HUNTSMAN_ABR_GUID holds the operator's free ABR web-services GUID: the registered entity name and type, ABN status, GST registration, state and postcode, and every business name. A register entry is a candidate to review, not a confirmed identity. Makes network requests.";

/// The longest query taken, in bytes.
const MAX_COMPANY_QUERY_BYTES: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyArgs {
    pub query: Query,
}

impl CompanyArgs {
    /// # Errors
    /// [`Error::Invalid`] for no query, [`Error::InvalidValue`] for one that is empty, too long, holds
    /// a control character, or is a number that is neither a valid ACN nor a valid ABN.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        if args.is_empty() {
            return Err(Error::Invalid("company needs a NAME, ACN or ABN".into()));
        }
        let raw = args.join(" ");
        crate::textnorm::within_query_bound(&raw, MAX_COMPANY_QUERY_BYTES, "query")?;
        let query = Query::parse(&raw).ok_or_else(|| {
            Error::invalid_value("the query is empty, or a number that is not a valid ACN or ABN")
        })?;
        Ok(Self { query })
    }
}

/// What the lookup found: its entities and each source's row.
pub type Report = crate::lookup_report::LookupReport;

pub type CompanyRun = SourceRun<Report>;

/// [`run_with_lists`] consulting no kept register.
#[must_use]
pub fn run<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    query: &Query,
    now_unix: u64,
) -> CompanyRun {
    run_with_lists(
        transport,
        keys,
        query,
        &crate::sanctions::Lists::none(),
        now_unix,
    )
}

/// Look up `query`, each leg only when the transport's lookup asks its module
/// ([`Transport::runs_module`]). ABN Lookup runs for an ABN or ACN when `HUNTSMAN_ABR_GUID` is set
/// in `keys`; without it the leg is recorded as not configured and sends nothing. The registers
/// `lists` keeps on the device screen the query last: a name against the sanctions lists and the
/// AEC returns, a number against the AEC returns that carry an ABN or ACN;
/// [`crate::sanctions::Lists::none`] consults none.
#[must_use]
pub fn run_with_lists<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    query: &Query,
    lists: &crate::sanctions::Lists,
    now_unix: u64,
) -> CompanyRun {
    let text = match query {
        Query::Acn(id) | Query::Abn(id) | Query::Name(id) => id.as_str(),
    };
    let scan_id = crate::entity::scan_id("company", text);
    let mut report = Report::default();

    if transport.runs_module(asic_orgs::SRC) {
        match asic_orgs::lookup(transport, query, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.extend(found.outcomes);
            }
            Err(error) => report.outcomes.push(SourceExecutionOutcome::of_leg_error(
                asic_orgs::SRC,
                now_unix,
                &error,
            )),
        }
    }
    let abr_id = match query {
        Query::Abn(abn) => Some(abn_lookup::Id::Abn(abn)),
        Query::Acn(acn) => Some(abn_lookup::Id::Acn(acn)),
        Query::Name(_) => None,
    };
    if let Some(id) = abr_id.filter(|_| transport.runs_module(abn_lookup::SOURCE)) {
        let api = &abn_lookup::API;
        let outcome = if api.wanted(keys) {
            match abn_lookup::lookup(transport, keys, id, now_unix) {
                Ok(record) => {
                    report
                        .entities
                        .extend(abn_lookup::entities(&record, &scan_id));
                    SourceExecutionOutcome::success(api.source, now_unix, 1).with_http_status(200)
                }
                Err(err) => err.outcome(api, now_unix),
            }
        } else {
            SourceExecutionOutcome::not_configured(api.source, now_unix)
        };
        report.outcomes.push(outcome);
    }
    // GLEIF searches legal names; it cannot be asked an ACN or ABN.
    if matches!(query, Query::Name(_)) && transport.runs_module(gleif::SOURCE) {
        match gleif::lookup(transport, text, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => report.outcomes.push(SourceExecutionOutcome::of_leg_error(
                gleif::SOURCE,
                now_unix,
                &error,
            )),
        }
    }
    kept_registers(lists, query, &scan_id, now_unix, &mut report);
    lookup_report::finish(report, &format!("no source answered for {text:?}"))
}

/// The registers kept on the device, into `report`: for a name, the sanctions listings and the
/// AEC returns that carry every word of it; for an ABN or ACN, the AEC returns that carry it.
fn kept_registers(
    lists: &crate::sanctions::Lists,
    query: &Query,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) {
    let Some(transport) = lists.transport() else {
        return;
    };
    let returns = match query {
        Query::Name(name) => {
            let (listed, outcomes) = crate::sanctions::check(lists, name, scan_id, now_unix);
            report.entities.extend(listed);
            report.outcomes.extend(outcomes);
            crate::aec_returns::check(transport, lists.dir(), name, scan_id, now_unix)
        }
        Query::Abn(id) | Query::Acn(id) => {
            crate::aec_returns::check_id(transport, lists.dir(), id, scan_id, now_unix)
        }
    };
    if let Some((rows, outcome)) = returns {
        report.entities.extend(rows);
        report.outcomes.push(outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_classify_names_and_checksummed_numbers() {
        let parse = |s: &str| CompanyArgs::parse(&[s.to_owned()]);
        assert_eq!(parse("Monaka").unwrap().query, Query::Name("Monaka".into()));
        assert_eq!(
            parse("000 000 019").unwrap().query,
            Query::Acn("000000019".into())
        );
        assert!(parse("000000018").is_err(), "bad checksum");
        assert!(parse("bad\nquery").is_err());
        assert!(CompanyArgs::parse(&[]).is_err());
        assert!(parse(&"x".repeat(MAX_COMPANY_QUERY_BYTES + 1)).is_err());
    }

    /// The registers kept on the device screen the query last, over the lists' own transport:
    /// a name against the sanctions lists (an entity listing) and the AEC returns, a number
    /// against the returns that carry an ABN; `run` consults none.
    #[test]
    fn kept_registers_screen_a_name_and_a_number() {
        use crate::test_support::RoutedTransport;
        const SDN: &str = "306,\"BANCO NACIONAL DE CUBA\",-0- ,\"CUBA\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,\"a.k.a. 'BNC'.\"\r\n";
        let lists = || {
            crate::sanctions::Lists::new(
                Box::new(
                    crate::aec_returns::tests::transport()
                        .with_bytes("https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV", 200, SDN.as_bytes().to_vec())
                        .with_bytes("https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ALT.CSV", 200, b"\r\n".to_vec()),
                ),
                None,
            )
        };
        let quiet = RoutedTransport::new(&[]);
        let keys = Keys::default();
        let report = match run_with_lists(
            &quiet,
            &keys,
            &Query::Name("Banco Nacional de Cuba".into()),
            &lists(),
            1,
        ) {
            SourceRun::Printed { report, .. } => report,
            other => panic!("{other:?}"),
        };
        assert!(
            report.entities.iter().any(
                |e| e.raw_value == "https://sanctionssearch.ofac.treas.gov/Details.aspx?id=306"
            ),
            "{:?}",
            report
                .entities
                .iter()
                .map(|e| e.raw_value.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            report
                .outcomes
                .iter()
                .any(|o| o.module == crate::sanctions::OFAC)
        );
        assert!(
            report
                .outcomes
                .iter()
                .any(|o| o.module == crate::aec_returns::SOURCE)
        );

        let report = match run_with_lists(
            &quiet,
            &keys,
            &Query::Name("Mineralogy Pty Ltd".into()),
            &lists(),
            1,
        ) {
            SourceRun::Printed { report, .. } => report,
            other => panic!("{other:?}"),
        };
        assert!(report.entities.iter().any(|e| {
            e.raw_value
                .contains("#donation-made/2023-24/mineralogy-pty-ltd")
        }));

        let report = match run_with_lists(
            &quiet,
            &keys,
            &Query::Abn("12345678901".into()),
            &lists(),
            1,
        ) {
            SourceRun::Printed { report, .. } => report,
            other => panic!("{other:?}"),
        };
        assert!(report.entities.iter().any(|e| {
            e.raw_value
                .ends_with("#third-party-return/2023-24/advance-australia-ltd")
        }));
        assert!(
            !report
                .outcomes
                .iter()
                .any(|o| o.module == crate::sanctions::OFAC),
            "no list is asked a number"
        );

        let plain = run(
            &quiet,
            &keys,
            &Query::Name("Banco Nacional de Cuba".into()),
            1,
        );
        if let SourceRun::Printed { report, .. } = plain {
            assert!(
                !report
                    .outcomes
                    .iter()
                    .any(|o| o.module == crate::sanctions::OFAC)
            );
        }
    }
}
