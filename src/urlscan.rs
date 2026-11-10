//! urlscan.io: public scans of web pages that involve one IP or domain.
//!
//! One lookup is one `GET https://urlscan.io/api/v1/search/?q={domain|ip}:"{value}"&size=100`.
//! urlscan.io answers searches without a key; with `HUNTSMAN_URLSCAN_KEY` set the key goes in the
//! `API-Key` header and the account's quota applies. A hundred is the most one search page gives
//! without a key (checked 2026-10-15). No match is a valid zero. Every search answer carries
//! `results`, empty when nothing matched (checked 2026-10-15): a JSON body without it, such as an
//! error or quota notice, is drift.
//!
//! Everything about the listed scans is kept: each scan whole as JSON in `raw_scans`, and, across
//! them, how many matched, the oldest and newest, every submitted and final URL, page title,
//! status, MIME type, server, TLS issuer, country, redirect kind, apex domain, scan id, result
//! and screenshot link, and urlscan's verdicts and highest score. A verdict judges the scanned
//! page: one on a page on the indicator (its domain or a name under it; for an address, served
//! from it) counts against the indicator and tags it `malicious`; one on another page that merely
//! involved the indicator is counted and kept apart, and does not. Each page's domain, address,
//! AS and AS holder, and each submitted domain, are pivots: linked when the scan was of a page
//! on the indicator, incidental when the page merely involved it.

use serde::Deserialize;
use serde_json::Value;

use crate::api_leg::{self, Api, Distinct, KeyPlace, KeyUse, LegError};
use crate::canonical::{canonical_domain, same_ip};
use crate::domains::is_or_subdomain_of;
use crate::http::{Transport, percent_encode_component};
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;

pub const SOURCE: &str = "urlscan";
pub const KEY_SLOT: &str = crate::environment::URLSCAN_KEY_ENV;
pub const API: Api = Api {
    source: SOURCE,
    provider: "urlscan.io",
    origin: "https://urlscan.io:443",
    key: Some(KeyUse {
        slot: KEY_SLOT,
        place: KeyPlace::Header("API-Key"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip, IndicatorKind::Domain],
    lookup,
};
/// Scans asked for per search: the most one page gives without a key.
pub const LIMIT: usize = 100;

#[derive(Deserialize)]
struct Body {
    results: Vec<Value>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    has_more: Option<bool>,
}

#[derive(Deserialize)]
struct Scan {
    #[serde(default)]
    page: Option<Page>,
    #[serde(default)]
    task: Option<Task>,
    #[serde(default)]
    verdicts: Option<Verdicts>,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    screenshot: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    apex_domain: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    asnname: Option<String>,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    status: Option<Value>,
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    tls_issuer: Option<String>,
    #[serde(default)]
    redirected: Option<Value>,
}

#[derive(Deserialize)]
struct Task {
    #[serde(default)]
    time: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

#[derive(Deserialize)]
struct Verdicts {
    #[serde(default)]
    overall: Option<Overall>,
}

#[derive(Deserialize)]
struct Overall {
    #[serde(default)]
    malicious: bool,
    #[serde(default)]
    score: Option<f64>,
}

/// The search URL for `indicator`, or `None` for a kind urlscan.io is not asked about. **Pure.**
#[must_use]
pub fn url(indicator: Indicator<'_>) -> Option<String> {
    let field = match indicator {
        Indicator::Ip(_) => "ip",
        Indicator::Domain(_) => "domain",
        Indicator::Email(_)
        | Indicator::Phone(_)
        | Indicator::Cell(_)
        | Indicator::MacAddress(_) => return None,
    };
    let query = format!("{field}:\"{}\"", indicator.value());
    Some(format!(
        "https://urlscan.io/api/v1/search/?q={}&size={LIMIT}",
        percent_encode_component(&query)
    ))
}

/// Look `indicator` up.
///
/// # Errors
/// The [`LegError`] that stopped the lookup.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Some(url) = url(indicator) else {
        return Ok(None);
    };
    let body = api_leg::get(transport, &API, keys, &url, now_unix)?.body_or_unexpected()?;
    decode(&body, indicator)
}

/// What the listed scans say, across them all. Verdicts are kept apart by whether the scanned
/// page was on the indicator (`malicious`, `best_score`) or merely involved it
/// (`involved_malicious`, `involved_best_score`). **Pure.**
#[derive(Default)]
struct Scans {
    on_indicator: usize,
    involving: usize,
    malicious: usize,
    best_score: Option<f64>,
    involved_malicious: usize,
    involved_best_score: Option<f64>,
    oldest: Option<String>,
    newest: Option<String>,
    urls: Distinct,
    page_urls: Distinct,
    titles: Distinct,
    statuses: Distinct,
    mime_types: Distinct,
    servers: Distinct,
    tls_issuers: Distinct,
    countries: Distinct,
    redirects: Distinct,
    apex_domains: Distinct,
    scan_ids: Distinct,
    results: Distinct,
    screenshots: Distinct,
}

impl Scans {
    fn read(scans: &[Scan], indicator: Indicator<'_>) -> Self {
        let mut out = Self::default();
        for scan in scans {
            let on = is_on(scan, indicator);
            let (count, malicious, best_score) = if on {
                (
                    &mut out.on_indicator,
                    &mut out.malicious,
                    &mut out.best_score,
                )
            } else {
                (
                    &mut out.involving,
                    &mut out.involved_malicious,
                    &mut out.involved_best_score,
                )
            };
            *count += 1;
            if let Some(overall) = scan.verdicts.as_ref().and_then(|v| v.overall.as_ref()) {
                *malicious += usize::from(overall.malicious);
                if let Some(score) = overall.score {
                    *best_score = Some(best_score.map_or(score, |best| best.max(score)));
                }
            }
            if let Some(task) = &scan.task {
                if let Some(time) = task.time.as_deref() {
                    if out.oldest.as_deref().is_none_or(|t| time < t) {
                        out.oldest = Some(time.to_owned());
                    }
                    if out.newest.as_deref().is_none_or(|t| time > t) {
                        out.newest = Some(time.to_owned());
                    }
                }
                out.urls.push_cleaned(task.url.as_deref());
                out.scan_ids.push_cleaned(task.uuid.as_deref());
            }
            if let Some(page) = &scan.page {
                out.page_urls.push_cleaned(page.url.as_deref());
                out.titles.push_cleaned(page.title.as_deref());
                out.statuses.push_scalar(page.status.as_ref());
                out.mime_types.push_cleaned(page.mime_type.as_deref());
                out.servers.push_cleaned(page.server.as_deref());
                out.tls_issuers.push_cleaned(page.tls_issuer.as_deref());
                out.countries.push_cleaned(page.country.as_deref());
                out.redirects.push_scalar(page.redirected.as_ref());
                out.apex_domains.push_cleaned(page.apex_domain.as_deref());
            }
            out.results.push_cleaned(scan.result.as_deref());
            out.screenshots.push_cleaned(scan.screenshot.as_deref());
        }
        out
    }

    fn into_finding(self, finding: Finding) -> Finding {
        finding
            .attr("scans_on_indicator", self.on_indicator.to_string())
            .attr("scans_involving", self.involving.to_string())
            .attr("malicious_scans", self.malicious.to_string())
            .opt_attr("max_verdict_score", self.best_score.map(|s| s.to_string()))
            .attr(
                "involved_malicious_scans",
                self.involved_malicious.to_string(),
            )
            .opt_attr(
                "max_involved_verdict_score",
                self.involved_best_score.map(|s| s.to_string()),
            )
            .opt_attr("oldest_scan", self.oldest)
            .opt_attr("newest_scan", self.newest)
            .list_attr("urls", self.urls.values())
            .list_attr("page_urls", self.page_urls.values())
            .list_attr("page_titles", self.titles.values())
            .list_attr("page_statuses", self.statuses.values())
            .list_attr("mime_types", self.mime_types.values())
            .list_attr("servers", self.servers.values())
            .list_attr("tls_issuers", self.tls_issuers.values())
            .list_attr("page_countries", self.countries.values())
            .list_attr("redirects", self.redirects.values())
            .list_attr("apex_domains", self.apex_domains.values())
            .list_attr("scan_ids", self.scan_ids.values())
            .list_attr("result_links", self.results.values())
            .list_attr("screenshots", self.screenshots.values())
            .tag_if(self.malicious > 0, tags::MALICIOUS)
    }
}

/// Whether a scan's final page was on the indicator: for a domain, the page's domain is the
/// indicator or a name under it; for an address, the page was served from it. **Pure.**
fn on_indicator(page: &Page, indicator: Indicator<'_>) -> bool {
    match indicator {
        Indicator::Domain(domain) => page
            .domain
            .as_deref()
            .and_then(canonical_domain)
            .is_some_and(|name| is_or_subdomain_of(&name, domain)),
        Indicator::Ip(ip) => page.ip.as_deref().is_some_and(|served| same_ip(served, ip)),
        _ => false,
    }
}

/// Whether a scan's final page was on the indicator. **Pure.**
fn is_on(scan: &Scan, indicator: Indicator<'_>) -> bool {
    scan.page
        .as_ref()
        .is_some_and(|page| on_indicator(page, indicator))
}

/// Whether a submitted domain is the indicator or a name under it. **Pure.**
fn under_indicator(domain: &str, indicator: Indicator<'_>) -> bool {
    match indicator {
        Indicator::Domain(apex) => {
            canonical_domain(domain).is_some_and(|name| is_or_subdomain_of(&name, apex))
        }
        _ => false,
    }
}

/// The domain a scan was submitted for, if the scan says. **Pure.**
fn submitted(scan: &Scan) -> Option<&str> {
    scan.task.as_ref().and_then(|task| task.domain.as_deref())
}

/// What a scan's final page names, in a fixed order: its domain, the address serving it, that
/// address's AS and the AS holder. Each comes with two summaries: the first for a page on the
/// indicator, the second for a page that merely involved it. **Pure.**
fn page_pivots(page: &Page) -> [(PivotKind, Option<&str>, &'static str, &'static str); 4] {
    [
        (
            PivotKind::Domain,
            page.domain.as_deref(),
            "Page domain of a urlscan.io scan of a page on the indicator",
            "Page domain in a urlscan.io scan involving the indicator",
        ),
        (
            PivotKind::Ip,
            page.ip.as_deref(),
            "Address serving the indicator's page in a urlscan.io scan",
            "Page address in a urlscan.io scan involving the indicator",
        ),
        (
            PivotKind::Asn,
            page.asn.as_deref(),
            "AS serving the indicator's page in a urlscan.io scan",
            "AS serving a page in a urlscan.io scan involving the indicator",
        ),
        (
            PivotKind::Organisation,
            page.asnname.as_deref(),
            "AS holder serving the indicator's page in a urlscan.io scan",
            "AS holder serving a page in a urlscan.io scan involving the indicator",
        ),
    ]
}

/// The domains, addresses and networks the scans name, except the indicator itself. A scan of
/// a page on the indicator names the indicator's own pages and the address and network serving
/// them: linked pivots. A scan of another page that merely involved the indicator (loaded a
/// resource from it, or passed through it on the way elsewhere) names that page's domain,
/// address and network: incidental pivots, kept but never followed. The site a scan was
/// submitted from is linked only when it is under the indicator; one that redirected into the
/// indicator is incidental. Linked pivots are emitted first, so a value both kinds of scan name
/// keeps the stronger reading. **Pure.**
fn pivots(mut finding: Finding, scans: &[Scan], indicator: Indicator<'_>) -> Finding {
    let other = |value: &str| !value.eq_ignore_ascii_case(indicator.value());
    let (on, involving): (Vec<&Scan>, Vec<&Scan>) =
        scans.iter().partition(|scan| is_on(scan, indicator));
    // Linked: the indicator's own pages, what serves them, and the sites under it they were
    // submitted from.
    for scan in &on {
        if let Some(page) = &scan.page {
            for (kind, value, on_summary, _) in page_pivots(page) {
                if let Some(value) = value.filter(|v| other(v)) {
                    finding = finding.pivot(kind, value, on_summary);
                }
            }
        }
        if let Some(domain) = submitted(scan).filter(|d| other(d) && under_indicator(d, indicator))
        {
            finding = finding.pivot(
                PivotKind::Domain,
                domain,
                "Submitted domain of a urlscan.io scan of a page on the indicator",
            );
        }
    }
    // Incidental: a site that led into the indicator ...
    for scan in &on {
        if let Some(domain) = submitted(scan).filter(|d| other(d) && !under_indicator(d, indicator))
        {
            finding = finding.incidental_pivot(
                PivotKind::Domain,
                domain,
                "Submitted domain of a urlscan.io scan that led to a page on the indicator",
            );
        }
    }
    // ... and the pages that merely involved it.
    for scan in &involving {
        if let Some(domain) = submitted(scan).filter(|d| other(d)) {
            finding = finding.incidental_pivot(
                PivotKind::Domain,
                domain,
                "Submitted domain of a urlscan.io scan involving the indicator",
            );
        }
        if let Some(page) = &scan.page {
            for (kind, value, _, involving_summary) in page_pivots(page) {
                if let Some(value) = value.filter(|v| other(v)) {
                    finding = finding.incidental_pivot(kind, value, involving_summary);
                }
            }
        }
    }
    finding
}

/// One search page for `indicator`. **Pure.**
///
/// # Errors
/// [`LegError::Decode`] for a body that is not the documented shape.
pub fn decode(body: &[u8], indicator: Indicator<'_>) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    if body.results.is_empty() {
        return Ok(None);
    }
    let scans = body
        .results
        .iter()
        .map(Scan::deserialize)
        .collect::<Result<Vec<Scan>, _>>()
        .map_err(|e| LegError::Decode(format!("unexpected scan shape: {e}")))?;
    let listed = scans.len() as u64;
    let total = body.total.unwrap_or(listed).max(listed);
    let read = Scans::read(&scans, indicator);
    let mut finding = Finding::new(format!(
        "urlscan.io: {total} public scan(s); of the newest {listed}, {} of pages on the \
         indicator ({} judged malicious) and {} of other pages that involved it ({} judged \
         malicious)",
        read.on_indicator, read.malicious, read.involving, read.involved_malicious
    ))
    .attr("scan_count", total.to_string())
    .attr("scans_listed", listed.to_string())
    .tag_if(total > listed || body.has_more == Some(true), "truncated");
    finding = read.into_finding(finding);
    finding = pivots(finding, &scans, indicator);
    Ok(Some(
        finding.attr("raw_scans", Value::Array(body.results).to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded without a key for `domain:example.com` on 2026-10-14 (one result, a second added
    /// with a malicious verdict).
    const RECORDED: &str = r#"{"results":[{"canonical":{"task":{"url":"glamours-designs.com/v6g/bf166c"},"page":{"url":"example.com"}},"task":{"visibility":"public","method":"manual","domain":"glamours-designs.com","apexDomain":"glamours-designs.com","time":"2026-10-14T15:05:47.894Z","uuid":"01a13af2-9db2-737d-b351-623c2b84b921","url":"https://glamours-designs.com/v6g/bf166c?e5b5=L3YzL3NpZ25pbi9pZGVudGlmaWVy"},"stats":{"uniqIPs":2,"uniqCountries":2,"dataLength":2956,"encodedDataLength":2610,"requests":3},"page":{"server":"cloudflare","redirected":"off-domain","ip":"104.20.23.154","mimeType":"text/html","title":"Example Domain","url":"https://example.com/","domain":"example.com","apexDomain":"example.com","asnname":"CLOUDFLARENET - Cloudflare, Inc., US","asn":"AS13335","status":"200"},"verdicts":null,"_id":"01a13af2-9db2-737d-b351-623c2b84b921","result":"https://urlscan.io/api/v1/result/01a13af2-9db2-737d-b351-623c2b84b921/","sort":[1791990347894,"01a13af2"]},{"task":{"time":"2026-10-13T01:00:00.000Z"},"page":{"server":"nginx","ip":"203.0.113.9","domain":"login-example.test","asn":"AS64500","asnname":"EXAMPLE-AS"},"verdicts":{"overall":{"malicious":true,"score":100}}}],"total":5906,"took":56,"has_more":false,"search_date_limit_days":30}"#;

    fn value<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
        f.attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_recorded_page_keeps_counts_verdicts_urls_and_pivots() {
        let f = decode(RECORDED.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        assert_eq!(
            f.summary,
            "urlscan.io: 5906 public scan(s); of the newest 2, 1 of pages on the indicator (0 \
             judged malicious) and 1 of other pages that involved it (1 judged malicious)"
        );
        for (key, expected) in [
            ("scan_count", "5906"),
            ("scans_listed", "2"),
            ("scans_on_indicator", "1"),
            ("scans_involving", "1"),
            ("malicious_scans", "0"),
            ("involved_malicious_scans", "1"),
            ("max_involved_verdict_score", "100"),
            ("oldest_scan", "2026-10-13T01:00:00.000Z"),
            ("newest_scan", "2026-10-14T15:05:47.894Z"),
            (
                "urls",
                "https://glamours-designs.com/v6g/bf166c?e5b5=L3YzL3NpZ25pbi9pZGVudGlmaWVy",
            ),
            ("page_urls", "https://example.com/"),
            ("page_titles", "Example Domain"),
            ("page_statuses", "200"),
            ("mime_types", "text/html"),
            ("servers", "cloudflare,nginx"),
            ("redirects", "off-domain"),
            ("apex_domains", "example.com"),
            ("scan_ids", "01a13af2-9db2-737d-b351-623c2b84b921"),
            (
                "result_links",
                "https://urlscan.io/api/v1/result/01a13af2-9db2-737d-b351-623c2b84b921/",
            ),
        ] {
            assert_eq!(value(&f, key), Some(expected), "{key}: {:?}", f.attrs);
        }
        // The one malicious verdict was on login-example.test's page, which merely involved
        // example.com: it is counted apart and does not make example.com malicious.
        assert_eq!(value(&f, "max_verdict_score"), None, "{:?}", f.attrs);
        assert!(!f.tags.contains(&tags::MALICIOUS), "{:?}", f.tags);
        assert!(f.tags.contains(&"truncated"), "{:?}", f.tags);
        let domains: Vec<&str> = f
            .pivots
            .iter()
            .filter(|p| p.kind == PivotKind::Domain)
            .map(|p| p.value.as_str())
            .collect();
        assert_eq!(domains, ["glamours-designs.com", "login-example.test"]);
        assert!(
            !f.pivots.iter().any(|p| p.value == "example.com"),
            "the indicator is not its own pivot"
        );
        // The first scan's page was example.com itself: the address and network serving it are
        // linked pivots, and the site that redirected into it is incidental. The second scan's
        // page was another site that involved example.com: everything it names is incidental.
        let incidental = |value: &str| {
            f.pivots
                .iter()
                .find(|p| p.value == value)
                .unwrap_or_else(|| panic!("no pivot {value}"))
                .incidental
        };
        assert!(
            incidental("glamours-designs.com"),
            "a redirect into the indicator"
        );
        assert!(
            incidental("login-example.test"),
            "a page that merely involved it"
        );
        let linked: Vec<&str> = f
            .pivots
            .iter()
            .filter(|p| !p.incidental)
            .map(|p| p.value.as_str())
            .collect();
        assert!(
            !linked.is_empty(),
            "the indicator's own page names its address and network"
        );
        assert!(
            linked
                .iter()
                .all(|value| value.starts_with("AS") || value.contains('.') || value.contains(' ')),
            "{linked:?}"
        );
        for pivot in &f.pivots {
            assert_eq!(
                pivot.summary.contains("involving the indicator")
                    || pivot.summary.contains("led to a page on the indicator"),
                pivot.incidental,
                "{}: {}",
                pivot.value,
                pivot.summary
            );
        }
    }

    #[test]
    fn every_listed_scan_is_kept_whole() {
        let f = decode(RECORDED.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("recorded body must decode"));
        let raw: Value =
            serde_json::from_str(value(&f, "raw_scans").unwrap_or_default()).unwrap_or_default();
        assert_eq!(raw.as_array().map(Vec::len), Some(2));
        assert_eq!(raw[0]["stats"]["requests"], 3);
        assert_eq!(
            raw[0]["canonical"]["task"]["url"],
            "glamours-designs.com/v6g/bf166c"
        );
        assert_eq!(raw[1]["verdicts"]["overall"]["score"], 100);
    }

    #[test]
    fn a_status_given_as_a_number_is_kept_as_text() {
        let body = r#"{"results":[{"page":{"status":404,"redirected":null}}],"total":1}"#;
        let f = decode(body.as_bytes(), Indicator::Ip("192.0.2.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("a scan with a numeric status must decode"));
        assert_eq!(value(&f, "page_statuses"), Some("404"));
        assert_eq!(value(&f, "redirects"), None);
        assert!(!f.tags.contains(&"truncated"));
    }

    #[test]
    fn a_redirect_given_as_a_flag_is_kept_as_text() {
        let body = r#"{"results":[{"page":{"status":" 200 ","redirected":false}},{"page":{"status":[200],"redirected":true}}],"total":2}"#;
        let f = decode(body.as_bytes(), Indicator::Ip("192.0.2.1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("scans with a flag for a redirect must decode"));
        assert_eq!(value(&f, "page_statuses"), Some("200"));
        assert_eq!(value(&f, "redirects"), Some("false,true"));
    }

    #[test]
    fn a_json_answer_without_results_is_drift_not_no_scans() {
        for body in [
            "{}",
            r#"{"message":"Search is temporarily unavailable","status":503}"#,
            r#"{"results":null,"total":0}"#,
        ] {
            let decoded = decode(body.as_bytes(), Indicator::Domain("example.com"));
            assert!(
                matches!(decoded, Err(LegError::Decode(_))),
                "{body}: {decoded:?}"
            );
        }
    }

    #[test]
    fn no_scan_is_a_zero_and_the_query_is_quoted() {
        let empty = r#"{"results":[],"total":0,"took":49,"has_more":false}"#;
        assert_eq!(
            decode(empty.as_bytes(), Indicator::Ip("192.0.2.1")),
            Ok(None)
        );
        assert!(decode(b"<html>", Indicator::Ip("192.0.2.1")).is_err());
        assert_eq!(
            url(Indicator::Ip("2001:db8::1")).as_deref(),
            Some("https://urlscan.io/api/v1/search/?q=ip%3A%222001%3Adb8%3A%3A1%22&size=100")
        );
    }

    #[test]
    fn a_malicious_verdict_on_the_indicators_own_page_marks_it_and_an_address_is_matched_by_ip() {
        // A phishing page under example.com, judged malicious; a benign page on the apex.
        let body = r#"{"results":[{"page":{"domain":"phish.example.com","ip":"203.0.113.10","asn":"AS64500","asnname":"EXAMPLE-AS"},"verdicts":{"overall":{"malicious":true,"score":90}}},{"page":{"domain":"www.example.com","ip":"203.0.113.11"},"verdicts":{"overall":{"malicious":false,"score":0}}}],"total":2}"#;
        let f = decode(body.as_bytes(), Indicator::Domain("example.com"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("scans on the indicator must decode"));
        assert_eq!(
            f.summary,
            "urlscan.io: 2 public scan(s); of the newest 2, 2 of pages on the indicator (1 \
             judged malicious) and 0 of other pages that involved it (0 judged malicious)"
        );
        assert_eq!(value(&f, "malicious_scans"), Some("1"));
        assert_eq!(value(&f, "max_verdict_score"), Some("90"));
        assert_eq!(value(&f, "involved_malicious_scans"), Some("0"));
        assert_eq!(value(&f, "max_involved_verdict_score"), None);
        assert!(f.tags.contains(&tags::MALICIOUS), "{:?}", f.tags);
        // Both pages are on the indicator: everything they name is linked.
        assert!(f.pivots.iter().all(|p| !p.incidental), "{:?}", f.pivots);
        assert!(f.pivots.iter().any(|p| p.value == "phish.example.com"));

        // For an address, a page is on the indicator when it was served from it, however the
        // address is written; a page served from elsewhere merely involved it.
        let body = r#"{"results":[{"page":{"domain":"a.example","ip":"2001:DB8::1"},"verdicts":{"overall":{"malicious":true,"score":100}}},{"page":{"domain":"b.example","ip":"2001:db8::2"},"verdicts":{"overall":{"malicious":true,"score":100}}}],"total":2}"#;
        let f = decode(body.as_bytes(), Indicator::Ip("2001:db8:0::1"))
            .ok()
            .flatten()
            .unwrap_or_else(|| panic!("scans for an address must decode"));
        assert_eq!(value(&f, "scans_on_indicator"), Some("1"));
        assert_eq!(value(&f, "malicious_scans"), Some("1"));
        assert_eq!(value(&f, "involved_malicious_scans"), Some("1"));
        assert!(f.tags.contains(&tags::MALICIOUS));
        let incidental = |value: &str| {
            f.pivots
                .iter()
                .find(|p| p.value == value)
                .unwrap_or_else(|| panic!("no pivot {value}"))
                .incidental
        };
        assert!(!incidental("a.example") && incidental("b.example"));
    }
}
