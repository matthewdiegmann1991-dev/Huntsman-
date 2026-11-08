//! ipapi.is IP intelligence: the address's owner, origin AS and location, and — with the optional
//! free key — whether it is hosting, a VPN or proxy exit, a Tor exit, a crawler or a recent abuser.
//!
//! The endpoint answers two shapes. Keyless, it gives a short anonymous answer (`company` and `asn`
//! as plain strings, flat location fields, no detection flags) at 30 lookups a day. With a key
//! (`HUNTSMAN_IPAPI_IS_KEY`, 1,000 a day free, commercial use included) it gives the full record.
//! A keyless answer never claims an address is clean: it records `detection=not_checked` so a
//! missing `vpn` or `proxy` tag reads as unknown, not as a negative.
use crate::api_leg::{self, Api, KeyPlace, KeyUse, LegError};
use crate::canonical::canonical_coordinates;
use crate::http::Transport;
use crate::indicator_sources::{Finding, Indicator, IndicatorKind, PivotKind, Source};
use crate::keys::Keys;
use crate::tags;
use serde::Deserialize;
use serde_json::Value;

pub const SOURCE: &str = "ipapi_is";
pub const API: Api = Api {
    source: SOURCE,
    provider: "ipapi.is",
    origin: "https://api.ipapi.is:443",
    key: Some(KeyUse {
        slot: crate::environment::IPAPI_IS_KEY_ENV,
        place: KeyPlace::Query("key"),
        required: false,
    }),
};
pub const INTEL: Source = Source {
    api: &API,
    kinds: &[IndicatorKind::Ip],
    lookup,
};

/// The owner: a plain name keyless, the registered company record with a key.
#[derive(Deserialize)]
#[serde(untagged)]
enum Owner {
    Name(String),
    Record(Company),
}

#[derive(Deserialize, Default)]
struct Company {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    abuser_score: Option<String>,
}

/// The origin AS: `"AS15169 Google LLC"` keyless, the AS record with a key.
#[derive(Deserialize)]
#[serde(untagged)]
enum AsnField {
    Text(String),
    Record(AsnRecord),
}

#[derive(Deserialize, Default)]
struct AsnRecord {
    #[serde(default)]
    asn: Option<u64>,
    #[serde(default)]
    route: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    descr: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
}

#[derive(Deserialize, Default)]
struct Location {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
}

#[derive(Deserialize, Default)]
struct Hosting {
    #[serde(default)]
    datacenter: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    network: Option<String>,
}

#[derive(Deserialize, Default)]
struct Vpn {
    #[serde(default)]
    service: Option<String>,
}

#[derive(Deserialize, Default)]
struct Egress {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Deserialize, Default)]
struct Abuse {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct Body {
    ip: String,
    #[serde(default)]
    rir: Option<String>,
    #[serde(default)]
    is_bogon: bool,
    // The detection flags are absent keyless. `is_vpn` may carry a truthy value other than
    // `true` and `is_crawler` is `false` or the bot's name, so all are read for truthiness.
    #[serde(default)]
    is_datacenter: Option<Value>,
    #[serde(default)]
    is_vpn: Option<Value>,
    #[serde(default)]
    is_proxy: Option<Value>,
    #[serde(default)]
    is_tor: Option<Value>,
    #[serde(default)]
    is_abuser: Option<Value>,
    #[serde(default)]
    is_mobile: Option<Value>,
    #[serde(default)]
    is_satellite: Option<Value>,
    #[serde(default)]
    is_anycast: Option<Value>,
    #[serde(default)]
    is_crawler: Option<Value>,
    #[serde(default)]
    company: Option<Owner>,
    #[serde(default)]
    asn: Option<AsnField>,
    #[serde(default)]
    datacenter: Option<Hosting>,
    #[serde(default)]
    vpn: Option<Vpn>,
    #[serde(default)]
    egress_service: Option<Egress>,
    #[serde(default)]
    abuse: Option<Abuse>,
    #[serde(default)]
    location: Option<Location>,
    // Keyless flat location fields.
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    timezone: Option<String>,
    /// Present only on the anonymous (keyless) answer.
    #[serde(default)]
    docs: Option<String>,
}

/// Whether a flag value is set: `true`, a non-empty string, or a non-zero number. **Pure.**
fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.trim().is_empty() && s != "false",
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Null) | None => false,
    }
}

/// The `AS` number and AS name in a keyless `"AS15169 Google LLC"`. **Pure.**
fn split_asn_text(text: &str) -> (Option<String>, Option<String>) {
    let text = text.trim();
    let (head, rest) = text.split_once(' ').unwrap_or((text, ""));
    let number = head
        .strip_prefix("AS")
        .or_else(|| head.strip_prefix("as"))
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        .map(|n| format!("AS{n}"));
    let name = Some(rest.trim())
        .filter(|r| !r.is_empty())
        .map(str::to_owned);
    match number {
        Some(asn) => (Some(asn), name),
        None => (None, Some(text.to_owned()).filter(|t| !t.is_empty())),
    }
}

fn known(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

#[must_use]
pub fn url(ip: &str) -> String {
    format!("https://api.ipapi.is/?q={ip}")
}

/// # Errors
/// Returns the guarded HTTP or decoding error.
pub fn lookup(
    transport: &dyn Transport,
    keys: &Keys,
    indicator: Indicator<'_>,
    now_unix: u64,
) -> Result<Option<Finding>, LegError> {
    let Indicator::Ip(ip) = indicator else {
        return Ok(None);
    };
    // Never interpolate a selector into a URL without validating it.
    let parsed = ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| LegError::Decode("invalid IP selector".into()))?
        .to_string();
    let body =
        api_leg::get(transport, &API, keys, &url(&parsed), now_unix)?.body_or_unexpected()?;
    decode(&body, &parsed)
}

/// Decode either answer shape without turning a missing field into a fabricated fact.
///
/// # Errors
/// Rejects malformed JSON and an answer naming a different address.
pub fn decode(body: &[u8], ip: &str) -> Result<Option<Finding>, LegError> {
    let body: Body = api_leg::decode(body)?;
    let expected = ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| LegError::Decode("invalid IP selector".into()))?;
    let actual = body
        .ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| LegError::Decode("invalid response IP".into()))?;
    if actual != expected {
        return Err(LegError::Decode("answer names another address".into()));
    }
    if body.is_bogon {
        return Ok(None);
    }
    let anonymous = body.docs.is_some();

    let (company_name, company) = match body.company {
        Some(Owner::Name(name)) => (Some(name), Company::default()),
        Some(Owner::Record(record)) => (record.name.clone(), record),
        None => (None, Company::default()),
    };
    let (asn, as_name, as_record) = match body.asn {
        Some(AsnField::Text(text)) => {
            let (asn, name) = split_asn_text(&text);
            (asn, name, AsnRecord::default())
        }
        Some(AsnField::Record(record)) => (
            record.asn.filter(|n| *n > 0).map(|n| format!("AS{n}")),
            record.org.clone().or_else(|| record.descr.clone()),
            record,
        ),
        None => (None, None, AsnRecord::default()),
    };
    let location = body.location.unwrap_or_default();
    let country = known(location.country.as_deref()).or(known(body.country.as_deref()));
    let region = known(location.state.as_deref()).or(known(body.region.as_deref()));
    let city = known(location.city.as_deref()).or(known(body.city.as_deref()));
    let timezone = known(location.timezone.as_deref()).or(known(body.timezone.as_deref()));
    let position = location
        .latitude
        .zip(location.longitude)
        .or(body.lat.zip(body.lon))
        .and_then(|(lat, lon)| canonical_coordinates(&format!("{lat},{lon}")));

    let crawler = match body.is_crawler.as_ref() {
        Some(Value::String(name)) if !name.trim().is_empty() && name != "false" => {
            Some(name.trim().to_owned())
        }
        _ => None,
    };
    let datacenter = truthy(body.is_datacenter.as_ref());
    let vpn = truthy(body.is_vpn.as_ref());
    let proxy = truthy(body.is_proxy.as_ref());
    let tor = truthy(body.is_tor.as_ref());
    let abuser = truthy(body.is_abuser.as_ref());
    let mut flags: Vec<&str> = [
        (datacenter, "datacenter"),
        (vpn, "vpn"),
        (proxy, "proxy"),
        (tor, "tor"),
        (abuser, "abuser"),
        (truthy(body.is_mobile.as_ref()), "mobile"),
        (truthy(body.is_satellite.as_ref()), "satellite"),
        (truthy(body.is_anycast.as_ref()), "anycast"),
    ]
    .into_iter()
    .filter_map(|(set, name)| set.then_some(name))
    .collect();
    if crawler.is_some() {
        flags.push("crawler");
    }

    let owner = known(company_name.as_deref())
        .or(known(as_name.as_deref()))
        .unwrap_or("owner not given");
    let mut summary = format!("ipapi.is: {owner}");
    if let Some(asn) = asn.as_deref() {
        summary.push_str(&format!(" ({asn})"));
    }
    if !flags.is_empty() {
        summary.push_str(&format!(" — {}", flags.join(", ")));
    }

    let hosting = body.datacenter.unwrap_or_default();
    let egress = body.egress_service.unwrap_or_default();
    let abuse = body.abuse.unwrap_or_default();
    let mut finding = Finding::new(summary)
        .attr(
            "detection",
            if anonymous { "not_checked" } else { "checked" },
        )
        .opt_attr("rir", known(body.rir.as_deref()))
        .opt_attr("company", known(company_name.as_deref()))
        .opt_attr("company_domain", known(company.domain.as_deref()))
        .opt_attr("company_type", known(company.kind.as_deref()))
        .opt_attr("company_network", known(company.network.as_deref()))
        .opt_attr(
            "company_abuser_score",
            known(company.abuser_score.as_deref()),
        )
        .opt_attr("asn", asn.as_deref())
        .opt_attr("as_name", known(as_name.as_deref()))
        .opt_attr("as_route", known(as_record.route.as_deref()))
        .opt_attr("as_domain", known(as_record.domain.as_deref()))
        .opt_attr("as_type", known(as_record.kind.as_deref()))
        .opt_attr("hosting_provider", known(hosting.datacenter.as_deref()))
        .opt_attr("hosting_domain", known(hosting.domain.as_deref()))
        .opt_attr("hosting_network", known(hosting.network.as_deref()))
        .opt_attr(
            "vpn_service",
            body.vpn.as_ref().and_then(|v| known(v.service.as_deref())),
        )
        .opt_attr("egress_service", known(egress.provider.as_deref()))
        .opt_attr("egress_type", known(egress.kind.as_deref()))
        .opt_attr("crawler", crawler.as_deref())
        .opt_attr("abuse_contact_name", known(abuse.name.as_deref()))
        .opt_attr("abuse_contact_email", known(abuse.email.as_deref()))
        .opt_attr("country", country)
        .opt_attr("country_code", known(location.country_code.as_deref()))
        .opt_attr("region", region)
        .opt_attr("city", city)
        .opt_attr("timezone", timezone)
        .tag_if(vpn, "vpn")
        .tag_if(proxy, "proxy")
        .tag_if(tor, tags::TOR_EXIT)
        .tag_if(abuser, "suspicious")
        .tag_if(truthy(body.is_anycast.as_ref()), "anycast");
    if !flags.is_empty() {
        finding = finding.list_attr("flags", &flags);
    }
    if let Some(asn) = asn.as_deref() {
        finding = finding.pivot(
            PivotKind::Asn,
            asn,
            "Origin AS ipapi.is gives for the address",
        );
    }
    if let Some(name) = known(company_name.as_deref()) {
        finding = finding.pivot(
            PivotKind::Organisation,
            name,
            "Organisation ipapi.is says the address is registered to",
        );
    }
    if let Some(domain) = known(company.domain.as_deref()) {
        finding = finding.pivot(
            PivotKind::Domain,
            domain,
            "Domain of the organisation ipapi.is says holds the address",
        );
    }
    if let Some(provider) = known(hosting.domain.as_deref()) {
        finding = finding.pivot(
            PivotKind::Domain,
            provider,
            "Hosting provider ipapi.is says serves the address",
        );
    }
    if let Some(position) = position {
        finding = finding.attr("coordinates", &position).pivot(
            PivotKind::Coordinates,
            position,
            "Position ipapi.is gives for the address",
        );
    }
    Ok(Some(finding))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr<'a>(finding: &'a Finding, key: &str) -> Option<&'a str> {
        finding
            .attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The keyless answer, as `api.ipapi.is/?q=8.8.8.8` returned it on 2026-11-08.
    const ANONYMOUS: &[u8] = br#"{"ip":"8.8.8.8","is_bogon":false,"company":"Google LLC","asn":"AS15169 Google LLC","city":"Mountain View","region":"California","country":"United States","lat":37.38605,"lon":-122.08385,"timezone":"America/Los_Angeles","docs":"https://ipapi.is/free-tier.html?ref=api"}"#;

    /// The keyed example answer from the ipapi.is documentation.
    const KEYED: &[u8] = br#"{"ip":"107.174.138.172","rir":"ARIN","is_bogon":false,"is_mobile":false,"is_satellite":false,"is_anycast":false,"is_crawler":false,"is_datacenter":true,"is_tor":true,"is_proxy":false,"is_vpn":false,"is_abuser":true,"datacenter":{"datacenter":"HostPapa","domain":"hostpapa.com","network":"107.172.0.0 - 107.175.255.255"},"company":{"name":"VPS ACE","abuser_score":"0.1016 (High)","domain":"vpsace.com","type":"business","network":"107.174.138.128 - 107.174.138.255","netname":"CC-107-174-138-0-25"},"abuse":{"name":"VPS ACE","address":"350 Main Street, Buffalo, NY, 14202, US","email":"support@vpsace.com","phone":"+1-855-587-7223"},"asn":{"asn":36352,"abuser_score":"0.0374 (High)","route":"107.174.138.0/24","descr":"AS-COLOCROSSING - HostPapa, US","country":"us","active":true,"org":"HostPapa","domain":"hostpapa.com","abuse":"net-abuse-global@hostpapa.com","type":"hosting","created":"2005-12-12","updated":"2024-01-04","rir":"ARIN"},"location":{"is_eu_member":false,"calling_code":"1","currency_code":"USD","continent":"NA","country":"United States","country_code":"US","state":"New York","city":"Buffalo","latitude":42.88645,"longitude":-78.87837,"zip":"14205","timezone":"America/New_York","accuracy":"VERY_HIGH"},"elapsed_ms":0.05}"#;

    #[test]
    fn keyless_answer_records_owner_and_location_but_never_claims_clean() {
        let finding = decode(ANONYMOUS, "8.8.8.8").unwrap().unwrap();
        assert_eq!(attr(&finding, "detection"), Some("not_checked"));
        assert_eq!(attr(&finding, "company"), Some("Google LLC"));
        assert_eq!(attr(&finding, "asn"), Some("AS15169"));
        assert_eq!(attr(&finding, "as_name"), Some("Google LLC"));
        assert_eq!(attr(&finding, "city"), Some("Mountain View"));
        assert_eq!(attr(&finding, "region"), Some("California"));
        assert!(attr(&finding, "flags").is_none());
        assert!(finding.tags.is_empty(), "{:?}", finding.tags);
        assert!(
            finding
                .pivots
                .iter()
                .any(|p| p.kind == PivotKind::Asn && p.value == "AS15169")
        );
        assert!(
            finding
                .pivots
                .iter()
                .any(|p| p.kind == PivotKind::Coordinates)
        );
    }

    #[test]
    fn keyed_answer_carries_hosting_tor_and_abuse_signals() {
        let finding = decode(KEYED, "107.174.138.172").unwrap().unwrap();
        assert_eq!(attr(&finding, "detection"), Some("checked"));
        assert_eq!(attr(&finding, "flags"), Some("datacenter,tor,abuser"));
        assert!(finding.tags.contains(&tags::TOR_EXIT));
        assert!(finding.tags.contains(&"suspicious"));
        assert!(!finding.tags.contains(&"vpn"));
        assert_eq!(attr(&finding, "asn"), Some("AS36352"));
        assert_eq!(attr(&finding, "as_route"), Some("107.174.138.0/24"));
        assert_eq!(attr(&finding, "hosting_provider"), Some("HostPapa"));
        assert_eq!(attr(&finding, "company"), Some("VPS ACE"));
        assert_eq!(
            attr(&finding, "abuse_contact_email"),
            Some("support@vpsace.com")
        );
        assert_eq!(attr(&finding, "country_code"), Some("US"));
        assert!(
            finding
                .pivots
                .iter()
                .any(|p| p.kind == PivotKind::Domain && p.value == "hostpapa.com")
        );
        assert!(
            finding
                .pivots
                .iter()
                .any(|p| p.kind == PivotKind::Organisation && p.value == "VPS ACE")
        );
    }

    #[test]
    fn truthy_vpn_record_and_named_crawler_are_flags() {
        let body = br#"{"ip":"187.13.12.227","is_vpn":{"service":"NordVPN"},"is_crawler":"GoogleBot","vpn":{"service":"NordVPN"},"company":{"name":"x"},"location":null}"#;
        let finding = decode(body, "187.13.12.227").unwrap().unwrap();
        assert!(finding.tags.contains(&"vpn"));
        assert_eq!(attr(&finding, "vpn_service"), Some("NordVPN"));
        assert_eq!(attr(&finding, "crawler"), Some("GoogleBot"));
        assert_eq!(attr(&finding, "flags"), Some("vpn,crawler"));
    }

    #[test]
    fn bogon_is_a_valid_zero() {
        let body = br#"{"ip":"10.0.0.1","rir":null,"is_bogon":true}"#;
        assert_eq!(decode(body, "10.0.0.1"), Ok(None));
    }

    #[test]
    fn rejects_another_address_bad_json_and_error_bodies() {
        assert!(decode(ANONYMOUS, "1.1.1.1").is_err());
        assert!(decode(b"not json", "8.8.8.8").is_err());
        let error =
            br#"{"error":"Invalid IP Address or AS Number","error_code":"ERR_INVALID_IP_OR_ASN"}"#;
        assert!(decode(error, "8.8.8.8").is_err());
    }

    #[test]
    fn ipv6_equivalent_spellings_match() {
        let body = br#"{"ip":"2001:4860:4860::8888","company":"Google LLC"}"#;
        assert!(decode(body, "2001:4860:4860:0:0:0:0:8888").is_ok());
    }

    #[test]
    fn asn_text_splits_number_and_name() {
        assert_eq!(
            split_asn_text("AS12322 Free SAS"),
            (Some("AS12322".into()), Some("Free SAS".into()))
        );
        assert_eq!(split_asn_text("AS15169"), (Some("AS15169".into()), None));
        assert_eq!(
            split_asn_text("Unknown Net"),
            (None, Some("Unknown Net".into()))
        );
    }

    #[test]
    fn key_is_optional_and_never_in_the_url() {
        let empty = Keys::parse("").expect("empty key file");
        assert!(API.wanted(&empty));
        assert!(!API.key.expect("optional key").required);
        assert_eq!(url("8.8.8.8"), "https://api.ipapi.is/?q=8.8.8.8");
    }
}
