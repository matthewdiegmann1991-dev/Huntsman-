//! Bluetooth LE advertisement decoding, offline, from the bytes a scanner shows.
//!
//! An advertisement and its scan response are a sequence of AD structures, each a length byte,
//! a type byte and that many data bytes less one (Core Specification Vol. 3, Part C, 11, and the
//! Supplement, Part A). This decoder reads the types an operator meets: flags, service UUID
//! lists, the local name, TX power, appearance, service data and manufacturer-specific data,
//! whose first two bytes are a Bluetooth SIG company identifier ([`crate::bt_company`]). The
//! bytes come as one or more hex strings (a whole payload, or `TYPE:DATA` fragments as some
//! scanner apps list them), never from a radio: nothing here scans, and nothing identifies a
//! person. A local name is a label the owner typed, a company is who registered the identifier
//! (the firmware's or the app's maker), and a manufacturer payload is shown only by its length
//! unless the operator asks for it, because such payloads carry rotating identifiers and
//! application data.

use serde::{Deserialize, Serialize};

use crate::ble_address::{self, BleAddressKind};
use crate::bt_company;
use crate::oui;

/// The most hex an operator can hand the decoder: a legacy advertisement and scan response are
/// 31 bytes each, an extended advertisement at most 1,650.
pub const MAX_ADVERTISEMENT_BYTES: usize = 4096;
/// The most hex strings one decode request takes.
pub const MAX_DECODE_TOKENS: usize = 64;
/// The most characters one hex string may have.
pub const MAX_DECODE_TOKEN_CHARS: usize = 8192;

/// One decode request as the MCP `ble_decode` tool and `POST /api/ble/decode` take it: the hex
/// strings in order, the device address if the scanner showed it, and whether payload bytes are
/// wanted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeRequest {
    pub bytes: Vec<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub raw: bool,
}

/// Decodes a request: bounds its strings, then [`parse_hex_tokens`], [`decode`] and, with an
/// address, [`with_address`]. **Pure.**
///
/// # Errors
/// No strings, too many, one too long or empty, or what the decoder refuses, in words.
pub fn decode_request(request: &DecodeRequest) -> Result<BleAdvReport, String> {
    if request.bytes.is_empty() || request.bytes.len() > MAX_DECODE_TOKENS {
        return Err(format!("bytes must hold 1 to {MAX_DECODE_TOKENS} strings"));
    }
    let mut tokens = Vec::with_capacity(request.bytes.len());
    for text in &request.bytes {
        let text = text.trim();
        if text.is_empty() || text.len() > MAX_DECODE_TOKEN_CHARS {
            return Err(format!(
                "each of bytes must be 1 to {MAX_DECODE_TOKEN_CHARS} characters"
            ));
        }
        tokens.push(text.to_owned());
    }
    let report = decode(&parse_hex_tokens(&tokens)?, request.raw)?;
    match request.address.as_deref().map(str::trim) {
        Some(address) if !address.is_empty() => with_address(report, address),
        _ => Ok(report),
    }
}

/// One AD structure as it appeared, by type and length, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdStructure {
    pub ad_type: u8,
    pub kind: &'static str,
    pub data_bytes: usize,
}

/// The Flags AD structure: the byte, and the names of the bits set in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flags {
    pub raw: u8,
    pub set: Vec<&'static str>,
}

/// The Flags bits, lowest first (Supplement, Part A, 1.3).
const FLAG_BITS: [&str; 5] = [
    "le_limited_discoverable",
    "le_general_discoverable",
    "br_edr_not_supported",
    "simultaneous_le_bredr_controller",
    "simultaneous_le_bredr_host",
];

/// A service UUID the advertisement listed, with a well-known name where the engine has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceUuid {
    pub uuid: String,
    pub service: Option<&'static str>,
    pub complete_list: bool,
}

/// Manufacturer-specific data: the company identifier and who it is assigned to, and the
/// payload's length; the payload itself only on request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManufacturerData {
    pub company_id: String,
    pub company: Option<&'static str>,
    pub payload_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hex: Option<String>,
}

/// Service data: the 16-bit service it belongs to and the data's length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceData {
    pub uuid: String,
    pub service: Option<&'static str>,
    pub data_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_hex: Option<String>,
}

/// The Appearance value and its category (its top ten bits).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Appearance {
    pub raw: u16,
    pub category: &'static str,
}

/// The device address the operator gave, read as a Bluetooth LE address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressReading {
    pub address: String,
    pub kind: &'static str,
    pub persistence: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<&'static str>,
}

/// Everything the bytes said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BleAdvReport {
    pub source: &'static str,
    pub input_bytes: usize,
    pub structures: Vec<AdStructure>,
    pub flags: Option<Flags>,
    pub local_name: Option<String>,
    pub local_name_complete: Option<bool>,
    pub service_uuids: Vec<ServiceUuid>,
    pub manufacturer: Vec<ManufacturerData>,
    pub tx_power_dbm: Option<i8>,
    pub appearance: Option<Appearance>,
    pub service_data: Vec<ServiceData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressReading>,
    pub notes: Vec<String>,
}

/// The AD type's name (Supplement, Part A; assigned numbers "Common Data Types"). **Pure.**
#[must_use]
pub const fn ad_type_name(ad_type: u8) -> &'static str {
    match ad_type {
        0x01 => "Flags",
        0x02 => "Incomplete List of 16-bit Service UUIDs",
        0x03 => "Complete List of 16-bit Service UUIDs",
        0x04 => "Incomplete List of 32-bit Service UUIDs",
        0x05 => "Complete List of 32-bit Service UUIDs",
        0x06 => "Incomplete List of 128-bit Service UUIDs",
        0x07 => "Complete List of 128-bit Service UUIDs",
        0x08 => "Shortened Local Name",
        0x09 => "Complete Local Name",
        0x0A => "Tx Power Level",
        0x0D => "Class of Device",
        0x10 => "Device ID",
        0x12 => "Peripheral Connection Interval Range",
        0x14 => "List of 16-bit Service Solicitation UUIDs",
        0x15 => "List of 128-bit Service Solicitation UUIDs",
        0x16 => "Service Data - 16-bit UUID",
        0x17 => "Public Target Address",
        0x18 => "Random Target Address",
        0x19 => "Appearance",
        0x1A => "Advertising Interval",
        0x1B => "LE Bluetooth Device Address",
        0x1C => "LE Role",
        0x20 => "Service Data - 32-bit UUID",
        0x21 => "Service Data - 128-bit UUID",
        0x24 => "URI",
        0x30 => "Broadcast Name",
        0x3D => "3D Information Data",
        0xFF => "Manufacturer Specific Data",
        _ => "unknown",
    }
}

/// The SIG's name for an assigned 16-bit UUID ([`crate::bt_uuid`]): a standard service's name,
/// or the company a member UUID is assigned to. Any other is shown by its value alone. **Pure.**
#[must_use]
pub fn service_name(uuid: u16) -> Option<&'static str> {
    crate::bt_uuid::name(uuid)
}

/// The Appearance category named by a value's top ten bits (assigned numbers "Appearance
/// Values"). **Pure.**
#[must_use]
pub const fn appearance_category(raw: u16) -> &'static str {
    match raw >> 6 {
        0x000 => "Unknown",
        0x001 => "Phone",
        0x002 => "Computer",
        0x003 => "Watch",
        0x004 => "Clock",
        0x005 => "Display",
        0x006 => "Remote Control",
        0x007 => "Eyeglasses",
        0x008 => "Tag",
        0x009 => "Keyring",
        0x00A => "Media Player",
        0x00B => "Barcode Scanner",
        0x00C => "Thermometer",
        0x00D => "Heart Rate Sensor",
        0x00E => "Blood Pressure",
        0x00F => "Human Interface Device",
        0x010 => "Glucose Meter",
        0x011 => "Running Walking Sensor",
        0x012 => "Cycling",
        0x013 => "Control Device",
        0x014 => "Network Device",
        0x015 => "Sensor",
        0x016 => "Light Fixtures",
        0x017 => "Fan",
        0x018 => "HVAC",
        0x019 => "Air Conditioning",
        0x01A => "Humidifier",
        0x01B => "Heating",
        0x01C => "Access Control",
        0x01D => "Motorized Device",
        0x01E => "Power Device",
        0x01F => "Light Source",
        0x020 => "Window Covering",
        0x021 => "Audio Sink",
        0x022 => "Audio Source",
        0x023 => "Motorized Vehicle",
        0x024 => "Domestic Appliance",
        0x025 => "Wearable Audio Device",
        0x026 => "Aircraft",
        0x027 => "AV Equipment",
        0x028 => "Display Equipment",
        0x029 => "Hearing Aid",
        0x02A => "Gaming",
        0x02B => "Signage",
        0x031 => "Pulse Oximeter",
        0x032 => "Weight Scale",
        0x033 => "Personal Mobility Device",
        0x034 => "Continuous Glucose Monitor",
        0x035 => "Insulin Pump",
        0x036 => "Medication Delivery",
        0x037 => "Spirometer",
        0x051 => "Outdoor Sports Activity",
        _ => "unassigned",
    }
}

fn hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '-' | '\t'))
        .collect();
    if digits.is_empty() {
        return Err("no hex digits".to_owned());
    }
    if !digits.len().is_multiple_of(2) {
        return Err(format!("{} hex digits: an odd number", digits.len()));
    }
    if let Some(bad) = digits.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("{bad:?} is not a hex digit"));
    }
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// The bytes the tokens describe, as AD structures: each token is a whole payload in hex, or a
/// `TYPE:DATA` fragment (`ff:7500...`) that becomes one structure. Tokens follow each other, so
/// an advertisement and its scan response can be given as two. **Pure.**
///
/// # Errors
/// A token that is not hex, a fragment whose type is not one byte, or more than
/// [`MAX_ADVERTISEMENT_BYTES`] in all.
pub fn parse_hex_tokens(tokens: &[String]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let fragment = token
            .split_once(':')
            .filter(|(kind, _)| kind.len() == 2 && kind.chars().all(|c| c.is_ascii_hexdigit()));
        if let Some((kind, data)) = fragment {
            let ad_type = u8::from_str_radix(kind, 16).map_err(|e| e.to_string())?;
            // A scanner lists a structure with no data as its type alone (`02:`).
            let data = if data.trim().is_empty() {
                Vec::new()
            } else {
                hex_bytes(data).map_err(|e| format!("token {}: {e}", index + 1))?
            };
            let length = u8::try_from(data.len() + 1)
                .map_err(|_| format!("token {}: a fragment holds at most 254 bytes", index + 1))?;
            out.push(length);
            out.push(ad_type);
            out.extend_from_slice(&data);
        } else {
            out.extend(hex_bytes(token).map_err(|e| format!("token {}: {e}", index + 1))?);
        }
        if out.len() > MAX_ADVERTISEMENT_BYTES {
            return Err(format!("more than {MAX_ADVERTISEMENT_BYTES} bytes"));
        }
    }
    if out.is_empty() {
        return Err("no bytes".to_owned());
    }
    Ok(out)
}

fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// A 128-bit UUID as the bytes carry it (little-endian), written the usual way. **Pure.**
fn uuid128(bytes: &[u8]) -> String {
    let mut reversed: Vec<u8> = bytes.to_vec();
    reversed.reverse();
    let hex = hex_string(&reversed);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn read_flags(data: &[u8], report: &mut BleAdvReport) {
    let Some(&raw) = data.first() else {
        report.notes.push("Flags with no byte".to_owned());
        return;
    };
    report.flags = Some(Flags {
        raw,
        set: FLAG_BITS
            .iter()
            .enumerate()
            .filter(|(bit, _)| raw & (1 << bit) != 0)
            .map(|(_, name)| *name)
            .collect(),
    });
}

fn read_uuids(data: &[u8], width: usize, complete: bool, report: &mut BleAdvReport) {
    if !data.len().is_multiple_of(width) {
        report.notes.push(format!(
            "a {}-bit UUID list of {} bytes is not whole",
            width * 8,
            data.len()
        ));
    }
    for chunk in data.chunks_exact(width) {
        let (uuid, service) = match width {
            2 => {
                let value = u16::from_le_bytes([chunk[0], chunk[1]]);
                (format!("{value:04x}"), service_name(value))
            }
            4 => {
                let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                (format!("{value:08x}"), None)
            }
            _ => (uuid128(chunk), None),
        };
        report.service_uuids.push(ServiceUuid {
            uuid,
            service,
            complete_list: complete,
        });
    }
}

fn read_manufacturer(data: &[u8], raw: bool, report: &mut BleAdvReport) {
    let Some((id, company)) = bt_company::company_of_manufacturer_data(data) else {
        report
            .notes
            .push("Manufacturer Specific Data shorter than a company identifier".to_owned());
        return;
    };
    let payload = &data[2..];
    report.manufacturer.push(ManufacturerData {
        company_id: format!("{id:04x}"),
        company,
        payload_bytes: payload.len(),
        payload_hex: raw.then(|| hex_string(payload)),
    });
}

fn read_service_data(data: &[u8], raw: bool, report: &mut BleAdvReport) {
    if data.len() < 2 {
        report
            .notes
            .push("Service Data shorter than its UUID".to_owned());
        return;
    }
    let value = u16::from_le_bytes([data[0], data[1]]);
    report.service_data.push(ServiceData {
        uuid: format!("{value:04x}"),
        service: service_name(value),
        data_bytes: data.len() - 2,
        data_hex: raw.then(|| hex_string(&data[2..])),
    });
}

fn read_structure(ad_type: u8, data: &[u8], raw: bool, report: &mut BleAdvReport) {
    match ad_type {
        0x01 => read_flags(data, report),
        0x02 | 0x03 => read_uuids(data, 2, ad_type == 0x03, report),
        0x04 | 0x05 => read_uuids(data, 4, ad_type == 0x05, report),
        0x06 | 0x07 => read_uuids(data, 16, ad_type == 0x07, report),
        0x08 | 0x09 => {
            let name = String::from_utf8_lossy(data).into_owned();
            // A complete name outranks a shortened one; the latest of a kind wins.
            if ad_type == 0x09 || report.local_name_complete != Some(true) {
                report.local_name = Some(crate::textnorm::escape_controls(&name));
                report.local_name_complete = Some(ad_type == 0x09);
            }
        }
        0x0A => {
            if let Some(&level) = data.first() {
                report.tx_power_dbm = Some(i8::from_le_bytes([level]));
            }
        }
        0x16 => read_service_data(data, raw, report),
        0x19 => {
            if data.len() >= 2 {
                let value = u16::from_le_bytes([data[0], data[1]]);
                report.appearance = Some(Appearance {
                    raw: value,
                    category: appearance_category(value),
                });
            }
        }
        0xFF => read_manufacturer(data, raw, report),
        _ => {}
    }
}

/// Decodes AD structures. A zero length ends the data (padding); a structure that runs past the
/// end is an error, because the bytes were cut. With `raw`, manufacturer and service payloads are
/// included in hex. **Pure.**
///
/// # Errors
/// Empty input, more than [`MAX_ADVERTISEMENT_BYTES`], or a truncated structure.
pub fn decode(bytes: &[u8], raw: bool) -> Result<BleAdvReport, String> {
    if bytes.is_empty() {
        return Err("no bytes".to_owned());
    }
    if bytes.len() > MAX_ADVERTISEMENT_BYTES {
        return Err(format!("more than {MAX_ADVERTISEMENT_BYTES} bytes"));
    }
    let mut report = BleAdvReport {
        source: "ble-adv",
        input_bytes: bytes.len(),
        structures: Vec::new(),
        flags: None,
        local_name: None,
        local_name_complete: None,
        service_uuids: Vec::new(),
        manufacturer: Vec::new(),
        tx_power_dbm: None,
        appearance: None,
        service_data: Vec::new(),
        address: None,
        notes: Vec::new(),
    };
    let mut at = 0;
    while at < bytes.len() {
        let length = bytes[at] as usize;
        if length == 0 {
            break;
        }
        let end = at + 1 + length;
        if end > bytes.len() {
            return Err(format!(
                "structure at byte {at} says {length} bytes but {} remain",
                bytes.len() - at - 1
            ));
        }
        let ad_type = bytes[at + 1];
        let data = &bytes[at + 2..end];
        report.structures.push(AdStructure {
            ad_type,
            kind: ad_type_name(ad_type),
            data_bytes: data.len(),
        });
        read_structure(ad_type, data, raw, &mut report);
        at = end;
    }
    if report.structures.is_empty() {
        return Err("no AD structure: the data begins with a zero length".to_owned());
    }
    Ok(report)
}

/// Adds the operator's device address, read as a Bluetooth LE address, to a report. **Pure.**
///
/// # Errors
/// An address that is not six octets.
pub fn with_address(mut report: BleAdvReport, address: &str) -> Result<BleAdvReport, String> {
    let info =
        oui::classify_mac(address).ok_or_else(|| format!("{address} is not a MAC address"))?;
    let vendor = (info.class != oui::DeviceClass::Randomized)
        .then(|| info.manufacturer())
        .flatten();
    let kind = ble_address::classify(address, vendor.is_some())
        .ok_or_else(|| format!("{address} is not a MAC address"))?;
    report.address = Some(AddressReading {
        address: address.to_ascii_lowercase(),
        kind: kind.name(),
        persistence: kind.persistence(),
        vendor: if kind == BleAddressKind::Public {
            vendor
        } else {
            None
        },
    });
    Ok(report)
}

/// The report as rows. **Pure.**
#[must_use]
pub fn render(report: &BleAdvReport) -> String {
    use std::fmt::Write as _;
    let mut out = format!(
        "source={}\tbytes={}\tstructures={}\n",
        report.source,
        report.input_bytes,
        report.structures.len()
    );
    for s in &report.structures {
        let _ = writeln!(
            out,
            "structure\t0x{:02x}\t{}\t{} bytes",
            s.ad_type, s.kind, s.data_bytes
        );
    }
    if let Some(flags) = &report.flags {
        let _ = writeln!(out, "flags\t0x{:02x}\t{}", flags.raw, flags.set.join(","));
    }
    if let Some(name) = &report.local_name {
        let _ = writeln!(
            out,
            "local_name\t{name}\tcomplete={}\ta label the owner typed, not an identity",
            report.local_name_complete.unwrap_or(false)
        );
    }
    for uuid in &report.service_uuids {
        let _ = writeln!(
            out,
            "service_uuid\t{}\t{}\tcomplete_list={}",
            uuid.uuid,
            uuid.service.unwrap_or(""),
            uuid.complete_list
        );
    }
    for m in &report.manufacturer {
        let _ = writeln!(
            out,
            "manufacturer\t0x{}\t{}\tpayload_bytes={}{}",
            m.company_id,
            m.company.unwrap_or("unassigned identifier"),
            m.payload_bytes,
            m.payload_hex
                .as_deref()
                .map_or(String::new(), |hex| format!("\tpayload={hex}"))
        );
    }
    for d in &report.service_data {
        let _ = writeln!(
            out,
            "service_data\t{}\t{}\tdata_bytes={}{}",
            d.uuid,
            d.service.unwrap_or(""),
            d.data_bytes,
            d.data_hex
                .as_deref()
                .map_or(String::new(), |hex| format!("\tdata={hex}"))
        );
    }
    if let Some(power) = report.tx_power_dbm {
        let _ = writeln!(out, "tx_power_dbm\t{power}");
    }
    if let Some(appearance) = &report.appearance {
        let _ = writeln!(
            out,
            "appearance\t0x{:04x}\t{}",
            appearance.raw, appearance.category
        );
    }
    if let Some(address) = &report.address {
        let _ = writeln!(
            out,
            "address\t{}\t{}\t{}{}",
            address.address,
            address.kind,
            address.persistence,
            address
                .vendor
                .map_or(String::new(), |vendor| format!("\tvendor={vendor}"))
        );
    }
    for note in &report.notes {
        let _ = writeln!(out, "note\t{note}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| (*t).to_owned()).collect()
    }

    /// Flags, a complete 16-bit UUID list (Battery), a complete local name, TX power, an
    /// appearance (a phone) and Samsung manufacturer data, as a phone might advertise them.
    const PAYLOAD: &str =
        "020106 03030f18 0c094572696b2773205332322b 020aff 03194000 0bff7500021861b10f3c908f";

    #[test]
    fn a_payload_decodes_every_structure_it_carries() {
        let bytes = parse_hex_tokens(&owned(&[PAYLOAD])).unwrap();
        let report = decode(&bytes, false).unwrap();
        let kinds: Vec<u8> = report.structures.iter().map(|s| s.ad_type).collect();
        assert_eq!(kinds, [0x01, 0x03, 0x09, 0x0A, 0x19, 0xFF]);
        let flags = report.flags.as_ref().unwrap();
        assert_eq!(flags.raw, 0x06);
        assert_eq!(
            flags.set,
            ["le_general_discoverable", "br_edr_not_supported"]
        );
        assert_eq!(report.local_name.as_deref(), Some("Erik's S22+"));
        assert_eq!(report.local_name_complete, Some(true));
        assert_eq!(report.service_uuids.len(), 1);
        assert_eq!(report.service_uuids[0].uuid, "180f");
        assert_eq!(report.service_uuids[0].service, Some("Battery"));
        assert!(report.service_uuids[0].complete_list);
        assert_eq!(report.tx_power_dbm, Some(-1));
        let appearance = report.appearance.as_ref().unwrap();
        assert_eq!((appearance.raw, appearance.category), (0x0040, "Phone"));
        assert_eq!(report.manufacturer.len(), 1);
        let samsung = &report.manufacturer[0];
        assert_eq!(samsung.company_id, "0075");
        assert_eq!(samsung.company, Some("Samsung Electronics Co. Ltd."));
        assert_eq!(samsung.payload_bytes, 8);
        assert_eq!(
            samsung.payload_hex, None,
            "payloads are shown only on request"
        );
        let raw = decode(&bytes, true).unwrap();
        assert_eq!(
            raw.manufacturer[0].payload_hex.as_deref(),
            Some("021861b10f3c908f")
        );
        assert!(report.notes.is_empty(), "{:?}", report.notes);
        let text = render(&report);
        assert!(
            text.contains("manufacturer\t0x0075\tSamsung Electronics Co. Ltd.\tpayload_bytes=8")
        );
        assert!(text.contains("local_name\tErik's S22+\tcomplete=true"));
        assert!(text.contains("appearance\t0x0040\tPhone"));
    }

    #[test]
    fn fragments_as_a_scanner_lists_them_decode_like_a_payload() {
        // The user's scanner listed the type and the data, no length: `0xFF` then the bytes.
        let bytes = parse_hex_tokens(&owned(&[
            "01:06",
            "ff:7500021861B10F3C908FD6B6C2309A2F4F5604AE24545B5A363A",
            "FF:750093F67DCFC4FF",
        ]))
        .unwrap();
        let report = decode(&bytes, false).unwrap();
        assert_eq!(report.structures.len(), 3);
        assert_eq!(report.manufacturer.len(), 2);
        assert!(
            report
                .manufacturer
                .iter()
                .all(|m| m.company == Some("Samsung Electronics Co. Ltd."))
        );
        assert_eq!(report.manufacturer[0].payload_bytes, 24);
        assert_eq!(report.manufacturer[1].payload_bytes, 6);
        // A 128-bit UUID list is written the usual way, and a shortened name yields to a
        // complete one whatever the order.
        let bytes = parse_hex_tokens(&owned(&[
            "07:9ecadc240ee5a9e093f3a3b50100406e",
            "09:4e616d65",
            "08:4e61",
        ]))
        .unwrap();
        let report = decode(&bytes, false).unwrap();
        assert_eq!(
            report.service_uuids[0].uuid,
            "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
        );
        assert_eq!(report.local_name.as_deref(), Some("Name"));
        // A member UUID names the company it is assigned to; an unassigned one has no name.
        let bytes = parse_hex_tokens(&owned(&["03:5afdaafe3412"])).unwrap();
        let report = decode(&bytes, false).unwrap();
        let named: Vec<(&str, Option<&str>)> = report
            .service_uuids
            .iter()
            .map(|u| (u.uuid.as_str(), u.service))
            .collect();
        assert_eq!(
            named,
            [
                ("fd5a", Some("Samsung Electronics Co., Ltd.")),
                ("feaa", Some("Google LLC")),
                ("1234", None)
            ]
        );
    }

    #[test]
    fn cut_or_malformed_bytes_are_refused_with_the_reason() {
        assert!(
            decode(&[0x05, 0x09, 0x41], false)
                .unwrap_err()
                .contains("says 5 bytes")
        );
        assert!(decode(&[0x00], false).unwrap_err().contains("zero length"));
        assert!(decode(&[], false).is_err());
        assert!(
            parse_hex_tokens(&owned(&["zz"]))
                .unwrap_err()
                .contains("not a hex digit")
        );
        assert!(
            parse_hex_tokens(&owned(&["abc"]))
                .unwrap_err()
                .contains("odd")
        );
        // A fragment with no data is a structure of its type alone, as a scanner lists one.
        let typed_only = parse_hex_tokens(&owned(&["02:", "01:06"])).unwrap();
        assert_eq!(typed_only, [0x01, 0x02, 0x02, 0x01, 0x06]);
        assert_eq!(decode(&typed_only, false).unwrap().structures.len(), 2);
        assert!(parse_hex_tokens(&owned(&[])).is_err());
        let big = "ff".repeat(MAX_ADVERTISEMENT_BYTES + 1);
        assert!(
            parse_hex_tokens(&owned(&[&big]))
                .unwrap_err()
                .contains("more than")
        );
        // An unassigned company identifier is reported as such, not invented.
        let report = decode(&[0x03, 0xFF, 0xFF, 0xFF], false).unwrap();
        assert_eq!(report.manufacturer[0].company, None);
        assert!(render(&report).contains("unassigned identifier"));
    }

    #[test]
    fn a_request_is_bounded_and_decoded_the_same_way() {
        let request = DecodeRequest {
            bytes: vec![" 01:06 ".into(), "ff:750093f6".into()],
            address: Some("67:06:21:95:C1:7C".into()),
            raw: true,
        };
        let report = decode_request(&request).unwrap();
        assert_eq!(
            report.manufacturer[0].company,
            Some("Samsung Electronics Co. Ltd.")
        );
        assert_eq!(report.manufacturer[0].payload_hex.as_deref(), Some("93f6"));
        assert_eq!(report.address.as_ref().unwrap().kind, "resolvable_private");
        let empty = DecodeRequest {
            bytes: Vec::new(),
            address: None,
            raw: false,
        };
        assert!(decode_request(&empty).unwrap_err().contains("1 to"));
        let blank = DecodeRequest {
            bytes: vec!["   ".into()],
            address: None,
            raw: false,
        };
        assert!(decode_request(&blank).is_err());
        let too_many = DecodeRequest {
            bytes: vec!["01:06".into(); MAX_DECODE_TOKENS + 1],
            address: None,
            raw: false,
        };
        assert!(decode_request(&too_many).is_err());
        // The JSON shape the web route and the MCP tool read; an unknown field is refused.
        let parsed: DecodeRequest =
            serde_json::from_str(r#"{"bytes":["020106"],"address":"67:06:21:95:C1:7C"}"#).unwrap();
        assert!(!parsed.raw);
        assert!(serde_json::from_str::<DecodeRequest>(r#"{"bytes":["020106"],"x":1}"#).is_err());
    }

    #[test]
    fn the_address_is_read_as_a_bluetooth_le_address() {
        let bytes = parse_hex_tokens(&owned(&["020106"])).unwrap();
        let report = with_address(decode(&bytes, false).unwrap(), "67:06:21:95:C1:7C").unwrap();
        let address = report.address.unwrap();
        assert_eq!(address.kind, "resolvable_private");
        assert!(
            address
                .persistence
                .contains("does not identify the device later")
        );
        assert_eq!(address.vendor, None);
        assert!(with_address(decode(&bytes, false).unwrap(), "not-an-address").is_err());
    }
}
