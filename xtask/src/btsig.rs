//! The Bluetooth SIG's 16-bit assigned numbers, packed for `huntsman_recon::bt_company` and
//! `huntsman_recon::bt_uuid`. `btsig pack` builds `src/bt_company.bin` from the SIG's company
//! identifier listing
//! (<https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml>),
//! `btsig pack-uuids` builds `src/bt_uuid.bin` from its service and member UUID listings
//! (`assigned_numbers/uuids/service_uuids.yaml` and `member_uuids.yaml`, merged), and `btsig dump`
//! lists a blob, so a refresh is one command and two blobs can be diffed.
//!
//! The layout, little-endian throughout: the magic `HSEBTC\x01\x00`; the identifier count as a
//! u32 and a reserved u32 of zero; the 16-bit identifiers as u16, strictly ascending; zero padding
//! to a multiple of four; `count + 1` u32 byte offsets into the name blob; the UTF-8 names,
//! concatenated. The same identifiers always pack to the same bytes, and
//! `xtask/tests/btsig_pack.rs` proves the committed blob is what `pack` makes of its own `dump`.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use crate::error::{self, Error, Result};

const USAGE: &str = "usage: cargo run --locked -p xtask -- btsig <pack YAML OUT|pack-uuids OUT YAML...|dump BIN>
  pack YAML OUT         pack the Bluetooth SIG company identifiers YAML
                        (https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml)
                        into OUT, the blob src/bt_company.bin embeds
  pack-uuids OUT YAML...  pack the SIG's 16-bit UUID listings (assigned_numbers/uuids/service_uuids.yaml
                        and member_uuids.yaml), merged, into OUT, the blob src/bt_uuid.bin embeds
  dump BIN              print a blob's entries, one `ID<TAB>NAME` line each, id as four hex digits";

const MAGIC: &[u8; 8] = b"HSEBTC\x01\x00";
const HEADER: usize = 16;

/// One identifier: a 16-bit company identifier and the company's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Company {
    pub id: u16,
    pub name: String,
}

#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let outcome = match args {
        [command, yaml, out] if command == "pack" => pack_file(Path::new(yaml), Path::new(out)),
        [command, out, yamls @ ..] if command == "pack-uuids" && !yamls.is_empty() => {
            pack_uuid_files(Path::new(out), yamls)
        }
        [command, bin] if command == "dump" => dump_file(Path::new(bin)),
        _ => return error::usage(USAGE),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(problem) => error::report("xtask btsig", &problem),
    }
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn text_of(yaml: &Path) -> Result<String> {
    String::from_utf8(read(yaml)?)
        .map_err(|_| Error::Invalid(format!("{}: not UTF-8", yaml.display())))
}

fn pack_file(yaml: &Path, out: &Path) -> Result<()> {
    let companies = companies_from_yaml(&text_of(yaml)?)?;
    let blob = pack(&companies)?;
    fs::write(out, &blob).map_err(|source| Error::Io {
        path: out.to_path_buf(),
        source,
    })?;
    println!(
        "{}: {} identifiers, {} bytes",
        out.display(),
        companies.len(),
        blob.len()
    );
    Ok(())
}

/// Packs the SIG's 16-bit UUID listings, merged: a UUID in two files is refused.
fn pack_uuid_files(out: &Path, yamls: &[String]) -> Result<()> {
    let mut entries = Vec::new();
    for yaml in yamls {
        entries.extend(entries_from_yaml(&text_of(Path::new(yaml))?, "uuid")?);
    }
    entries.sort_by_key(|entry| entry.id);
    for pair in entries.windows(2) {
        if pair[0].id == pair[1].id {
            return Err(Error::Invalid(format!(
                "{:04X} is listed twice ({:?} and {:?})",
                pair[0].id, pair[0].name, pair[1].name
            )));
        }
    }
    let blob = pack(&entries)?;
    fs::write(out, &blob).map_err(|source| Error::Io {
        path: out.to_path_buf(),
        source,
    })?;
    println!(
        "{}: {} UUIDs, {} bytes",
        out.display(),
        entries.len(),
        blob.len()
    );
    Ok(())
}

fn dump_file(bin: &Path) -> Result<()> {
    let mut listing = String::new();
    for company in decode(&read(bin)?)? {
        let _ = writeln!(listing, "{:04X}\t{}", company.id, company.name);
    }
    print!("{listing}");
    Ok(())
}

/// A YAML scalar as the listing writes names: single-quoted with `''` for a quote, double-quoted
/// with `\"` and `\\` escapes, or bare. **Pure.**
fn scalar(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if let Some(inner) = raw
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    {
        return Ok(inner.replace("''", "'"));
    }
    if let Some(inner) = raw
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some(other) => {
                        return Err(Error::Invalid(format!("unknown escape \\{other} in {raw}")));
                    }
                    None => return Err(Error::Invalid(format!("dangling escape in {raw}"))),
                }
            } else {
                out.push(c);
            }
        }
        return Ok(out);
    }
    if raw.starts_with('\'') || raw.starts_with('"') {
        return Err(Error::Invalid(format!("unterminated quote in {raw}")));
    }
    Ok(raw.to_owned())
}

/// Reads the SIG's company identifier listing (`- value: 0xNNNN` items).
pub fn companies_from_yaml(text: &str) -> Result<Vec<Company>> {
    entries_from_yaml(text, "value")
}

/// Reads a SIG listing: `- KEY: 0xNNNN` lines each followed by a `name:` line, under one
/// top-level heading. Entries come out ascending; a repeated identifier, an empty name or a stray
/// line is refused.
pub fn entries_from_yaml(text: &str, key: &str) -> Result<Vec<Company>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let item = format!("- {key}:");
    let mut companies: Vec<Company> = Vec::new();
    let mut pending: Option<u16> = None;
    for (number, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        let heading = trimmed.ends_with(':')
            && trimmed[..trimmed.len() - 1]
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_');
        // The UUID listings also carry each entry's textual `id:` (org.bluetooth.service.gap),
        // which the blob does not keep.
        if trimmed.is_empty() || trimmed.starts_with('#') || heading || trimmed.starts_with("id:") {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix(item.as_str()) {
            if pending.is_some() {
                return Err(Error::Invalid(format!(
                    "line {}: a value without a name",
                    number
                )));
            }
            let value = value.trim();
            let digits = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .ok_or_else(|| {
                    Error::Invalid(format!("line {}: {value} is not 0xNNNN", number + 1))
                })?;
            let id = u16::from_str_radix(digits, 16).map_err(|_| {
                Error::Invalid(format!("line {}: {value} is not 0xNNNN", number + 1))
            })?;
            pending = Some(id);
        } else if let Some(name) = trimmed.strip_prefix("name:") {
            let id = pending.take().ok_or_else(|| {
                Error::Invalid(format!("line {}: a name without a value", number + 1))
            })?;
            let name = scalar(name)?;
            if name.is_empty() {
                return Err(Error::Invalid(format!(
                    "line {}: {id:04X} has an empty name",
                    number + 1
                )));
            }
            companies.push(Company { id, name });
        } else {
            return Err(Error::Invalid(format!(
                "line {}: unexpected {trimmed:?}",
                number + 1
            )));
        }
    }
    if pending.is_some() {
        return Err(Error::Invalid(
            "the listing ends with a value and no name".to_string(),
        ));
    }
    companies.sort_by_key(|company| company.id);
    for pair in companies.windows(2) {
        if pair[0].id == pair[1].id {
            return Err(Error::Invalid(format!(
                "{:04X} is listed twice ({:?} and {:?})",
                pair[0].id, pair[0].name, pair[1].name
            )));
        }
    }
    Ok(companies)
}

/// Packs companies, which must ascend strictly by identifier, into the blob layout.
pub fn pack(companies: &[Company]) -> Result<Vec<u8>> {
    for (position, company) in companies.iter().enumerate() {
        if position > 0 && companies[position - 1].id >= company.id {
            return Err(Error::Invalid(format!(
                "identifiers must ascend: {:04X} follows {:04X}",
                company.id,
                companies[position - 1].id
            )));
        }
        if company.name.is_empty() {
            return Err(Error::Invalid(format!(
                "{:04X} has an empty name",
                company.id
            )));
        }
    }
    let count = u32::try_from(companies.len())
        .map_err(|_| Error::Invalid("more than 4,294,967,295 identifiers".to_string()))?;
    let mut out = Vec::with_capacity(HEADER + companies.len() * 40);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for company in companies {
        out.extend_from_slice(&company.id.to_le_bytes());
    }
    while out.len() % 4 != 0 {
        out.push(0);
    }
    let mut offset: u32 = 0;
    out.extend_from_slice(&offset.to_le_bytes());
    for company in companies {
        offset = u32::try_from(company.name.len())
            .ok()
            .and_then(|len| offset.checked_add(len))
            .ok_or_else(|| Error::Invalid("the names exceed 4 GiB".to_string()))?;
        out.extend_from_slice(&offset.to_le_bytes());
    }
    for company in companies {
        out.extend_from_slice(company.name.as_bytes());
    }
    Ok(out)
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

/// Reads a blob back into its companies, refusing one whose tables or names do not fit.
pub fn decode(bytes: &[u8]) -> Result<Vec<Company>> {
    let malformed =
        || Error::Invalid("the blob is not a packed company identifier table".to_string());
    if bytes.len() < HEADER || &bytes[..MAGIC.len()] != MAGIC {
        return Err(malformed());
    }
    let count = le_u32(bytes, 8).ok_or_else(malformed)? as usize;
    let ids = HEADER;
    let unpadded = ids
        .checked_add(count.checked_mul(2).ok_or_else(malformed)?)
        .ok_or_else(malformed)?;
    let offsets = unpadded + (4 - unpadded % 4) % 4;
    let blob = offsets
        .checked_add((count + 1).checked_mul(4).ok_or_else(malformed)?)
        .ok_or_else(malformed)?;
    if blob > bytes.len() {
        return Err(malformed());
    }
    let mut companies = Vec::with_capacity(count);
    for index in 0..count {
        let id = le_u16(bytes, ids + index * 2).ok_or_else(malformed)?;
        let start = le_u32(bytes, offsets + index * 4).ok_or_else(malformed)? as usize;
        let end = le_u32(bytes, offsets + (index + 1) * 4).ok_or_else(malformed)? as usize;
        if end < start {
            return Err(malformed());
        }
        let name = bytes
            .get(
                blob.checked_add(start).ok_or_else(malformed)?
                    ..blob.checked_add(end).ok_or_else(malformed)?,
            )
            .ok_or_else(malformed)?;
        let name = std::str::from_utf8(name).map_err(|_| malformed())?;
        companies.push(Company {
            id,
            name: name.to_owned(),
        });
    }
    Ok(companies)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "company_identifiers:\n\n  - value: 0x0075\n    name: 'Samsung Electronics Co. Ltd.'\n\n  - value: 0x004C\n    name: 'Apple, Inc.'\n\n  - value: 0x0001\n    name: \"Nokia \\\"Mobile\\\" Phones\"\n\n  - value: 0x0002\n    name: 'O''Reilly'\n";

    #[test]
    fn the_listing_is_read_ascending_with_its_quoting_undone() {
        let companies = companies_from_yaml(LISTING).unwrap();
        let listed: Vec<(u16, &str)> = companies.iter().map(|c| (c.id, c.name.as_str())).collect();
        assert_eq!(
            listed,
            [
                (0x0001, "Nokia \"Mobile\" Phones"),
                (0x0002, "O'Reilly"),
                (0x004C, "Apple, Inc."),
                (0x0075, "Samsung Electronics Co. Ltd."),
            ]
        );
    }

    #[test]
    fn a_uuid_listing_is_read_by_its_own_key() {
        let listing = "uuids:\n - uuid: 0x180F\n   name: Battery\n - uuid: 0xFD5A\n   name: \"Samsung Electronics Co., Ltd.\"\n";
        let entries = entries_from_yaml(listing, "uuid").unwrap();
        let listed: Vec<(u16, &str)> = entries.iter().map(|c| (c.id, c.name.as_str())).collect();
        assert_eq!(
            listed,
            [
                (0x180F, "Battery"),
                (0xFD5A, "Samsung Electronics Co., Ltd.")
            ]
        );
        assert!(
            entries_from_yaml(listing, "value").is_err(),
            "the other key is a stray line"
        );
    }

    #[test]
    fn a_blob_round_trips_and_a_repeated_identifier_is_refused() {
        let companies = companies_from_yaml(LISTING).unwrap();
        let blob = pack(&companies).unwrap();
        assert_eq!(decode(&blob).unwrap(), companies);
        assert_eq!(pack(&companies).unwrap(), blob, "packing is deterministic");
        let twice = format!("{LISTING}  - value: 0x004C\n    name: 'Again'\n");
        assert!(companies_from_yaml(&twice).is_err());
        assert!(decode(b"HSEOUI\x01\x00").is_err());
        assert!(
            companies_from_yaml("  - value: 0x0001\n  - value: 0x0002\n    name: 'x'\n").is_err()
        );
    }
}
