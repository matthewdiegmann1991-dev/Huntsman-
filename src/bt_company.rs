//! The Bluetooth SIG company identifiers, searched in place: the 16-bit identifier a Bluetooth
//! LE advertisement's manufacturer-specific data begins with (little-endian), and the company
//! the SIG assigned it to.
//!
//! `bt_company.bin` is built from the SIG's YAML listing,
//! <https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml>,
//! by `cargo run --locked -p xtask -- btsig pack company_identifiers.yaml src/bt_company.bin`;
//! `xtask btsig dump` lists a blob, and `xtask/tests/btsig_pack.rs` proves the committed blob is
//! what the packer makes of its own listing. The layout is documented with the packer, in
//! `xtask/src/btsig.rs`. A name is who registered the identifier, which says what made the
//! advertising firmware or the app behind it, never who owns the device.

const DATA: &[u8] = include_bytes!("bt_company.bin");
const MAGIC: &[u8] = b"HSEBTC\x01\x00";
const HEADER: usize = 16;

struct Layout {
    count: usize,
    ids: usize,
    offsets: usize,
    blob: usize,
}

fn le_u32(at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(DATA.get(at..at + 4)?.try_into().ok()?))
}

fn le_u16(at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(DATA.get(at..at + 2)?.try_into().ok()?))
}

fn layout() -> Option<&'static Layout> {
    static CELL: std::sync::OnceLock<Option<Layout>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        if DATA.len() < HEADER || DATA.get(..MAGIC.len())? != MAGIC {
            return None;
        }
        let count = le_u32(8)? as usize;
        let ids = HEADER;
        let unpadded = ids.checked_add(count.checked_mul(2)?)?;
        let offsets = unpadded.checked_add((4 - unpadded % 4) % 4)?;
        let blob = offsets.checked_add(count.checked_add(1)?.checked_mul(4)?)?;
        if blob > DATA.len() {
            return None;
        }
        Some(Layout {
            count,
            ids,
            offsets,
            blob,
        })
    })
    .as_ref()
}

/// The company the Bluetooth SIG assigned `id` to, or `None` for an unassigned identifier.
/// **Pure.**
#[must_use]
pub fn company_name(id: u16) -> Option<&'static str> {
    let layout = layout()?;
    let (mut low, mut high) = (0usize, layout.count);
    while low < high {
        let mid = low + (high - low) / 2;
        if le_u16(layout.ids + mid * 2)? < id {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if low >= layout.count || le_u16(layout.ids + low * 2)? != id {
        return None;
    }
    let start = le_u32(layout.offsets + low * 4)? as usize;
    let end = le_u32(layout.offsets + (low + 1) * 4)? as usize;
    if end < start {
        return None;
    }
    let bytes = DATA.get(layout.blob.checked_add(start)?..layout.blob.checked_add(end)?)?;
    std::str::from_utf8(bytes).ok()
}

/// The company identifier at the start of manufacturer-specific data, which carries it
/// little-endian, with its company. `None` for fewer than two bytes. **Pure.**
#[must_use]
pub fn company_of_manufacturer_data(data: &[u8]) -> Option<(u16, Option<&'static str>)> {
    let id = u16::from_le_bytes([*data.first()?, *data.get(1)?]);
    Some((id, company_name(id)))
}

/// How many identifiers the embedded table holds. **Pure.**
#[must_use]
pub fn count() -> usize {
    layout().map_or(0, |layout| layout.count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_names_assigned_identifiers_and_no_others() {
        assert_eq!(company_name(0x0075), Some("Samsung Electronics Co. Ltd."));
        assert_eq!(company_name(0x004C), Some("Apple, Inc."));
        assert_eq!(company_name(0x0000), Some("Ericsson AB"));
        assert_eq!(
            company_name(0xFFFF),
            None,
            "reserved for tests, never assigned"
        );
        assert!(count() > 4000, "{}", count());
        // Manufacturer data begins with the identifier little-endian: Samsung's 0x0075 is 75 00.
        assert_eq!(
            company_of_manufacturer_data(&[0x75, 0x00, 0x02, 0x18]),
            Some((0x0075, Some("Samsung Electronics Co. Ltd.")))
        );
        assert_eq!(company_of_manufacturer_data(&[0x75]), None);
    }

    #[test]
    fn every_identifier_in_the_table_is_found_by_the_search() {
        // The ids are ascending; the search must find each one at its own position.
        let layout = layout().expect("the embedded blob is well formed");
        let mut previous: Option<u16> = None;
        for index in 0..layout.count {
            let id = le_u16(layout.ids + index * 2).unwrap();
            assert!(
                previous.is_none_or(|p| p < id),
                "{id:04X} after {previous:?}"
            );
            let name = company_name(id).unwrap_or_else(|| panic!("{id:04X} unnamed"));
            assert!(!name.is_empty());
            previous = Some(id);
        }
    }
}
