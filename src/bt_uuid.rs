//! The Bluetooth SIG's 16-bit UUIDs, searched in place: the standard service UUIDs (`GAP`,
//! `Battery`, `Device Information`...) and the member UUIDs the SIG assigns to companies for
//! their own services (`0xFD5A` Samsung, `0xFEAA` Google...), as an advertisement's service UUID
//! lists and service data name them.
//!
//! `bt_uuid.bin` is built from the SIG's listings, `assigned_numbers/uuids/service_uuids.yaml`
//! and `member_uuids.yaml` under
//! <https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/>, merged, by
//! `cargo run --locked -p xtask -- btsig pack-uuids src/bt_uuid.bin service_uuids.yaml
//! member_uuids.yaml`; `xtask btsig dump` lists a blob, and `xtask/tests/btsig_pack.rs` proves
//! the committed blob is what the packer makes of its own listing. The name of a member UUID is
//! the company it was assigned to: what the service belongs to, never who owns the device.

use crate::bt_company::PackedU16Table;

static TABLE: PackedU16Table = PackedU16Table::new(include_bytes!("bt_uuid.bin"));

/// The SIG's name for an assigned 16-bit UUID (a standard service's name, or the company a
/// member UUID is assigned to), or `None` for one not assigned. **Pure.**
#[must_use]
pub fn name(uuid: u16) -> Option<&'static str> {
    TABLE.name(uuid)
}

/// How many UUIDs the embedded table holds. **Pure.**
#[must_use]
pub fn count() -> usize {
    TABLE.count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_names_standard_and_member_uuids_and_no_others() {
        assert_eq!(name(0x1800), Some("GAP"));
        assert_eq!(name(0x180F), Some("Battery"));
        assert_eq!(name(0x180A), Some("Device Information"));
        assert_eq!(name(0xFD5A), Some("Samsung Electronics Co., Ltd."));
        assert_eq!(name(0xFEAA), Some("Google LLC"));
        assert_eq!(name(0xFFFF), None);
        assert_eq!(name(0x0000), None);
        assert!(count() > 700, "{}", count());
    }
}
