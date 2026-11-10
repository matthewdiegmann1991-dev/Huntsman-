//! ZIP archives read in place: the end record, the central directory, each member stored or
//! deflated (checked against its CRC-32) within a byte limit. An APK ([`crate::apk_intel`]) and
//! an Office Open XML workbook ([`crate::workbook`]) are both ZIPs, read through this one reader.

use std::borrow::Cow;

use crate::error::Error;

pub(crate) const MAX_ENTRIES: usize = 8192;
pub(crate) const EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
pub(crate) const CENTRAL_SIGNATURE: &[u8] = b"PK\x01\x02";
pub(crate) const LOCAL_SIGNATURE: &[u8] = b"PK\x03\x04";

pub(crate) fn le16(data: &[u8], at: usize) -> Option<u16> {
    let field = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([field[0], field[1]]))
}

pub(crate) fn le32(data: &[u8], at: usize) -> Option<u32> {
    let field = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

pub(crate) fn checked_range(data: &[u8], at: usize, size: usize) -> Option<&[u8]> {
    data.get(at..at.checked_add(size)?)
}

/// Find the last complete ZIP EOCD record. The comment length must end at EOF.
pub(crate) fn eocd(data: &[u8]) -> Result<usize, Error> {
    if data.len() < 22 {
        return Err(Error::invalid_value(
            "APK is too short for a ZIP end record",
        ));
    }
    let start = data.len().saturating_sub(22 + 65535);
    for pos in (start..=data.len() - 22).rev() {
        if checked_range(data, pos, 4) == Some(EOCD_SIGNATURE)
            && le16(data, pos + 20).is_some_and(|len| usize::from(len) == data.len() - pos - 22)
        {
            return Ok(pos);
        }
    }
    Err(Error::invalid_value("missing complete ZIP end record"))
}

#[derive(Clone, Copy)]
pub(crate) struct Member<'a> {
    pub(crate) name: &'a str,
    pub(crate) flags: u16,
    pub(crate) method: u16,
    /// The CRC-32 and uncompressed size the central directory states.
    pub(crate) crc: u32,
    pub(crate) size: usize,
    pub(crate) next: usize,
    /// Where the local payload starts, and its stored (compressed) length.
    pub(crate) payload_start: usize,
    pub(crate) payload_len: usize,
}

pub(crate) fn member(
    data: &[u8],
    pos: usize,
    dir_start: usize,
    dir_end: usize,
) -> Result<Member<'_>, Error> {
    if checked_range(data, pos, 4) != Some(CENTRAL_SIGNATURE) {
        return Err(Error::invalid_value("invalid ZIP central directory entry"));
    }
    let flags = le16(data, pos + 8).ok_or_else(|| Error::invalid_value("truncated ZIP flags"))?;
    let method =
        le16(data, pos + 10).ok_or_else(|| Error::invalid_value("truncated ZIP compression"))?;
    let crc = le32(data, pos + 16).ok_or_else(|| Error::invalid_value("missing ZIP CRC-32"))?;
    let packed = usize::try_from(
        le32(data, pos + 20).ok_or_else(|| Error::invalid_value("missing compressed size"))?,
    )
    .map_err(|_| Error::invalid_value("compressed size overflow"))?;
    let size = usize::try_from(
        le32(data, pos + 24).ok_or_else(|| Error::invalid_value("missing uncompressed size"))?,
    )
    .map_err(|_| Error::invalid_value("uncompressed size overflow"))?;
    let name_len = usize::from(
        le16(data, pos + 28).ok_or_else(|| Error::invalid_value("missing ZIP name size"))?,
    );
    let extra = usize::from(
        le16(data, pos + 30).ok_or_else(|| Error::invalid_value("missing ZIP extra size"))?,
    );
    let comment = usize::from(
        le16(data, pos + 32).ok_or_else(|| Error::invalid_value("missing ZIP comment size"))?,
    );
    let local_at = usize::try_from(
        le32(data, pos + 42).ok_or_else(|| Error::invalid_value("missing local offset"))?,
    )
    .map_err(|_| Error::invalid_value("local offset overflow"))?;
    let name_at = pos
        .checked_add(46)
        .ok_or_else(|| Error::invalid_value("ZIP name offset overflow"))?;
    let raw = checked_range(data, name_at, name_len)
        .ok_or_else(|| Error::invalid_value("truncated ZIP entry name"))?;
    let name =
        std::str::from_utf8(raw).map_err(|_| Error::invalid_value("non UTF-8 APK entry name"))?;
    let next = name_at
        .checked_add(name_len)
        .and_then(|n| n.checked_add(extra))
        .and_then(|n| n.checked_add(comment))
        .ok_or_else(|| Error::invalid_value("ZIP entry overflow"))?;
    if next > dir_end {
        return Err(Error::invalid_value("ZIP entry exceeds directory boundary"));
    }
    if checked_range(data, local_at, 4) != Some(LOCAL_SIGNATURE) {
        return Err(Error::invalid_value("ZIP entry has invalid local header"));
    }
    let local_name_len = usize::from(
        le16(data, local_at + 26).ok_or_else(|| Error::invalid_value("missing local name"))?,
    );
    let local_extra_len = usize::from(
        le16(data, local_at + 28).ok_or_else(|| Error::invalid_value("missing local extra"))?,
    );
    let local_name_at = local_at
        .checked_add(30)
        .ok_or_else(|| Error::invalid_value("local header overflow"))?;
    if checked_range(data, local_name_at, local_name_len) != Some(raw) {
        return Err(Error::invalid_value(
            "central/local ZIP entry names disagree",
        ));
    }
    let payload_start = local_name_at
        .checked_add(local_name_len)
        .and_then(|n| n.checked_add(local_extra_len))
        .ok_or_else(|| Error::invalid_value("ZIP payload range overflow"))?;
    let payload_end = payload_start
        .checked_add(packed)
        .ok_or_else(|| Error::invalid_value("ZIP payload range overflow"))?;
    if payload_end > dir_start {
        return Err(Error::invalid_value(
            "ZIP payload exceeds start of central directory",
        ));
    }
    Ok(Member {
        name,
        flags,
        method,
        crc,
        size,
        next,
        payload_start,
        payload_len: packed,
    })
}

pub(crate) fn directory_bounds(data: &[u8]) -> Result<(usize, usize, usize), Error> {
    let end = eocd(data)?;
    let disks = (le16(data, end + 4), le16(data, end + 6));
    if disks != (Some(0), Some(0)) {
        return Err(Error::invalid_value(
            "multi-disk ZIP archives are unsupported",
        ));
    }
    let count = le16(data, end + 10).ok_or_else(|| Error::invalid_value("missing ZIP count"))?;
    if le16(data, end + 8) != Some(count) {
        return Err(Error::invalid_value("inconsistent ZIP entry counts"));
    }
    let size =
        le32(data, end + 12).ok_or_else(|| Error::invalid_value("missing ZIP directory size"))?;
    let start =
        le32(data, end + 16).ok_or_else(|| Error::invalid_value("missing ZIP directory offset"))?;
    if count == u16::MAX || size == u32::MAX || start == u32::MAX {
        return Err(Error::invalid_value("ZIP64 APK archives are unsupported"));
    }
    let count = usize::from(count);
    if count == 0 || count > MAX_ENTRIES {
        return Err(Error::invalid_value(
            "empty APK or APK exceeds 8192 ZIP entries",
        ));
    }
    let dir_start =
        usize::try_from(start).map_err(|_| Error::invalid_value("directory offset overflow"))?;
    let dir_end = dir_start
        .checked_add(
            usize::try_from(size).map_err(|_| Error::invalid_value("directory size overflow"))?,
        )
        .ok_or_else(|| Error::invalid_value("directory range overflow"))?;
    if dir_end > end {
        return Err(Error::invalid_value(
            "ZIP directory extends beyond end record",
        ));
    }

    Ok((count, dir_start, dir_end))
}

/// The bytes of the member named `name` in the ZIP `data`, stored or deflated, within `limit`
/// bytes, as an APK's members are read: a part of an Office Open XML workbook, say. `None` when
/// no member has that name.
///
/// # Errors
/// A directory or member that cannot be read, in words.
pub(crate) fn zip_member(data: &[u8], name: &str, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let (count, dir_start, dir_end) = directory_bounds(data).map_err(|error| error.to_string())?;
    let mut pos = dir_start;
    for _ in 0..count {
        let entry = member(data, pos, dir_start, dir_end).map_err(|error| error.to_string())?;
        pos = entry.next;
        if entry.name == name {
            let mut budget = limit;
            let (bytes, _) = read_member(data, &entry, limit, &mut budget)?;
            return Ok(Some(bytes.into_owned()));
        }
    }
    Ok(None)
}

/// The bytes of `member`, read in place when stored and inflated when deflated, within `limit`
/// and what is left of `budget`, and checked against the CRC-32 the directory states.
///
/// A member that names a compression method other than stored or deflate is read as stored when
/// its sizes agree, as Android's `libziparchive` reads it; this is a known way to make analysis
/// tools fail on an APK Android still installs, so it is returned as an evasion indicator.
pub(crate) fn read_member<'a>(
    data: &'a [u8],
    member: &Member<'_>,
    limit: usize,
    budget: &mut usize,
) -> Result<(Cow<'a, [u8]>, Option<String>), String> {
    let name = member.name;
    if member.flags & 1 != 0 {
        return Err(format!("{name} is encrypted"));
    }
    if member.size > limit {
        return Err(format!(
            "{name} inflates to {} bytes, over its {limit}-byte limit",
            member.size
        ));
    }
    if member.size > *budget {
        return Err(format!(
            "{name} inflates to {} bytes, past the {budget} left of the inflation budget",
            member.size
        ));
    }
    // Charge the declared inflation size before attempting decompression. A malformed
    // member must not get unlimited retries against the per-APK work budget.
    // Unsupported methods remain free because no decompression is attempted.
    if member.method == 8 || member.method == 0 || member.payload_len == member.size {
        *budget -= member.size;
    }
    let raw = &data[member.payload_start..member.payload_start + member.payload_len];
    let (bytes, quirk) = match member.method {
        8 => (
            Cow::Owned(
                miniz_oxide::inflate::decompress_to_vec_with_limit(raw, member.size)
                    .map_err(|error| format!("{name} does not inflate: {:?}", error.status))?,
            ),
            None,
        ),
        0 => (Cow::Borrowed(raw), None),
        other if member.payload_len == member.size => (
            Cow::Borrowed(raw),
            Some(format!(
                "{name} declares compression method {other}, read as stored as Android does"
            )),
        ),
        other => {
            return Err(format!(
                "{name} uses unsupported compression method {other}"
            ));
        }
    };
    if bytes.len() != member.size {
        return Err(format!("{name} is not the size its ZIP entry states"));
    }
    if crc32fast::hash(&bytes) != member.crc {
        return Err(format!("{name} fails its ZIP CRC-32 check"));
    }
    Ok((bytes, quirk))
}
