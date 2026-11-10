//! A published spreadsheet as rows: an Office Open XML workbook (`.xlsx`), as a publisher's
//! tool wrote it (its parts deflated, its text in the shared-strings part) or as
//! [`crate::xlsx::workbook`] wrote it (stored parts, inline strings), read through the one ZIP
//! reader the engine has ([`crate::zip_read::zip_member`]). A list a public body publishes as a
//! workbook, such as DFAT's Consolidated List, is read with it.

/// The rows of a workbook's first sheet, each cell as text: a shared or inline string as its
/// text (Excel's `_xHHHH_` escapes decoded), any other cell as the value written in it. A row's
/// cells are in column order, a skipped column a blank, and the rows in sheet order. Each part
/// is read within `limit` bytes.
///
/// # Errors
/// A ZIP or part that cannot be read, or a workbook without a first sheet, in words.
pub fn rows(workbook: &[u8], limit: usize) -> Result<Vec<Vec<String>>, String> {
    let part = |name: &str| crate::zip_read::zip_member(workbook, name, limit);
    let shared: Vec<String> = match part("xl/sharedStrings.xml")? {
        Some(bytes) => shared_strings(&String::from_utf8_lossy(&bytes)),
        None => Vec::new(),
    };
    let sheet = part("xl/worksheets/sheet1.xml")?
        .ok_or_else(|| "the workbook has no first worksheet part".to_owned())?;
    Ok(sheet_rows(&String::from_utf8_lossy(&sheet), &shared))
}

/// Each `<si>` of the shared-strings part as its text: every `<t>` run joined. **Pure.**
fn shared_strings(xml: &str) -> Vec<String> {
    elements(xml, "si")
        .into_iter()
        .map(|(_, inner)| runs(inner))
        .collect()
}

/// The text runs (`<t>` elements, attributes or not) of `inner`, joined and decoded. **Pure.**
fn runs(inner: &str) -> String {
    elements(inner, "t")
        .into_iter()
        .map(|(_, text)| decoded(text).into_owned())
        .collect::<String>()
}

/// The rows of a worksheet part: each `<row>`'s cells by their column letters. **Pure.**
fn sheet_rows(xml: &str, shared: &[String]) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for (_, row) in elements(xml, "row") {
        let mut cells: Vec<String> = Vec::new();
        for (attrs, inner) in elements(row, "c") {
            let at = attribute_of(attrs, "r")
                .and_then(|reference| column_index(&reference))
                .unwrap_or(cells.len());
            let text = match attribute_of(attrs, "t").as_deref() {
                Some("s") => elements(inner, "v")
                    .first()
                    .and_then(|(_, index)| index.trim().parse::<usize>().ok())
                    .and_then(|index| shared.get(index).cloned())
                    .unwrap_or_default(),
                Some("inlineStr") => runs(inner),
                _ => elements(inner, "v")
                    .first()
                    .map(|(_, value)| decoded(value).into_owned())
                    .unwrap_or_default(),
            };
            if cells.len() <= at {
                cells.resize(at + 1, String::new());
            }
            cells[at] = text;
        }
        rows.push(cells);
    }
    rows
}

/// Every `<name …>…</name>` or `<name …/>` element of `xml` in order, as its attribute text
/// and its raw inner markup, for a nested read or a leaf's [`decoded`] text. **Pure.**
fn elements<'a>(xml: &'a str, name: &str) -> Vec<(&'a str, &'a str)> {
    let close = format!("</{name}>");
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(at) = rest.find('<') {
        rest = &rest[at + 1..];
        let Some(after) = rest.strip_prefix(name) else {
            continue;
        };
        if !after.starts_with([' ', '>', '/', '\t', '\n', '\r']) {
            continue;
        }
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let attrs = after[..tag_end].trim();
        if let Some(attrs) = attrs.strip_suffix('/') {
            found.push((attrs.trim(), ""));
            rest = &after[tag_end + 1..];
            continue;
        }
        let body = &after[tag_end + 1..];
        let Some(end) = body.find(&close) else {
            break;
        };
        found.push((attrs, &body[..end]));
        rest = &body[end + close.len()..];
    }
    found
}

/// The value of attribute `key` in `attrs`, decoded. **Pure.**
fn attribute_of(attrs: &str, key: &str) -> Option<String> {
    let mut rest = attrs;
    while let Some(at) = rest.find(key) {
        let before_ok = at == 0 || !rest.as_bytes()[at - 1].is_ascii_alphanumeric();
        let after = &rest[at + key.len()..];
        let after = after.trim_start();
        if before_ok && after.starts_with('=') {
            let value = after[1..].trim_start();
            let quote = value.chars().next()?;
            if quote == '"' || quote == '\'' {
                let value = &value[1..];
                let end = value.find(quote)?;
                return Some(crate::textnorm::xml_unescape(&value[..end]));
            }
        }
        rest = &rest[at + key.len()..];
    }
    None
}

/// Cell text as Excel reads it: XML entities decoded, then `_xHHHH_` escapes. A text with
/// neither is borrowed as it is. **Pure.**
fn decoded(raw: &str) -> std::borrow::Cow<'_, str> {
    if !raw.contains('&') && !raw.contains("_x") {
        return std::borrow::Cow::Borrowed(raw);
    }
    let text = crate::textnorm::xml_unescape(raw);
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find("_x") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let code = tail
            .get(2..6)
            .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()));
        if let (Some(hex), Some(b'_')) = (code, tail.as_bytes().get(6)) {
            let c = u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
            out.push(c.unwrap_or('\u{fffd}'));
            rest = &tail[7..];
        } else {
            out.push_str("_x");
            rest = &tail[2..];
        }
    }
    out.push_str(rest);
    std::borrow::Cow::Owned(out)
}

/// The zero-based column of a cell reference such as `B7` or `AA3`. **Pure.**
fn column_index(reference: &str) -> Option<usize> {
    let letters: String = reference
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    if letters.is_empty() {
        return None;
    }
    let mut index = 0usize;
    for c in letters.chars() {
        index = index
            .checked_mul(26)?
            .checked_add(usize::from(c.to_ascii_uppercase() as u8 - b'A') + 1)?;
    }
    Some(index - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le16(out: &mut Vec<u8>, value: usize) {
        out.extend_from_slice(&u16::try_from(value).expect("fits").to_le_bytes());
    }

    fn le32(out: &mut Vec<u8>, value: usize) {
        out.extend_from_slice(&u32::try_from(value).expect("fits").to_le_bytes());
    }

    /// A ZIP of `parts`, each stored (method 0) or deflated (method 8), as a publisher's
    /// workbook is: the reader must take both.
    fn zip_of(parts: &[(&str, &[u8], u16)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        let mut count = 0usize;
        for (name, bytes, method) in parts {
            let packed = if *method == 8 {
                miniz_oxide::deflate::compress_to_vec(bytes, 6)
            } else {
                bytes.to_vec()
            };
            let crc = crc32fast::hash(bytes);
            let local_at = out.len();
            out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&crc.to_le_bytes());
            le32(&mut out, packed.len());
            le32(&mut out, bytes.len());
            le16(&mut out, name.len());
            le16(&mut out, 0);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&packed);
            central.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 20, 0, 20, 0, 0, 0]);
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0]);
            central.extend_from_slice(&crc.to_le_bytes());
            le32(&mut central, packed.len());
            le32(&mut central, bytes.len());
            le16(&mut central, name.len());
            le16(&mut central, 0);
            le16(&mut central, 0);
            le16(&mut central, 0);
            le16(&mut central, 0);
            le32(&mut central, 0);
            le32(&mut central, local_at);
            central.extend_from_slice(name.as_bytes());
            count += 1;
        }
        let central_at = out.len();
        out.extend_from_slice(&central);
        out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]);
        le16(&mut out, count);
        le16(&mut out, count);
        le32(&mut out, central.len());
        le32(&mut out, central_at);
        le16(&mut out, 0);
        out
    }

    /// What the writer wrote is read back whole: inline strings, their escapes decoded, a
    /// skipped column blank, and the rows in order.
    #[test]
    fn a_written_workbook_reads_back_as_its_rows() {
        let rows = vec![
            vec![
                "Reference".to_owned(),
                "Name".to_owned(),
                String::new(),
                "Note".to_owned(),
            ],
            vec![
                "1".to_owned(),
                "A & B <c>".to_owned(),
                String::new(),
                "tab\there".to_owned(),
            ],
            vec!["2".to_owned(), "bell\u{7}bell".to_owned()],
            vec!["3".to_owned(), "_x0041_ literal".to_owned()],
        ];
        let bytes = crate::xlsx::workbook(&[crate::xlsx::Sheet {
            name: "List".into(),
            rows: rows.clone(),
        }]);
        assert_eq!(super::rows(&bytes, 1 << 20).expect("read back"), rows);
    }

    /// A publisher's workbook: deflated parts, shared strings with several runs, a cell that
    /// names its column past a gap, a number, a formula string and an inline string.
    #[test]
    fn a_publisher_s_workbook_with_shared_strings_and_deflated_parts_is_read() {
        let shared = b"<?xml version=\"1.0\"?><sst xmlns=\"x\" count=\"3\"><si><t>Reference</t></si>\
<si><r><t>KIM </t></r><r><t xml:space=\"preserve\">Jong Un</t></r></si><si><t>a &amp; b_x000A_c</t></si></sst>";
        let sheet = b"<?xml version=\"1.0\"?><worksheet xmlns=\"x\"><sheetData>\
<row r=\"1\"><c r=\"A1\" t=\"s\"><v>0</v></c><c r=\"B1\" t=\"s\" s=\"1\"><v>1</v></c></row>\
<row r=\"3\"><c r=\"A3\"><v>6219</v></c><c r=\"B3\" s=\"2\"/><c r=\"D3\" t=\"s\"><v>2</v></c>\
<c r=\"E3\" t=\"str\"><v>=A3</v></c><c r=\"F3\" t=\"inlineStr\"><is><t>inline</t></is></c></row>\
</sheetData></worksheet>";
        let bytes = zip_of(&[
            ("[Content_Types].xml", b"<Types/>", 0),
            ("xl/sharedStrings.xml", shared, 8),
            ("xl/worksheets/sheet1.xml", sheet, 8),
        ]);
        assert_eq!(
            super::rows(&bytes, 1 << 20).expect("read"),
            vec![
                vec!["Reference".to_owned(), "KIM Jong Un".to_owned()],
                vec![
                    "6219".to_owned(),
                    String::new(),
                    String::new(),
                    "a & b\nc".to_owned(),
                    "=A3".to_owned(),
                    "inline".to_owned(),
                ],
            ]
        );
        let no_sheet = zip_of(&[("xl/sharedStrings.xml", shared, 8)]);
        assert!(
            super::rows(&no_sheet, 1 << 20)
                .unwrap_err()
                .contains("no first worksheet")
        );
        let over = zip_of(&[("xl/worksheets/sheet1.xml", sheet, 8)]);
        assert!(
            super::rows(&over, 16)
                .unwrap_err()
                .contains("over its 16-byte limit")
        );
        assert!(super::rows(b"not a zip", 1 << 20).is_err());
    }

    #[test]
    fn column_letters_and_attributes_are_read() {
        assert_eq!(column_index("A1"), Some(0));
        assert_eq!(column_index("Z9"), Some(25));
        assert_eq!(column_index("AA3"), Some(26));
        assert_eq!(column_index("AB3"), Some(27));
        assert_eq!(column_index("7"), None);
        assert_eq!(attribute_of("r=\"B2\" t=\"s\"", "t").as_deref(), Some("s"));
        assert_eq!(attribute_of("r=\"B2\" t=\"s\"", "r").as_deref(), Some("B2"));
        assert_eq!(
            attribute_of("rt=\"x\" t='inlineStr'", "t").as_deref(),
            Some("inlineStr")
        );
        assert_eq!(attribute_of("r=\"B2\"", "t"), None);
    }
}
