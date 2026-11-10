//! Stage 2 directory shim for the `core` home (see `docs/ARCHITECTURE.md`).
//!
//! Re-exports only. Every module still lives at its current `crate::<module>` path;
//! later stages move files here one at a time without changing those paths.

pub use crate::{
    address_au, au_id, base64, ble_address, bt_company, bt_uuid, canonical, circuit, clock,
    concurrent, cvss, directive_lock, dmarc, dns_wire, domains, engineering_command, environment,
    error, exit, fsio, geohash, html_text, json, lookup_args, md5, netblock, network_selector, oui,
    oui_ieee, pattern, phone_intl, postcode_au, radar, redact, scan_batch, sha256, source_profile,
    spf, stage, stdio_failure, tags, termination, textnorm, timefmt, tlsrpt, translit, union_find,
    username_variants, validation, value_syntax, workbook, x509, yaml_lite, zip_read,
};
