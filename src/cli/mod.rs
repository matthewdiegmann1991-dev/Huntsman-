//! CLI composition and dispatch for `huntsman-recon`.
//!
//! This module is deliberately an adapter layer: it parses process arguments,
//! constructs transports/configuration, and delegates to the library. Domain
//! behavior belongs in `huntsman_recon`, not in the binary front controller.

use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

const RECON_USAGE: &str = "usage: huntsman-recon recon crtsh TARGET | recon dns TARGET | recon stolen-tax QUERY [--keys FILE]";
/// The largest plain file a command reads or writes: a seed list, or a self-check scratch file.
/// A saved artifact has its own ceiling, `scan_artifact::MAX_ARTIFACT_BYTES`.
const MAX_PLAIN_FILE_BYTES: u64 = 1_048_576;
mod apk;
mod blueprint;
mod case_audit;
mod commands;
mod continuous;
mod credentials;
mod doctor;
mod help;
mod lookup;
mod mcp;
mod meta;
mod mitm;
mod network;
mod osint;
mod privacy;
mod public_osint;
mod radar;
mod report;
mod research;
mod reverse_image;
mod scans;
mod security_tools;
mod selfcheck;
mod service;
mod source_intel;
mod traffic_cameras;
mod utility;

use commands::{HELP, USAGE};
use report::{exit_on_output_failure, fail, terminal_json_pretty, usage_error};

/// Runs the command named by the process arguments (without the program name).
pub(crate) fn run(args: Vec<OsString>) -> ExitCode {
    exit_on_output_failure();
    let mut words = Vec::with_capacity(args.len());
    for (index, arg) in args.into_iter().enumerate() {
        match arg.into_string() {
            Ok(arg) => words.push(arg),
            Err(raw) => return help::argument_not_utf8(index + 1, raw.len()),
        }
    }
    let first = words.first().map(String::as_str);
    if matches!(first, Some("help" | "-h" | "--help")) {
        println!("{}\n{USAGE}", *HELP);
        return ExitCode::SUCCESS;
    }
    if matches!(first, Some("-V" | "--version")) {
        println!("huntsman-recon {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if words.len() == 2 && matches!(words[1].as_str(), "-h" | "--help") {
        return help::print_command_help(&words[0]);
    }
    let mut words = words.into_iter();
    let Some(name) = words.next() else {
        return help::no_command();
    };
    let args: Vec<String> = words.collect();
    match commands::find(&name) {
        Some(command) => (command.run)(&args),
        None => help::unknown_command(&name),
    }
}
