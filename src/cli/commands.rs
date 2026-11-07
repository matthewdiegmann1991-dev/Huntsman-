//! The one registry of `huntsman-recon` commands. Each command is declared once, here, with the
//! name it is called by, the line the general help lists it with, its synopsis in the usage
//! line, and the function that runs it. Dispatch, the general help and the usage line are all
//! read from this table, so a command cannot be runnable but unlisted, listed but unrunnable, or
//! described one way in the help and another in the usage line. A command's own `--help` text
//! lives with its implementation and is found through [`super::help::command_help`].

use std::fmt::Write as _;
use std::process::ExitCode;
use std::sync::LazyLock;

/// One command: what it is called, how the general help and the usage line describe it, and
/// what runs it.
pub(super) struct Command {
    pub(super) name: &'static str,
    /// The general help's one-line description.
    pub(super) summary: &'static str,
    pub(super) run: fn(&[String]) -> ExitCode,
}

/// The general help above the command list.
const HEADER: &str = "Huntsman Recon — local search, guarded fetch, and evidence-ledger tools\n\nUsage:\n  huntsman-recon <COMMAND> [ARGS]\n  huntsman-recon --help\n  huntsman-recon --version\n\nCommands:";

/// The general help below the command list.
const FOOTER: &str = "\nRun `huntsman-recon <COMMAND> --help` for command details.\nSearch and sources do not collect remote results. `fetch`, `hibp`, `recon`,\n`seeknow`, `people`, `people-discover`, `email`, `exposure`, `username`, `domain`, `network`, `crypto`, `query`, `dehashed`, networked `sf -s` lookups and `scans run` make HTTP requests; `serve` accepts inbound HTTP connections; their default\negress policy is public-only.";

/// Declares the registry: the command table, and the usage line built from it at compile time.
/// The usage line is a `concat!` of the synopses, so the binary holds it as one literal string;
/// the release workflow proves a published binary is huntsman-recon by finding that string in its
/// bytes (`strings | grep 'usage: huntsman-recon \[check'`).
macro_rules! registry {
    (
        name: $first_name:literal, summary: $first_summary:literal,
        synopsis: $first_synopsis:literal, run: $first_run:path;
        $(
            name: $name:literal, summary: $summary:literal,
            synopsis: $synopsis:literal, run: $run:path;
        )*
    ) => {
        /// Every command, in the order the general help and the usage line list them.
        pub(super) const COMMANDS: &[Command] = &[
            Command {
                name: $first_name,
                summary: $first_summary,
                run: $first_run,
            },
            $(
                Command {
                    name: $name,
                    summary: $summary,
                    run: $run,
                },
            )*
        ];

        /// The usage line: every command's synopsis, in order.
        pub(super) const USAGE: &str = concat!(
            "usage: huntsman-recon [",
            $first_synopsis,
            $(" | ", $synopsis,)*
            "]"
        );
    };
}

registry! {
    name: "check", summary: "Run offline self-acceptance; writes var/*.json here",
    synopsis: "check", run: super::selfcheck::check;
    name: "doctor", summary: "Check the whole install and name the fix for each problem",
    synopsis: "doctor [serve] [--fix] [--json] [--probe] [--bind ADDR]", run: super::doctor::doctor_cmd;
    name: "fix", summary: "Run doctor and make every repair that can be undone",
    synopsis: "fix [--json] [--probe] [--bind ADDR]", run: super::doctor::fix_cmd;
    name: "diagnostics", summary: "Print offline build/runtime/module/provider diagnostics",
    synopsis: "diagnostics [--json]", run: super::meta::diagnostics_cmd;
    name: "build-sha", summary: "Print the embedded source commit or unknown",
    synopsis: "build-sha", run: super::meta::build_sha_cmd;
    name: "command", summary: "Print and validate the executable engineering hierarchy",
    synopsis: "command [--json]", run: super::meta::command_cmd;
    name: "directive", summary: "Verify or repair canonical repository instruction mirrors",
    synopsis: "directive check|sync [ROOT]", run: super::meta::directive_cmd;
    name: "geo", summary: "Distance between two LAT,LON coordinates in metres",
    synopsis: "geo LAT,LON LAT,LON", run: super::utility::geo;
    name: "geohash", summary: "Encode LAT,LON (default precision: 7), or decode HASH",
    synopsis: "geohash LAT,LON [PRECISION]|HASH", run: super::utility::geohash_cmd;
    name: "coarsen", summary: "Round LAT,LON to one decimal place",
    synopsis: "coarsen LAT,LON", run: super::utility::coarsen_cmd;
    name: "case-check", summary: "Audit a public OSINT case package and original advert offline",
    synopsis: "case-check CASE-JSON ORIGINAL-ADVERT-TEXT", run: super::case_audit::case_check_cmd;
    name: "blueprint", summary: "The OSINT app blueprint: Android apps and their Huntsman equivalents",
    synopsis: "blueprint [--json] [--docx FILE|-]", run: super::blueprint::blueprint_cmd;
    name: "id", summary: "Classify and validate an Australian ABN, ACN, or BSB",
    synopsis: "id TOKEN...", run: super::utility::id_cmd;
    name: "search", summary: "Search the built-in fixture or one local text directory",
    synopsis: "search QUERY [DIR]", run: super::lookup::search_cmd;
    name: "sources", summary: "Classify an indicator and print curated routes (offline)",
    synopsis: "sources QUERY...", run: super::lookup::sources_cmd;
    name: "domain-lifecycle", summary: "Compare imported domain observations offline",
    synopsis: "domain-lifecycle analyze INPUT --as-of TIME [--output FILE]", run: super::meta::domain_lifecycle_cmd;
    name: "people", summary: "Look up a name on keyless ASIC/ACNC registers and Wikidata",
    synopsis: "people NAME [--save FILE] [--json]", run: super::lookup::people_cmd;
    name: "people-discover", summary: "Unverified public leads for a full name from web indexes and Open Library",
    synopsis: "people-discover [--region au|us|ae] [--bibliography-only] FULL NAME...", run: super::lookup::people_discover_cmd;
    name: "email", summary: "Enrich an email and query its public Gravatar profile",
    synopsis: "email ADDR [--save FILE] [--json]", run: super::lookup::email_cmd;
    name: "exposure", summary: "Keyed breach evidence for an email (HIBP account, stolen.tax, OathNet)",
    synopsis: "exposure ADDR|HANDLE [--save FILE] [--json]", run: super::lookup::exposure_cmd;
    name: "username", summary: "Enrich public profiles, including TikTok self-published bio contacts",
    synopsis: "username HANDLE [--save FILE] [--json]", run: super::lookup::username_cmd;
    name: "phone", summary: "Canonicalise and classify a phone number offline, plus a keyed carrier lookup",
    synopsis: "phone NUMBER [--save FILE] [--json]", run: super::lookup::phone_cmd;
    name: "domain", summary: "Certificate-transparency names and DNS records for one domain, plus keyed reputation and published addresses",
    synopsis: "domain DOMAIN [--save FILE] [--json]", run: super::lookup::domain_cmd;
    name: "ip", summary: "Open ports, routing, scanner status and keyed reputation for one public IP address",
    synopsis: "ip ADDRESS [--save FILE] [--json]", run: super::lookup::ip_cmd;
    name: "netblock", summary: "Registration, routing and every address's PTR names for one public address block",
    synopsis: "netblock CIDR [--save FILE] [--json]", run: super::lookup::netblock_cmd;
    name: "asn", summary: "Registration, holder, every announced prefix and BGP neighbour of one public AS",
    synopsis: "asn AS-NUMBER [--save FILE] [--json]", run: super::lookup::asn_cmd;
    name: "network", summary: "WiFi network by BSSID, SSID or LAT,LON (OUI offline, WiGLE keyed)",
    synopsis: "network BSSID|LAT,LON|ssid:NAME|cell:MCC:MNC:AREA:CELL [--save FILE] [--json]", run: super::lookup::network_cmd;
    name: "osint", summary: "Native source-backed casework, discovery, area risk",
    synopsis: "osint SUBCOMMAND [ARGS]", run: super::osint::osint_cmd;
    name: "security-tools", summary: "Canonical Rust coverage, SHA-256, HTTPS headers and path discovery",
    synopsis: "security-tools catalog|sha256-audit|headers|paths [ARGS]", run: super::security_tools::run;
    name: "crypto", summary: "Bitcoin account summary or read-only Base/Ethereum mainnet wallet or Solana account state (keyless; use base:0x…, eth:0x… or sol:…)",
    synopsis: "crypto BITCOIN-ADDRESS|base:0xADDRESS|eth:0xADDRESS|sol:ADDRESS [--save FILE] [--json]", run: super::lookup::crypto_cmd;
    name: "itunes", summary: "Search the Apple App Store for one keyword (keyless, iTunes Search API)",
    synopsis: "itunes KEYWORD", run: super::lookup::itunes_cmd;
    name: "wikidata", summary: "Look up a Wikidata item and its structured record (keyless)",
    synopsis: "wikidata QUERY", run: super::lookup::wikidata_cmd;
    name: "telegram-network", summary: "Map the public channels a Telegram channel forwards from or links to (keyless, bounded)",
    synopsis: "telegram-network HANDLE [--depth 1-3] [--max 1-50]", run: super::lookup::telegram_network_cmd;
    name: "gleif", summary: "Look up a legal entity on the GLEIF LEI register (keyless)",
    synopsis: "gleif [--country CC] [--jurisdiction CC[-SUB]] LEI|NAME", run: super::lookup::gleif_cmd;
    name: "company", summary: "Look up an Australian organisation on ASIC registers and GLEIF (keyless)",
    synopsis: "company NAME|ACN|ABN", run: super::lookup::company_cmd;
    name: "geocode", summary: "Geocode a place, address or lat,lon point (keyless, OpenStreetMap Nominatim)",
    synopsis: "geocode PLACE|LAT,LON [--save FILE] [--json]", run: super::lookup::geocode_cmd;
    name: "traffic-cameras", summary: "Read-only QLDTraffic public webcam metadata (one-shot, not live imagery)",
    synopsis: "traffic-cameras [--district NAME] [--locality NAME] [--limit N] [--reconcile]", run: super::traffic_cameras::run;
    name: "exif", summary: "Extract EXIF metadata and GPS coordinates from a local image (keyless, offline)",
    synopsis: "exif IMAGE-FILE", run: super::lookup::exif_cmd;
    name: "reverse-image", summary: "SHA-256 of a local image, offline; --live --provider NAME uploads it to that one provider",
    synopsis: "reverse-image IMAGE-FILE [--live --provider NAME] [--json]", run: super::reverse_image::reverse_image_cmd;
    name: "docmeta", summary: "Extract XMP-packet and PDF /Info metadata, with embedded GPS, from a local file (keyless, offline)",
    synopsis: "docmeta FILE", run: super::lookup::docmeta_cmd;
    name: "apk", summary: "Inventory or compare two APK ZIP archives offline (keyless, no root)",
    synopsis: "apk FILE [--json] | apk diff OLD NEW [--json] | apk set FILE [--json]", run: super::apk::apk_cmd;
    name: "source-intel", summary: "Project APK DEX URLs into offline evidence-scoped source leads",
    synopsis: "source-intel apk FILE --json", run: super::source_intel::run;
    name: "mitm", summary: "Offline or live advisory MITM/evil-twin audit",
    synopsis: "mitm audit [--file FILE] [--baseline FILE] [--json] [--require-evaluated] | mitm baseline --ssid SSID --bssid MAC... --minimum-security LEVEL --output FILE --confirmed", run: super::mitm::mitm_cmd;
    name: "radar", summary: "Read rootless Termux:API OS-cached WiFi/cells, import offline radio CSV, or track sweeps",
    synopsis: "radar wifi|cells [--json] [--file TERMUX_SCAN_JSON] | radar ble-adv [--address ADDR] [--raw] [--json] HEX... | radar survey-lte|survey-nr|survey-wifi|survey-bluetooth --file NETWORK_SURVEY_CSV [--json] | radar track [--json] [--wifi-file FILE] [--cells-file FILE] [--log FILE]", run: super::radar::radar_cmd;
    name: "scan", summary: "Route one selector or bounded seed-list into rebuilt lookup front-ends",
    synopsis: "scan SELECTOR [-k people|email|exposure|username|phone|domain|ip|netblock|asn|network|crypto|geocode] [--save FILE] [--json] | scan --input-file FILE [-k people|email|exposure|username|phone|domain|ip|netblock|asn|network|crypto|geocode] [--save-dir DIR] | scan --recurse SELECTOR... [--max-generations N] [--expand-floor F] [--json]", run: super::lookup::scan_cmd;
    name: "investigate", summary: "Extract actionable entities from local text or one bounded file",
    synopsis: "investigate TEXT... [--json]|--file FILE [--json]", run: super::lookup::investigate_cmd;
    name: "plan", summary: "Plan an offline investigation from seeds; save or reload it as a session",
    synopsis: "plan [--session-dir DIR] SEED... | plan --load-session DIR ID", run: super::lookup::plan_cmd;
    name: "research", summary: "Research any term using existing typed or keyless adaptive capabilities",
    synopsis: "research [--plan] [--all] TERM... [--json]", run: super::research::research_cmd;
    name: "query", summary: "Keyless web search; --adaptive aggregates leads; --all asks 13 engines; --exa uses optional search credits",
    synopsis: "query [--adaptive] [--all] QUERY... [--json] | query --exa QUERY... [--json]", run: super::lookup::query_cmd;
    name: "privacy-audit", summary: "Assess a source-backed public entity graph offline (no network)",
    synopsis: "privacy-audit PUBLIC-GRAPH.json", run: super::privacy::privacy_cmd;
    name: "public-osint", summary: "Independent GDELT news, FBI notices and multi-engine public dossiers",
    synopsis: "public-osint news|notices|web|dossier QUERY...", run: super::public_osint::run;
    name: "sf", summary: "SpiderFoot-compatible sf.py front end over saved scans",
    synopsis: "sf [-M|-T|-V]|-s TARGET [options]", run: super::lookup::sf_cmd;
    name: "scans", summary: "Run, list, read, export, flag, rerun and delete saved Spiderfoot-style scans",
    synopsis: "scans run|list|show|summary|elements|correlations|log|export|fp|delete|rerun|types [ARGS]", run: super::scans::scans_cmd;
    name: "serve", summary: "Start the embedded Web UI and JSON API",
    synopsis: "serve [--bind ADDR] [--history DIR]", run: super::service::serve_cmd;
    name: "mcp", summary: "Serve lookups to LLM apps over the Model Context Protocol (stdio)",
    synopsis: "mcp", run: super::mcp::mcp_cmd;
    name: "modules", summary: "List only currently reachable rebuilt modules",
    synopsis: "modules [--json]", run: super::meta::modules_cmd;
    name: "attack", summary: "MITRE ATT&CK Reconnaissance posture, coverage, gaps, or Navigator JSON",
    synopsis: "attack SUBCOMMAND", run: super::meta::attack_cmd;
    name: "classify", summary: "Classify an HTTP status and response body",
    synopsis: "classify STATUS BODY...", run: super::utility::classify;
    name: "fetch", summary: "Make a guarded HTTP request (network access)",
    synopsis: "fetch URL [options]", run: super::network::fetch_cmd;
    name: "hibp", summary: "Have I Been Pwned lookups (opt-in; keyed subcommands need a key)",
    synopsis: "hibp SUBCOMMAND", run: super::network::hibp_cmd;
    name: "dehashed", summary: "DeHashed exact-match search (opt-in; needs a key and --purpose)",
    synopsis: "dehashed SUBCOMMAND", run: super::network::dehashed_cmd;
    name: "recon", summary: "One crt.sh, DNS/mail, or stolen.tax lookup (network access)",
    synopsis: "recon crtsh TARGET|dns TARGET|stolen-tax QUERY [--keys FILE]", run: super::network::recon_cmd;
    name: "seeknow", summary: "SeekNow/See-Know lookup (opt-in; needs HUNTSMAN_SEEKNOW_KEY)",
    synopsis: "seeknow status|credits [--keys FILE] | seeknow search KIND VALUE [--deep|--fast-only] [--keys FILE]", run: super::network::seeknow_cmd;
    name: "keys", summary: "Inspect a private keys file, or set/remove a slot via private storage",
    synopsis: "keys FILE|set SLOT --stdin|remove SLOT", run: super::meta::keys_cmd;
    name: "credential-status", summary: "Show provider credential completeness without values",
    synopsis: "credential-status [--probe] [FILE]", run: super::meta::credential_status_cmd;
    name: "verify", summary: "Verify a saved evidence ledger",
    synopsis: "verify LEDGER", run: super::meta::verify;
    name: "correlate", summary: "Run the correlation rules over a saved scan artifact, and pivot it across a history of saved scans (offline)",
    synopsis: "correlate ARTIFACT [--history DIR]", run: super::meta::correlate_cmd;
    name: "run-history", summary: "Record test-run results and compare each with the earlier runs",
    synopsis: "run-history record|show [options]", run: super::meta::run_history_cmd;
}

/// The command called `name`, if there is one.
pub(super) fn find(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|command| command.name == name)
}

/// The general help: the header, one aligned line per command, and the footer.
pub(super) static HELP: LazyLock<String> = LazyLock::new(|| {
    let mut help = String::from(HEADER);
    for command in COMMANDS {
        let _ = write!(help, "\n  {:<22}{}", command.name, command.summary);
    }
    help.push('\n');
    help.push_str(FOOTER);
    help
});

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{COMMANDS, HELP, USAGE, find};

    #[test]
    fn every_command_is_declared_once_with_a_summary() {
        let mut seen = BTreeSet::new();
        for command in COMMANDS {
            assert!(
                seen.insert(command.name),
                "{} is declared twice",
                command.name
            );
            assert!(
                !command.summary.is_empty(),
                "{} has no summary",
                command.name
            );
        }
    }

    #[test]
    fn every_usage_alternative_belongs_to_a_command_and_every_command_has_one() {
        let body = USAGE
            .strip_prefix("usage: huntsman-recon [")
            .and_then(|rest| rest.strip_suffix(']'))
            .expect("the usage line's frame");
        let mut named = BTreeSet::new();
        for alternative in body.split(" | ") {
            let word = alternative.split(' ').next().unwrap_or_default();
            assert!(find(word).is_some(), "{alternative} names no command");
            named.insert(word);
        }
        for command in COMMANDS {
            assert!(
                named.contains(command.name),
                "{} is not in the usage line",
                command.name
            );
        }
    }

    /// The words of a synopsis, with its `|`, `[]` and `()` grouping removed.
    fn words(synopsis: &str) -> Vec<&str> {
        synopsis
            .split(|c: char| c.is_whitespace() || matches!(c, '|' | '[' | ']' | '(' | ')'))
            .filter(|word| !word.is_empty())
            .collect()
    }

    /// The options a synopsis names: `--word` and `-x`.
    fn flags(synopsis: &str) -> BTreeSet<&str> {
        words(synopsis)
            .into_iter()
            .filter(|word| {
                word.starts_with('-')
                    && word
                        .trim_start_matches('-')
                        .chars()
                        .next()
                        .is_some_and(char::is_alphabetic)
            })
            .collect()
    }

    /// The subcommands a help synopsis names: the lower-case word after the command name in
    /// each alternative (`apk diff`, `keys set`, `attack status|coverage`), never a value
    /// placeholder (`FILE`) or an option.
    fn subcommands<'a>(name: &str, synopsis: &'a str) -> BTreeSet<&'a str> {
        synopsis
            .split(" | ")
            .filter_map(|alternative| {
                let rest = alternative
                    .strip_prefix(name)
                    .map_or(alternative, str::trim_start);
                rest.split_whitespace().next()
            })
            .flat_map(|first| first.split('|'))
            .filter(|word| {
                !word.is_empty()
                    && !word.starts_with('-')
                    && word
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            })
            .collect()
    }

    /// The synopsis lines of a command's own help: its leading lines that start with the command
    /// name (after any `usage: huntsman-recon` prefix) and do not end a sentence (`TOKEN...`
    /// is a synopsis, not a sentence).
    fn help_synopsis(name: &str, help: &str) -> String {
        help.lines()
            .map(|line| line.strip_prefix("usage: huntsman-recon ").unwrap_or(line))
            .take_while(|line| {
                (*line == name || line.starts_with(&format!("{name} ")))
                    && (!line.ends_with('.') || line.ends_with("..."))
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// The usage line is one line for every command, so a synopsis there may abbreviate the
    /// command's own help with `SUBCOMMAND`, `[ARGS]` or `[options]`. It may never name an
    /// option the help does not, and unless it abbreviates, it names every option and every
    /// subcommand the help does: a command whose usage synopsis lags its help is one no one can
    /// find from the usage line (as `apk set`, `scan --recurse` and `mitm baseline` were).
    #[test]
    fn the_usage_line_abbreviates_each_commands_help_and_invents_nothing() {
        let body = USAGE
            .strip_prefix("usage: huntsman-recon [")
            .and_then(|rest| rest.strip_suffix(']'))
            .expect("the usage line's frame");
        for command in COMMANDS {
            let usage: Vec<&str> = body
                .split(" | ")
                .filter(|alternative| {
                    *alternative == command.name
                        || alternative.starts_with(&format!("{} ", command.name))
                })
                .collect();
            let usage = usage.join(" | ");
            let help = super::super::help::command_help(command.name).expect(command.name);
            let help = help_synopsis(command.name, help);
            assert!(
                !help.is_empty(),
                "{}: its help opens with no synopsis",
                command.name
            );
            let (usage_flags, help_flags) = (flags(&usage), flags(&help));
            let invented: Vec<&&str> = usage_flags.difference(&help_flags).collect();
            assert!(
                invented.is_empty(),
                "{}: the usage line names options its help does not: {invented:?}\n  usage: {usage}\n  help:  {help}",
                command.name
            );
            let abbreviates = ["SUBCOMMAND", "[ARGS]", "[options]"]
                .iter()
                .any(|placeholder| usage.contains(placeholder));
            if abbreviates {
                continue;
            }
            let missing: Vec<&&str> = help_flags.difference(&usage_flags).collect();
            assert!(
                missing.is_empty(),
                "{}: its help names options the usage line lacks: {missing:?}\n  usage: {usage}\n  help:  {help}",
                command.name
            );
            let usage_words: BTreeSet<&str> = words(&usage).into_iter().collect();
            let missing: Vec<&str> = subcommands(command.name, &help)
                .into_iter()
                .filter(|subcommand| !usage_words.contains(subcommand))
                .collect();
            assert!(
                missing.is_empty(),
                "{}: its help names subcommands the usage line lacks: {missing:?}\n  usage: {usage}\n  help:  {help}",
                command.name
            );
        }
    }

    #[test]
    fn every_command_has_its_own_help() {
        for command in COMMANDS {
            assert!(
                super::super::help::command_help(command.name).is_some(),
                "{} has no --help text",
                command.name
            );
        }
    }

    #[test]
    fn the_help_lists_every_command_once() {
        for command in COMMANDS {
            let line = format!("\n  {:<22}{}\n", command.name, command.summary);
            assert_eq!(HELP.matches(&line).count(), 1, "{}", command.name);
        }
    }
}
