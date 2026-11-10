//! A conservative universal research entry point over existing Huntsman capabilities.
//!
//! No new HTTP client, persistence model or execution engine. Unknown terms go through the
//! existing keyless adaptive web query; exact, supported identifiers use the existing scan path.

use std::process::ExitCode;

use huntsman_recon::clock;
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::research_route::{self, ResearchAction};
use huntsman_recon::web_query::{self, EngineSet};

use super::{fail, lookup};

const USAGE: &str = "usage: huntsman-recon research [--plan] [--all] TERM... [--json]";

pub(super) const RESEARCH_HELP: &str = "research [--plan] [--all] TERM... [--json]\nResearch arbitrary text using an existing Huntsman capability. Recognised exact identifiers use the established typed scan route; general phrases use the keyless adaptive web search over Bing, Brave and Mojeek. A coordinate point uses geocode rather than the older scan radio-area default. --plan selects and prints the route offline without fetching. --all asks all 13 keyless engines on the adaptive web route instead, inside one 110-second budget, as query --adaptive --all does; a typed scan route is unchanged. A typed scan can invoke existing configured source integrations; for guaranteed keyless research use query --adaptive. --json, given anywhere, prints one JSON object on one line instead of the text or pretty-printed report: on the typed scan route the shape GET /api/lookup returns; on the adaptive web route the shape GET /api/research and the MCP research tool return, with route adaptive_web_search and the report; with --plan, the chosen route as an object. Does not require root or a runtime LLM.";

pub(super) fn research_cmd(args: &[String]) -> ExitCode {
    // `--json` is taken from wherever it was typed, as the typed lookups take it.
    let (args, json) = match lookup::take_json(args) {
        Ok(split) => split,
        Err(error) => return fail(EX_USAGE, &format!("{error}\n{USAGE}")),
    };
    let mut preview = false;
    let mut all = false;
    let mut offset = 0;
    while let Some(flag) = args.get(offset).map(String::as_str) {
        match flag {
            "--plan" if !preview => preview = true,
            "--all" if !all => all = true,
            _ => break,
        }
        offset += 1;
    }
    let terms = &args[offset..];
    if terms.is_empty() || terms.iter().any(|value| value.starts_with("--")) {
        return fail(EX_USAGE, USAGE);
    }

    let input = terms.join(" ");
    let action = match research_route::plan(&input) {
        Ok(action) => action,
        Err(message) => return fail(EX_USAGE, message),
    };
    match action {
        ResearchAction::Targeted { kind, selector } => {
            if preview {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"route": "scan", "kind": kind.command()})
                    );
                } else {
                    println!("route=scan\tkind={}", kind.command());
                }
                return ExitCode::SUCCESS;
            }
            // An explicit kind prevents inference changing the target after canonicalisation.
            let mut scan = vec![selector, "-k".into(), kind.command().into()];
            if json {
                scan.push("--json".into());
            }
            lookup::scan_cmd(&scan)
        }
        ResearchAction::AdaptiveWeb { query } => {
            if preview {
                // `--all` changes only this route, so only its preview names the engine set.
                if json {
                    let mut plan = serde_json::json!({
                        "route": "adaptive_web_search",
                        "keyless": true,
                    });
                    if all {
                        plan["engines"] = serde_json::json!("all");
                    }
                    println!("{plan}");
                } else {
                    let engines = if all { "\tengines=all" } else { "" };
                    println!("route=adaptive_web_search\tkeyless=true{engines}");
                }
                return ExitCode::SUCCESS;
            }
            if json {
                let engines = if all {
                    EngineSet::All
                } else {
                    EngineSet::Default
                };
                return adaptive_json(&query, engines);
            }
            if all {
                lookup::query_cmd(&["--adaptive".into(), "--all".into(), query])
            } else {
                lookup::query_cmd(&["--adaptive".into(), query])
            }
        }
    }
}

/// The adaptive web route as one JSON object, the shape `GET /api/research` answers; exit 69
/// when no engine returned a hit, as `query --adaptive` does.
fn adaptive_json(query: &str, engines: EngineSet) -> ExitCode {
    let transport = UreqTransport::new(&TransportConfig::default());
    match web_query::adaptive_search(&transport, query, clock::unix_now(), engines) {
        Ok(report) => {
            let found = !report.hits.is_empty();
            println!("{}", super::service::research_json(&report));
            if found {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EX_UNAVAILABLE)
            }
        }
        Err(Error::Invalid(message)) => fail(EX_USAGE, &message),
        Err(Error::Network(message)) => fail(EX_NOPERM, &message),
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{ResearchAction, research_route};

    #[test]
    fn a_dry_run_is_offline_for_arbitrary_terms_and_known_indicators() {
        assert_eq!(
            research_route::plan("anything goes"),
            Ok(ResearchAction::AdaptiveWeb {
                query: "anything goes".into()
            })
        );
        assert_eq!(
            research_route::plan("example.org"),
            Ok(ResearchAction::Targeted {
                kind: huntsman_recon::scan_route::ScanKind::Domain,
                selector: "example.org".into()
            })
        );
    }
}
