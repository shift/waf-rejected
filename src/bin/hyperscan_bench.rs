//! Benchmark for the experimental Vectorscan/Hyperscan CRS body prefilter.
//!
//! ```text
//! nix develop -c cargo run --release --features hyperscan-eval \
//!   --bin hyperscan-bench -- --reps 100
//! ```
//!
//! The harness loads the committed `rules/crs/prefilter.json` artifact,
//! compiles its gated literal sets into block-mode Vectorscan databases, and
//! measures three things at 1/4/8/16/64 KiB:
//!
//! * the raw multi-pattern scanner floor (all literals, one pass, no
//!   transform machinery; **not** a sound prefilter),
//! * the sound prefilter with content-type-aware extraction (one of four body
//!   representations), and
//! * the sound prefilter with all four extraction variants, matching the
//!   existing Aho-Corasick prefilter's over-approximation.
//!
//! The existing Aho-Corasick prefilter is measured on the same bodies. Full
//! Coraza numbers are not re-measured here; the report in
//! `docs/suggestions_from_agents/hyperscan-evaluation.md` compares against the
//! native sidecar measured in this session with
//! `crs-prefilter-bench --socket` (same host).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use waf_ingress::waf::hyperscan::{version, HsScanner, LiteralPattern};
use waf_ingress::waf::prefilter::{
    extract_view, Prefilter, TransformChain, EMBEDDED_ARTIFACT, EXTRACTION_VARIANTS,
};
use waf_ingress::waf::prefilter_extract::PrefilterArtifact;

const BODY_SIZES: [usize; 5] = [1024, 4 * 1024, 8 * 1024, 16 * 1024, 64 * 1024];

#[derive(Debug, serde::Deserialize)]
struct Corpus {
    #[serde(default)]
    benign: Vec<Case>,
    #[serde(default)]
    attacks: Vec<Case>,
}

#[derive(Debug, serde::Deserialize)]
struct Case {
    #[serde(default)]
    name: String,
    #[serde(default)]
    body: String,
}

type LiteralKey = (String, bool);
type RuleIds = BTreeSet<u32>;
type GroupLiterals = BTreeMap<LiteralKey, RuleIds>;
type PendingGroups = BTreeMap<Vec<String>, GroupLiterals>;

/// Neutral fillers, tried in order. A clean body must not hit any literal, so
/// the harness verifies the choice against both engines before measuring.
const FILLERS: [&str; 5] = [
    "zq",
    "qz",
    "jqxv",
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ",
    "abcdefghijklmnopqrstuvwxyz0123456789 ",
];

#[derive(Debug, Clone, Copy)]
struct Stats {
    p50: Duration,
    p95: Duration,
    mean: Duration,
}

impl Stats {
    fn throughput_mb_s(&self, bytes: usize) -> f64 {
        let seconds = self.mean.as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        (bytes as f64 / (1024.0 * 1024.0)) / seconds
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let index = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn stats(mut samples: Vec<Duration>) -> Stats {
    samples.sort_unstable();
    let total: Duration = samples.iter().sum();
    let mean = total / samples.len().max(1) as u32;
    Stats {
        p50: percentile(&samples, 0.50),
        p95: percentile(&samples, 0.95),
        mean,
    }
}

fn measure<F>(body: &[u8], reps: usize, warmup: usize, mut f: F) -> (Stats, bool)
where
    F: FnMut(&[u8]) -> bool,
{
    for _ in 0..warmup {
        let _ = f(body);
    }
    let mut samples = Vec::with_capacity(reps);
    let mut hit = false;
    for _ in 0..reps {
        let started = Instant::now();
        hit = f(body);
        samples.push(started.elapsed());
    }
    (stats(samples), hit)
}

fn fill_to(size: usize, unit: &str) -> Vec<u8> {
    let unit = unit.as_bytes();
    let mut body = Vec::with_capacity(size + unit.len());
    while body.len() < size {
        body.extend_from_slice(unit);
    }
    body.truncate(size);
    body
}

fn attack_body(size: usize, filler: &str) -> Vec<u8> {
    let prefix = b"username=admin&password=x+union+select+password+from+users&data=";
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(prefix);
    while body.len() < size {
        body.extend_from_slice(filler.as_bytes());
    }
    body.truncate(size);
    body
}

fn extraction_for(content_type: &str) -> usize {
    match content_type {
        "form" | "urlencoded" => 1,
        "json" => 2,
        "xml" | "html" => 3,
        _ => 0,
    }
}

fn scan_groups(groups: &[Group], body: &[u8], extractions: &[usize], fast: bool) -> (bool, usize) {
    let mut hit = false;
    let mut scanned_bytes = 0usize;
    'outer: for &extraction in extractions {
        // Extract once per representation. In fast mode every group reuses
        // this buffer unless a transform is actually needed.
        let extracted = extract_view(body, extraction);
        for group in groups {
            let view: Cow<'_, [u8]> = if fast {
                group.chain.apply_view(&extracted)
            } else {
                Cow::Owned(group.chain.apply_view_naive(&extracted))
            };
            scanned_bytes += view.len();
            let matched = group.scanner.scan(&view).expect("vectorscan scan");
            if matched.hit {
                hit = true;
                break 'outer;
            }
        }
    }
    (hit, scanned_bytes)
}

struct Group {
    chain: TransformChain,
    scanner: HsScanner,
}

fn load_groups(artifact: &PrefilterArtifact) -> (Vec<Group>, HsScanner, usize) {
    // Key by transform chain only; case sensitivity is a per-pattern flag, so
    // caseless and case-sensitive literals can share one database.
    let mut pending: PendingGroups = BTreeMap::new();
    for gate in artifact.rules.iter().filter(|gate| gate.gated) {
        for literal_group in &gate.literal_groups {
            let entry = pending.entry(literal_group.transforms.clone()).or_default();
            for literal in &literal_group.literals {
                if literal.is_empty() {
                    continue;
                }
                entry
                    .entry((literal.clone(), literal_group.case_insensitive))
                    .or_default()
                    .insert(gate.id);
            }
        }
    }

    let mut groups = Vec::with_capacity(pending.len());
    let mut patterns = 0usize;
    let mut raw_patterns: GroupLiterals = BTreeMap::new();
    for (transforms, literals) in pending {
        let literal_patterns: Vec<LiteralPattern> = literals
            .into_iter()
            .map(|((literal, caseless), ids)| {
                raw_patterns
                    .entry((literal.clone(), caseless))
                    .or_default()
                    .extend(ids.iter().copied());
                LiteralPattern {
                    literal,
                    caseless,
                    rule_ids: ids.into_iter().collect(),
                }
            })
            .collect();
        patterns += literal_patterns.len();
        let chain = TransformChain::parse(&transforms).expect("known transforms");
        let scanner = HsScanner::compile(&literal_patterns).expect("compile literal group");
        groups.push(Group { chain, scanner });
    }

    let raw_literals: Vec<LiteralPattern> = raw_patterns
        .into_iter()
        .map(|((literal, caseless), ids)| LiteralPattern {
            literal,
            caseless,
            rule_ids: ids.into_iter().collect(),
        })
        .collect();
    let raw = HsScanner::compile(&raw_literals).expect("compile raw scanner");
    (groups, raw, patterns)
}

fn main() {
    let mut reps = 100usize;
    let mut warmup = 3usize;
    let mut content_type = "form".to_string();
    let mut json_out: Option<PathBuf> = None;
    let mut corpus_path = PathBuf::from("tests/corpus/crs-prefilter-corpus.json");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--reps" => reps = args.next().and_then(|v| v.parse().ok()).unwrap_or(reps),
            "--warmup" => warmup = args.next().and_then(|v| v.parse().ok()).unwrap_or(warmup),
            "--content-type" => {
                content_type = args.next().unwrap_or(content_type);
            }
            "--corpus" => corpus_path = args.next().map(PathBuf::from).unwrap_or(corpus_path),
            "--json-out" => json_out = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!(
                    "hyperscan-bench [--reps N] [--warmup N] \
                     [--content-type form|json|xml|text] [--corpus <json>] [--json-out <json>]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let artifact: PrefilterArtifact =
        serde_json::from_str(EMBEDDED_ARTIFACT).expect("embedded prefilter artifact parses");
    let load_started = Instant::now();
    let prefilter = Prefilter::from_json(EMBEDDED_ARTIFACT).expect("aho-corasick prefilter loads");
    let ac_load = load_started.elapsed();

    let compile_started = Instant::now();
    let (groups, raw, pattern_count) = load_groups(&artifact);
    let compile_elapsed = compile_started.elapsed();
    let db_bytes: usize = groups
        .iter()
        .filter_map(|g| g.scanner.database_size())
        .sum();

    let extraction = extraction_for(&content_type);
    let coverage = &artifact.coverage;

    println!("# Vectorscan/Hyperscan CRS body prefilter evaluation");
    println!();
    println!("- vectorscan: {}", version());
    println!(
        "- artifact: {} distinct literals, {}/{} body-relevant entries gated, {} transform chains",
        coverage.distinct_literals,
        coverage.body_relevant_gated,
        coverage.body_relevant_entries,
        groups.len()
    );
    println!(
        "- compiled: {} literal patterns in {} databases, {} KiB, {:.1} ms",
        pattern_count,
        groups.len(),
        db_bytes / 1024,
        compile_elapsed.as_secs_f64() * 1e3
    );
    println!(
        "- aho-corasick prefilter: {} automata, load {:.1} ms",
        prefilter.automaton_count(),
        ac_load.as_secs_f64() * 1e3
    );
    println!("- content-type: {content_type} (extraction {extraction} of {EXTRACTION_VARIANTS})");
    println!("- reps: {reps}, warmup: {warmup}");
    println!();

    // Pick a filler that produces no literal hit on either engine.
    let mut clean_unit = FILLERS[0];
    for candidate in FILLERS {
        let probe = fill_to(1024, candidate);
        let (hs_hit, _) = scan_groups(&groups, &probe, &[extraction], true);
        if !hs_hit && !prefilter.evaluate(&probe).hit {
            clean_unit = candidate;
            break;
        }
    }

    let mut json_rows = Vec::new();

    println!("## Clean body (no literal hit, filler `{clean_unit}`)");
    println!();
    println!("- `hs-fast`: sound prefilter, content-type extraction, shared extraction + no-op transform skip.");
    println!("- `hs-naive`: same extraction but re-runs extraction/transforms per group, like the AC prefilter.");
    println!("- `hs-all`: fast mode over all four extraction variants (over-approximation).");
    println!();
    println!(
        "| size | hs-raw MB/s | hs-raw p50 | hs-fast MB/s | hs-fast p50 | hs-fast p95 | hs-naive MB/s | hs-naive p50 | hs-naive p95 | hs-all MB/s | hs-all p50 | hs-all p95 | ac MB/s | ac p50 | ac p95 |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for &size in &BODY_SIZES {
        let body = fill_to(size, clean_unit);
        let (raw_stats, raw_hit) =
            measure(&body, reps, warmup, |b| raw.scan(b).expect("raw scan").hit);
        let (fast_stats, fast_hit) = measure(&body, reps, warmup, |b| {
            scan_groups(&groups, b, &[extraction], true).0
        });
        let (naive_stats, naive_hit) = measure(&body, reps, warmup, |b| {
            scan_groups(&groups, b, &[extraction], false).0
        });
        let (all_stats, all_hit) = measure(&body, reps, warmup, |b| {
            scan_groups(&groups, b, &[0, 1, 2, 3], true).0
        });
        let (ac_stats, ac_hit) = measure(&body, reps, warmup, |b| prefilter.evaluate(b).hit);

        if raw_hit || fast_hit || naive_hit || all_hit || ac_hit {
            eprintln!("warning: clean body at {size} produced a hit");
        }
        println!(
            "| {} KiB | {:.0} | {:.1} µs | {:.1} | {:.1} µs | {:.1} µs | {:.1} | {:.1} µs | {:.1} µs | {:.1} | {:.1} µs | {:.1} µs | {:.1} | {:.1} µs | {:.1} µs |",
            size / 1024,
            raw_stats.throughput_mb_s(size),
            raw_stats.p50.as_secs_f64() * 1e6,
            fast_stats.throughput_mb_s(size),
            fast_stats.p50.as_secs_f64() * 1e6,
            fast_stats.p95.as_secs_f64() * 1e6,
            naive_stats.throughput_mb_s(size),
            naive_stats.p50.as_secs_f64() * 1e6,
            naive_stats.p95.as_secs_f64() * 1e6,
            all_stats.throughput_mb_s(size),
            all_stats.p50.as_secs_f64() * 1e6,
            all_stats.p95.as_secs_f64() * 1e6,
            ac_stats.throughput_mb_s(size),
            ac_stats.p50.as_secs_f64() * 1e6,
            ac_stats.p95.as_secs_f64() * 1e6,
        );
        json_rows.push(serde_json::json!({
            "body": "clean",
            "size_bytes": size,
            "hs_raw": {"mb_s": raw_stats.throughput_mb_s(size), "p50_us": raw_stats.p50.as_secs_f64()*1e6, "p95_us": raw_stats.p95.as_secs_f64()*1e6},
            "hs_fast": {"mb_s": fast_stats.throughput_mb_s(size), "p50_us": fast_stats.p50.as_secs_f64()*1e6, "p95_us": fast_stats.p95.as_secs_f64()*1e6},
            "hs_naive": {"mb_s": naive_stats.throughput_mb_s(size), "p50_us": naive_stats.p50.as_secs_f64()*1e6, "p95_us": naive_stats.p95.as_secs_f64()*1e6},
            "hs_all_extractions": {"mb_s": all_stats.throughput_mb_s(size), "p50_us": all_stats.p50.as_secs_f64()*1e6, "p95_us": all_stats.p95.as_secs_f64()*1e6},
            "aho_corasick": {"mb_s": ac_stats.throughput_mb_s(size), "p50_us": ac_stats.p50.as_secs_f64()*1e6, "p95_us": ac_stats.p95.as_secs_f64()*1e6},
        }));
    }
    println!();

    println!("## Attack body (first-hit path)");
    println!();
    println!(
        "| size | hs-fast p50 | hs-fast p95 | hs-naive p50 | hs-naive p95 | hs-all p50 | hs-all p95 | ac p50 | ac p95 |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for &size in &BODY_SIZES {
        let body = attack_body(size, clean_unit);
        let (fast_stats, fast_hit) = measure(&body, reps, warmup, |b| {
            scan_groups(&groups, b, &[extraction], true).0
        });
        let (naive_stats, naive_hit) = measure(&body, reps, warmup, |b| {
            scan_groups(&groups, b, &[extraction], false).0
        });
        let (all_stats, all_hit) = measure(&body, reps, warmup, |b| {
            scan_groups(&groups, b, &[0, 1, 2, 3], true).0
        });
        let (ac_stats, ac_hit) = measure(&body, reps, warmup, |b| prefilter.evaluate(b).hit);
        if !fast_hit || !naive_hit || !all_hit || !ac_hit {
            eprintln!("warning: attack body at {size} missed");
        }
        println!(
            "| {} KiB | {:.1} µs | {:.1} µs | {:.1} µs | {:.1} µs | {:.1} µs | {:.1} µs | {:.1} µs | {:.1} µs |",
            size / 1024,
            fast_stats.p50.as_secs_f64() * 1e6,
            fast_stats.p95.as_secs_f64() * 1e6,
            naive_stats.p50.as_secs_f64() * 1e6,
            naive_stats.p95.as_secs_f64() * 1e6,
            all_stats.p50.as_secs_f64() * 1e6,
            all_stats.p95.as_secs_f64() * 1e6,
            ac_stats.p50.as_secs_f64() * 1e6,
            ac_stats.p95.as_secs_f64() * 1e6,
        );
        json_rows.push(serde_json::json!({
            "body": "attack",
            "size_bytes": size,
            "hs_fast": {"p50_us": fast_stats.p50.as_secs_f64()*1e6, "p95_us": fast_stats.p95.as_secs_f64()*1e6},
            "hs_naive": {"p50_us": naive_stats.p50.as_secs_f64()*1e6, "p95_us": naive_stats.p95.as_secs_f64()*1e6},
            "hs_all_extractions": {"p50_us": all_stats.p50.as_secs_f64()*1e6, "p95_us": all_stats.p95.as_secs_f64()*1e6},
            "aho_corasick": {"p50_us": ac_stats.p50.as_secs_f64()*1e6, "p95_us": ac_stats.p95.as_secs_f64()*1e6},
        }));
    }
    println!();

    println!("## Coverage and soundness");
    println!();
    println!(
        "- gated body-relevant entries: {} / {} ({:.1}%)",
        coverage.body_relevant_gated,
        coverage.body_relevant_entries,
        100.0 * coverage.body_relevant_gated as f64 / coverage.body_relevant_entries as f64
    );
    println!(
        "- ungated body-relevant entries: {} (must stay in Coraza)",
        coverage.body_relevant_ungated
    );
    println!(
        "- all body rules gated: {} (body-withholding fast path available: {})",
        coverage.all_body_rules_gated,
        prefilter.all_body_rules_gated()
    );
    println!();

    println!("## Corpus parity against the Aho-Corasick prefilter");
    println!();
    match std::fs::read_to_string(&corpus_path) {
        Ok(text) => match serde_json::from_str::<Corpus>(&text) {
            Ok(corpus) => {
                let cases = corpus.benign.iter().chain(corpus.attacks.iter());
                let mut total = 0usize;
                let mut ac_hits = 0usize;
                let mut hs_hits = 0usize;
                let mut ac_only = Vec::new();
                let mut hs_only = Vec::new();
                for case in cases {
                    total += 1;
                    let body = case.body.as_bytes();
                    let ac = prefilter.evaluate(body).hit;
                    let (hs, _) = scan_groups(&groups, body, &[0, 1, 2, 3], true);
                    ac_hits += usize::from(ac);
                    hs_hits += usize::from(hs);
                    if ac && !hs {
                        ac_only.push(case.name.clone());
                    }
                    if hs && !ac {
                        hs_only.push(case.name.clone());
                    }
                }
                println!("- corpus: `{}` ({total} cases)", corpus_path.display());
                println!("- hits: aho-corasick {ac_hits}, hyperscan {hs_hits}");
                println!(
                    "- aho-corasick hit but hyperscan miss (must be 0): {}",
                    ac_only.len()
                );
                if !ac_only.is_empty() {
                    println!("  - {}", ac_only.join(", "));
                }
                println!(
                    "- hyperscan hit but aho-corasick miss (expected 0): {}",
                    hs_only.len()
                );
                if !hs_only.is_empty() {
                    println!("  - {}", hs_only.join(", "));
                }
            }
            Err(err) => println!("- corpus parse failed: {err}"),
        },
        Err(err) => println!("- corpus unavailable at {}: {err}", corpus_path.display()),
    }
    println!();

    println!("## Full Coraza reference (native sidecar, same host, measured 2026-11-02)");
    println!();
    println!("| body | full CRS p50 | gated rules removed p50 |");
    println!("|---:|---:|---:|");
    println!("| 1 KiB | 10.10 ms | 6.78 ms |");
    println!("| 4 KiB | 37.64 ms | 25.09 ms |");
    println!("| 8 KiB | 74.57 ms | 52.71 ms |");
    println!("| 16 KiB | 149.22 ms | 99.58 ms |");
    println!("| 60 KiB | 571.38 ms | 352.55 ms |");
    println!();

    if let Some(path) = json_out {
        let payload = serde_json::json!({
            "vectorscan": version(),
            "artifact": {
                "distinct_literals": coverage.distinct_literals,
                "gated": coverage.body_relevant_gated,
                "body_relevant": coverage.body_relevant_entries,
                "ungated": coverage.body_relevant_ungated,
                "transform_chains": groups.len(),
                "patterns": pattern_count,
                "database_kib": db_bytes / 1024,
            },
            "content_type": content_type,
            "reps": reps,
            "rows": json_rows,
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&payload).expect("json"))
            .expect("write json output");
        println!("wrote {}", path.display());
    }
}
