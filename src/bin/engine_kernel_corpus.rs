//! Soundness harness for the experimental native engine kernel.
//!
//! ```sh
//! nix develop -c cargo run --no-default-features --features engine-kernel \
//!     --bin engine-kernel-corpus
//! ```
//!
//! Exit code 1 when the covered subset has a false negative.

use waf_ingress::waf::engine_kernel::corpus::run_path;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/corpus/crs/corpus.json".to_string());
    let report = match run_path(&path) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };

    println!("CRS corpus soundness: {path}");
    println!(
        "total={} covered={} ({:.1}%) block={} allow={} passed={}",
        report.total,
        report.covered,
        report.coverage_percent(),
        report.covered_block,
        report.covered_allow,
        report.passed
    );
    println!(
        "false negatives={} false positives={} uncovered={}",
        report.false_negatives.len(),
        report.false_positives.len(),
        report.uncovered
    );

    if !report.false_negatives.is_empty() {
        println!("\nFalse negatives:");
        for failure in &report.false_negatives {
            println!(
                "  {} expected={:?} observed={:?}",
                failure.id, failure.expected_rule_ids, failure.observed
            );
        }
    }
    if !report.false_positives.is_empty() {
        println!("\nFalse positives (covered negative cases):");
        for failure in &report.false_positives {
            println!(
                "  {} expected={:?} observed={:?}",
                failure.id, failure.expected_rule_ids, failure.observed
            );
        }
    }

    println!("\nCovered cases by rule:");
    let mut per_rule: Vec<(u32, usize)> = report.per_rule_cases.into_iter().collect();
    per_rule.sort_by_key(|(rule, count)| (std::cmp::Reverse(*count), *rule));
    for (rule, count) in per_rule {
        println!("  {rule}: {count}");
    }

    if !report.false_negatives.is_empty() {
        std::process::exit(1);
    }
}
