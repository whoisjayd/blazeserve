//! The `compare` command: reads two artifacts and reports their medians side by side.

use super::CompareArgs;
use super::schema::Artifact;
use super::validate::parse;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(super) struct Row {
    pub workload: String,
    pub unit: &'static str,
    pub a_median: Option<f64>,
    pub b_median: Option<f64>,
    pub delta: Option<f64>,
    pub percent: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(super) struct Comparison {
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
}

/// Report medians side by side. No threshold or significance is applied.
pub(super) fn compare(a: &Artifact, b: &Artifact) -> Comparison {
    let mut notes = Vec::new();
    if a.fixture != b.fixture {
        notes.push("fixture parameters differ between the artifacts".into());
    }
    if a.environment != b.environment {
        notes.push("environment differs between the artifacts".into());
    }
    if a.server.args != b.server.args {
        notes.push("server arguments differ between the artifacts".into());
    }
    let mut rows = Vec::new();
    for wa in &a.workloads {
        let Some(wb) = b.workloads.iter().find(|w| w.id == wa.id) else {
            notes.push(format!("workload {} is only in the first artifact", wa.id));
            continue;
        };
        let (am, bm) = (wa.summary.median, wb.summary.median);
        let delta = am.zip(bm).map(|(x, y)| y - x);
        let percent = am
            .zip(bm)
            .and_then(|(x, y)| (x > 0.0).then(|| (y - x) / x * 100.0));
        rows.push(Row {
            workload: wa.id.clone(),
            unit: "MiB/s",
            a_median: am,
            b_median: bm,
            delta,
            percent,
        });
    }
    for wb in &b.workloads {
        if !a.workloads.iter().any(|w| w.id == wb.id) {
            notes.push(format!("workload {} is only in the second artifact", wb.id));
        }
    }
    Comparison { rows, notes }
}

fn read_artifact(path: &std::path::Path) -> Result<Artifact, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    parse(&text).map_err(|e| format!("{} is not a valid artifact: {e}", path.display()))
}

fn print_comparison(c: &Comparison) {
    let num = |v: Option<f64>| v.map_or_else(|| "n/a".to_owned(), |v| format!("{v:.2}"));
    let signed = |v: Option<f64>, suffix: &str| {
        v.map_or_else(|| "n/a".to_owned(), |v| format!("{v:+.2}{suffix}"))
    };
    println!(
        "{:<8} {:>12} {:>12} {:>12} {:>9}",
        "Workload", "A median", "B median", "Delta", "Change"
    );
    for r in &c.rows {
        println!(
            "{:<8} {:>12} {:>12} {:>12} {:>9}",
            r.workload,
            num(r.a_median),
            num(r.b_median),
            signed(r.delta, ""),
            signed(r.percent, "%")
        );
    }
    println!("\nMedians in MiB/s. No threshold or significance test is applied.");
    for note in &c.notes {
        println!("Note: {note}");
    }
}

pub(super) fn run(args: &CompareArgs) -> Result<u8, String> {
    let a = read_artifact(&args.a)?;
    let b = read_artifact(&args.b)?;
    let comparison = compare(&a, &b);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&comparison).map_err(|e| e.to_string())?
        );
    } else {
        print_comparison(&comparison);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::bench::stats::summarize;
    use crate::cli::bench::test_support::good;

    #[test]
    fn compare_reports_delta_without_thresholds() {
        let a = good();
        let mut b = good();
        for s in &mut b.workloads[0].samples {
            s.throughput_mib_per_second = s.throughput_mib_per_second.map(|t| t * 2.0);
        }
        b.workloads[0].summary = summarize(
            &b.workloads[0]
                .samples
                .iter()
                .filter_map(|s| s.throughput_mib_per_second)
                .collect::<Vec<_>>(),
        );
        let c = compare(&a, &b);
        let row = &c.rows[0];
        assert_eq!(row.a_median, Some(11.0));
        assert_eq!(row.b_median, Some(22.0));
        assert_eq!(row.delta, Some(11.0));
        assert_eq!(row.percent, Some(100.0));
        assert!(c.notes.is_empty());
    }
}
