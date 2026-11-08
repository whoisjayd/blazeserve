//! Throughput, sample counts and the summary statistics of successful samples.

use super::schema::{Counts, Sample, Summary, Workload};

const MIB: f64 = 1024.0 * 1024.0;

pub(super) fn throughput(bytes: u64, seconds: f64) -> f64 {
    (bytes as f64 / MIB) / seconds.max(f64::EPSILON)
}

/// Summary over successful samples only; failed and incomplete transfers never count
/// as throughput.
pub(super) fn summarize(values: &[f64]) -> Summary {
    let mut summary = Summary {
        unit: "MiB/s".into(),
        samples_used: values.len() as u64,
        median: None,
        mean: None,
        min: None,
        max: None,
        stddev: None,
        p95: None,
        reason: None,
    };
    if values.is_empty() {
        summary.reason = Some("no successful samples".into());
        return summary;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let mean = sorted.iter().sum::<f64>() / n as f64;
    summary.median = Some(if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    });
    summary.mean = Some(mean);
    summary.min = Some(sorted[0]);
    summary.max = Some(sorted[n - 1]);
    // Nearest-rank percentile.
    let rank = ((0.95 * n as f64).ceil() as usize).clamp(1, n);
    summary.p95 = Some(sorted[rank - 1]);
    if n >= 2 {
        let var = sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
        summary.stddev = Some(var.sqrt());
    } else {
        summary.reason = Some("stddev needs at least 2 successful samples".into());
    }
    summary
}

pub(super) fn count(samples: &[Sample]) -> Counts {
    let mut c = Counts::default();
    for s in samples {
        match s.status.as_str() {
            "ok" => c.ok += 1,
            "incomplete" => c.incomplete += 1,
            _ => c.failed += 1,
        }
    }
    c
}

pub(super) fn totals(workloads: &[Workload]) -> Counts {
    workloads.iter().fold(Counts::default(), |mut t, w| {
        t.ok += w.counts.ok;
        t.incomplete += w.counts.incomplete;
        t.failed += w.counts.failed;
        t
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistics() {
        let s = summarize(&[4.0, 1.0, 2.0, 3.0]);
        assert_eq!(s.median, Some(2.5));
        assert_eq!(s.mean, Some(2.5));
        assert_eq!((s.min, s.max), (Some(1.0), Some(4.0)));
        assert_eq!(s.p95, Some(4.0));
        assert!((s.stddev.unwrap() - 1.2909944).abs() < 1e-6);
        let one = summarize(&[7.0]);
        assert_eq!((one.median, one.stddev), (Some(7.0), None));
        assert!(one.reason.is_some());
        let none = summarize(&[]);
        assert_eq!((none.median, none.samples_used), (None, 0));
    }
}
