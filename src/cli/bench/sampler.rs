//! Workload definitions and timed download samples.

use super::fixture::{FIXTURE_NAME, MIB};
use super::schema::{Sample, Workload};
use super::stats::{count, summarize, throughput};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum WorkloadSel {
    Full,
    Range,
    Both,
}

pub(super) struct Spec {
    id: &'static str,
    description: &'static str,
    path: String,
    range: Option<(u64, u64)>,
    expected: u64,
}

pub(super) fn specs(workload: WorkloadSel, external: bool, size: u64) -> Vec<Spec> {
    let full = if external {
        Spec {
            id: "full",
            description: "full download of /__speed__ from an external server",
            path: format!("/__speed__?bytes={size}"),
            range: None,
            expected: size,
        }
    } else {
        Spec {
            id: "full",
            description: "full-file GET of the fixture",
            path: format!("/{FIXTURE_NAME}"),
            range: None,
            expected: size,
        }
    };
    // The middle half of the file: starts off-zero so it cannot take a full-file path.
    let start = size / 4;
    let len = size / 2;
    let range = Spec {
        id: "range",
        description: "single byte range covering the middle half of the fixture",
        path: format!("/{FIXTURE_NAME}"),
        range: Some((start, start + len - 1)),
        expected: len,
    };
    match workload {
        WorkloadSel::Full => vec![full],
        WorkloadSel::Range => vec![range],
        WorkloadSel::Both => vec![full, range],
    }
}

fn sample_once(agent: &ureq::Agent, base: &str, spec: &Spec, index: u32) -> Sample {
    let url = format!("{base}{}", spec.path);
    let mut sample = Sample {
        base_url: base.to_owned(),
        workload: spec.id.to_owned(),
        index,
        status: "failed".into(),
        requested_bytes: spec.expected,
        downloaded_bytes: 0,
        elapsed_seconds: 0.0,
        throughput_mib_per_second: None,
        http_status: None,
        failure: None,
    };
    let start = Instant::now();
    let mut request = agent.get(&url);
    if let Some((first, last)) = spec.range {
        request = request.header("Range", format!("bytes={first}-{last}").as_str());
    }
    let response = match request.call() {
        Ok(r) => r,
        Err(e) => {
            sample.elapsed_seconds = start.elapsed().as_secs_f64();
            sample.failure = Some(format!("request failed: {e}"));
            return sample;
        }
    };
    let code = response.status().as_u16();
    sample.http_status = Some(code);
    let wanted = if spec.range.is_some() { 206 } else { 200 };
    if code != wanted {
        sample.elapsed_seconds = start.elapsed().as_secs_f64();
        sample.failure = Some(format!("expected HTTP {wanted}, received {code}"));
        return sample;
    }
    let mut reader = response.into_body().into_reader();
    let mut buf = vec![0u8; MIB as usize];
    let mut read_error = None;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => sample.downloaded_bytes += n as u64,
            Err(e) => {
                read_error = Some(e.to_string());
                break;
            }
        }
    }
    sample.elapsed_seconds = start.elapsed().as_secs_f64();
    let got = sample.downloaded_bytes;
    if got > spec.expected {
        sample.failure = Some(format!("received {got} bytes, expected {}", spec.expected));
    } else if got < spec.expected {
        sample.status = "incomplete".into();
        sample.failure = Some(match read_error {
            Some(e) => format!(
                "transfer interrupted after {got} of {} bytes: {e}",
                spec.expected
            ),
            None => format!("server closed after {got} of {} bytes", spec.expected),
        });
    } else if let Some(e) = read_error {
        sample.failure = Some(format!("read error after the last byte: {e}"));
    } else {
        sample.status = "ok".into();
        sample.throughput_mib_per_second = Some(throughput(got, sample.elapsed_seconds));
    }
    sample
}

fn build_workload(spec: &Spec, samples: Vec<Sample>) -> Workload {
    let ok: Vec<f64> = samples
        .iter()
        .filter_map(|s| s.throughput_mib_per_second)
        .collect();
    Workload {
        id: spec.id.to_owned(),
        description: spec.description.to_owned(),
        requested_bytes: spec.expected,
        counts: count(&samples),
        summary: summarize(&ok),
        samples,
    }
}

pub(super) fn collect(
    specs: &[Spec],
    base: &str,
    warmup: u32,
    runs: u32,
    cancel: &AtomicBool,
) -> Vec<Workload> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(None)
        .build()
        .into();
    let mut out = Vec::new();
    for spec in specs {
        for i in 0..warmup {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let _ = sample_once(&agent, base, spec, i);
        }
        let mut samples = Vec::new();
        for i in 0..runs {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            samples.push(sample_once(&agent, base, spec, i));
        }
        out.push(build_workload(spec, samples));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_start_off_zero_and_fit_the_file() {
        let size = 8 * MIB;
        let all = specs(WorkloadSel::Both, false, size);
        let range = &all[1];
        let (first, last) = range.range.unwrap();
        assert!(first > 0 && last < size);
        assert_eq!(last - first + 1, range.expected);
    }
}
