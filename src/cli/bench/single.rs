//! The single-download benchmark: one timed `/__speed__` transfer from a local or remote origin.

use super::BenchArgs;
use super::fixture::TempDir;
use crate::cli::ansi::{self, Style};
use crate::cli::util::{Progress, canonical, env_truthy};
use crate::config::Config;
use serde::Serialize;
use std::io::Read;
use std::time::Instant;

#[derive(Serialize)]
struct Report {
    base_url: String,
    requested_bytes: u64,
    downloaded_bytes: u64,
    elapsed_seconds: f64,
    throughput_mib_per_second: f64,
}

const URL_RULE: &str =
    "Benchmark URL must be an HTTP(S) origin without credentials, query, or fragment.";

pub(super) fn validate_url(url: &str) -> Result<String, String> {
    if url.contains(['?', '#']) {
        return Err(URL_RULE.to_owned());
    }
    let uri: ureq::http::Uri = url.parse().map_err(|_| URL_RULE.to_owned())?;
    let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
    let authority_ok = uri
        .authority()
        .is_some_and(|a| !a.as_str().contains('@') && !a.host().is_empty());
    if !(scheme_ok && authority_ok) {
        return Err(URL_RULE.to_owned());
    }
    Ok(url.trim_end_matches('/').to_owned())
}

fn measure(origin: &str, expected: u64, show_progress: bool) -> Result<(u64, f64), String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(None)
        .build()
        .into();
    let url = format!("{origin}/__speed__?bytes={expected}");
    let start = Instant::now();
    let response = agent.get(&url).call().map_err(|_| {
        format!(
            "Could not connect to a BlazeServe server at {origin}. \
             Start one with `blaze serve`, then run the benchmark again."
        )
    })?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "Benchmark server at {origin} returned HTTP {}. \
             Verify that the URL points to a running BlazeServe server.",
            response.status().as_u16()
        ));
    }
    let mut reader = response.into_body().into_reader();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut downloaded = 0u64;
    let mut progress = show_progress.then(|| Progress::new(Some(expected), 0));
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Benchmark failed: {e}"))?;
        if n == 0 {
            break;
        }
        downloaded += n as u64;
        if let Some(p) = progress.as_mut() {
            p.update(downloaded);
        }
    }
    if let Some(p) = progress.as_mut() {
        p.finish(downloaded);
    }
    let elapsed = start.elapsed().as_secs_f64();
    if downloaded != expected {
        return Err(format!(
            "Benchmark download was incomplete: expected {expected} bytes, received {downloaded}."
        ));
    }
    Ok((downloaded, elapsed))
}

fn local_run(size_bytes: u64, json: bool) -> Result<(String, u64, f64), String> {
    let dir = TempDir::create()?;
    let base = canonical(&dir.0)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("Benchmark failed: {e}"))?;
    runtime.block_on(async move {
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            base,
            log_json: !json && env_truthy("BLAZE_LOG_JSON"),
            ..Config::default()
        };
        let handle = crate::server::start(config)
            .await
            .map_err(|e| format!("Benchmark failed: {e}"))?;
        let origin = format!("http://127.0.0.1:{}", handle.local_addr().port());
        let probe = origin.clone();
        let result = tokio::task::spawn_blocking(move || measure(&probe, size_bytes, !json))
            .await
            .map_err(|e| format!("Benchmark failed: {e}"))
            .and_then(|r| r);
        handle.shutdown().await;
        result.map(|(downloaded, elapsed)| (origin, downloaded, elapsed))
    })
}

pub(super) fn run(args: &BenchArgs) -> Result<u8, String> {
    let expected = args.size_mb * 1024 * 1024;
    let style = Style::stdout();
    let remote = args.url.as_deref().map(validate_url).transpose()?;

    if !args.json {
        if let Some(origin) = &remote {
            anstream::println!("Benchmarking  {origin}");
        }
        anstream::println!("Download size  {} MB\n", args.size_mb);
        if args.size_mb > 500 {
            anstream::eprintln!(
                "{} Large benchmark size ({} MB) may impact server performance",
                Style::stderr().yellow("Warning:"),
                args.size_mb
            );
        }
    }

    let (origin, downloaded, elapsed) = match remote {
        Some(origin) => {
            let (d, e) = measure(&origin, expected, !args.json)?;
            (origin, d, e)
        }
        None => local_run(expected, args.json)?,
    };

    let mib_per_second = (downloaded as f64 / (1024.0 * 1024.0)) / elapsed.max(f64::EPSILON);
    if args.json {
        let report = Report {
            base_url: origin,
            requested_bytes: expected,
            downloaded_bytes: downloaded,
            elapsed_seconds: elapsed,
            throughput_mib_per_second: mib_per_second,
        };
        anstream::println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| e.to_string())?
        );
        return Ok(0);
    }

    anstream::println!("{}\n", style.bold("Benchmark complete"));
    anstream::print!(
        "{}",
        ansi::rows(
            style,
            &[
                (
                    "Downloaded",
                    format!("{:.2} MB", downloaded as f64 / (1024.0 * 1024.0))
                ),
                ("Time", format!("{elapsed:.2} seconds")),
                ("Speed", format!("{mib_per_second:.2} MB/s")),
            ],
        )
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        assert_eq!(
            validate_url("http://127.0.0.1:8000/").unwrap(),
            "http://127.0.0.1:8000"
        );
        assert!(validate_url("ftp://host").is_err());
        assert!(validate_url("http://user:pw@host").is_err());
        assert!(validate_url("http://host/?x=1").is_err());
        assert!(validate_url("http://host/#frag").is_err());
        assert!(validate_url("not a url").is_err());
    }
}
