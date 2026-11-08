use super::ansi::Style;
use super::util::display_path;
use clap::Args;
use serde::Serialize;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Directory to check
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Port to check availability
    #[arg(short, long, default_value_t = 8000, value_parser = clap::value_parser!(u16))]
    pub port: u16,
    /// Display machine-readable JSON
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Serialize)]
struct Check {
    id: &'static str,
    outcome: &'static str,
    details: String,
}

fn check(id: &'static str, outcome: &'static str, details: impl Into<String>) -> Check {
    Check {
        id,
        outcome,
        details: details.into(),
    }
}

fn base_path(path: &Path) -> Check {
    let readable = path.is_dir() && std::fs::read_dir(path).is_ok();
    if readable {
        check(
            "base_path",
            "pass",
            format!("Readable directory: {}", display_path(path)),
        )
    } else {
        check(
            "base_path",
            "fail",
            format!("Cannot read: {}", display_path(path)),
        )
    }
}

fn port_hint(port: u16) -> String {
    if cfg!(windows) {
        format!("Inspect it in PowerShell with: Get-NetTCPConnection -LocalPort {port}.")
    } else if cfg!(target_os = "macos") {
        format!("Inspect it with: lsof -nP -iTCP:{port} -sTCP:LISTEN.")
    } else {
        format!("Inspect it with: ss -ltnp 'sport = :{port}'.")
    }
}

fn port_binding(port: u16) -> Check {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) if port == 0 => check("port_binding", "pass", "An ephemeral port can be bound"),
        Ok(_) => check(
            "port_binding",
            "pass",
            format!("Port {port} is free to bind"),
        ),
        Err(e) => check(
            "port_binding",
            "fail",
            format!("Port {port} could not be bound: {e}. {}", port_hint(port)),
        ),
    }
}

fn async_io() -> Check {
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
    {
        Ok(_) => check("async_io", "pass", "Multi-threaded async runtime starts"),
        Err(e) => check(
            "async_io",
            "fail",
            format!("Async runtime failed to start: {e}"),
        ),
    }
}

fn tls_ready() -> Check {
    use tokio_rustls::rustls::{ServerConfig, crypto::ring};
    let provider = std::sync::Arc::new(ring::default_provider());
    match ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions() {
        Ok(_) => check(
            "tls_ready",
            "pass",
            "TLS 1.2 and 1.3 available through rustls",
        ),
        Err(e) => check(
            "tls_ready",
            "fail",
            format!("TLS provider unavailable: {e}"),
        ),
    }
}

fn file_descriptor_limit() -> Check {
    let Ok(limits) = std::fs::read_to_string("/proc/self/limits") else {
        return check(
            "file_descriptor_limit",
            "unavailable",
            "Not reported on this platform",
        );
    };
    let soft = limits
        .lines()
        .find(|l| l.starts_with("Max open files"))
        .and_then(|l| l.split_whitespace().nth(3));
    match soft {
        Some("unlimited") => check(
            "file_descriptor_limit",
            "pass",
            "No soft limit on open files",
        ),
        Some(v) => match v.parse::<u64>() {
            Ok(n) if n >= 4096 => check(
                "file_descriptor_limit",
                "pass",
                format!("Soft limit is {n} open files"),
            ),
            Ok(n) => check(
                "file_descriptor_limit",
                "fallback",
                format!(
                    "Soft limit is {n}; raise it with `ulimit -n 65536` for many concurrent transfers"
                ),
            ),
            Err(_) => check(
                "file_descriptor_limit",
                "unavailable",
                "Limit could not be parsed",
            ),
        },
        None => check("file_descriptor_limit", "unavailable", "Limit not listed"),
    }
}

#[derive(Serialize)]
struct Report<'a> {
    path: &'a str,
    port: u16,
    success: bool,
    checks: &'a [Check],
}

pub fn run(args: DoctorArgs) -> Result<u8, String> {
    let abs = std::path::absolute(&args.path).unwrap_or_else(|_| args.path.clone());
    let checks = vec![
        base_path(&abs),
        port_binding(args.port),
        async_io(),
        tls_ready(),
        file_descriptor_limit(),
    ];
    let success = checks.iter().all(|c| c.outcome != "fail");
    let path = display_path(&abs);

    if args.json {
        let report = Report {
            path: &path,
            port: args.port,
            success,
            checks: &checks,
        };
        anstream::println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| e.to_string())?
        );
    } else {
        print_table(&checks);
    }
    Ok(if success { 0 } else { 1 })
}

fn label(id: &str) -> &str {
    match id {
        "base_path" => "Base path",
        "port_binding" => "Port binding",
        "async_io" => "Async I/O",
        "tls_ready" => "TLS",
        "file_descriptor_limit" => "Open files",
        other => other,
    }
}

fn print_table(checks: &[Check]) {
    let style = Style::stdout();
    let status = |outcome: &str| match outcome {
        "pass" => style.green("ok"),
        "fail" => style.red("fail"),
        other => style.yellow(other),
    };
    anstream::println!("{}\n", style.bold("BlazeServe diagnostics"));
    for c in checks {
        let name = label(c.id);
        let word = status(c.outcome);
        let visible = if c.outcome == "pass" {
            2
        } else {
            c.outcome.chars().count()
        };
        anstream::println!(
            "  {name:<14}{word}{}  {}",
            " ".repeat(13usize.saturating_sub(visible)),
            c.details
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_directory_fails() {
        assert_eq!(base_path(Path::new("definitely/not/here")).outcome, "fail");
    }

    #[test]
    fn tls_provider_is_available() {
        assert_eq!(tls_ready().outcome, "pass");
    }
}
