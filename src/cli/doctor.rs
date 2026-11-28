use super::ansi::Style;
use super::util::display_path;
use clap::Args;
use serde::Serialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::config::DEFAULT_PORT;

#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Directory to check
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Bind address to check, as `blaze serve --host` takes it (IPv4/IPv6 literal or name)
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    /// Port to check availability
    #[arg(short, long, default_value_t = DEFAULT_PORT, value_parser = clap::value_parser!(u16))]
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

fn port_binding(host: &str, port: u16) -> Check {
    match crate::server::probe_bind(host, port) {
        Ok(addr) => {
            let named = host.trim_matches(['[', ']']).parse::<IpAddr>().is_err();
            let scope = if named {
                " Only this resolved address was checked."
            } else {
                ""
            };
            let note = format!(
                "Bound and released {addr}.{scope} This is a point-in-time check, not a reservation."
            );
            let lead = if port == 0 {
                "An ephemeral port can be bound.".to_owned()
            } else {
                format!("Port {port} is free to bind.")
            };
            check("port_binding", "pass", format!("{lead} {note}"))
        }
        Err(e) => check(
            "port_binding",
            "fail",
            format!(
                "Port {port} could not be bound on host {host}: {e}. {}",
                port_hint(port)
            ),
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
    host: &'a str,
    port: u16,
    success: bool,
    checks: &'a [Check],
}

pub fn run(args: DoctorArgs) -> Result<u8, String> {
    let abs = std::path::absolute(&args.path).unwrap_or_else(|_| args.path.clone());
    let checks = vec![
        base_path(&abs),
        port_binding(&args.host, args.port),
        async_io(),
        tls_ready(),
        file_descriptor_limit(),
    ];
    let success = checks.iter().all(|c| c.outcome != "fail");
    let path = display_path(&abs);

    if args.json {
        let report = Report {
            path: &path,
            host: &args.host,
            port: args.port,
            success,
            checks: &checks,
        };
        anstream::println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| e.to_string())?
        );
    } else {
        print_table(&checks, &path, &crate::cli::util::friendly_path(&abs));
        if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
            anstream::println!("{}", Style::stdout().bold(&verdict(&checks, &args)));
        }
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

/// Breaks `text` between words so no line is wider than `width`.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split(' ') {
        let last = lines.len() - 1;
        let line = &mut lines[last];
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(word.to_owned());
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    lines
}

fn print_table(checks: &[Check], path: &str, short: &str) {
    let style = Style::stdout();
    let line = |c: &Check, word: String, visible: usize| {
        format!(
            "  {:<14}{word}{}  {}\n",
            label(c.id),
            " ".repeat(13usize.saturating_sub(visible)),
            c.details
        )
    };
    let mut plain = format!("{}\n\n", style.bold("BlazeServe diagnostics"));
    let mut framed = String::new();
    // The columns before the details, and the card's own edges.
    let room = usize::from(console::Term::stdout().size().1)
        .saturating_sub(34)
        .clamp(30, 70);
    for c in checks {
        let (word, mark) = match c.outcome {
            "pass" => (style.green("ok"), style.green("\u{2713} ok")),
            "fail" => (style.red("fail"), style.red("\u{2717} fail")),
            other => (style.yellow(other), style.yellow(&format!("! {other}"))),
        };
        let visible = if c.outcome == "pass" {
            2
        } else {
            c.outcome.chars().count()
        };
        plain.push_str(&line(c, word, visible));
        let details = wrap(&c.details.replace(path, short), room);
        framed.push_str(&format!(
            "  {:<14}{mark}{}  {}  \n",
            label(c.id),
            " ".repeat(13usize.saturating_sub(visible + 2)),
            details.join(&format!("  \n{}", " ".repeat(31)))
        ));
    }
    crate::cli::ansi::card("BlazeServe diagnostics", &framed, &plain);
}

/// What to do next, said after the table at a terminal.
fn verdict(checks: &[Check], args: &DoctorArgs) -> String {
    let failed = checks.iter().filter(|c| c.outcome == "fail").count();
    if failed == 0 {
        format!(
            "Ready. Next: blaze serve {} --port {}",
            args.path.display(),
            args.port
        )
    } else {
        format!(
            "{failed} {} failed. Fix {} and run `blaze doctor` again, or `blaze bug` if it looks wrong.",
            if failed == 1 { "check" } else { "checks" },
            if failed == 1 { "it" } else { "them" }
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn long_details_wrap_between_words() {
        assert_eq!(super::wrap("one two three", 7), ["one two", "three"]);
        assert_eq!(super::wrap("unbroken", 3), ["unbroken"]);
    }

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
