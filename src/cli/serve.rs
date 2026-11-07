use super::ansi::{self, Style};
use super::util::{
    canonical, display_path, env_truthy, existing_file, existing_path, lan_ip, open_browser,
};
use crate::config::{Config, Credentials, DEFAULT_CHUNK_MB, DEFAULT_SNDBUF_MB, TrustedProxy};
use crate::usage;
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct Common {
    /// Print a QR code of the network URL
    #[arg(long)]
    pub qr: bool,
    /// Serve HTTP/1.1 only, without HTTP/2
    #[arg(long)]
    pub no_http2: bool,
    /// Bind address (IPv4/IPv6 literal ok)
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,
    /// Port to listen on
    #[arg(short, long, default_value_t = 8000, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
    /// Throttle to MB/s (omit for unlimited)
    #[arg(long, value_parser = parse_rate, value_name = "MB/S")]
    pub rate_mbps: Option<f64>,
    /// Enable HTTP Basic Auth
    #[arg(long, value_name = "USER:PASS")]
    pub auth: Option<String>,
    /// Load USER:PASS from an environment variable
    #[arg(long, value_name = "ENVVAR")]
    pub auth_env: Option<String>,
    /// TLS certificate (PEM)
    #[arg(long, value_parser = existing_file)]
    pub tls_cert: Option<PathBuf>,
    /// TLS private key (PEM)
    #[arg(long, value_parser = existing_file)]
    pub tls_key: Option<PathBuf>,
    /// Enable CORS
    #[arg(long, overrides_with = "no_cors")]
    pub cors: bool,
    /// Disable CORS (default)
    #[arg(long, overrides_with = "cors")]
    pub no_cors: bool,
    /// CORS allow origin
    #[arg(long, default_value = "*")]
    pub cors_origin: String,
    /// Disable HTTP caching
    #[arg(long)]
    pub no_cache: bool,
    /// Listen backlog size
    #[arg(long, default_value_t = 8192, value_parser = clap::value_parser!(u32).range(1..=20000))]
    pub backlog: u32,
    /// Serve .gz assets when safe (default)
    #[arg(long, overrides_with = "no_precompress")]
    pub precompress: bool,
    /// Never serve .gz assets
    #[arg(long, overrides_with = "precompress")]
    pub no_precompress: bool,
    /// Max upload size in MB (0 = uploads disabled)
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=1_048_576))]
    pub max_upload_mb: u64,
    /// Emit structured JSON log records (env BLAZE_LOG_JSON)
    #[arg(long, overrides_with = "no_log_json")]
    pub log_json: bool,
    /// Emit human-readable logs even when BLAZE_LOG_JSON is set
    #[arg(long, overrides_with = "log_json")]
    pub no_log_json: bool,
    /// Maximum simultaneously admitted connections
    #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u64).range(1..))]
    pub max_connections: u64,
    /// Seconds allowed to receive complete request headers
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub header_timeout: u64,
    /// Trust forwarded client identity from this proxy IP or CIDR (repeatable)
    #[arg(long = "trust-proxy", value_name = "CIDR", value_parser = parse_proxy)]
    pub trust_proxy: Vec<TrustedProxy>,
    /// Maximum proxy hops walked in a forwarded chain
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u64).range(1..=64))]
    pub max_proxy_hops: u64,
    /// Export traces and metrics over OTLP/HTTP to this collector (env OTEL_EXPORTER_OTLP_ENDPOINT)
    #[arg(long, value_name = "URL")]
    pub otlp_endpoint: Option<String>,
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Directory or file to serve
    #[arg(default_value = ".", value_parser = existing_path)]
    pub path: PathBuf,
    /// Serve exactly this file
    #[arg(long, value_parser = existing_file)]
    pub single: Option<PathBuf>,
    /// Disable directory listing
    #[arg(long)]
    pub no_listing: bool,
    /// Transfer chunk size in MB
    #[arg(long, default_value_t = DEFAULT_CHUNK_MB, value_parser = clap::value_parser!(u32).range(1..=4096))]
    pub chunk_mb: u32,
    /// SO_SNDBUF size in MB
    #[arg(long, default_value_t = DEFAULT_SNDBUF_MB, value_parser = clap::value_parser!(u32).range(1..=2048))]
    pub sock_sndbuf_mb: u32,
    /// Per-connection idle timeout in seconds
    #[arg(long, default_value_t = 1800, value_parser = clap::value_parser!(u64).range(60..=86400))]
    pub timeout: u64,
    /// Additional index filenames to try (repeatable)
    #[arg(long)]
    pub index: Vec<String>,
    /// Open the URL in a browser on start
    #[arg(long = "open")]
    pub open_browser: bool,
    /// Show tuning details in the startup banner
    #[arg(short, long)]
    pub verbose: bool,
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
pub struct SendArgs {
    /// File to share
    #[arg(value_parser = existing_file)]
    pub file: PathBuf,
    #[command(flatten)]
    pub common: Common,
}

fn parse_rate(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|_| format!("'{s}' is not a number"))?;
    if v.is_finite() && v >= 0.1 {
        Ok(v)
    } else {
        Err("must be at least 0.1".to_owned())
    }
}

fn parse_proxy(s: &str) -> Result<TrustedProxy, String> {
    TrustedProxy::parse(s).map_err(|e| e.to_string())
}

fn auth_env_hint(var: &str) -> String {
    format!(
        "Set it before retrying: PowerShell: $env:{var} = 'USER:PASS'; macOS/Linux: export {var}='USER:PASS'."
    )
}

/// A requested credential source that is absent or empty is an error: it must never
/// degrade to an unauthenticated server.
pub fn resolve_auth(
    auth: Option<&str>,
    auth_env: Option<&str>,
) -> Result<Option<Credentials>, String> {
    let raw = match (auth, auth_env) {
        (Some(a), _) => Some(a.to_owned()),
        (None, Some(var)) => match std::env::var(var) {
            Ok(v) if !v.is_empty() => Some(v),
            _ => {
                return Err(format!(
                    "Authentication environment variable {var:?} is missing or empty. {}",
                    auth_env_hint(var)
                ));
            }
        },
        (None, None) => None,
    };
    raw.map(|r| Credentials::parse(&r).map_err(|_| "Auth must be USER:PASS.".to_owned()))
        .transpose()
}

impl Common {
    fn apply(&self, cfg: &mut Config) -> Result<(), String> {
        cfg.host = self.host.clone();
        cfg.port = self.port;
        cfg.rate_mbps = self.rate_mbps;
        cfg.auth = resolve_auth(self.auth.as_deref(), self.auth_env.as_deref())?;
        cfg.tls = Config::tls_pair(self.tls_cert.clone(), self.tls_key.clone())
            .map_err(|e| format!("{e}."))?;
        cfg.cors = self.cors && !self.no_cors;
        cfg.cors_origin = if self.cors_origin.is_empty() {
            "*".into()
        } else {
            self.cors_origin.clone()
        };
        cfg.no_cache = self.no_cache;
        cfg.backlog = self.backlog;
        cfg.precompress = !self.no_precompress;
        cfg.max_upload_bytes = self.max_upload_mb * 1024 * 1024;
        cfg.log_json = self.log_json || (!self.no_log_json && env_truthy("BLAZE_LOG_JSON"));
        cfg.max_connections = usize::try_from(self.max_connections).unwrap_or(usize::MAX);
        cfg.http2 = !self.no_http2;
        cfg.header_timeout_secs = self.header_timeout;
        cfg.trusted_proxies = self.trust_proxy.clone();
        cfg.max_proxy_hops = self.max_proxy_hops as usize;
        cfg.otlp_endpoint = self
            .otlp_endpoint
            .clone()
            .or_else(|| crate::telemetry::env_endpoint_present().then(String::new));
        Ok(())
    }
}

pub fn serve_config(args: &ServeArgs) -> Result<Config, String> {
    let target = canonical(&args.path)?;
    let (base, single) = if let Some(single) = &args.single {
        let single = canonical(single)?;
        (parent_of(&single), Some(single))
    } else if target.is_file() {
        (parent_of(&target), Some(target))
    } else if target.is_dir() {
        (target, None)
    } else {
        return Err(format!("Path not found: {}", display_path(&target)));
    };
    let mut cfg = Config {
        base,
        single,
        listing: !args.no_listing,
        chunk_bytes: args.chunk_mb as usize * 1024 * 1024,
        sndbuf_bytes: args.sock_sndbuf_mb as usize * 1024 * 1024,
        timeout_secs: args.timeout,
        index: args.index.clone(),
        verbose: args.verbose,
        ..Config::default()
    };
    args.common.apply(&mut cfg)?;
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

pub fn send_config(args: &SendArgs) -> Result<Config, String> {
    let file = canonical(&args.file)?;
    let mut cfg = Config {
        base: parent_of(&file),
        single: Some(file),
        listing: false,
        timeout_secs: 1800,
        ..Config::default()
    };
    args.common.apply(&mut cfg)?;
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

fn parent_of(file: &std::path::Path) -> PathBuf {
    file.parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| file.to_path_buf())
}

fn loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

const PATH_SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Terminals are usually dark, so the code is drawn inverted: the filled blocks are the light
/// modules and the quiet zone, which is what a scanner needs to see around the code.
fn qr_block(url: &str) -> Option<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(url.as_bytes()).ok()?;
    Some(
        code.render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .build(),
    )
}

fn banner(cfg: &Config, verbose: bool, qr: bool) -> String {
    let style = Style::stdout();
    let scheme = if cfg.tls.is_some() { "https" } else { "http" };
    let port = cfg.port;
    let target = cfg.single.as_deref().unwrap_or(&cfg.base);
    let mut rows = vec![
        ("Serving", display_path(target)),
        ("Local", format!("{scheme}://localhost:{port}/")),
    ];
    let network = (!loopback_host(&cfg.host)).then(|| format!("{scheme}://{}:{port}/", lan_ip()));
    if let Some(url) = &network {
        rows.push(("Network", url.clone()));
    }
    let mut share = network
        .clone()
        .unwrap_or_else(|| format!("{scheme}://localhost:{port}/"));
    if let Some(file) = cfg.single.as_deref().and_then(|f| f.file_name()) {
        let raw = file.to_string_lossy();
        let name = percent_encoding::utf8_percent_encode(&raw, PATH_SEGMENT);
        share.push_str(&name.to_string());
        rows.push(("Download", format!("blaze get {share}")));
    }
    if verbose {
        rows.push((
            "Chunk size",
            format!("{} MB", cfg.chunk_bytes / (1024 * 1024)),
        ));
        rows.push((
            "Send buffer",
            format!("{} MB", cfg.sndbuf_bytes / (1024 * 1024)),
        ));
        rows.push(("Backlog", cfg.backlog.to_string()));
        rows.push(("Connections", format!("{} max", cfg.max_connections)));
        if let Some(rate) = cfg.rate_mbps {
            rows.push(("Rate limit", format!("{rate} MB/s")));
        }
        let host = network
            .as_deref()
            .map_or_else(|| format!("{scheme}://localhost:{port}/"), str::to_owned);
        rows.push(("Metrics", format!("{host}__metrics__")));
    }
    let qr_text = if qr {
        qr_block(&share).map_or_else(String::new, |q| format!("\n{}\n", q.trim_end()))
    } else {
        String::new()
    };
    format!(
        "{}\n\n{}\n{}\n{}\n",
        style.bold(&format!("BlazeServe {}", crate::VERSION)),
        ansi::rows(style, &rows).trim_end(),
        qr_text,
        style.dim("Press Ctrl+C to stop"),
    )
}

fn print_status(text: &str, json_logs: bool) {
    if json_logs {
        anstream::eprint!("{text}");
    } else {
        anstream::print!("{text}");
    }
}

type UsageSlot =
    std::sync::Arc<std::sync::Mutex<Option<(usage::Session, std::sync::Arc<crate::AppState>)>>>;

fn run_config(
    cfg: Config,
    command: usage::Command,
    verbose: bool,
    open: bool,
    qr: bool,
) -> Result<u8, String> {
    let json_logs = cfg.log_json;
    let text = banner(&cfg, verbose, qr);
    let url = format!(
        "{}://localhost:{}/",
        if cfg.tls.is_some() { "https" } else { "http" },
        cfg.port
    );
    let otlp = std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some_and(|v| !v.is_empty());
    let features = usage::Features::from_config(&cfg, otlp);
    let slot: UsageSlot = UsageSlot::default();
    let slot_in = slot.clone();
    crate::server::run(cfg, move |handle| {
        print_status(&text, json_logs);
        if let Some(session) = usage::begin_from_process(command, features)
            && let Ok(mut g) = slot_in.lock()
        {
            *g = Some((session, handle.state().clone()));
        }
        if open {
            open_browser(&url);
        }
    })
    .map_err(|e| e.to_string())?;
    let taken = slot.lock().ok().and_then(|mut g| g.take());
    if let Some((session, state)) = taken {
        let s = state.metrics.stats();
        usage::finish_from_process(
            session,
            usage::StopStats {
                requests_total: s.requests_total,
                bytes_sent: s.bytes_sent,
                errors_total: s.errors_total,
            },
        );
    }
    anstream::eprintln!("{}", Style::stderr().dim("Stopped"));
    Ok(0)
}

pub fn serve(args: ServeArgs) -> Result<u8, String> {
    let cfg = serve_config(&args)?;
    run_config(
        cfg,
        usage::Command::Serve,
        args.verbose,
        args.open_browser,
        args.common.qr,
    )
}

pub fn send(args: SendArgs) -> Result<u8, String> {
    let cfg = send_config(&args)?;
    run_config(cfg, usage::Command::Send, false, false, args.common.qr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_auth_env_is_an_error_with_hints() {
        let err = resolve_auth(None, Some("BLAZE_TEST_SURELY_UNSET_VAR")).unwrap_err();
        assert!(err.contains("missing or empty"));
        assert!(err.contains("$env:BLAZE_TEST_SURELY_UNSET_VAR"));
        assert!(err.contains("export BLAZE_TEST_SURELY_UNSET_VAR"));
    }

    #[test]
    fn explicit_auth_needs_a_colon() {
        assert!(resolve_auth(Some("nocolon"), None).is_err());
        assert!(resolve_auth(Some("u:p"), None).unwrap().is_some());
        assert!(resolve_auth(None, None).unwrap().is_none());
    }

    #[test]
    fn rate_floor_is_enforced() {
        assert!(parse_rate("0.05").is_err());
        assert!(parse_rate("abc").is_err());
        assert_eq!(parse_rate("2.5").unwrap(), 2.5);
    }

    #[test]
    fn loopback_detection() {
        assert!(loopback_host("127.0.0.1"));
        assert!(loopback_host("[::1]"));
        assert!(loopback_host("localhost"));
        assert!(!loopback_host("0.0.0.0"));
    }

    #[test]
    fn qr_block_is_a_rectangle_of_block_glyphs_with_a_quiet_zone() {
        let qr = qr_block("http://localhost:8000/").unwrap();
        let lines: Vec<&str> = qr.lines().collect();
        let width = lines[0].chars().count();
        assert!(width >= 21 + 8);
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(
            qr.chars()
                .all(|c| matches!(c, ' ' | '▀' | '▄' | '█' | '\n'))
        );
        assert!(qr.contains('█') || qr.contains('▀') || qr.contains('▄'));
        assert!(lines[0].chars().all(|c| c == '█'));
        assert!(
            lines
                .iter()
                .all(|l| l.chars().take(4).all(|c| matches!(c, '█' | '▀')))
        );
    }

    #[test]
    fn share_url_keeps_dots_and_escapes_only_unsafe_characters() {
        let encode =
            |name: &str| percent_encoding::utf8_percent_encode(name, PATH_SEGMENT).to_string();
        assert_eq!(encode("README.md"), "README.md");
        assert_eq!(encode("my file#1.tar.gz"), "my%20file%231.tar.gz");
        assert_eq!(encode("a?b%c"), "a%3Fb%25c");
    }

    #[test]
    fn qr_block_rejects_urls_beyond_capacity() {
        assert!(qr_block(&format!("http://h/{}", "a".repeat(4000))).is_none());
    }

    #[test]
    fn banner_adds_the_qr_only_when_asked() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            ..Config::default()
        };
        let plain = banner(&cfg, false, false);
        let with_qr = banner(&cfg, false, true);
        let qr = qr_block("http://localhost:8000/").unwrap();
        assert!(!plain.contains(qr.lines().nth(2).unwrap()));
        assert!(with_qr.contains(qr.lines().nth(2).unwrap()));
        assert!(with_qr.contains("http://localhost:8000/"));
        assert!(with_qr.contains("Press Ctrl+C to stop"));
        assert!(with_qr.len() > plain.len());
    }
}
