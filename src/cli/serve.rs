use super::ansi::{self, Style};
use super::live;
use super::util::{
    canonical, display_path, env_truthy, existing_file, existing_path, human_size, lan_ip,
    open_browser,
};
use crate::config::{Config, Credentials, DEFAULT_CHUNK_MB, DEFAULT_SNDBUF_MB, Hide, TrustedProxy};
use crate::usage;
use clap::Args;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

#[derive(Args, Debug)]
pub struct Common {
    /// Print a QR code of the network URL
    #[arg(long)]
    pub qr: bool,
    /// Serve HTTP/1.1 only, without HTTP/2
    #[arg(help_heading = "Network", long)]
    pub no_http2: bool,
    /// Bind address (IPv4/IPv6 literal ok)
    #[arg(help_heading = "Network", long, default_value = "0.0.0.0")]
    pub host: String,
    /// Port to listen on
    #[arg(help_heading = "Network", short, long, default_value_t = 8000, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
    /// Throttle to MB/s (omit for unlimited)
    #[arg(help_heading = "Speed and caching", long, value_parser = parse_rate, value_name = "MB/S")]
    pub rate_mbps: Option<f64>,
    /// Enable HTTP Basic Auth
    #[arg(help_heading = "Security", long, value_name = "USER:PASS")]
    pub auth: Option<String>,
    /// Load USER:PASS from an environment variable
    #[arg(help_heading = "Security", long, value_name = "ENVVAR")]
    pub auth_env: Option<String>,
    /// TLS certificate (PEM)
    #[arg(help_heading = "Security", long, value_parser = existing_file)]
    pub tls_cert: Option<PathBuf>,
    /// TLS private key (PEM)
    #[arg(help_heading = "Security", long, value_parser = existing_file)]
    pub tls_key: Option<PathBuf>,
    /// Enable CORS
    #[arg(help_heading = "Security", long, overrides_with = "no_cors")]
    pub cors: bool,
    /// Disable CORS (default)
    #[arg(help_heading = "Security", long, overrides_with = "cors")]
    pub no_cors: bool,
    /// CORS allow origin
    #[arg(help_heading = "Security", long, default_value = "*")]
    pub cors_origin: String,
    /// Disable HTTP caching
    #[arg(help_heading = "Speed and caching", long)]
    pub no_cache: bool,
    /// Listen backlog size
    #[arg(help_heading = "Network", long, default_value_t = 8192, value_parser = clap::value_parser!(u32).range(1..=20000))]
    pub backlog: u32,
    /// Serve .gz assets when safe (default)
    #[arg(
        help_heading = "Speed and caching",
        long,
        overrides_with = "no_precompress"
    )]
    pub precompress: bool,
    /// Never serve .gz assets
    #[arg(
        help_heading = "Speed and caching",
        long,
        overrides_with = "precompress"
    )]
    pub no_precompress: bool,
    /// Accept uploads, up to 10 GiB a file; makes a password if you give none
    #[arg(long, help_heading = "Uploads")]
    pub uploads: bool,
    /// Largest upload in MB; any value above 0 also turns uploads on
    #[arg(help_heading = "Uploads", long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=1_048_576))]
    pub max_upload_mb: u64,
    /// Emit structured JSON log records (env BLAZE_LOG_JSON)
    #[arg(long, overrides_with = "no_log_json")]
    pub log_json: bool,
    /// Emit human-readable logs even when BLAZE_LOG_JSON is set
    #[arg(long, overrides_with = "log_json")]
    pub no_log_json: bool,
    /// Maximum simultaneously admitted connections
    #[arg(help_heading = "Network", long, default_value_t = 1024, value_parser = clap::value_parser!(u64).range(1..))]
    pub max_connections: u64,
    /// Seconds allowed to receive complete request headers
    #[arg(help_heading = "Network", long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub header_timeout: u64,
    /// Trust forwarded client identity from this proxy IP or CIDR (repeatable)
    #[arg(help_heading = "Network", long = "trust-proxy", value_name = "CIDR", value_parser = parse_proxy)]
    pub trust_proxy: Vec<TrustedProxy>,
    /// Maximum proxy hops walked in a forwarded chain
    #[arg(help_heading = "Network", long, default_value_t = 8, value_parser = clap::value_parser!(u64).range(1..=64))]
    pub max_proxy_hops: u64,
    #[command(flatten)]
    pub bg: super::jobs::BackgroundArgs,
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
    /// Hide entries matching this glob from listings, ZIPs and direct requests (repeatable)
    #[arg(long, value_name = "GLOB")]
    pub hide: Vec<String>,
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
    /// Stop sharing after this long, for example 90s, 20m, 2h, 1d or 1h30m
    ///
    /// The countdown starts once the port is bound. At expiry the server stops accepting
    /// connections and ends keep-alive connections after their current response. Responses
    /// already in progress may keep sending for up to 10 more seconds, so this is not an exact
    /// cutoff. Ctrl+C or SIGTERM still stops the share earlier. The timer uses the monotonic
    /// clock, which on most systems pauses while the computer sleeps, so a suspended share is
    /// not expired the moment it wakes. Omit it to share until you stop it.
    #[arg(long, value_name = "DURATION", value_parser = parse_expiry)]
    pub expires_after: Option<Duration>,
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

const MAX_EXPIRY_SECS: u64 = 365 * 86_400;

/// One or more `<number><unit>` parts with units `s`, `m`, `h` and `d`, such as `90s` or `1h30m`.
fn parse_expiry(s: &str) -> Result<Duration, String> {
    parse_span(s, "expiry", MAX_EXPIRY_SECS)
}

/// `20m`, `1h30m` and the like. `noun` names the setting in error messages.
pub(super) fn parse_span(s: &str, noun: &str, max_secs: u64) -> Result<Duration, String> {
    let bad = || {
        format!(
            "'{s}' is not a duration; use a number with s, m, h or d, such as 90s, 20m, 2h, 1d or 1h30m"
        )
    };
    if s.is_empty() {
        return Err(bad());
    }
    let mut total: u64 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (number, tail) = rest.split_at(digits);
        let unit = tail.chars().next().ok_or_else(bad)?;
        let factor: u64 = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            _ => return Err(bad()),
        };
        let n: u64 = number.parse().map_err(|_| bad())?;
        total = n
            .checked_mul(factor)
            .and_then(|v| total.checked_add(v))
            .filter(|v| *v <= max_secs)
            .ok_or_else(|| {
                format!(
                    "'{s}' is too long; the longest {noun} is {}",
                    format_span(Duration::from_secs(max_secs))
                )
            })?;
        rest = &tail[unit.len_utf8()..];
    }
    if total == 0 {
        return Err(format!("the {noun} must be longer than zero"));
    }
    Ok(Duration::from_secs(total))
}

pub(super) fn format_span(span: Duration) -> String {
    let secs = span.as_secs();
    [
        (secs / 86_400, 'd'),
        (secs % 86_400 / 3600, 'h'),
        (secs % 3600 / 60, 'm'),
        (secs % 60, 's'),
    ]
    .iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, u)| format!("{n}{u}"))
    .collect()
}

fn parse_proxy(s: &str) -> Result<TrustedProxy, String> {
    TrustedProxy::parse(s).map_err(|e| e.to_string())
}

const DEFAULT_UPLOAD_MB: u64 = 10 * 1024;

/// A password for this run only: letters and digits that are not easily confused.
fn one_time_password() -> Result<String, String> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut raw = [0u8; 20];
    getrandom::fill(&mut raw).map_err(|e| format!("cannot create a password: {e}"))?;
    Ok(raw
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
        .collect())
}

/// `--uploads` without a password gets one, shown once at a terminal. Elsewhere it would
/// end up in a log, so a password has to be given.
fn protect_uploads(cfg: &mut Config, at_terminal: bool) -> Result<Option<String>, String> {
    if cfg.auth.is_some() {
        return Ok(None);
    }
    if !at_terminal || cfg.log_json {
        return Err(
            "--uploads needs a password here: set one with --auth-env VAR (VAR=user:password)"
                .to_owned(),
        );
    }
    let password = one_time_password()?;
    cfg.auth = Some(
        crate::config::Credentials::parse(&format!("blaze:{password}"))
            .map_err(|e| e.to_string())?,
    );
    Ok(Some(password))
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
        let limit = match self.max_upload_mb {
            0 if self.uploads => DEFAULT_UPLOAD_MB,
            given => given,
        };
        cfg.max_upload_bytes = limit * 1024 * 1024;
        cfg.log_json = self.log_json || (!self.no_log_json && env_truthy("BLAZE_LOG_JSON"));
        cfg.max_connections = usize::try_from(self.max_connections).unwrap_or(usize::MAX);
        cfg.http2 = !self.no_http2;
        cfg.header_timeout_secs = self.header_timeout;
        cfg.trusted_proxies = self.trust_proxy.clone();
        cfg.max_proxy_hops = self.max_proxy_hops as usize;
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
        hide: Hide::new(&args.hide).map_err(|e| e.to_string())?,
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

/// With colour the code is black on white whatever the terminal theme, which every scanner
/// reads. Without colour (piped, `NO_COLOR`) only glyphs are available, so the code is
/// inverted for the usual dark terminal: the filled blocks are the light modules.
fn qr_block(url: &str, style: Style) -> Option<String> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(url.as_bytes()).ok()?;
    if style.enabled() {
        let plain = code.render::<Dense1x2>().build();
        return Some(
            plain
                .lines()
                .map(|l| style.on_white(l))
                .collect::<Vec<_>>()
                .join("\n"),
        );
    }
    Some(
        code.render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .build(),
    )
}

fn banner(
    cfg: &Config,
    verbose: bool,
    qr: bool,
    expiry: Option<(Duration, SystemTime)>,
    password: Option<&str>,
) -> String {
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
    if cfg.max_upload_bytes > 0 && cfg.single.is_none() {
        rows.push((
            "Uploads",
            format!("on, up to {} a file", human_size(cfg.max_upload_bytes)),
        ));
        let credentials = match (password, &cfg.auth) {
            (Some(password), _) => format!(" --auth blaze:{password}"),
            (None, Some(_)) => " --auth-env YOUR_VAR".to_owned(),
            (None, None) => String::new(),
        };
        rows.push(("Upload", format!("blaze put FILE {share}{credentials}")));
        rows.push((
            "Browser",
            format!("open {share} and drop files on the page"),
        ));
        if let Some(password) = password {
            rows.push((
                "Sign in",
                format!("user blaze, password {password} (this run only)"),
            ));
        } else if cfg.auth.is_none() {
            rows.push((
                "Warning",
                "no password: anyone who can connect can upload".to_owned(),
            ));
        }
    }
    if let Some((after, at)) = expiry {
        let secs = at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        rows.push((
            "Expires",
            format!(
                "in {} (at {})",
                format_span(after),
                crate::logging::format_utc(secs)
            ),
        ));
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
        qr_block(&share, style).map_or_else(String::new, |q| format!("\n{}\n", q.trim_end()))
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

/// Kept from start to stop so the final report can read the server's counters.
type UsageSlot = std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<crate::AppState>>>>;

const HEARTBEAT: Duration = Duration::from_secs(60 * 60);

/// Reports the server's counters every hour until `stopped` closes.
fn heartbeat(
    reporter: usage::Reporter,
    command: &'static str,
    features: usage::Features,
    state: std::sync::Arc<crate::AppState>,
    stopped: std::sync::mpsc::Receiver<()>,
) {
    std::thread::spawn(move || {
        use std::sync::mpsc::RecvTimeoutError;
        while stopped.recv_timeout(HEARTBEAT) == Err(RecvTimeoutError::Timeout) {
            let counters = usage::ServerCounters::of(&state.metrics);
            reporter.server_heartbeat(command, features, counters, &mut std::io::stderr());
        }
    });
}

fn run_config(
    cfg: Config,
    command: &'static str,
    verbose: bool,
    open: bool,
    qr: bool,
    expires_after: Option<Duration>,
    password: Option<String>,
) -> Result<u8, String> {
    let json_logs = cfg.log_json;
    let banner_cfg = cfg.clone();
    let url = format!(
        "{}://localhost:{}/",
        if cfg.tls.is_some() { "https" } else { "http" },
        cfg.port
    );
    let features = usage::Features::from_config(&cfg);
    let slot: UsageSlot = UsageSlot::default();
    let slot_in = slot.clone();
    // Verbose and JSON runs print a line per request, which an in-place status line would
    // fight.
    let live_allowed = !verbose && !json_logs;
    let live: std::sync::Arc<std::sync::Mutex<Option<live::Live>>> = Default::default();
    let live_in = live.clone();
    // Dropping the sender ends the heartbeat.
    let (heartbeat_stop, heartbeat_stopped) = std::sync::mpsc::channel::<()>();
    let mut heartbeat_stopped = Some(heartbeat_stopped);
    let reason = crate::server::run_until(
        cfg,
        expires_after,
        super::jobs::stop_requested(),
        move |handle| {
            super::jobs::ready(|| super::jobs::Info {
                label: banner_cfg
                    .single
                    .as_deref()
                    .unwrap_or(&banner_cfg.base)
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                url: None,
                direction: None,
                listen: Some(format!(
                    "{}://{}",
                    if banner_cfg.tls.is_some() {
                        "https"
                    } else {
                        "http"
                    },
                    handle.local_addr()
                )),
            });
            let expiry = expires_after.map(|d| (d, SystemTime::now() + d));
            print_status(
                &banner(&banner_cfg, verbose, qr, expiry, password.as_deref()),
                json_logs,
            );
            if live_allowed && let Ok(mut g) = live_in.lock() {
                *g = live::Live::start(handle.state().clone());
            }
            if let Some(reporter) = super::report::current() {
                reporter.server_started(command, features, &mut std::io::stderr());
                if let Some(stopped) = heartbeat_stopped.take() {
                    heartbeat(reporter, command, features, handle.state().clone(), stopped);
                }
            }
            if let Ok(mut g) = slot_in.lock() {
                *g = Some(handle.state().clone());
            }
            if open {
                open_browser(&url);
            }
        },
    )
    .map_err(|e| e.to_string());
    drop(heartbeat_stop);
    if let Some(line) = live.lock().ok().and_then(|mut g| g.take()) {
        line.finish();
    }
    let reason = reason?;
    let taken = slot.lock().ok().and_then(|mut g| g.take());
    if let Some(state) = taken
        && let Some(reporter) = super::report::current()
    {
        reporter.server_stopped(
            command,
            features,
            usage::ServerCounters::of(&state.metrics),
            &mut std::io::stderr(),
        );
    }
    let stopped = match (reason, expires_after) {
        (crate::server::StopReason::Expired, Some(after)) => {
            format!("Stopped: share expired after {}", format_span(after))
        }
        _ => "Stopped".to_owned(),
    };
    anstream::eprintln!("{}", Style::stderr().dim(&stopped));
    Ok(0)
}

pub fn serve(args: ServeArgs) -> Result<u8, String> {
    let mut cfg = serve_config(&args)?;
    let password = if args.common.uploads {
        let at_terminal = std::io::IsTerminal::is_terminal(&std::io::stdout());
        protect_uploads(&mut cfg, at_terminal)?
    } else {
        None
    };
    run_config(
        cfg,
        "serve",
        args.verbose,
        args.open_browser,
        args.common.qr,
        None,
        password,
    )
}

pub fn send(args: SendArgs) -> Result<u8, String> {
    let cfg = send_config(&args)?;
    run_config(
        cfg,
        "send",
        false,
        false,
        args.common.qr,
        args.expires_after,
        None,
    )
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
        let qr = qr_block("http://localhost:8000/", Style::PLAIN).unwrap();
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

    fn decode(lines: &[String], dark: impl Fn(char, bool) -> bool) -> Vec<String> {
        const SCALE: usize = 4;
        let cols = lines[0].chars().count();
        let (w, h) = (cols * SCALE, lines.len() * 2 * SCALE);
        let mut px = vec![255u8; w * h];
        for (row, line) in lines.iter().enumerate() {
            for (col, ch) in line.chars().enumerate() {
                for (half, top) in [(0, true), (1, false)] {
                    if dark(ch, top) {
                        for dy in 0..SCALE {
                            for dx in 0..SCALE {
                                px[((row * 2 + half) * SCALE + dy) * w + col * SCALE + dx] = 0;
                            }
                        }
                    }
                }
            }
        }
        let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| px[y * w + x]);
        img.detect_grids()
            .into_iter()
            .filter_map(|g| g.decode().ok().map(|(_, text)| text))
            .collect()
    }

    #[test]
    fn coloured_qr_decodes_to_the_share_url_on_any_theme() {
        let url = "http://192.168.1.20:8000/My%20File.tar.gz";
        let qr = qr_block(url, Style::COLOR).unwrap();
        let stripped: Vec<String> = qr
            .lines()
            .map(|l| {
                l.replace("\x1b[30;107m", "")
                    .replace("\x1b[0m", "")
                    .replace("\x1b[m", "")
            })
            .collect();
        assert!(qr.contains("\x1b["), "{qr:?}");
        let decoded = decode(&stripped, |c, top| match c {
            '█' => true,
            '▀' => top,
            '▄' => !top,
            _ => false,
        });
        assert_eq!(decoded, [url]);
    }

    #[test]
    fn plain_qr_is_inverted_and_decodes_when_the_terminal_is_dark() {
        let url = "http://192.168.1.20:8000/";
        let qr = qr_block(url, Style::PLAIN).unwrap();
        let lines: Vec<String> = qr.lines().map(str::to_owned).collect();
        let decoded = decode(&lines, |c, top| match c {
            '█' => false,
            '▀' => !top,
            '▄' => top,
            _ => true,
        });
        assert_eq!(decoded, [url]);
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
    fn expiry_accepts_units_and_sums_parts() {
        let secs = |s: &str| parse_expiry(s).unwrap().as_secs();
        assert_eq!(secs("90s"), 90);
        assert_eq!(secs("20m"), 1200);
        assert_eq!(secs("2h"), 7200);
        assert_eq!(secs("1d"), 86_400);
        assert_eq!(secs("1h30m"), 5400);
        assert_eq!(secs("365d"), MAX_EXPIRY_SECS);
    }

    #[test]
    fn expiry_rejects_zero_negative_unitless_and_unsupported_input() {
        for bad in [
            "", "0", "0s", "0m0s", "-5m", "20", "m", "1.5h", "1w", "10 m", "5M", "1h30", "+5m",
            "abc",
        ] {
            assert!(parse_expiry(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn expiry_rejects_overflow_and_absurd_lengths() {
        assert!(parse_expiry("366d").is_err());
        assert!(parse_expiry("18446744073709551615s").is_err());
        assert!(parse_expiry("18446744073709551615d").is_err());
        assert!(parse_expiry("99999999999999999999999s").is_err());
    }

    #[test]
    fn span_formats_back_to_the_units_it_was_given() {
        assert_eq!(format_span(Duration::from_secs(1200)), "20m");
        assert_eq!(format_span(Duration::from_secs(5400)), "1h30m");
        assert_eq!(format_span(Duration::from_secs(90_061)), "1d1h1m1s");
    }

    #[test]
    fn banner_shows_the_lifetime_and_expected_expiry_only_when_set() {
        let cfg = Config::default();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let with = banner(
            &cfg,
            false,
            false,
            Some((Duration::from_secs(1200), at)),
            None,
        );
        assert!(with.contains("in 20m (at 2023-11-14T22:13:20Z)"), "{with}");
        assert!(!banner(&cfg, false, false, None, None).contains("Expires"));
    }

    #[test]
    fn qr_block_rejects_urls_beyond_capacity() {
        assert!(qr_block(&format!("http://h/{}", "a".repeat(4000)), Style::PLAIN).is_none());
    }

    #[test]
    fn banner_adds_the_qr_only_when_asked() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            ..Config::default()
        };
        let plain = banner(&cfg, false, false, None, None);
        let with_qr = banner(&cfg, false, true, None, None);
        let qr = qr_block("http://localhost:8000/", Style::PLAIN).unwrap();
        assert!(!plain.contains(qr.lines().nth(2).unwrap()));
        assert!(with_qr.contains(qr.lines().nth(2).unwrap()));
        assert!(with_qr.contains("http://localhost:8000/"));
        assert!(with_qr.contains("Press Ctrl+C to stop"));
        assert!(with_qr.len() > plain.len());
    }

    #[test]
    fn uploads_get_a_password_at_a_terminal_and_refuse_without_one_elsewhere() {
        let mut cfg = Config::default();
        assert!(protect_uploads(&mut cfg, false).is_err());
        assert!(cfg.auth.is_none());
        let password = protect_uploads(&mut cfg, true).unwrap().expect("made one");
        assert_eq!(password.len(), 20);
        assert!(cfg.auth.is_some());
        assert_eq!(
            protect_uploads(&mut cfg, false).unwrap(),
            None,
            "one was given"
        );
    }

    #[test]
    fn the_banner_says_how_to_upload() {
        let cfg = Config {
            host: "127.0.0.1".into(),
            max_upload_bytes: 10 << 30,
            auth: Some(Credentials::parse("blaze:pw").unwrap()),
            ..Config::default()
        };
        let text =
            anstream::adapter::strip_str(&banner(&cfg, false, false, None, Some("pw"))).to_string();
        assert!(
            text.contains("blaze put FILE http://localhost:8000/ --auth blaze:pw"),
            "{text}"
        );
        assert!(text.contains("up to 10.00 GiB"), "{text}");
    }
}
