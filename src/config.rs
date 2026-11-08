//! One typed, validated runtime configuration. Every entry point (`serve`, `send`,
//! the Rust API) resolves into [`Config`] and calls [`Config::validate`] before any
//! socket is bound. The Rust API never reads process environment implicitly.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

pub const DEFAULT_CHUNK_MB: u32 = 1;
pub const DEFAULT_SNDBUF_MB: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Credentials {
    pub fn parse(pair: &str) -> Result<Self, ConfigError> {
        match pair.split_once(':') {
            Some((u, p)) => Ok(Self {
                user: u.to_owned(),
                password: p.to_owned(),
            }),
            None => err("Auth must be USER:PASS"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// A trusted proxy peer or network (`10.0.0.0/8`, `::1`, `192.168.1.5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxy {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl TrustedProxy {
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .trim()
            .parse()
            .map_err(|_| ConfigError(format!("invalid trusted proxy address: {s:?}")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|v| *v <= max)
                .ok_or_else(|| ConfigError(format!("invalid prefix length in {s:?}")))?,
            None => max,
        };
        Ok(Self {
            addr: normalize(addr),
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(n), IpAddr::V4(i)) => mask_eq(&n.octets(), &i.octets(), self.prefix),
            (IpAddr::V6(n), IpAddr::V6(i)) => mask_eq(&n.octets(), &i.octets(), self.prefix),
            _ => false,
        }
    }
}

pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn mask_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = prefix % 8;
    rem == 0 || (a[full] ^ b[full]) >> (8 - rem) == 0
}

/// Entries that must look nonexistent: omitted from listings and archives, 404 when
/// requested. A pattern without `/` matches any path component (`*.env`, `.git`); one with
/// `/` is anchored at the served root (`secrets/**`, `docs/*.draft`) and `*` does not cross
/// `/`. Matching is case-insensitive where the filesystem is, so `.ENV` cannot dodge `.env`.
#[derive(Debug, Clone, Default)]
pub struct Hide {
    patterns: Vec<String>,
    names: GlobSet,
    paths: GlobSet,
}

impl Hide {
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Result<Self, ConfigError> {
        let fold = cfg!(any(windows, target_os = "macos"));
        let (mut names, mut paths) = (GlobSetBuilder::new(), GlobSetBuilder::new());
        let mut kept = Vec::new();
        for raw in patterns {
            let raw = raw.as_ref();
            let pat = raw.trim().trim_start_matches("./").trim_matches('/');
            if pat.is_empty() {
                return err(format!("--hide pattern must not be empty: {raw:?}"));
            }
            let compile = |p: &str| {
                GlobBuilder::new(p)
                    .literal_separator(true)
                    .case_insensitive(fold)
                    .build()
                    .map_err(|e| {
                        ConfigError(format!("invalid --hide pattern {raw:?}: {}", e.kind()))
                    })
            };
            if pat.contains('/') {
                paths.add(compile(pat)?);
                // `dir/**` must also hide `dir` itself, which globset only matches below it.
                if let Some(dir) = pat.strip_suffix("/**") {
                    paths.add(compile(dir)?);
                }
            } else {
                names.add(compile(pat)?);
            }
            kept.push(pat.to_owned());
        }
        let build = |b: GlobSetBuilder| {
            b.build()
                .map_err(|e| ConfigError(format!("invalid --hide pattern: {e}")))
        };
        Ok(Self {
            patterns: kept,
            names: build(names)?,
            paths: build(paths)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// `rel` is the path below the served root, one string per component. A hidden
    /// directory hides everything under it, so every prefix is tested.
    pub fn matches<S: AsRef<str>>(&self, rel: &[S]) -> bool {
        if self.is_empty() {
            return false;
        }
        let mut joined = String::new();
        for part in rel {
            // Windows opens `name.` and `name ` as `name`.
            let part = if cfg!(windows) {
                part.as_ref().trim_end_matches(['.', ' '])
            } else {
                part.as_ref()
            };
            if !joined.is_empty() {
                joined.push('/');
            }
            joined.push_str(part);
            if self.names.is_match(part) || self.paths.is_match(&joined) {
                return true;
            }
        }
        false
    }

    /// Tests the lexical path and the canonical one, so a visible symlink or a Windows
    /// short name cannot reach a hidden entry.
    pub fn hides_path(&self, base: &Path, path: &Path) -> bool {
        if self.is_empty() {
            return false;
        }
        let rel_of = |b: &Path, p: &Path| -> Option<Vec<String>> {
            Some(
                p.strip_prefix(b)
                    .ok()?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect(),
            )
        };
        if rel_of(base, path).is_some_and(|r| self.matches(&r)) {
            return true;
        }
        match (base.canonicalize(), path.canonicalize()) {
            (Ok(b), Ok(p)) => rel_of(&b, &p).is_some_and(|r| self.matches(&r)),
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub base: PathBuf,
    pub single: Option<PathBuf>,
    pub listing: bool,
    /// Transfer chunk size in bytes (read buffer per active transfer; bounded).
    pub chunk_bytes: usize,
    pub sndbuf_bytes: usize,
    /// Idle (keep-alive and body) timeout in seconds.
    pub timeout_secs: u64,
    /// Max seconds to receive complete request headers (slow-header defence).
    pub header_timeout_secs: u64,
    pub rate_mbps: Option<f64>,
    pub auth: Option<Credentials>,
    pub tls: Option<TlsConfig>,
    pub cors: bool,
    pub cors_origin: String,
    pub no_cache: bool,
    pub index: Vec<String>,
    pub hide: Hide,
    pub backlog: u32,
    pub precompress: bool,
    /// 0 disables uploads. The legacy server accepted unlimited uploads by default.
    pub max_upload_bytes: u64,
    pub log_json: bool,
    pub verbose: bool,
    pub max_connections: usize,
    /// Serve HTTP/2 (ALPN `h2` over TLS, prior-knowledge h2c over plaintext) next to HTTP/1.1.
    pub http2: bool,
    /// Trusted reverse proxies. Empty (default) means forwarding headers are ignored.
    pub trusted_proxies: Vec<TrustedProxy>,
    pub max_proxy_hops: usize,
    /// OTLP/HTTP collector base URL. `None` disables export; an empty string opts in to the
    /// standard `OTEL_EXPORTER_OTLP_*` environment variables.
    pub otlp_endpoint: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 8000,
            base: PathBuf::from("."),
            single: None,
            listing: true,
            chunk_bytes: DEFAULT_CHUNK_MB as usize * 1024 * 1024,
            sndbuf_bytes: DEFAULT_SNDBUF_MB as usize * 1024 * 1024,
            timeout_secs: 60,
            header_timeout_secs: 10,
            rate_mbps: None,
            auth: None,
            tls: None,
            cors: false,
            cors_origin: "*".into(),
            no_cache: false,
            index: Vec::new(),
            hide: Hide::default(),
            backlog: 4096,
            precompress: true,
            max_upload_bytes: 0,
            log_json: false,
            verbose: false,
            max_connections: 1024,
            http2: true,
            trusted_proxies: Vec::new(),
            max_proxy_hops: 8,
            otlp_endpoint: None,
        }
    }
}

impl Config {
    /// Fail closed on any inconsistent combination, naming the offending option.
    /// Never echoes credentials or key material.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(r) = self.rate_mbps
            && !(r.is_finite() && r > 0.0)
        {
            return err("--rate-mbps must be greater than zero when configured");
        }
        if let Some(a) = &self.auth
            && a.user.is_empty()
            && a.password.is_empty()
        {
            return err("authentication credentials must not be empty");
        }
        if self.chunk_bytes < 4 * 1024 {
            return err("--chunk-mb is too small");
        }
        if self.max_connections == 0 {
            return err("--max-connections must be at least 1");
        }
        if self.header_timeout_secs == 0 || self.timeout_secs == 0 {
            return err("timeouts must be at least 1 second");
        }
        if let Some(s) = &self.single
            && !s.is_file()
        {
            return err(format!("single file not found: {}", s.display()));
        }
        if !self.base.is_dir() {
            return err(format!(
                "path not found or not a directory: {}",
                self.base.display()
            ));
        }
        if let Some(t) = &self.tls {
            if !t.cert.is_file() {
                return err("--tls-cert file not found");
            }
            if !t.key.is_file() {
                return err("--tls-key file not found");
            }
        }
        Ok(())
    }

    pub fn tls_pair(
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
    ) -> Result<Option<TlsConfig>, ConfigError> {
        match (cert, key) {
            (None, None) => Ok(None),
            (Some(cert), Some(key)) => Ok(Some(TlsConfig { cert, key })),
            _ => err("--tls-cert and --tls-key must be provided together"),
        }
    }

    pub fn rate_bps(&self) -> Option<f64> {
        self.rate_mbps.map(|m| m * 1024.0 * 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_debug_is_redacted() {
        let c = Credentials::parse("admin:hunter2").unwrap();
        let s = format!("{c:?}");
        assert!(!s.contains("hunter2") && !s.contains("admin"));
    }

    #[test]
    fn password_may_contain_colon() {
        assert_eq!(Credentials::parse("u:p:q").unwrap().password, "p:q");
        assert!(Credentials::parse("nocolon").is_err());
    }

    #[test]
    fn trusted_proxy_matching() {
        let n = TrustedProxy::parse("10.0.0.0/8").unwrap();
        assert!(n.contains("10.1.2.3".parse().unwrap()));
        assert!(!n.contains("11.0.0.1".parse().unwrap()));
        assert!(n.contains("::ffff:10.9.9.9".parse().unwrap()));
        assert!(TrustedProxy::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn hide_patterns_match_names_and_anchored_paths() {
        let h = Hide::new(&["*.env", ".git", "secrets/**", "docs/*.draft"]).unwrap();
        assert!(h.matches(&["a", "prod.env"]));
        assert!(h.matches(&[".git", "config"]));
        assert!(h.matches(&["secrets"]) && h.matches(&["secrets", "k", "v"]));
        assert!(h.matches(&["docs", "a.draft"]));
        assert!(!h.matches(&["docs", "x", "a.draft"]));
        assert!(!h.matches(&["a", "secrets"]) && !h.matches(&["ok.txt"]));
        assert_eq!(
            h.matches(&["PROD.ENV"]),
            cfg!(any(windows, target_os = "macos"))
        );
    }

    #[test]
    fn bad_hide_pattern_is_rejected() {
        assert!(Hide::new(&["[unclosed"]).is_err());
        assert!(Hide::new(&["  "]).is_err());
    }

    #[test]
    fn half_tls_pair_is_rejected() {
        assert!(Config::tls_pair(Some("a".into()), None).is_err());
        assert!(Config::tls_pair(None, None).unwrap().is_none());
    }
}
