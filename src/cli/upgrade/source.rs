//! Where releases come from: the GitHub Releases API and release downloads, over HTTPS only.

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::time::Duration;

const DEFAULT_API: &str = "https://api.github.com/repos/whoisjayd/blazeserve";
const DEFAULT_DOWNLOADS: &str = "https://github.com/whoisjayd/blazeserve/releases/download";
pub const API_ENV: &str = "BLAZE_UPGRADE_API";
pub const DOWNLOADS_ENV: &str = "BLAZE_UPGRADE_DOWNLOADS";

/// The release metadata response is a few kilobytes; anything near this is wrong.
const MAX_API_BYTES: u64 = 1024 * 1024;

pub trait Source {
    /// The tag of the newest stable release.
    fn latest_tag(&self) -> Result<String, String>;
    /// Streams one release asset into `sink`, failing if it is larger than `limit` bytes.
    fn download(
        &self,
        tag: &str,
        asset: &str,
        limit: u64,
        sink: &mut dyn Write,
    ) -> Result<(), String>;
}

pub struct HttpSource {
    agent: ureq::Agent,
    api: String,
    downloads: String,
}

/// A base URL must be HTTPS. Plain HTTP is accepted only for a loopback host, which is how
/// the tests and a local mirror reach it. Credentials in a URL are never accepted.
fn checked_base(name: &str, value: &str) -> Result<(String, bool), String> {
    let value = value.trim().trim_end_matches('/');
    let (plain, rest) = if let Some(rest) = value.strip_prefix("https://") {
        (false, rest)
    } else if let Some(rest) = value.strip_prefix("http://") {
        (true, rest)
    } else {
        return Err(format!("{name} must be an https:// URL"));
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("{name} must name a host and carry no credentials"));
    }
    if plain {
        let host = if let Some(v6) = authority.strip_prefix('[') {
            v6.split(']').next().unwrap_or_default()
        } else {
            authority.split(':').next().unwrap_or_default()
        };
        if !matches!(host, "localhost" | "127.0.0.1" | "::1") {
            return Err(format!(
                "{name} must use https:// unless it points at this machine"
            ));
        }
    }
    Ok((value.to_owned(), plain))
}

impl HttpSource {
    pub fn from_env() -> Result<Self, String> {
        let get = |name: &str, default: &str| {
            std::env::var(name)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| default.to_owned())
        };
        let (api, plain_api) = checked_base(API_ENV, &get(API_ENV, DEFAULT_API))?;
        let (downloads, plain_dl) =
            checked_base(DOWNLOADS_ENV, &get(DOWNLOADS_ENV, DEFAULT_DOWNLOADS))?;
        // ureq reads HTTPS_PROXY, HTTP_PROXY, ALL_PROXY and NO_PROXY on its own.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(!(plain_api || plain_dl))
            .http_status_as_error(false)
            .user_agent(format!("blazeserve-upgrade/{}", crate::VERSION))
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_recv_response(Some(Duration::from_secs(30)))
            .timeout_per_read(Some(Duration::from_secs(30)))
            .timeout_per_write(Some(Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self {
            agent,
            api,
            downloads,
        })
    }
}

fn status_error(status: u16, what: &str) -> String {
    match status {
        404 => format!("{what} was not found"),
        403 | 429 => format!(
            "GitHub refused the request for {what} (status {status}), probably its rate limit; \
             wait a while, or name the release with --version to skip the lookup"
        ),
        _ => format!("unexpected response (status {status}) for {what}"),
    }
}

impl Source for HttpSource {
    fn latest_tag(&self) -> Result<String, String> {
        let url = format!("{}/releases/latest", self.api);
        let mut response = self
            .agent
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .call()
            .map_err(|e| format!("cannot reach the release server: {e}"))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(status_error(status, "the latest release"));
        }
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_API_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("cannot read the release information: {e}"))?;
        if body.len() as u64 > MAX_API_BYTES {
            return Err("the release information is unexpectedly large".to_owned());
        }
        parse_latest(&body)
    }

    fn download(
        &self,
        tag: &str,
        asset: &str,
        limit: u64,
        sink: &mut dyn Write,
    ) -> Result<(), String> {
        let url = format!("{}/{tag}/{asset}", self.downloads);
        let mut response = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| format!("cannot download {asset}: {e}"))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(status_error(status, &format!("{asset} in release {tag}")));
        }
        if response
            .body()
            .content_length()
            .is_some_and(|len| len > limit)
        {
            return Err(format!("{asset} is larger than the {limit} byte limit"));
        }
        let mut reader = response.body_mut().as_reader().take(limit + 1);
        let copied = std::io::copy(&mut reader, sink)
            .map_err(|e| format!("download of {asset} failed: {e}"))?;
        if copied > limit {
            return Err(format!("{asset} is larger than the {limit} byte limit"));
        }
        Ok(())
    }
}

fn parse_latest(body: &[u8]) -> Result<String, String> {
    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| "the release server sent something that is not JSON".to_owned())?;
    if json["draft"].as_bool() == Some(true) || json["prerelease"].as_bool() == Some(true) {
        return Err(
            "the newest release is a draft or pre-release; use --version to pick one".into(),
        );
    }
    json["tag_name"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "the release information has no tag".to_owned())
}

/// Looks up `name` in `sha256sum` output (`<hex>  <name>` or `<hex> *<name>`).
pub fn checksum_for(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, rest) = line.trim().split_once(char::is_whitespace)?;
        let file = rest.trim_start().trim_start_matches('*');
        (file == name && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

/// Hashes everything written through it.
pub struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    pub fn finish(self) -> (W, String) {
        (self.inner, crate::cli::util::hex(&self.hasher.finalize()))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bases_must_be_https_or_loopback_without_credentials() {
        assert!(checked_base("X", "https://api.github.com/repos/a/b/").is_ok());
        assert!(checked_base("X", "http://127.0.0.1:8080/api").unwrap().1);
        assert!(checked_base("X", "http://[::1]:9/x").is_ok());
        for bad in [
            "http://example.com/x",
            "ftp://example.com",
            "https://user:pw@example.com/x",
            "https://",
            "example.com",
            "http://127.0.0.1.evil.com/x",
        ] {
            assert!(checked_base("X", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn finds_checksums_in_both_sha256sum_styles() {
        let a = "a".repeat(64);
        let b = "B".repeat(64);
        let sums = format!("{a}  one.tar.gz\n{b} *two.zip\nshort  three\n");
        assert_eq!(checksum_for(&sums, "one.tar.gz"), Some(a));
        assert_eq!(checksum_for(&sums, "two.zip"), Some("b".repeat(64)));
        assert_eq!(checksum_for(&sums, "three"), None);
        assert_eq!(checksum_for(&sums, "one"), None);
    }

    #[test]
    fn latest_release_must_be_stable_and_tagged() {
        assert_eq!(parse_latest(br#"{"tag_name":"v1.2.3"}"#).unwrap(), "v1.2.3");
        assert!(parse_latest(br#"{"tag_name":"v1.2.3","prerelease":true}"#).is_err());
        assert!(parse_latest(br#"{}"#).is_err());
        assert!(parse_latest(b"<html>").is_err());
    }
}
