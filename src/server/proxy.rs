//! Trusted-proxy client identity from `Forwarded` and `X-Forwarded-For`.

use crate::config::{Config, TrustedProxy, normalize};
use hyper::HeaderMap;
use std::net::{IpAddr, Ipv4Addr};

const MAX_FORWARDED_HEADER: usize = 2048;

pub(super) fn client_ip_for(config: &Config, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let peer = normalize(peer);
    if config.trusted_proxies.is_empty() || !is_trusted(&config.trusted_proxies, peer) {
        return peer;
    }
    let joined = |name: &str| -> Result<Option<String>, ()> {
        let mut parts = Vec::new();
        for v in headers.get_all(name) {
            parts.push(v.to_str().map_err(|_| ())?);
        }
        Ok((!parts.is_empty()).then(|| parts.join(", ")))
    };
    match (joined("forwarded"), joined("x-forwarded-for")) {
        (Ok(fwd), Ok(xff)) => resolve_client_ip(config, peer, xff.as_deref(), fwd.as_deref()),
        _ => peer,
    }
}

fn is_trusted(proxies: &[TrustedProxy], ip: IpAddr) -> bool {
    proxies.iter().any(|p| p.contains(ip))
}

/// A trusted peer's `Forwarded` header wins over `X-Forwarded-For`. The chain is walked
/// right to left, skipping trusted hops; the first untrusted address is the client. Any
/// malformed, overlong or excessive chain falls back to the socket peer.
pub fn resolve_client_ip(
    config: &Config,
    peer: IpAddr,
    forwarded_for: Option<&str>,
    forwarded: Option<&str>,
) -> IpAddr {
    let peer = normalize(peer);
    if config.trusted_proxies.is_empty() || !is_trusted(&config.trusted_proxies, peer) {
        return peer;
    }
    let chain = match forwarded.map(parse_forwarded) {
        Some(Err(())) => return peer,
        Some(Ok(Some(chain))) => chain,
        Some(Ok(None)) | None => match forwarded_for.map(parse_x_forwarded_for) {
            Some(Ok(chain)) => chain,
            _ => return peer,
        },
    };
    if chain.is_empty() || chain.len() > config.max_proxy_hops.saturating_add(1) {
        return peer;
    }
    let mut skipped = 0usize;
    for ip in chain.into_iter().rev() {
        if !is_trusted(&config.trusted_proxies, ip) {
            return ip;
        }
        skipped += 1;
        if skipped > config.max_proxy_hops {
            return peer;
        }
    }
    peer
}

fn parse_x_forwarded_for(value: &str) -> Result<Vec<IpAddr>, ()> {
    if value.len() > MAX_FORWARDED_HEADER {
        return Err(());
    }
    value.split(',').map(parse_node).collect()
}

/// `Ok(None)` means no element carries `for=`; a mix of present and absent is malformed
/// because positions in the chain would no longer line up with proxies.
fn parse_forwarded(value: &str) -> Result<Option<Vec<IpAddr>>, ()> {
    if value.len() > MAX_FORWARDED_HEADER {
        return Err(());
    }
    let mut chain = Vec::new();
    let mut elements = 0usize;
    for element in value.split(',') {
        elements += 1;
        let mut found = None;
        for pair in element.split(';') {
            let Some((key, val)) = pair.split_once('=') else {
                return Err(());
            };
            if key.trim().eq_ignore_ascii_case("for") {
                if found.is_some() {
                    return Err(());
                }
                found = Some(parse_node(val)?);
            }
        }
        if let Some(ip) = found {
            chain.push(ip);
        }
    }
    match chain.len() {
        0 => Ok(None),
        n if n == elements => Ok(Some(chain)),
        _ => Err(()),
    }
}

/// Zone ids, `unknown` and obfuscated identifiers are rejected.
fn parse_node(raw: &str) -> Result<IpAddr, ()> {
    let s = raw.trim().trim_matches('"');
    if s.is_empty() || s.contains('%') {
        return Err(());
    }
    let port_ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| n <= 65535)
    };
    let ip = if let Some(rest) = s.strip_prefix('[') {
        let (inner, tail) = rest.split_once(']').ok_or(())?;
        if !tail.is_empty() && !tail.strip_prefix(':').is_some_and(port_ok) {
            return Err(());
        }
        inner.parse::<std::net::Ipv6Addr>().map_err(|_| ())?.into()
    } else if s.matches(':').count() == 1 {
        let (host, port) = s.split_once(':').ok_or(())?;
        if !port_ok(port) {
            return Err(());
        }
        host.parse::<Ipv4Addr>().map_err(|_| ())?.into()
    } else {
        s.parse::<IpAddr>().map_err(|_| ())?
    };
    Ok(normalize(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(proxies: &[&str]) -> Config {
        Config {
            trusted_proxies: proxies
                .iter()
                .map(|p| TrustedProxy::parse(p).unwrap())
                .collect(),
            ..Config::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_cannot_choose_identity() {
        let c = cfg(&["10.0.0.1"]);
        assert_eq!(
            resolve_client_ip(&c, ip("203.0.113.9"), Some("1.1.1.1"), Some("for=2.2.2.2")),
            ip("203.0.113.9")
        );
        assert_eq!(
            resolve_client_ip(&Config::default(), ip("10.0.0.1"), Some("1.1.1.1"), None),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn trusted_peer_resolves_chain_right_to_left() {
        let c = cfg(&["10.0.0.0/8"]);
        assert_eq!(
            resolve_client_ip(&c, ip("10.0.0.1"), Some("198.51.100.7, 10.0.0.2"), None),
            ip("198.51.100.7")
        );
        assert_eq!(
            resolve_client_ip(
                &c,
                ip("10.0.0.1"),
                Some("6.6.6.6, 198.51.100.7, 10.0.0.2"),
                None
            ),
            ip("198.51.100.7")
        );
        assert_eq!(
            resolve_client_ip(&c, ip("10.0.0.1"), Some("10.0.0.3"), None),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn forwarded_header_wins_over_x_forwarded_for() {
        let c = cfg(&["10.0.0.1"]);
        let got = resolve_client_ip(
            &c,
            ip("10.0.0.1"),
            Some("9.9.9.9"),
            Some("for=198.51.100.1;proto=https"),
        );
        assert_eq!(got, ip("198.51.100.1"));
        let v6 = resolve_client_ip(&c, ip("10.0.0.1"), None, Some("for=\"[2001:db8::1]:4711\""));
        assert_eq!(v6, ip("2001:db8::1"));
    }

    #[test]
    fn mapped_ipv6_is_normalized() {
        let c = cfg(&["10.0.0.1"]);
        assert_eq!(
            resolve_client_ip(&c, ip("::ffff:10.0.0.1"), Some("::ffff:198.51.100.2"), None),
            ip("198.51.100.2")
        );
    }

    #[test]
    fn malformed_or_oversized_chains_fall_back_to_peer() {
        let c = cfg(&["10.0.0.1"]);
        for bad in [
            "unknown",
            "1.2.3.4, bogus",
            "fe80::1%eth0",
            "1.2.3.4:99999",
            "[::1",
            "",
            "1.2.3.4:",
        ] {
            assert_eq!(
                resolve_client_ip(&c, ip("10.0.0.1"), Some(bad), None),
                ip("10.0.0.1"),
                "{bad:?}"
            );
        }
        assert_eq!(
            resolve_client_ip(&c, ip("10.0.0.1"), None, Some("for=1.1.1.1, proto=https")),
            ip("10.0.0.1")
        );
        let long = vec!["1.1.1.1"; 400].join(",");
        assert_eq!(
            resolve_client_ip(&c, ip("10.0.0.1"), Some(&long), None),
            ip("10.0.0.1")
        );
        let mut bounded = cfg(&["10.0.0.0/8"]);
        bounded.max_proxy_hops = 2;
        assert_eq!(
            resolve_client_ip(
                &bounded,
                ip("10.0.0.1"),
                Some("1.1.1.1, 10.0.0.2, 10.0.0.3, 10.0.0.4"),
                None
            ),
            ip("10.0.0.1")
        );
    }
}
