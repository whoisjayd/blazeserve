use blazeserve::config::{Config, TrustedProxy};
use blazeserve::server::resolve_client_ip;
use std::net::IpAddr;

fn behind(proxies: &[&str]) -> Config {
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
fn forwarding_headers_are_ignored_by_default() {
    let config = Config::default();
    assert_eq!(
        resolve_client_ip(
            &config,
            ip("10.0.0.1"),
            Some("198.51.100.1"),
            Some("for=198.51.100.2")
        ),
        ip("10.0.0.1")
    );
}

#[test]
fn direct_client_cannot_spoof_identity_even_with_trust_configured() {
    let config = behind(&["10.0.0.1"]);
    assert_eq!(
        resolve_client_ip(&config, ip("203.0.113.50"), Some("198.51.100.1"), None),
        ip("203.0.113.50")
    );
}

#[test]
fn two_clients_behind_one_proxy_resolve_separately() {
    let config = behind(&["10.0.0.1"]);
    let a = resolve_client_ip(&config, ip("10.0.0.1"), Some("198.51.100.1"), None);
    let b = resolve_client_ip(&config, ip("10.0.0.1"), Some("198.51.100.2"), None);
    assert_ne!(a, b);
    assert_eq!(
        a,
        resolve_client_ip(&config, ip("10.0.0.1"), Some("198.51.100.1"), None)
    );
}

#[test]
fn client_supplied_prefix_is_not_trusted_over_proxy_appended_entry() {
    let config = behind(&["10.0.0.0/8"]);
    let got = resolve_client_ip(
        &config,
        ip("10.0.0.1"),
        Some("1.2.3.4, 198.51.100.9, 10.0.0.2"),
        None,
    );
    assert_eq!(got, ip("198.51.100.9"));
}

#[test]
fn equivalent_address_forms_normalize_identically() {
    let config = behind(&["10.0.0.1"]);
    let plain = resolve_client_ip(&config, ip("10.0.0.1"), Some("198.51.100.4"), None);
    let mapped = resolve_client_ip(
        &config,
        ip("::ffff:10.0.0.1"),
        Some("::ffff:198.51.100.4"),
        None,
    );
    let bracketed = resolve_client_ip(
        &config,
        ip("10.0.0.1"),
        None,
        Some("for=\"198.51.100.4:8080\""),
    );
    assert_eq!(plain, mapped);
    assert_eq!(plain, bracketed);
}

#[test]
fn rejected_inputs_fall_back_to_the_socket_peer() {
    let config = behind(&["10.0.0.1"]);
    for bad in [
        "not-an-ip",
        "fe80::1%eth0",
        "198.51.100.1:70000",
        "[2001:db8::1",
        "198.51.100.1, ,198.51.100.2",
    ] {
        assert_eq!(
            resolve_client_ip(&config, ip("10.0.0.1"), Some(bad), None),
            ip("10.0.0.1"),
            "{bad:?}"
        );
    }
}
