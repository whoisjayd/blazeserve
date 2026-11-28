mod cli_support;

use cli_support::{blaze, code, run, stderr, stdout};

#[test]
fn version_json_has_identity() {
    let out = run(&["version", "--json"]);
    assert_eq!(code(&out), 0);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["name"], "blazeserve");
    assert_eq!(v["version"], blazeserve::VERSION);
    assert!(v["platform"].is_string() && v["architecture"].is_string());
}

#[test]
fn version_flag_and_help_list_commands() {
    let out = run(&["--version"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains(blazeserve::VERSION));

    let help = stdout(&run(&["--help"]));
    for cmd in [
        "serve",
        "send",
        "checksum",
        "version",
        "doctor",
        "benchmark",
        "get",
        "put",
    ] {
        assert!(help.contains(cmd), "help should list {cmd}");
    }
}

#[test]
fn serve_help_documents_options() {
    let help = stdout(&run(&["serve", "--help"]));
    for flag in [
        "--chunk-mb",
        "--sock-sndbuf-mb",
        "--rate-mbps",
        "--cors",
        "--log-json",
        "--max-connections",
        "--header-timeout",
        "--trust-proxy",
        "--max-proxy-hops",
        "--tls-cert",
        "--auth-env",
    ] {
        assert!(help.contains(flag), "serve help should list {flag}");
    }
}

#[test]
fn checksum_streams_known_digest() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("abc.txt");
    std::fs::write(&file, b"abc").unwrap();
    let out = run(&["checksum", file.to_str().unwrap()]);
    assert_eq!(code(&out), 0);
    let text = stdout(&out);
    assert!(text.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    assert!(text.contains("3 B"));
}

#[test]
fn checksum_missing_file_is_usage_error() {
    let out = run(&["checksum", "definitely-missing-file.bin"]);
    assert_eq!(code(&out), 2);
    assert!(stderr(&out).to_lowercase().contains("invalid value"));
}

#[test]
fn doctor_json_reports_checks() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(&["doctor", dir.path().to_str().unwrap(), "-p", "0", "--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["success"], true);
    assert_eq!(v["port"], 0);
    let checks = v["checks"].as_array().unwrap();
    for id in [
        "base_path",
        "port_binding",
        "async_io",
        "tls_ready",
        "file_descriptor_limit",
    ] {
        assert!(checks.iter().any(|c| c["id"] == id), "missing check {id}");
    }
    let base = checks.iter().find(|c| c["id"] == "base_path").unwrap();
    assert_eq!(base["outcome"], "pass");
}

fn doctor_port_check(args: &[&str]) -> (i32, serde_json::Value) {
    let dir = tempfile::tempdir().unwrap();
    let mut full = vec!["doctor", dir.path().to_str().unwrap(), "--json"];
    full.extend_from_slice(args);
    let out = run(&full);
    let v = serde_json::from_str(&stdout(&out)).unwrap();
    (code(&out), v)
}

fn port_check(v: &serde_json::Value) -> &serde_json::Value {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "port_binding")
        .unwrap()
}

#[test]
fn doctor_defaults_to_loopback_and_names_the_address() {
    let (status, v) = doctor_port_check(&["-p", "0"]);
    assert_eq!(status, 0);
    assert_eq!(v["host"], "127.0.0.1");
    let details = port_check(&v)["details"].as_str().unwrap();
    assert!(details.contains("127.0.0.1:"), "{details}");
    assert!(details.contains("not a reservation"), "{details}");
}

#[test]
fn doctor_checks_the_wildcard_host_it_was_given() {
    let (status, v) = doctor_port_check(&["--host", "0.0.0.0", "-p", "0"]);
    assert_eq!(status, 0);
    assert_eq!(v["host"], "0.0.0.0");
    let details = port_check(&v)["details"].as_str().unwrap();
    assert!(details.contains("0.0.0.0:"), "{details}");
}

#[test]
fn doctor_reports_ipv6_only_when_it_can_bind() {
    let ipv6 = std::net::TcpListener::bind(("::1", 0)).is_ok();
    let (status, v) = doctor_port_check(&["--host", "::1", "-p", "0"]);
    assert_eq!(status == 0, ipv6, "{v}");
    assert_eq!(
        port_check(&v)["outcome"],
        if ipv6 { "pass" } else { "fail" }
    );
    if ipv6 {
        let details = port_check(&v)["details"].as_str().unwrap();
        assert!(details.contains("[::1]:"), "{details}");
    }
}

#[test]
fn doctor_fails_on_an_occupied_matching_address() {
    let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = held.local_addr().unwrap().port().to_string();
    let (status, v) = doctor_port_check(&["--host", "127.0.0.1", "-p", &port]);
    assert_eq!(status, 1);
    assert_eq!(v["success"], false);
    let check = port_check(&v);
    assert_eq!(check["outcome"], "fail");
    assert!(check["details"].as_str().unwrap().contains("127.0.0.1:"));
    drop(held);
}

#[test]
fn doctor_fails_for_an_address_not_on_this_machine() {
    let (status, v) = doctor_port_check(&["--host", "192.0.2.1", "-p", "0"]);
    assert_eq!(status, 1);
    assert_eq!(port_check(&v)["outcome"], "fail");
    let details = port_check(&v)["details"].as_str().unwrap();
    assert!(details.contains("192.0.2.1"), "{details}");
}

#[test]
fn doctor_fails_for_an_unresolvable_host() {
    let (status, v) = doctor_port_check(&["--host", "no-such-host.invalid", "-p", "0"]);
    assert_eq!(status, 1);
    assert_eq!(port_check(&v)["outcome"], "fail");
}

#[test]
fn doctor_fails_for_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    let out = run(&["doctor", missing.to_str().unwrap(), "-p", "0", "--json"]);
    assert_eq!(code(&out), 1);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(v["success"], false);
}

#[test]
fn doctor_human_output_has_title() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(&["doctor", dir.path().to_str().unwrap(), "-p", "0"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).contains("BlazeServe diagnostics"));
}

#[test]
fn out_of_range_port_is_usage_error() {
    assert_eq!(code(&run(&["serve", "--port", "0"])), 2);
}

#[test]
fn missing_tls_file_is_rejected_before_binding() {
    let out = run(&[
        "serve",
        "--tls-cert",
        "missing.pem",
        "--tls-key",
        "missing.key",
    ]);
    assert_eq!(code(&out), 2);
    let err = stderr(&out).to_lowercase();
    assert!(err.contains("invalid value") && err.contains("exist"));
}

#[test]
fn half_tls_pair_fails_before_binding() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    std::fs::write(&cert, b"x").unwrap();
    let out = run(&[
        "serve",
        dir.path().to_str().unwrap(),
        "--tls-cert",
        cert.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("must be provided together"));
}

#[test]
fn missing_auth_env_never_starts_unauthenticated() {
    let dir = tempfile::tempdir().unwrap();
    let out = blaze()
        .args([
            "serve",
            dir.path().to_str().unwrap(),
            "--auth-env",
            "BLAZE_TEST_UNSET_CREDENTIALS",
        ])
        .env_remove("BLAZE_TEST_UNSET_CREDENTIALS")
        .output()
        .unwrap();
    assert_eq!(code(&out), 1);
    let err = stderr(&out);
    assert!(err.contains("missing or empty"));
    assert!(err.contains("$env:BLAZE_TEST_UNSET_CREDENTIALS"));
    assert!(err.contains("export BLAZE_TEST_UNSET_CREDENTIALS"));
}

#[test]
fn empty_auth_env_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let out = blaze()
        .args([
            "serve",
            dir.path().to_str().unwrap(),
            "--auth-env",
            "BLAZE_TEST_EMPTY_CREDENTIALS",
        ])
        .env("BLAZE_TEST_EMPTY_CREDENTIALS", "")
        .output()
        .unwrap();
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("missing or empty"));
}

#[test]
fn auth_without_colon_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(&["serve", dir.path().to_str().unwrap(), "--auth", "nocolon"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("USER:PASS"));
}

#[test]
fn send_requires_an_existing_file() {
    assert_eq!(code(&run(&["send", "definitely-missing-file.bin"])), 2);
}

#[test]
fn benchmark_rejects_unsafe_urls() {
    for url in [
        "ftp://host",
        "http://user:pw@127.0.0.1:1",
        "http://127.0.0.1:1/?x=1",
    ] {
        let out = run(&["benchmark", "--url", url, "--size-mb", "1"]);
        assert_eq!(code(&out), 1, "{url}");
        assert!(
            stderr(&out).contains("HTTP(S) origin without credentials"),
            "{url}"
        );
    }
}

#[test]
fn benchmark_url_never_starts_a_server() {
    let out = run(&["benchmark", "--url", "http://127.0.0.1:1", "--size-mb", "1"]);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("Could not connect to a BlazeServe server"));
}

#[test]
fn benchmark_local_json_is_one_line() {
    let out = run(&["benchmark", "--size-mb", "1", "--json"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1);
    let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(v["requested_bytes"], 1024 * 1024);
    assert_eq!(v["downloaded_bytes"], 1024 * 1024);
    assert!(
        v["base_url"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:")
    );
    assert!(v["elapsed_seconds"].as_f64().unwrap() > 0.0);
    assert!(v["throughput_mib_per_second"].as_f64().unwrap() > 0.0);
}

#[test]
fn send_rejects_bad_expiry_before_listening() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f.txt");
    std::fs::write(&file, b"x").unwrap();
    for bad in [
        "0",
        "0s",
        "-5m",
        "20",
        "10x",
        "99999999999999999999d",
        "366d",
    ] {
        let flag = format!("--expires-after={bad}");
        let out = run(&["send", file.to_str().unwrap(), &flag]);
        assert_eq!(code(&out), 2, "{bad}: {}", stderr(&out));
        assert!(stderr(&out).contains("expires-after"), "{bad}");
        assert!(stdout(&out).is_empty(), "{bad} must not print a banner");
    }
}

#[test]
fn send_expires_on_its_own_and_reports_why() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("f.txt");
    std::fs::write(&file, b"x").unwrap();
    let port = {
        let probe = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        probe.local_addr().unwrap().port().to_string()
    };
    let out = run(&[
        "send",
        file.to_str().unwrap(),
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--expires-after",
        "1s",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("in 1s (at "), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("Stopped: share expired after 1s"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn send_help_explains_the_expiry_grace_period() {
    let help = stdout(&run(&["send", "--help"]));
    assert!(help.contains("--expires-after"));
    assert!(help.contains("10 more seconds"), "{help}");
    assert!(help.contains("sleeps"), "{help}");
}

#[test]
fn man_prints_a_man_page() {
    let out = run(&["man"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let page = stdout(&out);
    assert!(page.contains(".TH blaze 1"), "{page}");
    assert!(page.contains("Download a file"), "{page}");
}
