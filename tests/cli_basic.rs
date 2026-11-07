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
    assert!(text.contains("3.00B"));
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
