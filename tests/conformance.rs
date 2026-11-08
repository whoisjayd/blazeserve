mod conformance_support;
mod http_common;

use conformance_support::*;
use http_common::{Resp, start_with};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_cases_conform_to_the_documented_behavior() {
    let files = files();
    let fx = start_with(|root, _| install(root)).await;
    let learned = learn(fx.addr, &files).unwrap_or_else(|e| panic!("fixture learning failed: {e}"));
    let cfg = config_from_env();
    let mut stats = Stats::default();
    for seed in &cfg.seeds {
        if let Err(report) = run_seed(
            fx.addr,
            &files,
            &learned,
            *seed,
            cfg.cases,
            Mutation::None,
            &mut stats,
        ) {
            panic!("{report}");
        }
    }
    println!(
        "conformance: {} seeds x {} cases, outcomes {stats:?}",
        cfg.seeds.len(),
        cfg.cases
    );
    if !cfg.single_seed && cfg.cases >= 100 {
        stats
            .covers_every_outcome()
            .unwrap_or_else(|e| panic!("{e}: {stats:?}"));
    }
    fx.stop().await;
}

#[test]
fn replaying_a_seed_generates_identical_cases() {
    let files = files();
    let first = format!("{:?}", gen_cases(7, 80, &files));
    let second = format!("{:?}", gen_cases(7, 80, &files));
    assert_eq!(first, second);
    assert_ne!(first, format!("{:?}", gen_cases(8, 80, &files)));
    let prefix = format!("{:?}", gen_cases(7, 20, &files));
    let longer = gen_cases(7, 80, &files);
    assert_eq!(
        prefix,
        format!("{:?}", &longer[..20]),
        "case i must not depend on the case count"
    );
    for case in &longer {
        assert!((2..=6).contains(&case.len()));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_oracle_is_reported_with_seed_sequence_and_replay_command() {
    let files = files();
    let fx = start_with(|root, _| install(root)).await;
    let learned = learn(fx.addr, &files).expect("fixtures learned");
    let mut stats = Stats::default();
    let report = run_seed(
        fx.addr,
        &files,
        &learned,
        11,
        60,
        Mutation::RangeEndOffByOne,
        &mut stats,
    )
    .expect_err("a sabotaged oracle must be detected");
    println!("{report}");
    assert!(report.contains("seed: 11"), "{report}");
    assert!(
        report.contains("BLAZE_CONFORMANCE_SEED=11 cargo test --test conformance -- --nocapture"),
        "{report}"
    );
    assert!(report.contains("request sequence"), "{report}");
    assert!(report.contains("header content-range"), "{report}");
    let minimized = report
        .split("minimized sequence (")
        .nth(1)
        .expect("minimized section");
    assert!(
        minimized.starts_with("1 requests)"),
        "shrinking should reach one request:\n{report}"
    );
    assert!(minimized.contains("Range: "), "{report}");
    fx.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_checker_rejects_each_kind_of_deviation() {
    let files = files();
    let fx = start_with(|root, _| install(root)).await;
    let learned = learn(fx.addr, &files).expect("fixtures learned");
    let req = Req {
        file: 0,
        head: false,
        range: RangeKind::Valid {
            specs: vec![Spec::Span(Num::Lit(0), Num::Lit(4))],
            upper_unit: false,
        },
        if_range: IfRange::None,
        inm: Inm::None,
        ims: Ims::None,
        ae: Ae::None,
        rid: Rid::None,
    };
    let exp = expect(&req, &files, &learned, Mutation::None);
    let good =
        http_common::Conn::open(fx.addr).send("GET", "/hello.txt", &[("Range", "bytes=0-4")]);
    assert!(check(&exp, &good, false).is_ok());

    let clone = |r: &Resp| Resp {
        status: r.status,
        headers: r.headers.clone(),
        body: r.body.clone(),
    };
    let mut wrong_status = clone(&good);
    wrong_status.status = 200;
    assert!(check(&exp, &wrong_status, false).is_err());

    let mut wrong_body = clone(&good);
    wrong_body.body[0] ^= 0xFF;
    assert!(check(&exp, &wrong_body, false).is_err());

    let mut wrong_length = clone(&good);
    for (k, v) in &mut wrong_length.headers {
        if k.eq_ignore_ascii_case("content-length") {
            *v = "6".into();
        }
    }
    assert!(check(&exp, &wrong_length, false).is_err());

    let mut missing_header = clone(&good);
    missing_header
        .headers
        .retain(|(k, _)| !k.eq_ignore_ascii_case("etag"));
    assert!(check(&exp, &missing_header, false).is_err());

    let mut closing = clone(&good);
    closing.headers.push(("Connection".into(), "close".into()));
    assert!(check(&exp, &closing, false).is_err());

    let mut head_with_body = clone(&good);
    head_with_body.body = b"Hello".to_vec();
    assert!(check(&exp, &head_with_body, true).is_err());
    fx.stop().await;
}
