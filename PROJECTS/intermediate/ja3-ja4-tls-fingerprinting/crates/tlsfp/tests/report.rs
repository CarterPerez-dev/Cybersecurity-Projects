// ©AngelaMos | 2026
// report.rs

//! End to end coverage of the forensic report mode.
//!
//! These drive the real binary against a vendored capture the way an analyst
//! would, then assert on what it prints. The capture is read with a database
//! path that does not exist, so the report runs as a pure fingerprint inventory
//! with no intelligence side effects and no dependence on a seeded store, which
//! keeps the test hermetic.

use std::path::PathBuf;
use std::process::Command;

/// The vendored capture used throughout: a browser session with TLS, QUIC, and
/// certificate handshakes, enough to exercise every section of the report.
fn capture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/pcap/tls-handshake.pcapng")
}

/// A database path under the temp directory that is guaranteed not to exist, so
/// the report stays a pure inventory and never writes a store behind the test.
fn absent_db() -> PathBuf {
    std::env::temp_dir().join(format!(
        "tlsfp-report-test-{}-absent.db",
        std::process::id()
    ))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tlsfp"))
        .args(args)
        .output()
        .expect("running the tlsfp binary")
}

#[test]
fn text_report_has_every_section() {
    let db = absent_db();
    let output = run(&[
        "pcap",
        capture().to_str().unwrap(),
        "--report",
        "--db",
        db.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "report run failed");
    let text = String::from_utf8(output.stdout).expect("utf8 report");

    for section in [
        "== capture ==",
        "== fingerprints by kind ==",
        "== top client ja4 ==",
        "== endpoints ==",
        "== intelligence ==",
        "== alerts ==",
        "== coverage ==",
    ] {
        assert!(text.contains(section), "missing section {section}");
    }
    assert!(text.contains("t13d1516h2_8daaf6152771_e5627efa2ab1"));
    assert!(text.contains("q13d0310h3_55b375c5d22e_cd85d2d88918"));
    assert!(text.contains("tls miss rate"));
    assert!(text.contains("fp/s"));
    assert!(!db.exists(), "report must not create a database");
}

#[test]
fn json_report_is_well_formed() {
    let db = absent_db();
    let output = run(&[
        "pcap",
        capture().to_str().unwrap(),
        "--report",
        "--json",
        "--db",
        db.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "json report run failed");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("report is valid JSON");

    assert!(value["capture"]["frames"].as_u64().unwrap() > 0);
    assert!(
        value["coverage"]["counters"]["tls_handshakes_fingerprinted"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(value["coverage"]["events_per_sec"].as_f64().unwrap() > 0.0);
    assert!(
        !value["distribution"]["top_ja4"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let endpoints = value["endpoints"].as_array().unwrap();
    assert!(endpoints.iter().any(|e| e["ip"] == "192.168.1.168"));
}

#[test]
fn top_flag_caps_ranked_rows() {
    let db = absent_db();
    let output = run(&[
        "pcap",
        capture().to_str().unwrap(),
        "--report",
        "--json",
        "--top",
        "2",
        "--db",
        db.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "capped report run failed");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("report is valid JSON");
    assert!(value["distribution"]["top_sni"].as_array().unwrap().len() <= 2);
}
