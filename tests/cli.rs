//! End-to-end tests of the real `jxscout-rs` binary (closing the CLI gaps
//! from the independent review). Everything talks to local mock servers.

mod common;

use std::io::Write as _;
use std::process::{Command, Output, Stdio};

use common::*;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_jxscout-rs"))
}

/// Run the binary with common flags for an isolated output dir.
fn run_cli(out: &std::path::Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut cmd = bin();
    cmd.arg("--output-dir")
        .arg(out)
        .args([
            "--allow-private-targets",
            "--rate-limit-rps",
            "0",
            "--no-sourcemaps",
        ])
        .args(args)
        .env_remove("RUST_LOG")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

fn json_stdout(o: &Output) -> serde_json::Value {
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&o.stdout)))
}

async fn js_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(path("/app.js"))
        .respond_with(js("fetch('/api/v1/me'); el.innerHTML = x;"))
        .mount(&server)
        .await;
    server
}

/// #20: the real stdin path of `ingest-urls -`.
#[tokio::test]
async fn ingest_urls_from_stdin() {
    let server = js_server().await;
    let tmp = tempfile::tempdir().unwrap();
    let out = run_cli(
        tmp.path(),
        &["ingest-urls", "-", "--json"],
        Some(&format!("# list\n{}/app.js\n", server.uri())),
    );
    let v = json_stdout(&out);
    assert_eq!(v["submitted"], 1);
    assert_eq!(v["stats"]["saved"], 1);
    assert!(v["stats"]["findings"].as_u64().unwrap() >= 2);
}

/// #20 / #9 (review item 9): HAR size cap and per-entry admission through
/// the CLI.
#[tokio::test]
async fn har_limits_through_the_cli() {
    let tmp = tempfile::tempdir().unwrap();
    let big_body = "a".repeat(2 * 1024 * 1024);
    let har = serde_json::json!({"log": {"entries": [
        {"request": {"method": "GET", "url": "https://h.test/small.js"},
         "response": {"status": 200, "headers": [{"name": "content-type", "value": "text/javascript"}],
                      "content": {"text": "small()"}}},
        {"request": {"method": "GET", "url": "https://h.test/big.js"},
         "response": {"status": 200, "headers": [{"name": "content-type", "value": "text/javascript"}],
                      "content": {"text": big_body}}}
    ]}});
    let file = tmp.path().join("s.har");
    std::fs::write(&file, har.to_string()).unwrap();
    let f = file.to_str().unwrap();

    // Over the file-size cap: refused up front.
    let refused = run_cli(tmp.path(), &["ingest-har", f, "--max-har-mb", "1"], None);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--max-har-mb"));

    // Under the cap, but one entry is larger than the memory budget.
    let out = run_cli(
        tmp.path(),
        &["--memory-budget-mb", "1", "ingest-har", f, "--json"],
        None,
    );
    let v = json_stdout(&out);
    assert_eq!(
        (v["submitted"].as_u64(), v["rejected"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(v["stats"]["saved"], 1);
}

/// #9: `--debug` explains dropped requests on stderr: URL, host, origin,
/// and the reason (no match / which exclusion).
#[tokio::test]
async fn debug_logs_explain_out_of_scope_requests() {
    let server = js_server().await;
    let tmp = tempfile::tempdir().unwrap();
    let url = format!("{}/app.js", server.uri());

    let no_match = run_cli(
        tmp.path(),
        &["--debug", "-s", "*.target.test", "ingest-urls", "-"],
        Some(&url),
    );
    let err = String::from_utf8_lossy(&no_match.stderr);
    assert!(err.contains(&url), "{err}");
    assert!(err.contains("host=127.0.0.1"), "{err}");
    assert!(err.contains("origin=url-list"), "{err}");
    assert!(err.contains("no scope pattern matched"), "{err}");

    let excluded = run_cli(
        tmp.path(),
        &["--debug", "-s", "127.0.0.1,!127.0.0.1", "ingest-urls", "-"],
        Some(&url),
    );
    let err = String::from_utf8_lossy(&excluded.stderr);
    assert!(err.contains("excluded by `!127.0.0.1`"), "{err}");
}

/// #8: `--scope-file` merges with `-s`, and exclusions win either way.
#[tokio::test]
async fn scope_file_merges_with_flags() {
    let server = js_server().await;
    let tmp = tempfile::tempdir().unwrap();
    let url = format!("{}/app.js\n", server.uri());
    let exclude = tmp.path().join("exclude.txt");
    std::fs::write(&exclude, "# keep this out\n!127.0.0.1\n").unwrap();
    let include = tmp.path().join("include.txt");
    std::fs::write(&include, "127.0.0.1\n").unwrap();

    let v = json_stdout(&run_cli(
        tmp.path(),
        &[
            "-s",
            "127.0.0.1",
            "--scope-file",
            exclude.to_str().unwrap(),
            "ingest-urls",
            "-",
            "--json",
        ],
        Some(&url),
    ));
    assert_eq!(
        (
            v["stats"]["out_of_scope"].as_u64(),
            v["stats"]["saved"].as_u64()
        ),
        (Some(1), Some(0))
    );

    let v = json_stdout(&run_cli(
        tmp.path(),
        &[
            "-s",
            "*.other.test",
            "--scope-file",
            include.to_str().unwrap(),
            "-p",
            "inc",
            "ingest-urls",
            "-",
            "--json",
        ],
        Some(&url),
    ));
    assert_eq!(v["stats"]["saved"], 1, "file pattern adds to -s patterns");
}

/// #27: `findings --json` and the TUI's startup state show the same asset,
/// path, and findings.
#[tokio::test]
async fn findings_json_matches_tui_state() {
    let server = js_server().await;
    let tmp = tempfile::tempdir().unwrap();
    let url = format!("{}/app.js", server.uri());
    json_stdout(&run_cli(
        tmp.path(),
        &["ingest-urls", "-", "--json"],
        Some(&url),
    ));

    let cli: serde_json::Value = json_stdout(&run_cli(tmp.path(), &["findings", "--json"], None));
    let cli_rows: Vec<(String, String, u64)> = cli
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["category"].as_str().unwrap().to_string(),
                f["value"].as_str().unwrap().to_string(),
                f["line"].as_u64().unwrap(),
            )
        })
        .collect();

    let db = jxscout::store::Db::open(&jxscout::pipeline::db_path(tmp.path(), "default")).unwrap();
    let app = jxscout::tui::snapshot(&db, Default::default());
    let asset = app.selected_asset().unwrap();
    assert_eq!(asset.url, url);
    assert_eq!(asset.path, format!("{}/app.js", host_dir(&server)));
    assert_eq!(asset.findings, cli_rows.len());
    let tui_rows: Vec<(String, String, u64)> = app
        .findings
        .iter()
        .map(|f| (f.category.clone(), f.value.clone(), f.line as u64))
        .collect();
    assert_eq!(tui_rows, cli_rows);
    assert!(!tui_rows.is_empty());
}

/// Review item 12: `--version` prints the package version (the release
/// smoke test and the Homebrew formula test rely on this).
#[test]
fn version_matches_package() {
    let out = bin().arg("--version").output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("jxscout-rs {}", env!("CARGO_PKG_VERSION"))
    );
}
