//! Regression tests for the independent review of PR #2 (see the
//! "Independent review (T3 Codex)" section of docs/REVIEW_LOG.md).

mod common;

use std::io::Write as _;

use common::*;
use jxscout::config::Config;
use jxscout::ingest::IngestSource as _;
use jxscout::ingest::har::HarSource;
use jxscout::ingest::server::{ServerConfig, ServerSource};
use jxscout::rules::Registry;
use tokio::io::AsyncWriteExt as _;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{header, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn map_with(source: &str, content: &str) -> String {
    serde_json::json!({
        "version": 3, "sources": [source], "sourcesContent": [content],
        "names": [], "mappings": ""
    })
    .to_string()
}

/// #3: inline scripts of two pages in one directory, and sources of two
/// bundles with the same `src/index.ts`, all keep their own files.
#[tokio::test]
async fn inline_scripts_and_recovered_sources_do_not_collide() {
    let server = MockServer::start().await;
    let base = server.uri();
    for (bundle, marker) in [("main", "MAIN"), ("admin", "ADMIN")] {
        Mock::given(path(format!("/js/{bundle}.js.map")))
            .respond_with(json(&map_with("webpack://app/src/index.ts", marker)))
            .mount(&server)
            .await;
    }
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    for page in ["a", "b"] {
        let html = format!("<script>var page = '{page}';</script>");
        p.submit(captured(
            &format!("{base}/docs/{page}.html"),
            "text/html",
            &html,
            &[],
        ));
    }
    for bundle in ["main", "admin"] {
        p.submit(captured(
            &format!("{base}/js/{bundle}.js"),
            "application/javascript",
            "x()",
            &[],
        ));
    }
    p.wait_idle().await;
    let host = host_dir(&server);
    assert!(
        read(&p, &format!("{host}/docs/a.html.inline-1.js"))
            .unwrap()
            .contains("page = \"a\"")
    );
    assert!(
        read(&p, &format!("{host}/docs/b.html.inline-1.js"))
            .unwrap()
            .contains("page = \"b\"")
    );
    let main = read(
        &p,
        &format!("{host}/(sourcemaps)/js/main.js/app/src/index.ts"),
    )
    .unwrap();
    let admin = read(
        &p,
        &format!("{host}/(sourcemaps)/js/admin.js/app/src/index.ts"),
    )
    .unwrap();
    assert_eq!((main.as_str(), admin.as_str()), ("MAIN", "ADMIN"));
}

/// #4 / #13: one ordered job per script. A valid header map wins over a
/// valid inline map; a 200 HTML page falls through to the next candidate.
#[tokio::test]
async fn sourcemap_candidate_order_is_respected() {
    use base64::Engine as _;
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(path("/header.map"))
        .respond_with(json(&map_with("h.js", "HEADER")))
        .mount(&server)
        .await;
    Mock::given(path("/login.map"))
        .respond_with(html("<html>log in</html>"))
        .mount(&server)
        .await;
    Mock::given(path("/real.map"))
        .respond_with(json(&map_with("r.js", "REAL")))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    let inline = base64::engine::general_purpose::STANDARD.encode(map_with("i.js", "INLINE"));
    let mut both = captured(
        &format!("{base}/both.js"),
        "application/javascript",
        &format!("a()\n//# sourceMappingURL=data:application/json;base64,{inline}"),
        &[],
    );
    both.response
        .as_mut()
        .unwrap()
        .headers
        .push("SourceMap", "/header.map");
    let mut fallthrough = captured(
        &format!("{base}/ft.js"),
        "application/javascript",
        "b()\n//# sourceMappingURL=/real.map",
        &[],
    );
    fallthrough
        .response
        .as_mut()
        .unwrap()
        .headers
        .push("SourceMap", "/login.map");
    p.submit(both);
    p.submit(fallthrough);
    p.wait_idle().await;

    assert_eq!(
        p.db()
            .sourcemap_of(&format!("{base}/both.js"))
            .unwrap()
            .map(|m| m.0),
        Some(format!("{base}/header.map"))
    );
    assert_eq!(
        p.db()
            .sourcemap_of(&format!("{base}/ft.js"))
            .unwrap()
            .map(|m| m.0),
        Some(format!("{base}/real.map"))
    );
    assert_eq!(p.stats().sourcemaps, 2, "exactly one map per script");
}

/// #5 / #13: a failed map lookup leaves discovery incomplete, so
/// re-ingesting the *unchanged* script retries it.
#[tokio::test]
async fn unchanged_script_retries_incomplete_discovery() {
    let server = MockServer::start().await;
    let base = server.uri();
    // First run: 503 on every attempt (1 try + 2 retries).
    Mock::given(path("/app.js.map"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(3)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(path("/app.js.map"))
        .respond_with(json(&map_with("a.js", "A")))
        .with_priority(2)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    let item = captured(
        &format!("{base}/app.js"),
        "application/javascript",
        "a()",
        &[],
    );
    run(&p, item.clone()).await;
    assert_eq!(p.stats().sourcemaps, 0);
    let (_, complete) = p
        .db()
        .asset_state(&format!("{base}/app.js"))
        .unwrap()
        .unwrap();
    assert!(!complete, "discovery must be marked incomplete");

    run(&p, item.clone()).await;
    assert_eq!(p.stats().sourcemaps, 1, "{:?}", p.stats());
    let (_, complete) = p
        .db()
        .asset_state(&format!("{base}/app.js"))
        .unwrap()
        .unwrap();
    assert!(complete);

    // A third, unchanged ingest is now skipped.
    run(&p, item).await;
    assert_eq!(p.stats().unchanged, 1);
}

/// #6 / #31: a chunk and a source map behind login. Anonymous discovery
/// gets login pages; after logging in, re-ingesting the same script fetches
/// both.
#[tokio::test]
async fn authenticated_rediscovery_after_login_page() {
    let server = MockServer::start().await;
    let base = server.uri();
    for p in ["/js/1.c.js", "/js/main.js.map"] {
        Mock::given(path(p))
            .and(header("cookie", "session=ok"))
            .respond_with(if p.ends_with(".map") {
                json(&map_with("src/secret.ts", "SECRET"))
            } else {
                js("internal()")
            })
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(path(p))
            .respond_with(html("<html>please log in</html>"))
            .with_priority(2)
            .mount(&server)
            .await;
    }
    let runtime = r#"r.u = e => "js/" + e + "." + {1:"c"}[e] + ".js";"#;
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    let url = format!("{base}/js/main.js");
    run(&p, captured(&url, "application/javascript", runtime, &[])).await;
    let host = host_dir(&server);
    assert!(read(&p, &format!("{host}/js/1.c.js")).is_none());
    assert_eq!(p.stats().sourcemaps, 0);

    run(
        &p,
        captured(
            &url,
            "application/javascript",
            runtime,
            &[("Cookie", "session=ok")],
        ),
    )
    .await;
    assert_eq!(
        read(&p, &format!("{host}/js/1.c.js")).unwrap().trim(),
        "internal();"
    );
    assert_eq!(p.stats().sourcemaps, 1, "{:?}", p.stats());
}

/// #7: captured bodies are decoded per Content-Encoding, and a gzip bomb is
/// refused without leaking budget.
#[tokio::test]
async fn encoded_captured_bodies() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = offline_config(tmp.path());
    cfg.fetch.max_body_bytes = 1024 * 1024;
    let p = pipeline(cfg);
    let mut ok = captured("https://enc.test/a.js", "application/javascript", "", &[]);
    {
        let r = ok.response.as_mut().unwrap();
        r.body = gzip(b"eval(location.hash)");
        r.headers.push("Content-Encoding", "gzip");
    }
    let mut bomb = captured(
        "https://enc.test/bomb.js",
        "application/javascript",
        "",
        &[],
    );
    {
        let r = bomb.response.as_mut().unwrap();
        r.body = gzip(&vec![b'a'; 8 * 1024 * 1024]);
        r.headers.push("Content-Encoding", "gzip");
    }
    // Already-decoded body with a stale Content-Encoding header: kept as-is.
    let mut stale = captured(
        "https://enc.test/stale.js",
        "application/javascript",
        "stale()",
        &[],
    );
    stale
        .response
        .as_mut()
        .unwrap()
        .headers
        .push("Content-Encoding", "gzip");
    p.submit(ok);
    p.submit(bomb);
    p.submit(stale);
    p.wait_idle().await;
    assert_eq!(
        read(&p, "enc.test/a.js").unwrap().trim(),
        "eval(location.hash);"
    );
    assert!(read(&p, "enc.test/bomb.js").is_none());
    assert_eq!(read(&p, "enc.test/stale.js").unwrap().trim(), "stale();");
    assert_eq!(p.budget().in_use(), 0);
    assert!(p.peak_memory_bytes() <= p.budget().capacity());
}

/// #8: a client that stalls mid-body times out and frees its slot.
#[tokio::test]
async fn stalled_bodies_time_out() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = ServerConfig::loopback(addr, "localhost", None);
    cfg.body_timeout = std::time::Duration::from_millis(200);
    let shutdown = CancellationToken::new();
    tokio::spawn(
        ServerSource {
            listener,
            config: cfg,
            shutdown: shutdown.clone(),
        }
        .run(p.clone()),
    );

    // More stalled uploads than there are body permits (8).
    let mut stalled = Vec::new();
    for _ in 0..10 {
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "POST /ingest HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{\"request\"",
            addr.port()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        stalled.push(s);
    }
    let started = std::time::Instant::now();
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/ingest"))
        .json(&serde_json::json!({"request": {"url": "https://a.test/x.js"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));

    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), {
        use tokio::io::AsyncReadExt as _;
        stalled[0].read(&mut buf)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("408"));
    shutdown.cancel();
}

/// #9: a HAR entry that can never fit the memory budget is reported as
/// rejected, not submitted.
#[tokio::test]
async fn har_reports_actual_admission() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = offline_config(tmp.path());
    cfg.discovery.memory_budget = 256 * 1024;
    let p = pipeline(cfg);
    let big = "a".repeat(512 * 1024);
    let har = serde_json::json!({"log": {"entries": [
        {"request": {"method": "GET", "url": "https://h.test/small.js"},
         "response": {"status": 200, "headers": [{"name": "content-type", "value": "text/javascript"}],
                      "content": {"text": "small()"}}},
        {"request": {"method": "GET", "url": "https://h.test/big.js"},
         "response": {"status": 200, "headers": [{"name": "content-type", "value": "text/javascript"}],
                      "content": {"text": big}}}
    ]}});
    let report = HarSource::parse(&har.to_string())
        .unwrap()
        .run(p.clone())
        .await
        .unwrap();
    p.wait_idle().await;
    assert_eq!((report.submitted, report.rejected), (1, 1));
    assert!(read(&p, "h.test/small.js").is_some());
}

/// #16 gap: the default registry reports something for every advertised
/// rule family on one fixture.
#[test]
fn default_registry_covers_every_family() {
    let fixture = r#"
        window.addEventListener("message", h);
        el.innerHTML = x;
        localStorage.setItem("k", v);
        fetch("/api/v1/users", {method: "POST"});
        const u = "https://api.example.com/v2/x?id=1";
        const r = /^[a-z]+$/;
        const q = "query Me { me { id } }";
        const key = "AKIAIOSFODNN7EXAMPLE";
        const props = {dangerouslySetInnerHTML: {__html: x}};
    "#;
    let reg = Registry::default();
    let findings = jxscout::rules::analyze_source(fixture, &reg).unwrap();
    for rule in reg.rules() {
        assert!(
            findings.iter().any(|f| f.rule == rule.id()),
            "rule `{}` found nothing: {findings:#?}",
            rule.id()
        );
    }
}

/// #19 gap: concurrent writes where one asset's file is another's directory
/// keep every DB path pointing at the right file content.
#[tokio::test]
async fn concurrent_file_dir_collisions_stay_consistent() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    for i in 0..20 {
        // `/p{i}.html` is a page (file); `/p{i}.html/x.js` needs that name
        // as a directory.
        p.submit(captured(
            &format!("https://c.test/p{i}.html"),
            "text/html",
            &format!("<p>{i}</p>"),
            &[],
        ));
        p.submit(captured(
            &format!("https://c.test/p{i}.html/x.js"),
            "application/javascript",
            &format!("var n = {i};"),
            &[],
        ));
    }
    p.wait_idle().await;
    let rows = p.db().assets(None, 100, 0).unwrap();
    assert_eq!(rows.len(), 40);
    for row in rows {
        let on_disk = std::fs::read_to_string(p.store().root().join(&row.path))
            .unwrap_or_else(|e| panic!("{} -> {}: {e}", row.url, row.path));
        let n: String = row.url.chars().filter(|c| c.is_ascii_digit()).collect();
        assert!(
            on_disk.contains(&n),
            "{} -> {} has {on_disk:?}",
            row.url,
            row.path
        );
    }
}

/// #10: a symlinked metadata directory is refused at startup.
#[cfg(unix)]
#[test]
fn symlinked_metadata_dir_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join(".jxscout-rs")).unwrap();
    let cfg = Config::for_tests(tmp.path());
    assert!(jxscout::Pipeline::new(cfg, Default::default()).is_err());
    assert!(
        std::fs::read_dir(elsewhere.path())
            .unwrap()
            .next()
            .is_none()
    );
}
