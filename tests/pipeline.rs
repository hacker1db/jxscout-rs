//! End-to-end pipeline tests against a local mock server.

mod common;

use common::*;
use jxscout::config::ForwardAuth;
use jxscout::model::{Captured, Origin};
use jxscout::scope::Scope;
use url::Url;
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RUNTIME: &str = r#"
(function(){
  var r = {};
  r.p = "/";
  r.u = function(e){ return "static/js/" + e + "." + {101:"aaaa1111",202:"bbbb2222"}[e] + ".chunk.js"; };
  window.addEventListener("message", function(ev){ document.getElementById("o").innerHTML = ev.data; });
  fetch("/api/v1/users", {method: "POST", headers: {"X-Requested-With": "x"}});
})();
//# sourceMappingURL=main.js.map
"#;

#[tokio::test]
async fn html_to_scripts_to_chunks_to_sourcemaps() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(path("/static/js/main.js"))
        .respond_with(js(RUNTIME))
        .mount(&server)
        .await;
    Mock::given(path("/static/js/main.js.map"))
        .respond_with(json(MAP))
        .mount(&server)
        .await;
    Mock::given(path("/static/js/101.aaaa1111.chunk.js"))
        .respond_with(js("export const a = '/api/v2/chunk-a';"))
        .mount(&server)
        .await;
    Mock::given(path("/static/js/202.bbbb2222.chunk.js"))
        .respond_with(js("window.postMessage('x', '*');"))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    let page = r#"<html><script src="/static/js/main.js"></script><script>var k = "/api/inline";</script></html>"#.to_string();
    run(&p, captured(&format!("{base}/"), "text/html", &page, &[])).await;

    let host = host_dir(&server);
    let stats = p.stats();
    assert_eq!(stats.errors, 0, "{stats:?}");
    assert!(read(&p, &format!("{host}/(index).html")).is_some());
    assert!(read(&p, &format!("{host}/(inline-1).js")).is_some());
    // beautified
    let main = read(&p, &format!("{host}/static/js/main.js")).unwrap();
    assert!(main.lines().count() > 5);
    // chunks
    assert!(read(&p, &format!("{host}/static/js/101.aaaa1111.chunk.js")).is_some());
    assert!(read(&p, &format!("{host}/static/js/202.bbbb2222.chunk.js")).is_some());
    // source map reversed
    let app = read(&p, &format!("{host}/(sourcemaps)/demo/src/api.js")).unwrap();
    assert!(app.contains("/api/v1/admin"));

    // relations + findings
    let main_url = format!("{base}/static/js/main.js");
    assert_eq!(
        p.db().scripts_of(&format!("{base}/")).unwrap(),
        vec![main_url.clone()]
    );
    let findings = p.db().findings(Some(&main_url), None).unwrap();
    let cats: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    assert!(
        cats.contains(&"Client Behavior/Events/addEventListener"),
        "{cats:?}"
    );
    assert!(cats.contains(&"Client Behavior/innerHTML"));
    assert!(cats.contains(&"Client Behavior/fetch"));
    assert!(cats.contains(&"Data/Headers"));
    assert!(p.db().sourcemap_of(&main_url).unwrap().is_some());
}

/// Regression for upstream #31: chunks behind auth are fetched with the
/// captured cookies instead of saving a login redirect.
#[tokio::test]
async fn chunks_behind_auth_use_captured_cookies() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(path("/js/1.secret.js"))
        .and(header("cookie", "session=abc123"))
        .respond_with(js("const internal = '/api/internal/admin';"))
        .mount(&server)
        .await;
    // Without the cookie: redirect to a login page.
    Mock::given(path("/js/1.secret.js"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/login"))
        .mount(&server)
        .await;
    Mock::given(path("/login"))
        .respond_with(html("<html>please log in</html>"))
        .mount(&server)
        .await;
    Mock::given(path("/js/main.js.map"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let runtime = r#"r.u = e => "js/" + e + "." + {1:"secret"}[e] + ".js";"#;
    let item = captured(
        &format!("{base}/js/main.js"),
        "application/javascript",
        runtime,
        &[("Cookie", "session=abc123")],
    );

    // Default (same-origin forwarding): the real chunk is saved.
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    run(&p, item.clone()).await;
    let chunk = read(&p, &format!("{}/js/1.secret.js", host_dir(&server))).expect("chunk saved");
    assert!(chunk.contains("/api/internal/admin"));

    // Forwarding disabled: the login HTML is NOT saved as JS.
    let tmp2 = tempfile::tempdir().unwrap();
    let mut cfg = config(tmp2.path());
    cfg.fetch.forward_auth = ForwardAuth::Never;
    let p2 = pipeline(cfg);
    run(&p2, item).await;
    assert!(read(&p2, &format!("{}/js/1.secret.js", host_dir(&server))).is_none());
}

/// Regression for upstream #19: unparsable JS is saved as-is and the rest
/// of the page is still processed.
#[tokio::test]
async fn malformed_js_does_not_stop_the_pipeline() {
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(path("/bad.js"))
        .respond_with(js("function ( { <<< unexpected token"))
        .mount(&server)
        .await;
    Mock::given(path("/good.js"))
        .respond_with(js("eval(location.hash)"))
        .mount(&server)
        .await;
    Mock::given(path("/bad.js.map"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(path("/good.js.map"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    let page = r#"<script src="/bad.js"></script><script src="/good.js"></script>"#;
    run(
        &p,
        captured(&format!("{base}/index.html"), "text/html", page, &[]),
    )
    .await;

    let host = host_dir(&server);
    assert_eq!(
        read(&p, &format!("{host}/bad.js")).unwrap(),
        "function ( { <<< unexpected token"
    );
    assert!(read(&p, &format!("{host}/good.js")).is_some());
    let f = p
        .db()
        .findings(Some(&format!("{base}/good.js")), None)
        .unwrap();
    assert!(f.iter().any(|f| f.category == "Client Behavior/eval"));
    assert_eq!(p.stats().errors, 0);
}

/// Upstream #13: every discovery method works, and invalid candidates fall
/// through to the next one.
#[tokio::test]
async fn sourcemap_discovery_methods() {
    let server = MockServer::start().await;
    let base = server.uri();
    // 1. header
    Mock::given(path("/maps/h.map"))
        .respond_with(json(MAP))
        .mount(&server)
        .await;
    // 2. stale header (404) then valid comment
    Mock::given(path("/stale.map"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(path("/c.js.map"))
        .respond_with(json(MAP))
        .mount(&server)
        .await;
    // 3. guess, after a 404 that *contains* valid map JSON (must be rejected)
    Mock::given(path("/404.map"))
        .respond_with(ResponseTemplate::new(404).set_body_string(MAP))
        .mount(&server)
        .await;
    Mock::given(path("/g.js.map"))
        .respond_with(json(MAP))
        .mount(&server)
        .await;
    // 4. retry: 503 once, then OK
    Mock::given(path("/r.js.map"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(path("/r.js.map"))
        .respond_with(json(MAP))
        .with_priority(2)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    let mut by_header = captured(
        &format!("{base}/h.js"),
        "application/javascript",
        "a()",
        &[],
    );
    by_header
        .response
        .as_mut()
        .unwrap()
        .headers
        .push("SourceMap", "/maps/h.map");
    let mut stale = captured(
        &format!("{base}/c.js"),
        "application/javascript",
        "b()\n//# sourceMappingURL=c.js.map",
        &[],
    );
    stale
        .response
        .as_mut()
        .unwrap()
        .headers
        .push("X-SourceMap", "/stale.map");
    let guess = captured(
        &format!("{base}/g.js?v=9"),
        "application/javascript",
        "c()\n//# sourceMappingURL=/404.map",
        &[],
    );
    let retry = captured(
        &format!("{base}/r.js"),
        "application/javascript",
        "d()",
        &[],
    );
    let b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(MAP)
    };
    let inline = captured(
        &format!("{base}/i.js"),
        "application/javascript",
        &format!("e()\n//# sourceMappingURL=data:application/json;base64,{b64}"),
        &[],
    );
    for item in [by_header, stale, guess, retry, inline] {
        p.submit(item);
    }
    p.wait_idle().await;

    for (js, expected_map) in [
        ("h.js", format!("{base}/maps/h.map")),
        ("c.js", format!("{base}/c.js.map")),
        ("g.js?v=9", format!("{base}/g.js.map")),
        ("r.js", format!("{base}/r.js.map")),
        ("i.js", format!("{base}/i.js#inline-map")),
    ] {
        let got = p.db().sourcemap_of(&format!("{base}/{js}")).unwrap();
        assert_eq!(got.map(|(m, _)| m), Some(expected_map), "for {js}");
    }
    assert_eq!(p.stats().sourcemaps, 5);
}

#[tokio::test]
async fn out_of_scope_captures_are_dropped() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = config(tmp.path());
    cfg.scope = Scope::from_patterns(["*.target.test"]);
    let p = pipeline(cfg);
    run(
        &p,
        captured(
            "https://other.test/a.js",
            "application/javascript",
            "x()",
            &[],
        ),
    )
    .await;
    let s = p.stats();
    assert_eq!((s.out_of_scope, s.saved), (1, 0));
}

#[tokio::test]
async fn oversized_downloads_are_rejected() {
    let server = MockServer::start().await;
    let big = "a".repeat(64 * 1024);
    Mock::given(path("/big.js"))
        .respond_with(js(&big))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = config(tmp.path());
    cfg.fetch.max_body_bytes = 1024;
    let p = pipeline(cfg);
    let item = Captured::url_only(
        Url::parse(&format!("{}/big.js", server.uri())).unwrap(),
        Origin::UrlList,
    );
    run(&p, item).await;
    assert_eq!(p.stats().saved, 0);
    assert_eq!(p.stats().errors, 1);
}

/// SSRF guard (R-56): with the default config, a script cannot make the
/// tool fetch loopback addresses.
#[tokio::test]
async fn ssrf_guard_blocks_private_targets_by_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(js("x()"))
        .expect(0)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = offline_config(tmp.path());
    cfg.fetch.allow_private_targets = false;
    let p = pipeline(cfg);
    // The captured script lives on a public-looking host but references
    // chunks on the loopback mock server.
    let runtime = format!(
        r#"import("{}/evil.js"); r.u = e => "{}/" + e + ".js";"#,
        server.uri(),
        server.uri()
    );
    run(
        &p,
        captured(
            "https://public.test/app.js",
            "application/javascript",
            &runtime,
            &[],
        ),
    )
    .await;
    // `expect(0)` is verified when `server` drops.
}

/// Redirect hops are policy-checked: a chunk redirecting to an out-of-scope
/// host is not followed, so cookies can't leak there.
#[tokio::test]
async fn redirects_to_out_of_scope_hosts_are_blocked() {
    let target = MockServer::start().await;
    let evil = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(js("leak()"))
        .expect(0)
        .mount(&evil)
        .await;
    Mock::given(path("/js/1.x.js"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("{}/steal", evil.uri().replace("127.0.0.1", "localhost")),
        ))
        .mount(&target)
        .await;
    Mock::given(path("/js/main.js.map"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&target)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = config(tmp.path());
    cfg.scope = Scope::from_patterns(["127.0.0.1"]);
    let p = pipeline(cfg);
    let runtime = r#"r.u = e => "js/" + e + "." + {1:"x"}[e] + ".js";"#;
    run(
        &p,
        captured(
            &format!("{}/js/main.js", target.uri()),
            "application/javascript",
            runtime,
            &[("Cookie", "s=1")],
        ),
    )
    .await;
    assert!(p.stats().errors >= 1, "blocked redirect is reported");
}

/// Re-ingesting identical content is skipped (R-35).
#[tokio::test]
async fn unchanged_assets_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let item = captured(
        "https://a.test/x.js",
        "application/javascript",
        "let a = 1;",
        &[],
    );
    run(&p, item.clone()).await;
    run(&p, item).await;
    let s = p.stats();
    assert_eq!((s.saved, s.unchanged), (1, 1));
}

/// Codex M2 #2: once a redirect chain leaves the first origin, credentials
/// are never re-sent, even when it comes back.
#[tokio::test]
async fn credentials_are_not_resent_after_leaving_the_origin() {
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    Mock::given(path("/js/1.x.js"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{}/bounce", b.uri())),
        )
        .mount(&a)
        .await;
    Mock::given(path("/bounce"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/js/final.js", a.uri())),
        )
        .mount(&b)
        .await;
    Mock::given(header_exists("cookie"))
        .respond_with(ResponseTemplate::new(418))
        .expect(0)
        .mount(&b)
        .await;
    Mock::given(path("/js/final.js"))
        .and(header_exists("cookie"))
        .respond_with(ResponseTemplate::new(418))
        .expect(0)
        .with_priority(1)
        .mount(&a)
        .await;
    Mock::given(path("/js/final.js"))
        .respond_with(js(r#"import("/js/child.js");"#))
        .with_priority(2)
        .mount(&a)
        .await;
    // Codex M5 #1: descendants of a chain that left the origin and came
    // back get no credentials either.
    Mock::given(path("/js/child.js"))
        .and(header_exists("cookie"))
        .respond_with(ResponseTemplate::new(418))
        .expect(0)
        .with_priority(1)
        .mount(&a)
        .await;
    Mock::given(path("/js/child.js"))
        .respond_with(js("child()"))
        .expect(1)
        .with_priority(2)
        .mount(&a)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = offline_config(tmp.path());
    cfg.scope = Scope::from_patterns(["127.0.0.1"]);
    let p = pipeline(cfg);
    let runtime = r#"r.u = e => "js/" + e + "." + {1:"x"}[e] + ".js";"#;
    run(
        &p,
        captured(
            &format!("{}/js/main.js", a.uri()),
            "application/javascript",
            runtime,
            &[("Cookie", "s=1")],
        ),
    )
    .await;
    // Saved under the requested URL, resolved through the redirect chain.
    assert!(read(&p, &format!("{}/js/1.x.js", host_dir(&a))).is_some());
}

/// Codex M2 #7: relative references resolve against the final URL after
/// a redirect, not the requested one.
#[tokio::test]
async fn redirected_pages_resolve_against_final_url() {
    let server = MockServer::start().await;
    Mock::given(path("/old"))
        .respond_with(ResponseTemplate::new(301).insert_header("location", "/app/index.html"))
        .mount(&server)
        .await;
    Mock::given(path("/app/index.html"))
        .respond_with(html(r#"<script src="main.js"></script>"#))
        .mount(&server)
        .await;
    Mock::given(path("/app/main.js"))
        .respond_with(js("x()"))
        .expect(1)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let item = Captured::url_only(
        Url::parse(&format!("{}/old", server.uri())).unwrap(),
        Origin::UrlList,
    );
    run(&p, item).await;
    assert!(
        read(&p, &format!("{}/app/main.js", host_dir(&server))).is_some(),
        "{:?} {:?}",
        p.stats(),
        p.db().assets(None, 10, 0)
    );
}

/// Security review (2nd pass) #1: after a redirect to another origin, that
/// origin does not become a trusted parent: its same-origin references get
/// no scope exemption and no captured credentials.
#[tokio::test]
async fn redirect_target_is_not_a_trusted_parent() {
    let a = MockServer::start().await; // the in-scope app
    let b = MockServer::start().await; // a different origin
    let b_url = b.uri();
    let a_local = a.uri().replace("127.0.0.1", "localhost");
    Mock::given(path("/js/1.x.js"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{b_url}/landing.js")),
        )
        .mount(&a)
        .await;
    // B serves a script whose chunk lives on B, outside the scope pattern.
    Mock::given(path("/landing.js"))
        .respond_with(js(r#"import("/evil.js");"#))
        .mount(&b)
        .await;
    Mock::given(path("/evil.js"))
        .respond_with(js("x()"))
        .expect(0)
        .mount(&b)
        .await;
    Mock::given(header_exists("cookie"))
        .respond_with(ResponseTemplate::new(418))
        .expect(0)
        .mount(&b)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = offline_config(tmp.path());
    // A by host; on B only the landing script itself is in scope.
    cfg.scope = Scope::from_patterns(["localhost", &format!("{b_url}/landing.js")]);
    let p = pipeline(cfg);
    let runtime = r#"r.u = e => "js/" + e + "." + {1:"x"}[e] + ".js";"#;
    run(
        &p,
        captured(
            &format!("{a_local}/js/main.js"),
            "application/javascript",
            runtime,
            &[("Cookie", "s=1")],
        ),
    )
    .await;
    // The redirected chunk itself was fetched (its final URL is in scope) …
    assert!(
        read(
            &p,
            &format!(
                "{}/js/1.x.js",
                host_dir(&a).replace("127.0.0.1", "localhost")
            )
        )
        .is_some()
    );
    // … but `/evil.js` on B was not (expect(0) verified on drop).
}

/// Codex M5 #3: a derived URL that failed (404/503/401) can be retried when
/// another script references it later in the same session.
#[tokio::test]
async fn failed_derived_fetch_can_be_rediscovered() {
    let server = MockServer::start().await;
    Mock::given(path("/c.js"))
        .respond_with(ResponseTemplate::new(404))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(path("/c.js"))
        .respond_with(js("c()"))
        .with_priority(2)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let base = server.uri();
    let script = r#"import("./c.js");"#;
    run(
        &p,
        captured(
            &format!("{base}/a.js"),
            "application/javascript",
            script,
            &[],
        ),
    )
    .await;
    assert!(read(&p, &format!("{}/c.js", host_dir(&server))).is_none());
    run(
        &p,
        captured(
            &format!("{base}/b.js"),
            "application/javascript",
            script,
            &[],
        ),
    )
    .await;
    assert!(read(&p, &format!("{}/c.js", host_dir(&server))).is_some());
}

/// Security review (3rd pass): URL-only items, chunks, and source maps are
/// fetched by the tool, so their bodies must count against the memory
/// budget too. Many large fetched bodies never exceed it, and none are lost.
#[tokio::test]
async fn fetched_bodies_respect_the_memory_budget() {
    let server = MockServer::start().await;
    // 600 KiB scripts with a 300 KiB source map each.
    let big = format!("var x = \"{}\";", "a".repeat(600 * 1024));
    Mock::given(wiremock::matchers::path_regex(r"^/s\d+\.js$"))
        .respond_with(js(&big))
        .mount(&server)
        .await;
    let map = format!(
        r#"{{"version":3,"sources":["a.js"],"sourcesContent":["{}"],"names":[],"mappings":""}}"#,
        "b".repeat(300 * 1024)
    );
    Mock::given(wiremock::matchers::path_regex(r"^/s\d+\.js\.map$"))
        .respond_with(json(&map))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = config(tmp.path());
    let budget = 1024 * 1024; // room for one script + one map, not two scripts
    cfg.discovery.memory_budget = budget;
    let p = pipeline(cfg);
    for i in 0..8 {
        let url = Url::parse(&format!("{}/s{i}.js", server.uri())).unwrap();
        assert!(p.submit(Captured::url_only(url, Origin::UrlList)));
    }
    p.wait_idle().await;

    let s = p.stats();
    assert_eq!((s.saved, s.sourcemaps, s.errors), (8, 8, 0), "{s:?}");
    assert!(
        p.peak_memory_bytes() <= budget,
        "peak {} > budget {budget}",
        p.peak_memory_bytes()
    );
    assert!(p.peak_memory_bytes() > 0);
}
