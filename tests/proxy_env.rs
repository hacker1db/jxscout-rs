//! Security review #1: an `HTTP(S)_PROXY` in the environment must not be
//! used, because a proxy resolves hostnames itself and would bypass the
//! SSRF guard's resolver. Lives in its own test binary because it mutates
//! process-wide environment variables.

mod common;

use common::*;
use jxscout::model::{Captured, Origin};
use url::Url;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer};

#[tokio::test]
async fn environment_proxy_is_ignored() {
    // A proxy that doesn't exist: if it were used, the fetch would fail.
    // SAFETY: this test binary has a single test, so no other thread reads
    // the environment concurrently.
    unsafe {
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:9");
        std::env::set_var("http_proxy", "http://127.0.0.1:9");
        std::env::set_var("ALL_PROXY", "http://127.0.0.1:9");
    }
    let server = MockServer::start().await;
    Mock::given(path("/a.js"))
        .respond_with(js("a()"))
        .expect(1)
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let item = Captured::url_only(
        Url::parse(&format!("{}/a.js", server.uri())).unwrap(),
        Origin::UrlList,
    );
    run(&p, item).await;
    assert_eq!(p.stats().saved, 1, "{:?}", p.stats());
}
