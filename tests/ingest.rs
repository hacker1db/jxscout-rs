//! Ingest sources: the HTTP endpoint (Caido plugin payloads), URL lists,
//! and HAR files.

mod common;

use base64::Engine as _;
use common::*;
use jxscout::ingest::IngestSource;
use jxscout::ingest::har::HarSource;
use jxscout::ingest::server::ServerSource;
use jxscout::ingest::urls::UrlListSource;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn start_server(p: jxscout::Pipeline, token: Option<&str>) -> (String, CancellationToken) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let src = ServerSource {
        listener,
        token: token.map(String::from),
        shutdown: shutdown.clone(),
    };
    tokio::spawn(src.run(p));
    (format!("http://{addr}"), shutdown)
}

/// Exactly what `integrations/caido` sends: header maps of string arrays
/// and a base64 body.
fn caido_payload(url: &str, js_body: &str) -> serde_json::Value {
    json!({
        "request": {
            "url": url,
            "method": "GET",
            "headers": { "Host": ["app.test"], "Cookie": ["sid=1"] }
        },
        "response": {
            "status": 200,
            "headers": { "Content-Type": ["application/javascript; charset=utf-8"] },
            "body_base64": base64::engine::general_purpose::STANDARD.encode(js_body)
        }
    })
}

#[tokio::test]
async fn caido_shaped_payload_is_processed() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let (base, shutdown) = start_server(p.clone(), None).await;
    let client = reqwest::Client::new();

    assert_eq!(
        client
            .get(format!("{base}/health"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );

    let resp = client
        .post(format!("{base}/ingest"))
        .json(&caido_payload(
            "https://app.test/static/app.js",
            "localStorage.setItem('jwt', t);",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    p.wait_idle().await;

    assert!(read(&p, "app.test/static/app.js").is_some());
    let f = p
        .db()
        .findings(Some("https://app.test/static/app.js"), None)
        .unwrap();
    assert!(
        f.iter().any(
            |f| f.category == "Client Behavior/Storage/localStorage/setItem" && f.value == "jwt"
        )
    );
    shutdown.cancel();
}

#[tokio::test]
async fn batch_and_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let (base, shutdown) = start_server(p.clone(), None).await;
    let client = reqwest::Client::new();

    let batch = json!([
        caido_payload("https://a.test/1.js", "a()"),
        {"request": {"url": "file:///etc/passwd"}},
    ]);
    let resp: serde_json::Value = client
        .post(format!("{base}/ingest/batch"))
        .json(&batch)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp, json!({"accepted": 1, "rejected": 1}));

    let bad = client
        .post(format!("{base}/ingest"))
        .json(&json!({"request": {"url": "ftp://x"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    let too_many: Vec<_> = (0..1001)
        .map(|i| caido_payload(&format!("https://a.test/{i}.js"), ""))
        .collect();
    let resp = client
        .post(format!("{base}/ingest/batch"))
        .json(&too_many)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    shutdown.cancel();
}

#[tokio::test]
async fn ingest_token_is_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let (base, shutdown) = start_server(p.clone(), Some("s3cret-token")).await;
    let client = reqwest::Client::new();
    let body = caido_payload("https://a.test/1.js", "a()");

    let no = client
        .post(format!("{base}/ingest"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(no.status(), 401);
    let wrong = client
        .post(format!("{base}/ingest/batch"))
        .bearer_auth("nope")
        .json(&json!([body.clone()]))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    let yes = client
        .post(format!("{base}/ingest"))
        .bearer_auth("s3cret-token")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(yes.status(), 202);
    shutdown.cancel();
}

/// Upstream #20: a URL list works without any proxy.
#[tokio::test]
async fn url_list_source_fetches_urls() {
    let server = MockServer::start().await;
    Mock::given(path("/a.js"))
        .respond_with(js("fetch('/api/a')"))
        .mount(&server)
        .await;
    Mock::given(path("/a.js.map"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(config(tmp.path()));
    let list = format!("# my targets\n{}/a.js\n\nnot a url\n", server.uri());
    let report = UrlListSource::new(list.as_bytes())
        .run(p.clone())
        .await
        .unwrap();
    p.wait_idle().await;
    assert_eq!((report.submitted, report.rejected), (1, 1));
    assert!(read(&p, &format!("{}/a.js", host_dir(&server))).is_some());
}

#[tokio::test]
async fn har_source_imports_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let p = pipeline(offline_config(tmp.path()));
    let har = json!({"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": "https://h.test/app.js", "headers": []},
         "response": {"status": 200, "headers": [{"name": "content-type", "value": "text/javascript"}],
                      "content": {"mimeType": "text/javascript", "text": "document.write(x)"}}}
    ]}});
    let report = HarSource::parse(&har.to_string())
        .unwrap()
        .run(p.clone())
        .await
        .unwrap();
    p.wait_idle().await;
    assert_eq!(report.submitted, 1);
    assert!(read(&p, "h.test/app.js").is_some());
}
