//! Shared helpers for integration tests. Every test runs against a local
//! wiremock server; nothing touches the network.

#![allow(dead_code)]

use std::path::Path;

use jxscout::Pipeline;
use jxscout::config::Config;
use jxscout::events::EventBus;
use jxscout::model::{Captured, CapturedRequest, CapturedResponse, Headers, Origin};
use url::Url;
use wiremock::ResponseTemplate;

pub const MAP: &str = r#"{"version":3,"file":"main.js","sources":["webpack://demo/./src/App.js","webpack://demo/./src/api.js"],"sourcesContent":["export const App = () => 'hi';\n","export const api = '/api/v1/admin';\n"],"names":[],"mappings":"AAAA"}"#;

pub fn config(dir: &Path) -> Config {
    Config::for_tests(dir)
}

/// Config for tests whose URLs use fake hosts: no source-map guessing, so
/// nothing tries to resolve `*.test` names.
pub fn offline_config(dir: &Path) -> Config {
    let mut cfg = Config::for_tests(dir);
    cfg.discovery.sourcemaps = false;
    cfg
}

pub fn pipeline(cfg: Config) -> Pipeline {
    Pipeline::new(cfg, EventBus::default()).expect("pipeline")
}

// `set_body_raw` sets the body *and* its Content-Type; `set_body_string`
// would silently reset Content-Type to text/plain.
pub fn js(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.as_bytes().to_vec(), "application/javascript")
}

pub fn html(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.as_bytes().to_vec(), "text/html; charset=utf-8")
}

pub fn json(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.as_bytes().to_vec(), "application/json")
}

/// A captured response, as if a proxy had sent it.
pub fn captured(
    url: &str,
    content_type: &str,
    body: &str,
    req_headers: &[(&str, &str)],
) -> Captured {
    let mut rh = Headers::new();
    for (k, v) in req_headers {
        rh.push(*k, *v);
    }
    let mut h = Headers::new();
    h.push("Content-Type", content_type);
    Captured {
        request: CapturedRequest {
            url: Url::parse(url).unwrap(),
            method: "GET".into(),
            headers: rh,
        },
        response: Some(CapturedResponse {
            status: 200,
            headers: h,
            body: body.as_bytes().to_vec(),
        }),
        origin: Origin::Proxy,
        depth: 0,
        parent: None,
        auth: None,
        owner: None,
    }
}

/// Process one item and wait for everything it spawned.
pub async fn run(p: &Pipeline, item: Captured) {
    p.submit(item);
    p.wait_idle().await;
}

pub fn read(p: &Pipeline, rel: &str) -> Option<String> {
    std::fs::read_to_string(p.store().root().join(rel)).ok()
}

pub fn host_dir(server: &wiremock::MockServer) -> String {
    let u = Url::parse(&server.uri()).unwrap();
    format!("{}_{}", u.host_str().unwrap(), u.port().unwrap())
}
