//! HAR 1.2 import (SPEC R-12c, upstream #20).
//!
//! Only the fields we need are modelled; serde ignores the rest.

use base64::Engine as _;
use serde::Deserialize;
use url::Url;

use super::{IngestReport, IngestSource};
use crate::model::{Captured, CapturedRequest, CapturedResponse, Headers, Origin};
use crate::pipeline::Pipeline;

#[derive(Debug, Deserialize)]
pub struct Har {
    pub log: HarLog,
}

#[derive(Debug, Deserialize)]
pub struct HarLog {
    #[serde(default)]
    pub entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
pub struct HarEntry {
    pub request: HarRequest,
    pub response: HarResponse,
}

#[derive(Debug, Deserialize)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<HarHeader>,
}

#[derive(Debug, Deserialize)]
pub struct HarResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<HarHeader>,
    #[serde(default)]
    pub content: HarContent,
}

#[derive(Debug, Default, Deserialize)]
pub struct HarContent {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub encoding: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

fn headers(h: Vec<HarHeader>) -> Headers {
    Headers(h.into_iter().map(|h| (h.name, h.value)).collect())
}

/// Convert one entry. Entries without a body become "fetch it yourself".
pub fn entry_to_captured(e: HarEntry) -> Result<Captured, String> {
    let url = Url::parse(&e.request.url).map_err(|err| format!("`{}`: {err}", e.request.url))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("`{url}`: unsupported scheme"));
    }
    let body = match (
        e.response.content.text,
        e.response.content.encoding.as_deref(),
    ) {
        (Some(t), Some("base64")) => Some(
            base64::engine::general_purpose::STANDARD
                .decode(t.trim())
                .map_err(|err| format!("`{url}`: bad base64 body: {err}"))?,
        ),
        (Some(t), _) => Some(t.into_bytes()),
        (None, _) => None,
    };
    Ok(Captured {
        request: CapturedRequest {
            url,
            method: e.request.method,
            headers: headers(e.request.headers),
        },
        response: body.map(|body| CapturedResponse {
            status: e.response.status,
            headers: headers(e.response.headers),
            body,
        }),
        origin: Origin::Har,
        depth: 0,
        parent: None,
        auth: None,
    })
}

/// A parsed HAR file.
pub struct HarSource {
    har: Har,
}

impl HarSource {
    pub fn parse(json: &str) -> serde_json::Result<Self> {
        Ok(Self {
            har: serde_json::from_str(json)?,
        })
    }
}

impl IngestSource for HarSource {
    fn name(&self) -> &'static str {
        "har"
    }

    async fn run(self, pipeline: Pipeline) -> anyhow::Result<IngestReport> {
        let mut report = IngestReport::default();
        for entry in self.har.log.entries {
            match entry_to_captured(entry) {
                Ok(c) => {
                    pipeline.submit_wait(c).await;
                    report.submitted += 1;
                }
                Err(e) => {
                    tracing::warn!("skipping HAR entry {e}");
                    report.rejected += 1;
                }
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_entries() {
        let json = r#"{"log": {"version": "1.2", "entries": [
          {"request": {"method": "GET", "url": "https://a.test/x.js", "headers": [{"name": "Cookie", "value": "s=1"}]},
           "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "text/javascript"}],
                        "content": {"mimeType": "text/javascript", "text": "dmFyIGE9MTs=", "encoding": "base64"}}},
          {"request": {"method": "GET", "url": "https://a.test/"},
           "response": {"status": 200, "content": {}}}
        ]}}"#;
        let har = HarSource::parse(json).unwrap();
        let mut entries = har.har.log.entries.into_iter();
        let first = entry_to_captured(entries.next().unwrap()).unwrap();
        assert_eq!(first.response.unwrap().body, b"var a=1;");
        assert_eq!(first.request.headers.get("cookie"), Some("s=1"));
        let second = entry_to_captured(entries.next().unwrap()).unwrap();
        assert!(second.response.is_none());
    }
}
