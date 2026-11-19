//! Data types for captured traffic and the ingest DTO (SPEC R-11).

use std::collections::BTreeMap;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use url::Url;

/// An ordered list of `(name, value)` header pairs.
///
/// HTTP allows repeated headers, so a map would lose information. Lookups
/// are case-insensitive.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Headers(pub Vec<(String, String)>);

impl Headers {
    pub fn new() -> Self {
        Self::default()
    }

    /// First value of header `name`, case-insensitively.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn push(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push((name.into(), value.into()));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Keep only the headers named in `names` (case-insensitive).
    pub fn filtered(&self, names: &[String]) -> Headers {
        Headers(
            self.0
                .iter()
                .filter(|(k, _)| names.iter().any(|n| n.eq_ignore_ascii_case(k)))
                .cloned()
                .collect(),
        )
    }

    /// The media type of `Content-Type` without parameters, lower-cased.
    pub fn content_type(&self) -> Option<String> {
        self.get("content-type")
            .and_then(|v| v.split(';').next())
            .map(|v| v.trim().to_ascii_lowercase())
    }
}

/// How an item entered the pipeline. Used for logging, the database, and to
/// decide which scope exceptions apply (R-25, R-56).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// Posted by a proxy plugin or curl to the ingest endpoint.
    Proxy,
    /// From a URL list (`ingest-urls`).
    UrlList,
    /// From a HAR file (`ingest-har`).
    Har,
    /// A `<script src>` referenced by an HTML page.
    Referred,
    /// A chunk discovered inside another script.
    Chunk,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::UrlList => "url-list",
            Self::Har => "har",
            Self::Referred => "referred",
            Self::Chunk => "chunk",
        }
    }

    /// Whether the item was captured directly by the user (as opposed to
    /// derived by the tool). Captured items must be in scope (R-20).
    pub fn is_captured(self) -> bool {
        matches!(self, Self::Proxy | Self::UrlList | Self::Har)
    }
}

/// The request half of a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRequest {
    pub url: Url,
    pub method: String,
    pub headers: Headers,
}

/// The response half of a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedResponse {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

/// One unit of work for the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub request: CapturedRequest,
    /// `None` means "fetch it yourself" (URL lists, chunks, referred JS).
    pub response: Option<CapturedResponse>,
    pub origin: Origin,
    /// Recursion depth: 0 for captured items, +1 per discovery hop.
    pub depth: u32,
    /// URL of the page/script this item was discovered from, if any.
    pub parent: Option<Url>,
    /// Auth headers from the *originally captured* request, carried down the
    /// discovery tree so chunks behind auth can be fetched (R-60, upstream #31).
    pub auth: Option<AuthContext>,
    /// Database key of the script whose discovery produced this item. Used
    /// to mark that script's discovery complete only when every child
    /// succeeded, so failures are retried on the next ingest.
    pub owner: Option<String>,
}

/// Credentials captured with a request and the origin they belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    /// The origin the credentials were sent to by the browser.
    pub origin: url::Origin,
    pub headers: Headers,
}

impl Captured {
    /// A capture with no response (the pipeline will fetch the URL).
    pub fn url_only(url: Url, origin: Origin) -> Self {
        Self {
            request: CapturedRequest {
                url,
                method: "GET".into(),
                headers: Headers::new(),
            },
            response: None,
            origin,
            depth: 0,
            parent: None,
            auth: None,
            owner: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Ingest DTO
// ---------------------------------------------------------------------------

/// A header value in JSON may be one string or a list of strings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

/// JSON headers: `{ "Name": "v" }` or `{ "Name": ["v1", "v2"] }`.
pub type HeaderMapDto = BTreeMap<String, OneOrMany>;

fn headers_from_dto(map: HeaderMapDto) -> Headers {
    let mut h = Headers::new();
    for (k, v) in map {
        match v {
            OneOrMany::One(v) => h.push(k.clone(), v),
            OneOrMany::Many(vs) => vs.into_iter().for_each(|v| h.push(k.clone(), v)),
        }
    }
    h
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequestDto {
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub headers: HeaderMapDto,
}

fn default_method() -> String {
    "GET".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseDto {
    pub status: u16,
    #[serde(default)]
    pub headers: HeaderMapDto,
    /// UTF-8 body text.
    #[serde(default)]
    pub body: Option<String>,
    /// Base64 body (for binary-safe transport, e.g. from the Caido plugin).
    #[serde(default)]
    pub body_base64: Option<String>,
}

/// The JSON accepted by `POST /ingest` (R-11).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngestPayload {
    pub request: RequestDto,
    #[serde(default)]
    pub response: Option<ResponseDto>,
}

/// Errors turning a DTO into a [`Captured`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("invalid url `{0}`")]
    BadUrl(String),
    #[error("only http and https urls are accepted, got `{0}`")]
    BadScheme(String),
    #[error("`body` and `body_base64` are mutually exclusive")]
    BothBodies,
    #[error("invalid base64 body")]
    BadBase64,
}

impl IngestPayload {
    /// Validate and convert into a pipeline item.
    pub fn into_captured(self, origin: Origin) -> Result<Captured, PayloadError> {
        let url = Url::parse(&self.request.url).map_err(|_| {
            PayloadError::BadUrl(crate::text::clean(&self.request.url).into_owned())
        })?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(PayloadError::BadScheme(url.scheme().to_string()));
        }
        let response = match self.response {
            None => None,
            Some(r) => {
                let body = match (r.body, r.body_base64) {
                    (Some(_), Some(_)) => return Err(PayloadError::BothBodies),
                    (Some(text), None) => Some(text.into_bytes()),
                    (None, Some(b64)) => Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(b64.trim())
                            .map_err(|_| PayloadError::BadBase64)?,
                    ),
                    (None, None) => None,
                };
                // A response without a body is treated like "no response":
                // the pipeline fetches the URL itself.
                body.map(|body| CapturedResponse {
                    status: r.status,
                    headers: headers_from_dto(r.headers),
                    body,
                })
            }
        };
        Ok(Captured {
            request: CapturedRequest {
                url,
                method: self.request.method,
                headers: headers_from_dto(self.request.headers),
            },
            response,
            origin,
            depth: 0,
            parent: None,
            auth: None,
            owner: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_are_case_insensitive() {
        let mut h = Headers::new();
        h.push("Content-Type", "text/JavaScript; charset=utf-8");
        assert_eq!(
            h.get("content-type"),
            Some("text/JavaScript; charset=utf-8")
        );
        assert_eq!(h.content_type().as_deref(), Some("text/javascript"));
    }

    #[test]
    fn payload_with_one_or_many_headers() {
        let json = r#"{
            "request": {"url": "https://a.test/x.js", "headers": {"Cookie": ["a=1", "b=2"], "Accept": "*/*"}},
            "response": {"status": 200, "headers": {"Content-Type": "text/javascript"}, "body": "let a = 1;"}
        }"#;
        let p: IngestPayload = serde_json::from_str(json).unwrap();
        let c = p.into_captured(Origin::Proxy).unwrap();
        assert_eq!(c.request.method, "GET");
        assert_eq!(c.request.headers.0.len(), 3);
        assert_eq!(c.response.unwrap().body, b"let a = 1;");
    }

    #[test]
    fn payload_base64_body() {
        let json = r#"{"request": {"url": "https://a.test/"},
                       "response": {"status": 200, "body_base64": "aGk="}}"#;
        let c: IngestPayload = serde_json::from_str(json).unwrap();
        assert_eq!(
            c.into_captured(Origin::Proxy)
                .unwrap()
                .response
                .unwrap()
                .body,
            b"hi"
        );
    }

    #[test]
    fn payload_rejects_bad_input() {
        let bad_scheme: IngestPayload =
            serde_json::from_str(r#"{"request": {"url": "file:///etc/passwd"}}"#).unwrap();
        assert_eq!(
            bad_scheme.into_captured(Origin::Proxy).unwrap_err(),
            PayloadError::BadScheme("file".into())
        );
        let both: IngestPayload = serde_json::from_str(
            r#"{"request": {"url": "https://a.test/"}, "response": {"status": 200, "body": "x", "body_base64": "eA=="}}"#,
        )
        .unwrap();
        assert_eq!(
            both.into_captured(Origin::Proxy).unwrap_err(),
            PayloadError::BothBodies
        );
    }
}
