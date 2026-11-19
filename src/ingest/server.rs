//! The HTTP ingest endpoint used by proxy plugins and curl (SPEC R-10, R-11).
//!
//! ```text
//! POST /ingest        one IngestPayload           → 202 {"accepted":1}
//! POST /ingest/batch  [IngestPayload, …] (≤1000)  → 202 {"accepted":n,"rejected":m}
//! GET  /health                                    → 200 ok
//! ```
//!
//! ## Hardening (R-11a)
//!
//! A local HTTP API is reachable by any web page you visit, through DNS
//! rebinding (`evil.test` re-resolving to 127.0.0.1) or "simple" cross-site
//! POSTs. A guard middleware runs **before** the body is read and rejects:
//!
//! * a `Host` header that isn't loopback / the configured bind host (`403`),
//! * a missing or wrong bearer token when one is configured (`401`),
//! * a `Content-Type` other than `application/json` (`415`), which browsers
//!   cannot send cross-site without a CORS preflight we never answer.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use super::{IngestReport, IngestSource};
use crate::model::{IngestPayload, Origin};
use crate::pipeline::Pipeline;

/// Max request body (R-11).
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Max items per batch (R-11).
pub const MAX_BATCH: usize = 1000;

/// Time allowed to receive a whole request body. A client that stalls
/// mid-body would otherwise hold one of the body permits forever.
pub const DEFAULT_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Access rules for the endpoint.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Required bearer token; `None` disables auth (`--no-auth`).
    pub token: Option<String>,
    /// Accepted `Host` header values (lower-case, with port). `None`
    /// accepts any host (only with `--allow-remote-ingest`).
    pub allowed_hosts: Option<Vec<String>>,
    /// Deadline for reading a request body (`408` after it).
    pub body_timeout: std::time::Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            token: None,
            allowed_hosts: None,
            body_timeout: DEFAULT_BODY_TIMEOUT,
        }
    }
}

impl ServerConfig {
    /// Loopback-only hosts for a server bound to `addr`, plus `hostname`
    /// as typed by the user (e.g. `localhost`).
    pub fn loopback(addr: SocketAddr, hostname: &str, token: Option<String>) -> Self {
        let port = addr.port();
        let mut hosts = vec![
            format!("localhost:{port}"),
            format!("127.0.0.1:{port}"),
            format!("[::1]:{port}"),
            format!("{}:{port}", hostname.to_ascii_lowercase()),
        ];
        hosts.push(match addr {
            SocketAddr::V4(a) => format!("{}:{port}", a.ip()),
            SocketAddr::V6(a) => format!("[{}]:{port}", a.ip()),
        });
        hosts.sort();
        hosts.dedup();
        Self {
            token,
            allowed_hosts: Some(hosts),
            body_timeout: DEFAULT_BODY_TIMEOUT,
        }
    }
}

#[derive(Clone)]
struct AppState {
    pipeline: Pipeline,
    cfg: ServerConfig,
    /// Bounds how many request bodies are buffered/decoded at once.
    bodies: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Concurrent ingest requests whose bodies may be in memory at once.
pub const MAX_CONCURRENT_BODIES: usize = 8;

/// Refuse non-loopback binds unless explicitly allowed (R-11a).
pub fn check_bind_addr(addr: &SocketAddr, allow_remote: bool) -> Result<(), String> {
    if addr.ip().is_loopback() || allow_remote {
        Ok(())
    } else {
        Err(format!(
            "refusing to listen on non-loopback address {addr}; pass --allow-remote-ingest \
             (and keep the ingest token enabled) if you really want this"
        ))
    }
}

/// A random 32-hex-character token for `--ingest-token` defaults.
pub fn generate_token() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS random number generator available");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compare without early exit so response timing doesn't leak the token.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// Host / token / content-type checks, run before the body is read.
async fn guard(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let headers = req.headers();
    if let Some(allowed) = &state.cfg.allowed_hosts {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| h.to_ascii_lowercase());
        if !host.as_ref().is_some_and(|h| allowed.contains(h)) {
            return error(StatusCode::FORBIDDEN, "unexpected Host header");
        }
    }
    if req.method() == Method::POST {
        if let Some(expected) = &state.cfg.token {
            let ok = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|got| constant_time_eq(got.as_bytes(), expected.as_bytes()));
            if !ok {
                return error(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
            }
        }
        if !is_json(headers) {
            return error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/json",
            );
        }
        // Held while the body is read and decoded by the handler.
        let Ok(_permit) = state.bodies.clone().acquire_owned().await else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "shutting down");
        };
        // Read the whole body under a deadline (and the size cap), so a
        // stalled client can't hold the permit forever.
        let (parts, body) = req.into_parts();
        let bytes = match tokio::time::timeout(
            state.cfg.body_timeout,
            axum::body::to_bytes(body, MAX_BODY_BYTES),
        )
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(_)) => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body too large or unreadable",
                );
            }
            Err(_) => {
                return error(
                    StatusCode::REQUEST_TIMEOUT,
                    "request body not received in time",
                );
            }
        };
        return next
            .run(Request::from_parts(parts, Body::from(bytes)))
            .await;
    }
    next.run(req).await
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}

async fn ingest_one(State(state): State<AppState>, Json(payload): Json<IngestPayload>) -> Response {
    match payload.into_captured(Origin::Proxy) {
        Ok(item) => {
            if !state.pipeline.submit(item) {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "pipeline overloaded, retry later",
                );
            }
            (StatusCode::ACCEPTED, Json(json!({ "accepted": 1 }))).into_response()
        }
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn ingest_batch(
    State(state): State<AppState>,
    Json(payloads): Json<Vec<IngestPayload>>,
) -> Response {
    if payloads.len() > MAX_BATCH {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("batch has {} items, max is {MAX_BATCH}", payloads.len()),
        );
    }
    let mut report = IngestReport::default();
    for p in payloads {
        match p.into_captured(Origin::Proxy) {
            Ok(item) => {
                if state.pipeline.submit(item) {
                    report.submitted += 1;
                } else {
                    report.rejected += 1;
                }
            }
            Err(e) => {
                tracing::debug!("rejected batch item: {e}");
                report.rejected += 1;
            }
        }
    }
    (
        StatusCode::ACCEPTED,
        Json(json!({ "accepted": report.submitted, "rejected": report.rejected })),
    )
        .into_response()
}

/// Build the router. Public so tests can drive it directly.
pub fn router(pipeline: Pipeline, cfg: ServerConfig) -> Router {
    let state = AppState {
        pipeline,
        cfg,
        bodies: std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BODIES)),
    };
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ingest", post(ingest_one))
        .route("/ingest/batch", post(ingest_batch))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Serves the ingest API until `shutdown` is cancelled.
pub struct ServerSource {
    pub listener: TcpListener,
    pub config: ServerConfig,
    pub shutdown: CancellationToken,
}

impl IngestSource for ServerSource {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn run(self, pipeline: Pipeline) -> anyhow::Result<IngestReport> {
        let addr = self.listener.local_addr()?;
        tracing::info!("ingest endpoint listening on http://{addr}/ingest");
        let app = router(pipeline, self.config);
        axum::serve(self.listener, app)
            .with_graceful_shutdown(self.shutdown.cancelled_owned())
            .await?;
        Ok(IngestReport::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_policy() {
        assert!(check_bind_addr(&"127.0.0.1:3333".parse().unwrap(), false).is_ok());
        assert!(check_bind_addr(&"[::1]:3333".parse().unwrap(), false).is_ok());
        assert!(check_bind_addr(&"0.0.0.0:3333".parse().unwrap(), false).is_err());
        assert!(check_bind_addr(&"0.0.0.0:3333".parse().unwrap(), true).is_ok());
    }

    #[test]
    fn token_compare_and_generation() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        let (a, b) = (generate_token(), generate_token());
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn loopback_hosts() {
        let c = ServerConfig::loopback("127.0.0.1:3333".parse().unwrap(), "LocalHost", None);
        let hosts = c.allowed_hosts.unwrap();
        assert!(hosts.contains(&"localhost:3333".to_string()));
        assert!(hosts.contains(&"127.0.0.1:3333".to_string()));
        assert!(!hosts.iter().any(|h| h.contains("evil")));
    }
}
