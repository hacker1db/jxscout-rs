//! The HTTP ingest endpoint used by proxy plugins and curl (SPEC R-10, R-11).
//!
//! ```text
//! POST /ingest        one IngestPayload           → 202 {"accepted":1}
//! POST /ingest/batch  [IngestPayload, …] (≤1000)  → 202 {"accepted":n,"rejected":m}
//! GET  /health                                    → 200 ok
//! ```

use std::net::SocketAddr;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
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

#[derive(Clone)]
struct AppState {
    pipeline: Pipeline,
    token: Option<String>,
}

/// Refuse non-loopback binds unless explicitly allowed (R-11a).
pub fn check_bind_addr(addr: &SocketAddr, allow_remote: bool) -> Result<(), String> {
    if addr.ip().is_loopback() || allow_remote {
        Ok(())
    } else {
        Err(format!(
            "refusing to listen on non-loopback address {addr}; pass --allow-remote-ingest \
             (and ideally --ingest-token) if you really want this"
        ))
    }
}

/// Compare without early exit so response timing doesn't leak the token.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn authorized(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = &state.token else {
        return true;
    };
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|got| constant_time_eq(got.as_bytes(), expected.as_bytes()))
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

async fn ingest_one(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IngestPayload>,
) -> Response {
    if !authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
    }
    match payload.into_captured(Origin::Proxy) {
        Ok(item) => {
            state.pipeline.submit(item);
            (StatusCode::ACCEPTED, Json(json!({ "accepted": 1 }))).into_response()
        }
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn ingest_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payloads): Json<Vec<IngestPayload>>,
) -> Response {
    if !authorized(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
    }
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
                state.pipeline.submit(item);
                report.submitted += 1;
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
pub fn router(pipeline: Pipeline, token: Option<String>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ingest", post(ingest_one))
        .route("/ingest/batch", post(ingest_batch))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(AppState { pipeline, token })
}

/// Serves the ingest API until `shutdown` is cancelled.
pub struct ServerSource {
    pub listener: TcpListener,
    pub token: Option<String>,
    pub shutdown: CancellationToken,
}

impl IngestSource for ServerSource {
    fn name(&self) -> &'static str {
        "http"
    }

    async fn run(self, pipeline: Pipeline) -> anyhow::Result<IngestReport> {
        let addr = self.listener.local_addr()?;
        tracing::info!("ingest endpoint listening on http://{addr}/ingest");
        let app = router(pipeline, self.token);
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
    fn token_compare() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
