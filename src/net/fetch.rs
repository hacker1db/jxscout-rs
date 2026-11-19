//! The outbound HTTP client used for every tool-initiated request.
//!
//! One [`Fetcher`] is shared by the whole pipeline. It enforces, in order:
//!
//! 1. the outbound policy ([`Fetcher::check_target`], SPEC R-56) on the
//!    first URL **and every redirect hop** (redirects are followed manually
//!    so the policy and the header rules can be re-applied per hop);
//! 2. the concurrency limit (a semaphore) and the rate limit (R-55);
//! 3. auth-header forwarding rules (R-60..R-62);
//! 4. the response size cap on the decompressed stream (R-36);
//! 5. retries with exponential backoff for transient failures (R-72).

use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, LOCATION};
use tokio::sync::Semaphore;
use url::Url;

use super::guard::{GuardedResolver, check_url_host};
use super::ratelimit::RateLimiter;
use crate::budget::{Budget, Reservation};
use crate::config::{FetchConfig, ForwardAuth};
use crate::model::{AuthContext, Headers};
use crate::scope::{Decision, Scope};

/// Why something is being fetched. Determines which scope exceptions apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A URL the user asked for directly (URL list / ingest without body).
    Captured,
    /// A `<script src>` from an HTML page (R-25).
    Referred,
    /// A discovered chunk.
    Chunk,
    /// A source map.
    SourceMap,
}

/// Context for one fetch.
#[derive(Debug, Clone, Copy)]
pub struct FetchContext<'a> {
    pub purpose: Purpose,
    /// The asset this URL was discovered from.
    pub parent: Option<&'a Url>,
    /// Credentials captured with the original request.
    pub auth: Option<&'a AuthContext>,
}

impl<'a> FetchContext<'a> {
    pub fn new(purpose: Purpose) -> Self {
        Self {
            purpose,
            parent: None,
            auth: None,
        }
    }

    pub fn with_parent(mut self, parent: Option<&'a Url>) -> Self {
        self.parent = parent;
        self
    }

    pub fn with_auth(mut self, auth: Option<&'a AuthContext>) -> Self {
        self.auth = auth;
        self
    }
}

/// A completed response.
#[derive(Debug)]
pub struct FetchResponse {
    /// Final URL after redirects.
    pub url: Url,
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// `false` if the redirect chain ever left the first request's origin.
    /// Anything discovered from this response must not carry captured
    /// credentials, even if the chain ended back on the original origin.
    pub stayed_on_origin: bool,
    /// The memory-budget reservation covering `body` (when the fetcher has
    /// a [`Budget`]). Keep it alive as long as you keep the body.
    pub memory: Option<Reservation>,
}

impl FetchResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("blocked: {0}")]
    Blocked(String),
    #[error("response larger than {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("memory budget exhausted while downloading")]
    OverBudget,
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("invalid redirect location `{0}`")]
    BadRedirect(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

impl FetchError {
    /// Whether retrying might help (R-72).
    fn is_transient(&self) -> bool {
        match self {
            Self::Http(e) => e.is_connect() || e.is_timeout() || e.is_body(),
            _ => false,
        }
    }
}

/// Shared, cheap-to-clone HTTP client.
#[derive(Debug, Clone)]
pub struct Fetcher {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    client: reqwest::Client,
    cfg: FetchConfig,
    scope: Arc<Scope>,
    download_referred: bool,
    limiter: RateLimiter,
    permits: Semaphore,
    budget: Option<Budget>,
}

impl Fetcher {
    pub fn new(
        cfg: FetchConfig,
        scope: Arc<Scope>,
        download_referred: bool,
    ) -> Result<Self, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            .user_agent(cfg.user_agent.clone())
            .timeout(cfg.timeout)
            // We follow redirects ourselves, see module docs.
            .redirect(reqwest::redirect::Policy::none())
            // An HTTP(S)_PROXY from the environment would resolve hostnames
            // itself and bypass the guarded resolver below (R-56).
            .no_proxy();
        if !cfg.allow_private_targets {
            builder = builder.dns_resolver(Arc::new(GuardedResolver));
        }
        let client = builder.build()?;
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                limiter: RateLimiter::new(cfg.max_rps, cfg.max_rpm),
                permits: Semaphore::new(cfg.concurrency.max(1)),
                budget: None,
                cfg,
                scope,
                download_referred,
            }),
        })
    }

    /// Charge every downloaded body to `budget`. The reservation is taken
    /// once response headers arrive, *before* the body is read: the
    /// announced length (or `max_body_bytes` when unknown), grown chunk by
    /// chunk if the server lied, and shrunk to the real size at the end.
    pub fn with_budget(
        cfg: FetchConfig,
        scope: Arc<Scope>,
        download_referred: bool,
        budget: Budget,
    ) -> Result<Self, reqwest::Error> {
        let mut f = Self::new(cfg, scope, download_referred)?;
        Arc::get_mut(&mut f.inner)
            .expect("fresh fetcher is unshared")
            .budget = Some(budget);
        Ok(f)
    }

    pub fn scope(&self) -> &Scope {
        &self.inner.scope
    }

    /// The outbound policy (R-56). Exclusions always win (R-22a).
    pub fn check_target(&self, url: &Url, ctx: &FetchContext<'_>) -> Result<(), FetchError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(FetchError::Blocked(format!(
                "scheme `{}` is not allowed",
                url.scheme()
            )));
        }
        check_url_host(url, self.inner.cfg.allow_private_targets).map_err(FetchError::Blocked)?;

        let decision = self.inner.scope.check(url);
        if decision.is_excluded() {
            return Err(FetchError::Blocked(format!("{url}: {decision}")));
        }
        if decision.is_in() {
            return Ok(());
        }
        let same_origin_as_parent = ctx.parent.is_some_and(|p| p.origin() == url.origin());
        if same_origin_as_parent && ctx.purpose != Purpose::Captured {
            return Ok(());
        }
        if ctx.purpose == Purpose::Referred && self.inner.download_referred {
            return Ok(());
        }
        Err(FetchError::Blocked(format!(
            "{url}: out of scope ({decision})"
        )))
    }

    /// Headers for one hop to `url` (R-60..R-62).
    fn headers_for(&self, url: &Url, ctx: &FetchContext<'_>) -> HeaderMap {
        let cfg = &self.inner.cfg;
        let decision = self.inner.scope.check(url);
        let explicitly_in_scope = matches!(decision, Decision::Included(_));
        let mut out = HeaderMap::new();

        if let Some(auth) = ctx.auth {
            let target = url.origin();
            let allowed = match cfg.forward_auth {
                ForwardAuth::Never => false,
                // Captured credentials only ever go back to the exact origin
                // (scheme + host + port) they were captured for (R-61).
                ForwardAuth::SameOrigin => target == auth.origin,
            };
            if allowed {
                append_all(&mut out, auth.headers.iter());
            }
        }

        // Static headers go to explicitly in-scope origins, or — when no
        // positive scope is configured — to the parent's origin only.
        let no_includes = self.inner.scope.includes().next().is_none();
        let same_as_parent = ctx.parent.is_some_and(|p| p.origin() == url.origin());
        if explicitly_in_scope || (no_includes && same_as_parent && !decision.is_excluded()) {
            append_all(
                &mut out,
                cfg.extra_headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str())),
            );
        }
        out
    }

    /// GET `url` with policy, limits, and retries.
    pub async fn get(
        &self,
        url: &Url,
        ctx: &FetchContext<'_>,
    ) -> Result<FetchResponse, FetchError> {
        // Fail fast without consuming a rate-limit slot.
        self.check_target(url, ctx)?;
        let retries = self.inner.cfg.retries;
        let mut attempt = 0;
        loop {
            // Hold a concurrency permit only while a request is in flight,
            // not while sleeping between retries.
            let result = {
                let _permit = self
                    .inner
                    .permits
                    .acquire()
                    .await
                    .expect("semaphore is never closed");
                self.get_once(url, ctx).await
            };
            let retry = match &result {
                Ok(r) => r.status == 429 || (500..600).contains(&r.status),
                Err(e) => e.is_transient(),
            };
            if !retry || attempt >= retries {
                return result;
            }
            let delay = self.inner.cfg.retry_base_delay * 2u32.pow(attempt);
            tracing::debug!(%url, attempt, ?delay, "retrying fetch");
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }

    /// One attempt, following redirects manually.
    ///
    /// Every hop is policy-checked and rate-limited. Once a redirect leaves
    /// the origin of the first request, no credentials (captured or static)
    /// are sent again for the rest of the chain — even if a later hop comes
    /// back to an in-scope origin.
    async fn get_once(
        &self,
        url: &Url,
        ctx: &FetchContext<'_>,
    ) -> Result<FetchResponse, FetchError> {
        let first_origin = url.origin();
        let mut send_credentials = true;
        let mut current = url.clone();
        for _hop in 0..=self.inner.cfg.max_redirects {
            self.check_target(&current, ctx)?;
            if current.origin() != first_origin {
                send_credentials = false;
            }
            let headers = if send_credentials {
                self.headers_for(&current, ctx)
            } else {
                HeaderMap::new()
            };
            self.inner.limiter.acquire().await;
            let resp = self
                .inner
                .client
                .get(current.clone())
                .headers(headers)
                .send()
                .await?;

            if resp.status().is_redirection()
                && let Some(loc) = resp.headers().get(LOCATION)
            {
                let loc = loc.to_str().unwrap_or_default();
                current = current
                    .join(loc)
                    .map_err(|_| FetchError::BadRedirect(loc.to_string()))?;
                continue;
            }
            let mut r = self.read_response(current, resp).await?;
            r.stayed_on_origin = send_credentials;
            return Ok(r);
        }
        Err(FetchError::TooManyRedirects)
    }

    async fn read_response(
        &self,
        url: Url,
        mut resp: reqwest::Response,
    ) -> Result<FetchResponse, FetchError> {
        let limit = self.inner.cfg.max_body_bytes;
        // Cheap early exit when the server announces a huge body. We still
        // enforce the limit while streaming, because Content-Length can be
        // absent or lie, and because bodies are decompressed on the fly.
        if resp.content_length().is_some_and(|n| n > limit) {
            return Err(FetchError::TooLarge { limit });
        }
        let status = resp.status().as_u16();
        let headers = Headers(
            resp.headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect(),
        );
        // Reserve memory before reading a single body byte. The task calling
        // us holds no other reservation, so waiting here can't deadlock.
        // Content-Length is untrusted. It sizes the *reservation* (so a
        // download waits for room up front instead of failing halfway
        // under contention) and refuses early when it can never fit, but
        // the buffer itself starts small and grows inside the reservation;
        // anything beyond it must be charged first (`BodyBuf::charge`).
        if let (Some(b), Some(n)) = (&self.inner.budget, resp.content_length())
            && n > b.capacity() as u64
        {
            return Err(FetchError::OverBudget);
        }
        let reserve = resp
            .content_length()
            .unwrap_or(UNKNOWN_LENGTH_START as u64)
            .min(limit) as usize;
        let memory = match &self.inner.budget {
            Some(b) => Some(b.reserve(reserve).await.ok_or(FetchError::OverBudget)?),
            None => None,
        };
        let initial = reserve.min(UNKNOWN_LENGTH_START);
        let mut body = BodyBuf::new(initial, limit, memory);
        while let Some(chunk) = resp.chunk().await? {
            body.push(&chunk)?;
        }
        let (body, memory) = body.finish();
        Ok(FetchResponse {
            url,
            status,
            headers,
            body,
            stayed_on_origin: true,
            memory,
        })
    }
}

/// Initial buffer (and reservation) when the server sends no Content-Length.
const UNKNOWN_LENGTH_START: usize = 64 * 1024;

/// A response body being streamed in, whose memory reservation always
/// covers the buffer's *capacity* (not just its length): `Vec` grows by
/// doubling, so charging only `len()` could under-count by up to 2×.
struct BodyBuf {
    buf: Vec<u8>,
    limit: u64,
    memory: Option<Reservation>,
}

impl BodyBuf {
    fn new(initial: usize, limit: u64, memory: Option<Reservation>) -> Self {
        // Never allocate more than is reserved.
        let cap = memory.as_ref().map_or(initial, |m| initial.min(m.bytes()));
        let b = Self {
            buf: Vec::with_capacity(cap),
            limit,
            memory,
        };
        b.debug_check();
        b
    }

    /// The invariant: reserved bytes cover the buffer's capacity.
    fn debug_check(&self) {
        if let Some(m) = &self.memory {
            debug_assert!(
                m.bytes() >= self.buf.capacity(),
                "{} < {}",
                m.bytes(),
                self.buf.capacity()
            );
        }
    }

    /// Append a chunk, growing the reservation *before* the buffer grows.
    fn push(&mut self, chunk: &[u8]) -> Result<(), FetchError> {
        let new_len = self.buf.len() + chunk.len();
        if new_len as u64 > self.limit {
            return Err(FetchError::TooLarge { limit: self.limit });
        }
        if new_len > self.buf.capacity() {
            // Grow geometrically (amortized O(1) appends) but never past
            // the download cap, and charge the new capacity first.
            let doubled = (self.buf.capacity() * 2).min(self.limit as usize);
            let reserved = self.memory.as_ref().map_or(usize::MAX, Reservation::bytes);
            // Stay inside the reservation while the body fits in it (no new
            // budget needed); beyond it, grow geometrically and charge.
            let target = if new_len <= reserved {
                new_len.max(doubled.min(reserved))
            } else {
                new_len.max(doubled)
            };
            self.charge(target)?;
            self.buf.reserve_exact(target - self.buf.len());
            // `reserve_exact` may round up; cover whatever we really got.
            self.charge(self.buf.capacity())?;
        }
        self.buf.extend_from_slice(chunk);
        self.debug_check();
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> Result<(), FetchError> {
        match self.memory.as_mut() {
            Some(m) => {
                if m.try_grow(bytes) {
                    Ok(())
                } else {
                    Err(FetchError::OverBudget)
                }
            }
            None => Ok(()),
        }
    }

    /// Trim the buffer and give back the unused reservation.
    fn finish(mut self) -> (Vec<u8>, Option<Reservation>) {
        self.buf.shrink_to_fit();
        if let Some(m) = self.memory.as_mut() {
            m.shrink_to(self.buf.capacity());
        }
        (self.buf, self.memory)
    }
}

fn append_all<'a>(map: &mut HeaderMap, pairs: impl Iterator<Item = (&'a str, &'a str)>) {
    for (k, v) in pairs {
        // Silently skip names/values that are not valid HTTP; they came from
        // user input or captured traffic and must not crash a fetch.
        if let (Ok(name), Ok(value)) = (HeaderName::try_from(k), HeaderValue::from_str(v)) {
            map.append(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetcher(scope: &[&str], forward: ForwardAuth) -> Fetcher {
        let cfg = FetchConfig {
            forward_auth: forward,
            extra_headers: vec![("X-Api".into(), "static".into())],
            ..FetchConfig::default()
        };
        Fetcher::new(cfg, Arc::new(Scope::from_patterns(scope)), false).unwrap()
    }

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn auth_for(origin: &str) -> AuthContext {
        let mut h = Headers::new();
        h.push("Cookie", "session=1");
        AuthContext {
            origin: u(origin).origin(),
            headers: h,
        }
    }

    /// Security review (5th pass): the reservation covers the buffer's
    /// capacity at every step, not just its length.
    #[tokio::test]
    async fn body_buffer_reservation_covers_capacity() {
        let budget = crate::budget::Budget::new(1024 * 1024);
        let res = budget.reserve(100).await.unwrap();
        let mut b = BodyBuf::new(100, 600 * 1024, Some(res));
        for i in 0..200 {
            b.push(&vec![b'x'; 1000 + i * 7]).unwrap();
            let reserved = b.memory.as_ref().unwrap().bytes();
            assert!(
                reserved >= b.buf.capacity(),
                "step {i}: {reserved} < {}",
                b.buf.capacity()
            );
        }
        let len = b.buf.len();
        let (body, mem) = b.finish();
        assert_eq!(body.len(), len);
        assert!(mem.as_ref().unwrap().bytes() >= body.capacity());
        assert!(budget.peak() <= budget.capacity());
        // Over the cap → TooLarge; over the budget → OverBudget.
        let mut small = BodyBuf::new(0, 10, None);
        assert!(matches!(
            small.push(&[0; 11]),
            Err(FetchError::TooLarge { .. })
        ));
        let tiny = crate::budget::Budget::new(2048);
        let mut over = BodyBuf::new(1024, 1 << 20, Some(tiny.reserve(1024).await.unwrap()));
        assert!(matches!(over.push(&[0; 4096]), Err(FetchError::OverBudget)));
    }

    /// Security review (6th pass): a Content-Length larger than the whole
    /// budget is refused before any body allocation.
    #[tokio::test]
    async fn content_length_over_budget_is_refused() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(path("/big.js"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 256 * 1024]))
            .mount(&server)
            .await;
        let cfg = FetchConfig {
            allow_private_targets: true,
            max_rps: 0,
            ..FetchConfig::default()
        };
        let budget = crate::budget::Budget::new(64 * 1024);
        let f =
            Fetcher::with_budget(cfg, Arc::new(Scope::default()), false, budget.clone()).unwrap();
        let url = u(&format!("{}/big.js", server.uri()));
        let err = f
            .get(&url, &FetchContext::new(Purpose::Captured))
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::OverBudget), "{err}");
        assert_eq!(budget.in_use(), 0);
        assert_eq!(budget.peak(), 0, "nothing was reserved or allocated");
    }

    #[test]
    fn same_origin_forwarding_only() {
        let f = fetcher(&["*.app.test"], ForwardAuth::SameOrigin);
        let auth = auth_for("https://www.app.test/");
        let ctx = FetchContext::new(Purpose::Chunk).with_auth(Some(&auth));
        assert!(
            f.headers_for(&u("https://www.app.test/x.js"), &ctx)
                .contains_key("cookie")
        );
        // Different port = different origin.
        assert!(
            !f.headers_for(&u("https://www.app.test:8443/x.js"), &ctx)
                .contains_key("cookie")
        );
        assert!(
            !f.headers_for(&u("https://cdn.app.test/x.js"), &ctx)
                .contains_key("cookie")
        );
    }

    #[test]
    fn never_forwarding() {
        let f = fetcher(&[], ForwardAuth::Never);
        let auth = auth_for("https://www.app.test/");
        let ctx = FetchContext::new(Purpose::Chunk).with_auth(Some(&auth));
        assert!(
            !f.headers_for(&u("https://www.app.test/x.js"), &ctx)
                .contains_key("cookie")
        );
    }

    #[test]
    fn extra_headers_only_in_scope() {
        let f = fetcher(&["*.app.test"], ForwardAuth::SameOrigin);
        let ctx = FetchContext::new(Purpose::Chunk);
        assert!(
            f.headers_for(&u("https://a.app.test/"), &ctx)
                .contains_key("x-api")
        );
        assert!(
            !f.headers_for(&u("https://other.test/"), &ctx)
                .contains_key("x-api")
        );
    }

    #[test]
    fn policy() {
        let f = fetcher(&["*.app.test", "!ads.app.test"], ForwardAuth::SameOrigin);
        let parent = u("https://cdn.other.test/main.js");
        let chunk = FetchContext::new(Purpose::Chunk).with_parent(Some(&parent));
        // in scope
        assert!(
            f.check_target(&u("https://a.app.test/x.js"), &chunk)
                .is_ok()
        );
        // same origin as parent
        assert!(
            f.check_target(&u("https://cdn.other.test/1.js"), &chunk)
                .is_ok()
        );
        // unrelated
        assert!(
            f.check_target(&u("https://evil.test/1.js"), &chunk)
                .is_err()
        );
        // exclusion beats same-origin
        let ads = u("https://ads.app.test/main.js");
        let ctx = FetchContext::new(Purpose::Chunk).with_parent(Some(&ads));
        assert!(
            f.check_target(&u("https://ads.app.test/1.js"), &ctx)
                .is_err()
        );
        // bad scheme, private ip
        assert!(f.check_target(&u("file:///etc/passwd"), &chunk).is_err());
        assert!(
            f.check_target(&u("http://169.254.169.254/"), &chunk)
                .is_err()
        );
    }
}
