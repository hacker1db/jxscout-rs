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
#[derive(Debug, Clone)]
pub struct FetchResponse {
    /// Final URL after redirects.
    pub url: Url,
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
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
            .redirect(reqwest::redirect::Policy::none());
        if !cfg.allow_private_targets {
            builder = builder.dns_resolver(Arc::new(GuardedResolver));
        }
        let client = builder.build()?;
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                limiter: RateLimiter::new(cfg.max_rps, cfg.max_rpm),
                permits: Semaphore::new(cfg.concurrency.max(1)),
                cfg,
                scope,
                download_referred,
            }),
        })
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
                ForwardAuth::SameOrigin => target == auth.origin,
                ForwardAuth::InScope => {
                    let downgrade = matches!(&auth.origin, url::Origin::Tuple(s, _, _) if s == "https")
                        && url.scheme() == "http";
                    target == auth.origin || (explicitly_in_scope && !downgrade)
                }
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
        let _permit = self
            .inner
            .permits
            .acquire()
            .await
            .expect("semaphore is never closed");
        let retries = self.inner.cfg.retries;
        let mut attempt = 0;
        loop {
            self.inner.limiter.acquire().await;
            let result = self.get_once(url, ctx).await;
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
    async fn get_once(
        &self,
        url: &Url,
        ctx: &FetchContext<'_>,
    ) -> Result<FetchResponse, FetchError> {
        let mut current = url.clone();
        for _hop in 0..=self.inner.cfg.max_redirects {
            self.check_target(&current, ctx)?;
            let resp = self
                .inner
                .client
                .get(current.clone())
                .headers(self.headers_for(&current, ctx))
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
            return self.read_response(current, resp).await;
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
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if body.len() as u64 + chunk.len() as u64 > limit {
                return Err(FetchError::TooLarge { limit });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(FetchResponse {
            url,
            status,
            headers,
            body,
        })
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
    fn in_scope_forwarding_blocks_downgrade() {
        let f = fetcher(&["*.app.test"], ForwardAuth::InScope);
        let auth = auth_for("https://www.app.test/");
        let ctx = FetchContext::new(Purpose::Chunk).with_auth(Some(&auth));
        assert!(
            f.headers_for(&u("https://cdn.app.test/x.js"), &ctx)
                .contains_key("cookie")
        );
        assert!(
            !f.headers_for(&u("http://cdn.app.test/x.js"), &ctx)
                .contains_key("cookie")
        );
        assert!(
            !f.headers_for(&u("https://evil.test/x.js"), &ctx)
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
