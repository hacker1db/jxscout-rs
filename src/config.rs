//! Runtime configuration.
//!
//! The CLI (`src/main.rs`) parses flags with clap and converts them into a
//! [`Config`]. Library code and tests build a `Config` directly, usually via
//! [`Config::for_tests`], so nothing in the library depends on clap.

use std::path::PathBuf;
use std::time::Duration;

use crate::scope::Scope;

/// How captured authentication headers are forwarded on tool-initiated
/// fetches (SPEC R-60, R-61).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardAuth {
    /// Only to the exact origin (scheme + host + port) of the captured request.
    #[default]
    SameOrigin,
    /// Never forward.
    Never,
}

impl std::str::FromStr for ForwardAuth {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "same-origin" => Ok(Self::SameOrigin),
            "never" => Ok(Self::Never),
            other => Err(format!(
                "unknown forward-auth mode `{other}` (expected same-origin or never)"
            )),
        }
    }
}

/// Settings for every outbound HTTP request the tool makes itself.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Max concurrent fetches (R-55).
    pub concurrency: usize,
    /// Max requests per second, 0 = unlimited (R-55).
    pub max_rps: u32,
    /// Max requests per minute, 0 = unlimited (R-55).
    pub max_rpm: u32,
    /// Total per-request timeout (R-36).
    pub timeout: Duration,
    /// Max decompressed body size in bytes (R-36).
    pub max_body_bytes: u64,
    /// Retries for transient failures (R-72).
    pub retries: u32,
    /// Base delay of the exponential retry backoff.
    pub retry_base_delay: Duration,
    /// Auth forwarding policy (R-61).
    pub forward_auth: ForwardAuth,
    /// Header names copied from the captured request (R-60). Case-insensitive.
    pub forward_headers: Vec<String>,
    /// Static headers sent to in-scope origins (R-62).
    pub extra_headers: Vec<(String, String)>,
    /// Allow loopback / private destinations (R-56). Off by default.
    pub allow_private_targets: bool,
    /// Max redirects followed per request (R-56).
    pub max_redirects: usize,
    pub user_agent: String,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            concurrency: 5,
            max_rps: 2,
            max_rpm: 0,
            timeout: Duration::from_secs(30),
            max_body_bytes: 20 * 1024 * 1024,
            retries: 2,
            retry_base_delay: Duration::from_millis(250),
            forward_auth: ForwardAuth::SameOrigin,
            forward_headers: vec!["cookie".into(), "authorization".into()],
            extra_headers: Vec::new(),
            allow_private_targets: false,
            max_redirects: 5,
            user_agent: concat!("jxscout-rs/", env!("CARGO_PKG_VERSION")).to_string(),
        }
    }
}

/// Limits and switches for chunk / source-map discovery and analysis.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Numeric ids tried when a chunk-name function has no key table (R-52).
    pub bruteforce_limit: u32,
    /// Max recursion depth for chunks discovered from chunks (R-54).
    pub max_depth: u32,
    /// Max chunk URLs scheduled from one script (R-36).
    pub max_chunks_per_script: usize,
    /// Max sources written from one source map (R-36).
    pub max_sourcemap_sources: usize,
    pub chunks: bool,
    pub sourcemaps: bool,
    pub analyze: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            bruteforce_limit: 3000,
            max_depth: 3,
            max_chunks_per_script: 4000,
            max_sourcemap_sources: 10_000,
            chunks: true,
            sourcemaps: true,
            analyze: true,
        }
    }
}

/// Everything the pipeline needs to run.
#[derive(Debug, Clone)]
pub struct Config {
    /// Root of all projects, `~/jxscout` by default (R-30).
    pub output_dir: PathBuf,
    /// Project folder name, validated by [`crate::store::validate_project_name`].
    pub project: String,
    pub scope: Scope,
    /// Download out-of-scope JS referenced from in-scope pages (R-25).
    pub download_referred_js: bool,
    pub fetch: FetchConfig,
    pub discovery: DiscoveryConfig,
}

impl Config {
    /// Default output directory: `~/jxscout`, or `./jxscout` if there is no home.
    pub fn default_output_dir() -> PathBuf {
        directories::BaseDirs::new()
            .map(|d| d.home_dir().join("jxscout"))
            .unwrap_or_else(|| PathBuf::from("jxscout"))
    }

    /// A config suitable for tests: writes into `output_dir`, talks to
    /// loopback servers, no rate limit, fast retries.
    pub fn for_tests(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            project: "test".into(),
            scope: Scope::default(),
            download_referred_js: false,
            fetch: FetchConfig {
                max_rps: 0,
                allow_private_targets: true,
                retry_base_delay: Duration::from_millis(5),
                timeout: Duration::from_secs(5),
                ..FetchConfig::default()
            },
            discovery: DiscoveryConfig {
                bruteforce_limit: 20,
                ..DiscoveryConfig::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_auth_parses() {
        assert_eq!("same-origin".parse(), Ok(ForwardAuth::SameOrigin));
        // Cross-origin forwarding was removed on purpose (security review).
        assert!("in-scope".parse::<ForwardAuth>().is_err());
        assert_eq!("never".parse(), Ok(ForwardAuth::Never));
        assert!("bogus".parse::<ForwardAuth>().is_err());
    }
}
