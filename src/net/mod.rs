//! Outbound networking: SSRF guard, rate limiting, and the shared fetcher.

pub mod decode;
pub mod fetch;
pub mod guard;
pub mod ratelimit;

pub use fetch::{FetchContext, FetchError, FetchResponse, Fetcher, Purpose};
