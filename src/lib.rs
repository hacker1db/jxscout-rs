//! # jxscout-rs
//!
//! A clean-room Rust reimplementation of the behavior described in the
//! upstream jxscout docs. See `docs/SPEC.md` for the requirements (`R-xx`)
//! that the modules below implement.
//!
//! The crate is split so that every piece of logic is testable without a
//! terminal or a network:
//!
//! | module | responsibility |
//! | --- | --- |
//! | [`config`] | runtime configuration shared by every component |
//! | [`scope`] | wildcard scope matching (R-20..R-24) |
//! | [`model`] | captured request/response types and the ingest DTO (R-11) |
//! | [`net`] | outbound HTTP: SSRF guard, rate limiting, auth forwarding (R-36, R-55..R-62) |
//! | [`store`] | URL → safe file path mapping and the SQLite index (R-30..R-36) |
//! | [`js`] | parsing, beautifying, HTML script extraction, chunk + source-map discovery |
//! | [`rules`] | the extensible AST rule engine (R-80..R-83) |
//! | [`pipeline`] | glues everything together (R-40..R-43) |
//! | [`ingest`] | ingest sources: HTTP endpoint, URL lists, HAR files (R-10..R-14) |
//! | [`events`] | progress events consumed by the TUI and logs |
//! | [`tui`] | the ratatui terminal UI (R-90, R-91) |

pub mod config;
pub mod events;
pub mod ingest;
pub mod js;
pub mod model;
pub mod net;
pub mod pipeline;
pub mod rules;
pub mod scope;
pub mod store;
pub mod tui;

pub use config::Config;
pub use pipeline::Pipeline;
