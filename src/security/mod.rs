//! Security helpers for handling external content (web bodies, docs, emails).
//!
//! - [`url_guard`]: risk-graded phishing/abuse assessment of a URL before or
//!   during retrieval (inspired by thClaws' `external_url` / `net_guard`).
//! - [`injection`]: prompt-injection detection for untrusted text so the agent
//!   can recognize and resist embedded instructions (inspired by microclaw's
//!   `injection_scan`).
pub mod injection;
pub mod url_guard;
