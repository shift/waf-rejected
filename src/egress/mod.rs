//! Egress mode: a local fetch service for agents.
//!
//! Edge mode is a reverse proxy: the client opens a connection, the proxy
//! forwards it. Egress mode is different on purpose. An agent asks this local
//! service to fetch a URL, the service performs the request itself, and it
//! returns the body plus a verdict. That is what makes response inspection
//! possible without a CONNECT tunnel, a local CA, or TLS termination.
//!
//! The rules are fixed identifiers (`EG-*`) implemented in [`rules`]; the
//! fetcher, handler and listener are in [`service`]; [`verdict`] is the wire
//! type.
//!
//! See `docs/egress-mode.md` for the design choice, the rule table and the
//! laptop run command.

pub mod rules;
pub mod service;
pub mod verdict;

pub use rules::{
    effective_port, hidden_text_present, injection_marker, EgressPolicy, RuleHit, ALL_RULE_IDS,
    EG_BODY_TOO_LARGE, EG_CONTENT_TYPE, EG_CREDENTIAL_QUERY, EG_DENIED_DOMAIN,
    EG_DOMAIN_NOT_ALLOWED, EG_INJECTION, EG_METADATA_ADDRESS, EG_PORT, EG_PRIVATE_ADDRESS,
    EG_SCHEME,
};
pub use service::{EgressResolver, EgressService, SystemResolver};
pub use verdict::{Outcome, Verdict};
