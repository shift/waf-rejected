//! QuicCrunch transport entry point (`quiccrunch-transport` feature).
//!
//! The dependency is intentionally **not** vendored yet. `quiccrunch-core` is
//! not published on crates.io, and the Nix build resolves its Cargo dependency
//! graph offline, so a git dependency cannot be added without a vendoring
//! change. This module is the cfg-guarded seam: enabling the feature makes the
//! transport selectable and compiles, but construction fails closed with an
//! actionable error until the dependency lands.
//!
//! Enablement steps (also in `docs/operations/quiccrunch-transport.md`):
//! add the pinned git dependency, regenerate `Cargo.lock` and the Nix vendor
//! hash, then replace this stub with the client that presents
//! `quiccrunch.client_cert_path`/`client_key_path` and verifies the server
//! against `quiccrunch.ca_cert_path` — never an insecure mode.

use std::sync::Arc;

use super::traits::DistributedError;
use super::transport::TransportClient;
use crate::config::DistributedConfig;

/// Build the real QuicCrunch client.
///
/// Always fails closed for now: silently returning a gRPC client would make
/// `transport = "quiccrunch"` a lie and could send policy traffic over the
/// wrong endpoint/identity.
pub fn build(config: &DistributedConfig) -> Result<Arc<dyn TransportClient>, DistributedError> {
    let qc = &config.quiccrunch;
    Err(DistributedError::invalid(format!(
        "waf.distributed.transport = \"quiccrunch\" is compiled in, but the quiccrunch-core \
         dependency is not vendored (endpoint '{}', server '{}'); add the pinned git dependency, \
         refresh Cargo.lock and the Nix vendor hash, and implement the client per \
         docs/operations/quiccrunch-transport.md",
        qc.endpoint, qc.server_name
    )))
}
