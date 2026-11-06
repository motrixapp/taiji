//! Process-level TLS provider installation (workspace TLS stack
//! standardized on ring).
//!
//! Under reqwest 0.13's `rustls-no-provider` feature, every
//! `Client::builder()` build point reads the rustls process-wide default
//! CryptoProvider at build() time — with none installed the build fails.
//! This repo has more than one reqwest build point (taiji-http data/probe
//! transports, taiji-bt tracker HTTP client), so the installer lives in
//! the dependency-common base crate taiji-io (bt -> io and http -> io are
//! both established allow-listed edges) and every build point calls
//! [`install_ring_provider_default`] as an idempotent declaration.
//!
//! ring is wired via the workspace `rustls` (default-features off;
//! aws_lc_rs stays out of the graph); `CryptoProvider::install_default`
//! is rustls' official multi-provider process installation API (the
//! pattern from the reqwest tls module docs). A duplicate install
//! returns `Err` — idempotent semantics; callers ignore it.

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Install the ring CryptoProvider process-wide (idempotent; the first
/// call takes effect, later calls are zero-cost and never overwrite the
/// existing default).
pub fn install_ring_provider_default() {
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
