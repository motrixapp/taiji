//! `taiji-rpc` — the RPC service (SPEC §8.1/§8.2).
//!
//! Module map (transport base + Basic auth):
//! - [`server`]: axum HTTP service — `POST /jsonrpc` (single / batch /
//!   system.multicall), `GET /jsonrpc` WebSocket upgrade, Basic auth
//!   gate, CORS, body limit, 1s unauthorized delay, graceful shutdown;
//! - [`jsonrpc`]: JSON-RPC 2.0 codec (positional params only; no
//!   XML-RPC);
//! - [`auth`]: `token:` first-parameter stripping + secret validation
//!   (aria2 RpcMethod.cc) + HTTP Basic (in-process random HMAC compare,
//!   HttpServer.cc; plaintext never lingers);
//! - [`base64`]: addTorrent first-parameter decoding (hand-rolled
//!   standard base64, RpcMethodImpl.cc counterpart; fuzz target
//!   `rpc_base64`);
//! - [`dispatch`]: method dispatch, real method semantics,
//!   system.multicall RPC-layer expansion;
//! - [`aria2`]: the aria2 v1 adapter layer — the four mapping tables
//!   (`status` words, `error` codes/messages — the repo-wide single
//!   error-mapping source, `event` names, `option` names); the only
//!   place wire strings are produced, and removable without touching
//!   the kernel (the excision check);
//! - [`guards`] (crate-internal): exposure guards — connection
//!   concurrency ledger (total 256 / per-IP 32) + auth-failure
//!   exponential backoff (1s..60s); caps/thresholds are injectable
//!   constants, not CLI knobs.
//!
//! Compatibility freeze: the method registration surface =
//! `taiji_core::session::RPC_METHODS` (the promised-method table, 35
//! names unchanged). API presentation, one face at a time: default =
//! canonical `taiji.*` names + six `taiji.onXxx` events +
//! `taiji.*` listMethods/listNotifications; `--rpc-aria2-compat` on =
//! methods additionally accept `aria2.<name>` aliases (aria2 registers
//! only prefixed names, RpcMethodFactory.cc), the six events are pushed
//! as `aria2.onXxx`, and listMethods/listNotifications present the
//! aria2 face. Alias normalization and face gating have a single
//! source: [`dispatch::canonical_method`] /
//! [`dispatch::method_face_names`] / [`aria2::event::notification_face`].
//! Details: Upstream anchor mapping: docs/design/rpc.md
//!
//! Dependency direction: depends only on `taiji-core`.

pub mod aria2;
pub mod auth;
pub mod base64;
pub mod dispatch;
/// RPC exposure guards (crate-internal): connection concurrency caps +
/// auth-failure backoff.
pub(crate) mod guards;
pub mod jsonrpc;
/// metalink data-plane consumption seam (feature `metalink` on by
/// default). With it off the whole tree does not compile —
/// taiji-metalink leaves the dependency graph and addMetalink is not
/// registered.
#[cfg(feature = "metalink")]
pub mod metalink;
/// Prometheus `/metrics` rendering surface.
/// Rendering pure functions are pub(crate) (test surface + server
/// routing); no new dependencies.
pub(crate) mod metrics;
/// Task-cookie direct-pass parameter parsing seam (shared by
/// addUriWithCookies/setTaskCookies — mirrors RpcCookie.cc
/// parseRpcCookies verbatim; module-doc anchor).
pub mod rpc_cookies;
pub mod server;

/// [`server::normalize_secret`]: the single source of rpc-secret
/// normalization (empty / all-whitespace = unset) — shared by the
/// CLI/conf ingest point and the serve guards.
pub use server::{RpcConfig, ServerHandle, normalize_secret, serve};

/// Crate-wide std-Mutex lock policy: poisoning (a thread panicked while
/// holding the guard) means a guarded invariant was lost — continuing on
/// the recovered guard would silently operate on corrupt state, so
/// poisoning is fatal: the helper fails loudly via `expect` and the
/// resulting process terminal state is taken over by the existing
/// panic-watcher. Poisoning is never recovered from (no
/// `into_inner` on the error path).
#[expect(clippy::expect_used, reason = "lock poisoning is fatal by policy")]
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock()
        .expect("lock poisoned: invariant lost, fail loudly")
}
