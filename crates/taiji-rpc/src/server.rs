//! axum transport for the RPC face: `POST /jsonrpc` (single/batch/
//! multicall), `GET /jsonrpc` WS upgrade, Basic + token auth, CORS,
//! request-size caps, the 1s unauthorized delay (consumed by both the HTTP
//! and WS paths), the WS same-origin gate, the Basic+Bearer-gated
//! `/metrics`, and graceful shutdown.
//!
//! Upstream anchor mapping: docs/design/rpc.md (HttpServerCommand.cc,
//! HttpServerBodyCommand.cc, WebSocketSession.cc, WebSocketSessionMan.cc).
//!
//! Hard invariants: Basic auth is checked at the header layer before the
//! body is read (401 precedes 413); every unauthorized response is delayed
//! 1s and abandoned on shutdown, on both transport paths; the bind face
//! only follows `--rpc-listen-all` while credentials only decide auth
//! gates; `listen_all` without usable credentials refuses to start; with
//! `listen_all` + secret and Basic unset or user-only, the /metrics and WS
//! event-stream anonymous faces are guarded by the secret itself (Bearer /
//! first-message token).
//!
//! Concurrency discipline: no locks across await; no new channels
//! (backpressure is carried by the SessionActor mpsc(64) and the event bus
//! broadcast(256)); tokens/passwords are never logged or echoed.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Extension, Request, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, AUTHORIZATION, CONNECTION,
    CONTENT_LENGTH, CONTENT_TYPE, HOST, ORIGIN, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HyperAutoBuilder;
use hyper_util::service::TowerToHyperService;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use tokio_util::sync::CancellationToken;
use tower_service::Service;
use tracing::{info, warn};

use serde_json::{Value, json};
use taiji_core::session::{
    MEDIA_PHASE_EVENT_METHOD, MediaEvent, RecoveryEvent, RecoveryEventKind, SessionEvent,
    SessionHandle, TASK_COOKIE_EVENT_METHOD, TaskCookieEvent,
};

use crate::dispatch::{AppState, handle_payload};
use crate::error::{STR_REQUEST_TOO_LARGE, http_status};
use crate::guards::{AuthBackoff, ConnLeaseSlot, ConnLedger, ConnScope, RpcGuards};
use crate::jsonrpc::parse_error_response;

/// Unauthorized-response delay (DelayedCommand 1_s, HttpServerBodyCommand.cc).
const UNAUTHORIZED_DELAY: Duration = Duration::from_secs(1);

/// RPC service configuration (CLI options → the rpc-* option group).
#[derive(Clone)]
pub struct RpcConfig {
    /// `--rpc-listen-port` (default 6800).
    pub port: u16,
    /// `--rpc-listen-all` (default false, matching the reference
    /// OptionHandlerFactory.cc A2_V_FALSE): the only input to the bind axis
    /// — true binds 0.0.0.0, false binds 127.0.0.1 only (usage_text.h "If
    /// false is given, listen only on local loopback interface"). Decoupled
    /// from credentials: secret/Basic only decide the auth gates and never
    /// widen the bind face.
    pub listen_all: bool,
    /// `--rpc-secret` (auth gate; never a bind decision — with no
    /// credentials at all there is only a startup warning).
    pub secret: Option<String>,
    /// `--rpc-user` (Basic auth; empty string = unset, per the reference
    /// HttpServer.cc reset semantics).
    pub rpc_user: Option<String>,
    /// `--rpc-passwd` (empty string = unset → the password is not checked, HttpServer.cc).
    pub rpc_passwd: Option<String>,
    /// `--rpc-allow-origin-all`: Access-Control-Allow-Origin: *.
    pub allow_origin_all: bool,
    /// `--rpc-max-request-size` (bytes; default 10 MiB).
    pub max_request_size: usize,
    /// `--rpc-aria2-compat` (the alias mode; default false, a
    /// session-level startup option). true = methods accept `aria2.*`
    /// aliases, the six events push as `aria2.onXxx`, and listMethods/
    /// listNotifications present the aria2 face; false = the single
    /// canonical `taiji.*` face (one API face at a time, never both).
    pub aria2_compat: bool,
    /// `--rpc-secure` (RPC over TLS switch; the reference
    /// OptionHandlerFactory.cc `PREF_RPC_SECURE` BooleanOption-
    /// Handler entry of the same name, default
    /// **false** = the plaintext HTTP/WS status quo, zero change). true =
    /// the listener switches to TLS: a [`TlsAcceptor`] wraps the TCP
    /// listener and handshake-accepted streams go to the hyper-util auto
    /// Builder (h1/h2 auto-selection + WS upgrade fidelity) — the bind
    /// axis / credential face / middleware stack are shared with the
    /// plaintext path (TLS is a transport-layer swap; it changes no
    /// auth/gate semantics). Pairing = [`Self::certificate`] +
    /// [`Self::private_key`] (either half missing is refused; see the
    /// [`serve_with_guards`] guards).
    pub secure: bool,
    /// `--rpc-certificate` (TLS server certificate, a PEM `CERTIFICATE`
    /// section; a certificate chain may span several). Consumed only when
    /// [`Self::secure`] = true; given one-sidedly (no secure or no key) =
    /// refuse to start (explicitness — silently ignoring security
    /// material violates this repo's fail-closed discipline).
    pub certificate: Option<PathBuf>,
    /// `--rpc-private-key` (TLS server private key, PEM; a PKCS#8/RSA/EC
    /// private key section, any of the three). Consumed in pair with
    /// [`Self::certificate`]. Nothing outside the key path ever enters
    /// logs.
    pub private_key: Option<PathBuf>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            port: 6800,
            listen_all: false,
            secret: None,
            rpc_user: None,
            rpc_passwd: None,
            allow_origin_all: false,
            max_request_size: 10 * 1024 * 1024,
            aria2_compat: false,
            secure: false,
            certificate: None,
            private_key: None,
        }
    }
}

/// Debug-rendering wrapper for a credential field: the value itself
/// never enters Debug — only the set/unset shape does (the auth.rs
/// invariant: secrets never appear in logs or Debug output).
struct CredentialPresence(bool);

impl std::fmt::Debug for CredentialPresence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0 { "<set>" } else { "<unset>" })
    }
}

impl std::fmt::Debug for RpcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written redacting Debug: `secret`/`rpc_user`/`rpc_passwd`
        // are plaintext credentials — only their presence is rendered
        // (same invariant as `BasicAuth`'s Debug in auth.rs). Every other
        // field renders verbatim (the certificate/key paths are not
        // credentials: the key material never enters this struct, only
        // the path does, and the path may enter logs by design).
        f.debug_struct("RpcConfig")
            .field("port", &self.port)
            .field("listen_all", &self.listen_all)
            .field("secret", &CredentialPresence(self.secret.is_some()))
            .field("rpc_user", &CredentialPresence(self.rpc_user.is_some()))
            .field("rpc_passwd", &CredentialPresence(self.rpc_passwd.is_some()))
            .field("allow_origin_all", &self.allow_origin_all)
            .field("max_request_size", &self.max_request_size)
            .field("aria2_compat", &self.aria2_compat)
            .field("secure", &self.secure)
            .field("certificate", &self.certificate)
            .field("private_key", &self.private_key)
            .finish()
    }
}

/// Handle to the running RPC server: listen address + task JoinHandle.
#[derive(Debug)]
pub struct ServerHandle {
    pub local_addr: SocketAddr,
    join: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    /// Waits for the server task to exit (graceful shutdown is driven by the `shutdown` token).
    pub async fn join(self) -> Result<(), tokio::task::JoinError> {
        self.join.await
    }
}

/// Weak-credential warning threshold: a set `--rpc-secret` shorter than
/// this logs one startup warn (startup is not refused; the secret itself
/// is never logged — only its length).
const WEAK_SECRET_MIN_LEN: usize = 16;

/// Single normalization point for rpc-secret: trim, then None if empty.
/// aria2 semantics are "empty string = unset" (the reference `option->get`
/// returns "" when undefined; HttpServer.cc resets user/passwd on empty
/// strings) — `--rpc-secret ""` and conf `rpc-secret=` are
/// misconfigurations that must not count as set credentials (they would
/// bypass the listen_all guard and make `validate(Some(""), …)` always
/// true). Trim also tightens "pure whitespace = unset" (shell quotes /
/// editor trailing whitespace are the only realistic sources). Consumed by
/// the CLI, the conf `rpc-secret` arm, and `serve_with_guards` —
/// idempotent.
pub fn normalize_secret(secret: Option<String>) -> Option<String> {
    secret
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Single RPC TLS assembly point (`--rpc-secure`): switch off = `Ok(None)`
/// (the plaintext path, zero behavior change); switch on = pairing
/// validation + PEM loading + [`rustls::ServerConfig`] construction,
/// producing a [`TlsAcceptor`].
///
/// Three fail-closed arms (all before bind — config errors flow through
/// the same stream and code as bind errors,
/// `io::ErrorKind::InvalidInput`, with fix guidance in the text):
/// 1. secure with the certificate/private key missing either half ->
/// refuse (a TLS server identity cannot hold with half of it missing);
/// 2. certificate/private key given while secure is off -> refuse
/// (silently ignoring security material violates explicitness — the
/// aria2 `--rpc-certificate` docs require `--rpc-secure` alongside;
/// here that is made a hard error, not a warning);
/// 3. PEM load/parse failure (missing section / bad base64 / key not
/// matching the certificate) -> refuse.
///
/// Protocol versions = `with_safe_default_protocol_versions` (TLS
/// 1.2+1.3; the workspace rustls "tls12" feature is enabled). Provider =
/// ring (one workspace TLS stack, the same stack as the taiji-io::tls
/// installer — this build point builds its own instance and does not
/// depend on process-level default install order). No client-certificate
/// verification face (one-way server authentication — the aria2 shape:
/// RPC client auth goes through token/Basic at the application layer;
/// mTLS client certificates are not on this face).
fn build_rpc_tls_acceptor(cfg: &RpcConfig) -> std::io::Result<Option<TlsAcceptor>> {
    if !cfg.secure {
        if cfg.certificate.is_some() || cfg.private_key.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--rpc-certificate/--rpc-private-key given without --rpc-secure=true: \
                 the TLS listener is off; add --rpc-secure or remove the certificate options",
            ));
        }
        return Ok(None);
    }
    let (Some(cert_path), Some(key_path)) = (&cfg.certificate, &cfg.private_key) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--rpc-secure requires both --rpc-certificate and --rpc-private-key (PEM): \
             a TLS server identity needs the certificate chain and its private key",
        ));
    };
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("rpc certificate {}: {e}", cert_path.display()),
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("rpc certificate {}: {e}", cert_path.display()),
            )
        })?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "rpc certificate {}: no PEM 'CERTIFICATE' section found",
                cert_path.display()
            ),
        ));
    }
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("rpc private key {}: {e}", key_path.display()),
        )
    })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("rpc tls identity: {e} (certificate and private key must match)"),
            )
        })?;
    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

/// TLS accept loop (the `--rpc-secure` branch; the plaintext path's
/// axum::serve is untouched): a per-connection [`TlsAcceptor`] handshake
/// -> a hyper-util auto Builder service loop (h1/h2 chosen by the
/// handshake; `serve_connection_with_upgrades` preserves the WS upgrade
/// face). ConnectInfo is injected via [`Service::call`] (the MakeService
/// shape of `into_make_service_with_connect_info` — the conn_gate/logging
/// peer face is unchanged). Shutdown semantics mirror the plaintext path:
/// the accept loop selects on the shutdown token and exits; in-flight
/// connections select on the same token, then `graceful_shutdown` drains
/// them (the same connection-task pattern as axum::serve's
/// `WithGracefulShutdown` — axum serve/mod.rs). A handshake
/// failure = a single-connection warn (peer probing / plaintext scanning
/// is routine noise; the loop is never broken).
async fn run_tls_accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router,
    shutdown: CancellationToken,
) {
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    loop {
        let (tcp, peer) = tokio::select! {
        // Clone, then await owned — the select arm consumes the clone,
        // leaving the original token for per-connection task re-clones
        // (cancelled_owned takes self by value).
                   _ = shutdown.clone().cancelled_owned() => break,
                   accepted = listener.accept() => match accepted {
                       Ok(pair) => pair,
                       Err(_) => break,
                   },
               };
        let acceptor = acceptor.clone();
        let shutdown = shutdown.clone();
        let mut make_service = make_service.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(tls) => tls,
                Err(e) => {
                    warn!(
                        target: "taiji::rpc::server",
                        %peer, error = %e,
                        "rpc tls handshake failed"
                    );
                    return;
                }
            };
            // IntoMakeServiceWithConnectInfo::call is always Ok (an
            // Infallible error type) — the empty match makes that type
            // fact explicit; it does not swallow errors. The tower Service
            // -> hyper Service adaptation is the same as axum::serve's
            // (serve/mod.rs TowerToHyperService — the axum face is a
            // tower Service; the hyper-util auto Builder face, a
            // hyper::service::Service).
            let tower_svc = match Service::call(&mut make_service, peer).await {
                Ok(svc) => svc,
                Err(e) => match e {},
            };
            let svc = TowerToHyperService::new(tower_svc);
            // Bind the builder to a local — the connection returned by
            // `serve_connection_with_upgrades(&self)` borrows the builder,
            // and borrowing a dropped temporary is an error (E0716).
            let builder = HyperAutoBuilder::new(TokioExecutor::new());
            let mut conn =
                std::pin::pin!(builder.serve_connection_with_upgrades(TokioIo::new(tls), svc));
            tokio::select! {
                _ = conn.as_mut() => {}
                _ = shutdown.cancelled() => {
                    conn.as_mut().graceful_shutdown();
                    let _ = conn.as_mut().await;
                }
            }
        });
    }
}

/// Binds and starts the RPC server (production entry; guard limits stay at
/// the 256/32/5 engine constants — no CLI knobs).
pub async fn serve(
    cfg: RpcConfig,
    session: Arc<SessionHandle>,
    shutdown: CancellationToken,
) -> std::io::Result<ServerHandle> {
    serve_with_guards(cfg, session, shutdown, RpcGuards::default()).await
}

/// [`serve`] with injectable guard parameters (connection caps / backoff
/// threshold) for e2e tests (pub(crate)).
///
/// The bind face and the credential face are two decoupled axes, matching
/// the aria2 orthogonal design — binding only looks at `--rpc-listen-all`
/// (HttpListenCommand.cc adds AI_PASSIVE only when listen-all is set);
/// credentials only decide the auth gates: `listen_all = false` (default)
/// → 127.0.0.1; true → 0.0.0.0. No credentials (neither secret nor Basic)
/// → one startup warning (text per the reference "Neither --rpc-secret nor
/// a combination of --rpc-user and --rpc-passwd is set",
/// DownloadEngineFactory.cc); the warning never changes binding.
/// Controlled difference (fail-closed): `listen_all` with no usable
/// credentials refuses to start (io::Error with fix guidance) — aria2 only
/// WARNs and listens anyway.
///
/// The `shutdown` token drives four paths: axum graceful shutdown, the WS
/// session loop, and the Basic/token unauthorized delay (halt abandons the
/// response, HttpServerBodyCommand.cc).
///
/// Basic credentials become a process-random HMAC tag at construction
/// (HttpServerCommand.cc → HttpServer.cc setUsernamePassword); the
/// plaintext user/passwd are dropped with `cfg` and never enter
/// [`AppState`].
pub(crate) async fn serve_with_guards(
    cfg: RpcConfig,
    session: Arc<SessionHandle>,
    shutdown: CancellationToken,
    guards: RpcGuards,
) -> std::io::Result<ServerHandle> {
    // RPC over TLS assembly (`--rpc-secure`): pairing validation + PEM
    // loading comes first of all (before any partial move of the cfg
    // fields and before the credential guards — the config error face
    // surfaces first; completed before bind, leaving no half-started
    // "port listening but TLS failed to come up" shape). None = the
    // plaintext path (the default, zero behavior change).
    let tls_acceptor = build_rpc_tls_acceptor(&cfg)?;
    let basic = crate::auth::BasicAuth::new(cfg.rpc_user.as_deref(), cfg.rpc_passwd.as_deref());
    // Normalize again defensively: the CLI/conf intakes already normalize,
    // but no bypass constructing RpcConfig may smuggle Some("") into
    // AppState (validate(Some(""), …) is always true and the write gate
    // would treat it as set).
    let secret = normalize_secret(cfg.secret);
    // Combined guard (fail-closed): listen_all without *usable*
    // credentials refuses to start. Usable = non-empty normalized secret,
    // or Basic with a password — user-only Basic leaves the password slot
    // None unchecked (HttpServer.cc `!password_ ||`), so knowing the user
    // name alone passes the Basic gate and is not a usable credential.
    // 0.0.0.0 + zero auth is a network-wide anonymous exposure; the error
    // text gives both fix paths. Controlled difference: aria2 only WARNs
    // for this combination (DownloadEngineFactory.cc) and listens anyway.
    let basic_has_password = basic
        .as_ref()
        .is_some_and(crate::auth::BasicAuth::password_is_set);
    if cfg.listen_all && secret.is_none() && !basic_has_password {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--rpc-listen-all without usable credentials is refused (fail-closed): \
             blank or whitespace --rpc-secret counts as unset, and --rpc-user \
             without --rpc-passwd leaves the password unchecked; set --rpc-secret \
             (recommended) or --rpc-user with --rpc-passwd, or drop --rpc-listen-all \
             to bind loopback only",
        ));
    }
    // Weak-credential startup warning: warn only, no refusal.
    if let Some(secret) = secret.as_deref()
        && secret.len() < WEAK_SECRET_MIN_LEN
    {
        warn!(
            target: "taiji::rpc::server",
            len = secret.len(),
            "--rpc-secret is shorter than {WEAK_SECRET_MIN_LEN} characters; prefer 16+ \
             for brute-force resistance"
        );
    }
    // Bind axis only looks at listen_all (credentials never participate).
    let host = if cfg.listen_all {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    };
    // RPC over TLS assembly (`--rpc-secure`): pairing validation + PEM
    // loading precedes bind — the config error face flows through the
    // same stream as bind errors (io::Error -> the caller exits 1),
    // leaving no half-started "port listening but TLS failed to come up"
    // shape. None = the plaintext path (the default, zero behavior
    // change). (The assembly point sits at the very top of the function —
    // before the cfg.secret partial move.)
    let listener = TcpListener::bind((host, cfg.port)).await?;
    let local_addr = listener.local_addr()?;
    if secret.is_none() && basic.is_none() {
        // Token enforcement presumes a secret; with no
        // credentials at all there is only this warning
        // (DownloadEngineFactory.cc WARN text) — it never changes binding
        // (a listen_all shape would already have been refused above, so
        // the bind is loopback). Secret/user/passwd values are never
        // logged.
        tracing::warn!(
            target: "taiji::rpc::server",
            addr = %local_addr,
            "neither --rpc-secret nor --rpc-user/--rpc-passwd set: binding \
             loopback only; set --rpc-secret (or --rpc-user and --rpc-passwd) \
             to require auth"
        );
    }
    let state = Arc::new(AppState {
        session,
        // AppState only ever sees the normalized secret — blank/
        // whitespace is uniformly "unset" across the guard, warning, and
        // token/write-gate consumers.
        secret,
        basic,
        allow_origin_all: cfg.allow_origin_all,
        max_request_size: cfg.max_request_size,
        shutdown: shutdown.clone(),
        aria2_compat: cfg.aria2_compat,
        listen_all: cfg.listen_all,
        conn: Arc::new(ConnLedger::new(
            guards.max_total_conns,
            guards.max_per_ip_conns,
        )),
        auth_backoff: Arc::new(AuthBackoff::new(guards.auth_fail_threshold)),
    });
    let app = Router::new()
        .route(
            "/jsonrpc",
            post(http_jsonrpc).get(ws_upgrade).options(preflight),
        )
        // Prometheus text /metrics on the same port and bind
        // face as /jsonrpc (the bind axis only looks at --rpc-listen-all).
        // Hardening: /metrics sits behind the same Basic gate as /jsonrpc
        // ([`basic_gate`]); with listen_all + secret (Basic unset or
        // user-only → zero-entropy or always-true Basic gate) it switches
        // to the Bearer<secret> gate ([`bearer_gate`]) so the metrics face
        // is never anonymous on 0.0.0.0.
        .route("/metrics", get(metrics_gate))
        .layer(middleware::from_fn_with_state(state.clone(), cors))
        // Connection gate outermost: the concurrency lease is decided
        // before CORS/auth, so floods are 503-rejected before any
        // downstream work.
        .layer(middleware::from_fn_with_state(state.clone(), conn_gate))
        .with_state(state);
    let join = match tls_acceptor {
        // `--rpc-secure`: the TLS accept loop (handshake -> the hyper-util
        // service loop; shutdown semantics in [`run_tls_accept_loop`]).
        Some(acceptor) => {
            info!(target: "taiji::rpc::server", %local_addr, "rpc server up (tls)");
            tokio::spawn(run_tls_accept_loop(listener, acceptor, app, shutdown))
        }
        // Plaintext path (the default): axum::serve as-is — the
        // zero-behavior-change anchor.
        None => {
            info!(target: "taiji::rpc::server", %local_addr, "rpc server up");
            tokio::spawn(async move {
                let _ = axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await;
            })
        }
    };
    Ok(ServerHandle { local_addr, join })
}

/// CORS: with allow-origin-all, adds `Access-Control-Allow-Origin: *` to every response.
async fn cors(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    if state.allow_origin_all {
        resp.headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    }
    resp
}

/// Connection-cap rejection: HTTP 503 + the
/// `taiji_rpc_conn_rejected_total{scope}` metric + warn. HTTP requests and
/// WS upgrades share the rejection face (WS is rejected before the 101 is
/// sent).
fn conn_rejected(state: &AppState, ip: IpAddr, scope: ConnScope) -> Response {
    match scope {
        ConnScope::Total => state.session.metrics().note_rpc_conn_rejected_total(),
        ConnScope::PerIp => state.session.metrics().note_rpc_conn_rejected_per_ip(),
    }
    let scope = match scope {
        ConnScope::Total => "total",
        ConnScope::PerIp => "per_ip",
    };
    warn!(
        target: "taiji::rpc::server",
        %ip, scope,
        "rpc connection rejected at concurrency cap"
    );
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

/// Connection gate: every incoming HTTP request (including WS upgrade
/// handshakes) first takes a concurrency lease — total and per-IP
/// concurrency are checked against the [`ConnLedger`] caps, over the cap
/// is a 503. Lifecycle accounting:
/// - plain HTTP: the middleware releases after the response;
/// - WS: `ws_upgrade` transfers the handshake lease into a session lease
/// via [`ConnLeaseSlot`] (one accounting entry held continuously),
/// released when `ws_loop` exits;
/// - middleware fallback: a lease the handler did not take is dropped from
/// the slot after the response — RAII keeps the pairing.
///
/// Zero impact for localhost without credentials: the 256/32 caps are far
/// above single-client local use, but the gate is always semantically on.
async fn conn_gate(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let Some(ip) = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
    else {
        // No peer address (no connect-info — embedded/test router): the
        // gate is inert and always passes.
        return next.run(req).await;
    };
    let lease = match state.conn.acquire(ip) {
        Ok(lease) => lease,
        Err(scope) => return conn_rejected(&state, ip, scope),
    };
    let slot = Arc::new(std::sync::Mutex::new(Some(lease)));
    let mut req = req;
    req.extensions_mut()
        .insert(ConnLeaseSlot(Arc::clone(&slot)));
    let resp = next.run(req).await;
    // Response produced (HTTP done / WS 101 sent): release any lease not
    // taken by ws_upgrade; session leases are released when the session
    // exits.
    drop(crate::lock(&slot).take());
    resp
}

/// OPTIONS preflight (mirrors HttpServerBodyCommand.cc).
async fn preflight(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let mut resp = StatusCode::OK.into_response();
    let has_origin = headers.contains_key(ORIGIN);
    let has_acrm = headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD);
    if state.allow_origin_all && has_origin && has_acrm {
        let h = resp.headers_mut();
        h.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST, GET, OPTIONS"),
        );
        h.insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("1728000"));
        // Echo the requested headers (reference: "We allow all headers requested").
        if let Some(req_headers) = headers.get(ACCESS_CONTROL_REQUEST_HEADERS)
            && let Ok(v) = req_headers.to_str()
            && let Ok(val) = HeaderValue::from_str(v)
        {
            h.insert(HeaderName::from_static("access-control-allow-headers"), val);
        }
    }
    resp
}

/// Explicit over-limit error: HTTP 413 + `taiji.request.too_large`. The
/// reference just drops the connection (HttpServerCommand.cc); here the
/// error is explicit, with the string code registered in error.rs.
fn too_large_response() -> Response {
    let err = crate::error::RpcError {
        code: crate::error::CODE_GENERIC,
        message: format!("{STR_REQUEST_TOO_LARGE}: see --rpc-max-request-size"),
        unauthorized: false,
    };
    let resp = crate::jsonrpc::RpcResponse::error(&err, serde_json::Value::Null).encode();
    let status = StatusCode::PAYLOAD_TOO_LARGE;
    (status, [(CONTENT_TYPE, "application/json-rpc")], Json(resp)).into_response()
}

fn json_rpc_response(outcome: &crate::dispatch::RpcOutcome) -> Response {
    let status = http_status(outcome.code);
    (
        status,
        [(CONTENT_TYPE, "application/json-rpc")],
        Json(outcome.body.clone()),
    )
        .into_response()
}

/// Basic unauthorized response (HttpServerCommand.cc): 401 +
/// `WWW-Authenticate: Basic realm="aria2"` + Connection: close
/// (disableKeepAlive), empty body (reference feedResponse sends no text).
fn basic_unauthorized() -> Response {
    let mut resp = StatusCode::UNAUTHORIZED.into_response();
    let h = resp.headers_mut();
    h.insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"aria2\""),
    );
    h.insert(CONNECTION, HeaderValue::from_static("close"));
    resp
}

/// Basic auth gate (HttpServerCommand.cc): checked at the header layer;
/// unauthorized → 1s delay, then 401 (the "unauthorized delay 1s"
/// behavior; a
/// shutdown request abandons the response). None = allow. `ip` is the
/// transport peer (the auth-backoff ledger key; None = no peer — backoff
/// does not bookkeep but the credential decision still runs).
async fn basic_gate(state: &AppState, ip: Option<IpAddr>, headers: &HeaderMap) -> Option<Response> {
    if state.basic.is_some() {
        // Auth attempt face: wait first while a window is armed (even valid
        // credentials — the backoff penalizes by source).
        state.auth_backoff.wait(ip).await;
    }
    let header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    if crate::auth::basic_authorized(state.basic.as_ref(), header) {
        if state.basic.is_some() {
            // A real credential check passing clears the count (an always-true
            // unconfigured gate does not).
            state.auth_backoff.note_success(ip);
        }
        return None;
    }
    // Auth failure: count it and arm the exponential backoff (merged with
    // the token gate into one per-IP ledger). Credentials are never logged.
    state.session.metrics().note_rpc_auth_fail();
    if let Some(window) = state.auth_backoff.note_failure(ip) {
        warn!(
            target: "taiji::rpc::server",
            ?ip,
            window_secs = window.as_secs(),
            "auth failure backoff window armed"
        );
    }
    if !unauthorized_delay(state).await {
        return Some(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    Some(basic_unauthorized())
}

/// Unauthorized-response delay (DelayedCommand 1_s, HttpServerBodyCommand.cc).
/// Returns false = shutdown arrived, abandon the response (halt branch).
/// Both HTTP and WS paths consume it (otherwise a single WS connection
/// could guess tokens thousands of times per second).
async fn unauthorized_delay(state: &AppState) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(UNAUTHORIZED_DELAY) => true,
        _ = state.shutdown.cancelled() => false,
    }
}

/// Gated-form predicate: listen_all + a set secret + Basic unset **or
/// user-only** (no --rpc-passwd → the password slot is None and never
/// checked, [`crate::auth::BasicAuth::password_is_set`] — knowing the user
/// name alone passes the Basic gate, so it is not a usable credential). In
/// this form the secret is the only usable credential, and it directly
/// guards the two anonymous faces: /metrics (Bearer) and the WS event
/// stream (first-message token); the Basic transport gate still covers
/// upgrades and /jsonrpc. Other forms keep the current behavior: without a
/// secret, listen_all was already refused (bind is loopback); with
/// password Basic, the transport gate is already a real credential gate.
fn listen_all_secret_only(state: &AppState) -> bool {
    state.listen_all
        && state.secret.is_some()
        && state.basic.as_ref().is_none_or(|b| !b.password_is_set())
}

/// Bearer<secret> unauthorized response: 401 + Bearer challenge +
/// Connection: close (same shape as [`basic_unauthorized`], scheme
/// swapped).
fn bearer_unauthorized() -> Response {
    let mut resp = StatusCode::UNAUTHORIZED.into_response();
    let h = resp.headers_mut();
    h.insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"taiji\""),
    );
    h.insert(CONNECTION, HeaderValue::from_static("close"));
    resp
}

/// Bearer<secret> gate: closes the /metrics anonymous face in the
/// listen_all + secret-only form — requires `Authorization: Bearer
/// <secret>`, validated via [`crate::auth::validate`] (fixed-length
/// digests both sides + constant-time comparison; plaintext `==` leaks
/// prefix-match progress). Failure path mirrors [`basic_gate`]: merged
/// backoff ledger, `taiji_rpc_auth_fail_total`, 1s delay then 401
/// (shutdown abandons the response).
async fn bearer_gate(
    state: &AppState,
    ip: Option<IpAddr>,
    headers: &HeaderMap,
) -> Option<Response> {
    state.auth_backoff.wait(ip).await;
    let header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());
    // Scheme is case-sensitive (HTTP registry convention; matches the Basic
    // gate's streq semantics).
    let token = header.and_then(|h| h.strip_prefix("Bearer "));
    if crate::auth::validate(state.secret(), token) {
        state.auth_backoff.note_success(ip);
        return None;
    }
    // Auth failure: count it and arm the backoff (credentials never logged).
    state.session.metrics().note_rpc_auth_fail();
    if let Some(window) = state.auth_backoff.note_failure(ip) {
        warn!(
            target: "taiji::rpc::server",
            ?ip,
            window_secs = window.as_secs(),
            "auth failure backoff window armed"
        );
    }
    if !unauthorized_delay(state).await {
        return Some(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    Some(bearer_unauthorized())
}

/// `/metrics` gate: in the gated form ([`listen_all_secret_only`] —
/// listen_all + secret, Basic unset or user-only) the only gate is
/// Bearer<secret> (the 0.0.0.0 bind must not expose exact versions, task
/// counts, and method usage without credentials); other forms share the
/// /jsonrpc Basic gate. The gates never stack: both consume the same
/// Authorization header, so running Basic first would 401 valid Bearer
/// requests on scheme, and user-only Basic adds no entropy — stacking
/// only adds rejections. On pass, [`crate::metrics::metrics_handler`]
/// renders.
async fn metrics_gate(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if listen_all_secret_only(&state) {
        if let Some(resp) = bearer_gate(&state, Some(addr.ip()), &headers).await {
            return resp;
        }
    } else if let Some(resp) = basic_gate(&state, Some(addr.ip()), &headers).await {
        return resp;
    }
    crate::metrics::metrics_handler(State(state)).await
}

/// `POST /jsonrpc`: body → JSON → single/batch dispatch → response (with status mapping and delay).
async fn http_jsonrpc(State(state): State<Arc<AppState>>, req: Request) -> Response {
    // Peer address (ConnectInfo injected by the connection gate; None = no peer).
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    // Basic auth runs at the header layer, before the body is read (the
    // reference authenticates once headers are complete,
    // HttpServerCommand.cc — so 401 precedes the 413 over-limit face).
    if let Some(resp) = basic_gate(&state, ip, req.headers()).await {
        return resp;
    }
    // Content-Length precheck (the reference rejects before reading the
    // body, HttpServerCommand.cc).
    let declared = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    if let Some(len) = declared
        && len > state.max_request_size
    {
        return too_large_response();
    }
    let bytes = match axum::body::to_bytes(req.into_body(), state.max_request_size + 1).await {
        Ok(b) => b,
        Err(_) => {
            // Chunked over-limit without Content-Length: same explicit error face.
            return too_large_response();
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            // Parse failure → -32700 (HTTP 500, mirroring the
            // HttpServerBodyCommand.cc default branch; see error.rs
            // http_status).
            let resp = parse_error_response();
            let outcome = crate::dispatch::RpcOutcome {
                code: resp.code,
                unauthorized: false,
                body: resp.encode(),
            };
            return json_rpc_response(&outcome);
        }
    };
    let outcome = handle_payload(&state, &value, ip).await;
    if outcome.unauthorized {
        // DelayedCommand 1_s (HttpServerBodyCommand.cc); on shutdown the
        // response is abandoned (halt branch).
        if !unauthorized_delay(&state).await {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    json_rpc_response(&outcome)
}

/// WS upgrade Origin gate (hardening: WS is cross-origin by nature and a
/// browser can drive RPC over a cross-site WS straight at the loopback
/// service). Allowed only when:
/// - there is no Origin header (curl/aria2 CLI and other non-browser
/// clients); or
/// - the Origin authority matches the Host header (host:port, ASCII
/// case-insensitive); or
/// - `--rpc-allow-origin-all` explicitly allows all (the user's explicit
/// opt-in, consistent with CORS).
///
/// `Origin: null` (sandboxed context) has no matchable Host → reject.
fn ws_origin_allowed(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // Non-browser client: no cross-origin driver face.
    };
    if state.allow_origin_all {
        return true;
    }
    let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    origin_authority(origin).is_some_and(|auth| auth.eq_ignore_ascii_case(host))
}

/// The authority segment of an Origin URL (`scheme://host[:port]/path` →
/// `host[:port]`; browsers never put userinfo in Origin, so no special
/// branch).
fn origin_authority(origin: &str) -> Option<&str> {
    let rest = origin.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    (!authority.is_empty()).then_some(authority)
}

/// `GET /jsonrpc`: WebSocket upgrade. Upgrades pass the same
/// Basic gate (the reference authenticates before the WS branch,
/// HttpServerCommand.cc) and the Origin same-origin gate. Upgrading
/// subscribes to the six-event bus immediately (subscription starts before
/// request processing, so no events are lost in the upgrade window) —
/// except in the listen_all + secret with Basic unset or user-only form,
/// where subscription waits for the first valid-token message (see
/// [`ws_loop`]; the Basic upgrade gate is zero-entropy or always-true
/// there, and event frames profile download behavior).
///
/// Connection lease: the gate middleware took a lease for the handshake
/// and passed it via [`ConnLeaseSlot`] — taken here once the gates pass,
/// transferred into the `on_upgrade` closure as the session lease
/// (released when `ws_loop` exits); the middleware fallback finds it
/// already taken. Without the middleware (test routers) a fresh lease is
/// acquired; over the cap the upgrade is 503-rejected as usual.
async fn ws_upgrade(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    lease_slot: Option<Extension<ConnLeaseSlot>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !ws_origin_allowed(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(resp) = basic_gate(&state, Some(addr.ip()), &headers).await {
        return resp;
    }
    let ip = addr.ip();
    let lease = lease_slot
        .and_then(|Extension(slot)| crate::lock(&slot.0).take())
        .map(Ok)
        .unwrap_or_else(|| state.conn.acquire(ip));
    match lease {
        Ok(lease) => ws
            // Protocol-level message cap aligned with the HTTP face
            // (`max_request_size + 1`, matching http_jsonrpc's
            // `to_bytes(.., max_request_size + 1)`; a message of exactly
            // the cap is still delivered — tungstenite is strictly
            // greater-than). Oversized messages fail at the protocol layer
            // with Capacity → ws_loop sees Err and disconnects. Without
            // this, tungstenite buffers a whole message (including
            // fragmented reassembly) up to 64MiB before delivering, and
            // ws_loop's app-layer length check runs only after buffering —
            // a 64MiB per-connection transient amplification within the
            // connection cap (an unauthenticated OOM face; the same attack
            // over HTTP is stopped by the to_bytes limit). The app-layer
            // text.len check in ws_loop stays as defense in depth.
            .max_message_size(state.max_request_size.saturating_add(1))
            // Frame cap set to the same value: max_message_size only
            // bounds the reassembled message, while single frames would
            // otherwise still hit tungstenite's default 16MiB frame cap —
            // with --rpc-max-request-size > 16MiB a legal single-frame
            // message would be silently Capacity-disconnected at the
            // protocol layer while HTTP answers the same size (an
            // inter-face asymmetry). Single-frame messages satisfy both
            // caps; fragmented messages are bounded by the message cap.
            .max_frame_size(state.max_request_size.saturating_add(1))
            .on_upgrade(move |socket| {
                // The session lease lives in the async block (the closure
                // frame is dropped once the future is returned — a lease in
                // the closure frame would be released before the upgrade
                // completes): disconnect/shutdown/lag → ws_loop returns →
                // drop (same single lease, no double count).
                async move {
                    let _lease = lease;
                    ws_loop(socket, state, ip).await;
                }
            }),
        Err(scope) => conn_rejected(&state, ip, scope),
    }
}

/// Event → WS text-frame payload. Envelope mirrors WebSocketSessionMan.cc
/// field by field: `{jsonrpc:"2.0", method, params:[{gid}]}`. Event names
/// have two faces — canonical `taiji.onXxx`
/// (`EventKind::notification_method`, the core source) / compat
/// `aria2.onXxx` (`aria2_notification_method`, frozen names) — selected by
/// `--rpc-aria2-compat` (one face at a time; the dispatch tables have
/// consistency tests). gid = hex16 (GroupId::toHex). No id field: a
/// JSON-RPC notification, not a response.
fn notification_frame(aria2_compat: bool, ev: &SessionEvent) -> String {
    let method = if aria2_compat {
        ev.kind.aria2_notification_method()
    } else {
        ev.kind.notification_method()
    };
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": [{ "gid": ev.gid.to_string() }],
    })
    .to_string()
}

/// recovery extension event → WS text-frame payload. Same envelope as the
/// six events (`{jsonrpc,method,params:[{gid,...}]}`, per
/// WebSocketSessionMan.cc); the method name lives in the `taiji.*`
/// extension namespace (the aria2 six and the frozen listNotifications
/// table are untouched). params[0] schema: `gid` (hex16) + `files`
/// (1-based client file order, numbers as strings); completed adds
/// `status` (currently "ready" — no failure terminal state exists, no
/// third event is sent, and the status key leaves room for one).
fn recovery_notification_frame(ev: &RecoveryEvent) -> String {
    let mut params = serde_json::Map::new();
    params.insert("gid".into(), json!(ev.gid.to_string()));
    params.insert(
        "files".into(),
        Value::Array(ev.files.iter().map(|f| json!(f.to_string())).collect()),
    );
    if ev.kind == RecoveryEventKind::Completed {
        params.insert("status".into(), json!("ready"));
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": ev.kind.notification_method(),
        "params": [params],
    })
    .to_string()
}

/// Media extension event → WS text-frame payload (the extension bypass):
/// same envelope as the six events; the method name is always
/// `taiji.media.phaseChanged` (no compat face, never in
/// listNotifications). params[0] schema: `gid` (hex16) + `phase`
/// (the media ten-state domain string) + optional `phaseDetail` (the
/// pause phase memory) + optional `warning: {code, message}` (the
/// alarm face — sidecar degradations, both-channels
/// failures, `template_unsafe`: an alarm rides the same bypass, the
/// payload's `warning` key distinguishing it from a pure transition).
fn media_notification_frame(ev: &MediaEvent) -> String {
    let mut params = serde_json::Map::new();
    params.insert("gid".into(), json!(ev.gid.to_string()));
    params.insert("phase".into(), json!(ev.phase.as_str()));
    if let Some(detail) = &ev.phase_detail {
        params.insert("phaseDetail".into(), json!(detail));
    }
    if let Some(w) = &ev.warning {
        params.insert(
            "warning".into(),
            json!({ "code": w.code, "message": w.message }),
        );
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": MEDIA_PHASE_EVENT_METHOD,
        "params": [params],
    })
    .to_string()
}

/// Task-cookie alert → WS text-frame payload (the extension bypass
/// shape): same envelope as the six events; the method
/// name is always `taiji.task.cookiesClearedOnError` (no compat face,
/// never in listNotifications). params[0] schema: `gid` (hex16) +
/// `taskKind` (`http`|`media`) + `count` (rows cleared, a number) —
/// **never a cookie value/name/domain** (the redact discipline).
fn task_cookie_notification_frame(ev: &TaskCookieEvent) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": TASK_COOKIE_EVENT_METHOD,
        "params": [{
            "gid": ev.gid.to_string(),
            "taskKind": ev.task_kind,
            "count": ev.count,
        }],
    })
    .to_string()
}

/// WS session loop: text frames → JSON-RPC handling → reply; event-bus
/// subscription → notification frames; shutdown token cancels and
/// disconnects.
///
/// Event-stream gate: in the listen_all + secret with Basic unset or
/// user-only form (the upgrade Basic gate is always-true or zero-entropy),
/// bus subscription waits for the **first Text message carrying a valid
/// token** — an anonymous upgrade must not receive any event frame
/// (onDownloadStart/Error… profile download behavior). An invalid or
/// tokenless first message disconnects (same failure face as the token
/// gate: 1s unauthorized delay + backoff, so reconnecting cannot bypass
/// the delay to guess tokens). Other forms subscribe at upgrade time
/// (subscription starts before request processing, so no events are lost
/// in the upgrade window).
///
/// Backpressure: the bus is bounded at 256 and senders (engine/actor)
/// never block; a subscriber that falls behind gets `Lagged(n)` — count,
/// warn, then disconnect this WS session (the reference has no such
/// problem: aria2 pushes unbounded, WebSocketSessionMan.cc has no
/// backlog).
async fn ws_loop(mut ws: WebSocket, state: Arc<AppState>, ip: IpAddr) {
    info!(target: "taiji::rpc::server", "ws session up");
    let mut first_text: Option<String> = None;
    if listen_all_secret_only(&state) {
        // Gated form: pass the first-message token gate before
        // subscribing (the unauthenticated connection has no bus receiver).
        match ws_first_message_gate(&mut ws, &state, ip).await {
            Some(text) => first_text = Some(text),
            None => {
                info!(target: "taiji::rpc::server", "ws session down");
                return;
            }
        }
    }
    let mut event_rx = state.session.subscribe_events();
    // recovery event bus subscription: same discipline as the six events —
    // at upgrade, or after the first valid token in the gated form.
    let mut recovery_rx = state.session.subscribe_recovery_events();
    // media extension event bus (the extension bypass) — the same
    // subscription discipline.
    let mut media_rx = state.session.subscribe_media_events();
    // task-cookie alert bus (the same bypass
    // discipline).
    let mut cookie_rx = state.session.subscribe_task_cookie_events();
    loop {
        // The gate-authorized first message goes back through the regular
        // handling path (over-limit/parse-failure faces and the
        // unauthorized delay all use the same exit as later messages).
        if let Some(text) = first_text.take() {
            if !ws_handle_text(&mut ws, &state, ip, &text).await {
                break;
            }
            continue;
        }
        tokio::select! {
                   biased;
                   _ = state.shutdown.cancelled() => {
                       let _ = ws.send(Message::Close(None)).await;
                       break;
                   }
                   ev = event_rx.recv() => match ev {
                       Ok(ev) => {
                           let frame = notification_frame(state.aria2_compat, &ev);
                           if ws.send(Message::Text(frame.into())).await.is_err() {
                               break;
                           }
                       }
                       Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
        // Lagged(n) = n notifications overwritten (the bounded
        // bus's explicit cost).
                           warn!(
                               target: "taiji::rpc::server",
                               lagged = n,
                               "ws subscriber lagged beyond the event bus capacity; \
                                disconnecting (bounded broadcast backpressure, PLAN C.4b)"
                           );
                           let _ = ws.send(Message::Close(None)).await;
                           break;
                       }
                       Err(tokio::sync::broadcast::error::RecvError::Closed) => {
        // All bus senders dropped = the SessionActor exited;
        // the shutdown arm closes the stop path.
                           break;
                       }
                   },
        // Extension event arm — the same lag/disconnect policy as the
        // six-event arm (slow subscribers are not exempt).
                   ev = recovery_rx.recv() => match ev {
                       Ok(ev) => {
                           let frame = recovery_notification_frame(&ev);
                           if ws.send(Message::Text(frame.into())).await.is_err() {
                               break;
                           }
                       }
                       Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                           warn!(
                               target: "taiji::rpc::server",
                               lagged = n,
                               "ws subscriber lagged beyond the recovery event bus capacity; \
                                disconnecting (bounded broadcast backpressure)"
                           );
                           let _ = ws.send(Message::Close(None)).await;
                           break;
                       }
                       Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                   },
        // Media extension event arm (the phaseChanged bypass) — the
        // same lag/disconnect policy.
                   ev = media_rx.recv() => match ev {
                       Ok(ev) => {
                           let frame = media_notification_frame(&ev);
                           if ws.send(Message::Text(frame.into())).await.is_err() {
                               break;
                           }
                       }
                       Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                           warn!(
                               target: "taiji::rpc::server",
                               lagged = n,
                               "ws subscriber lagged beyond the media event bus capacity; \
                                disconnecting (bounded broadcast backpressure)"
                           );
                           let _ = ws.send(Message::Close(None)).await;
                           break;
                       }
                       Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                   },
        // Task-cookie alert arm (the cookiesClearedOnError bypass) —
        // the same lag/disconnect policy.
                   ev = cookie_rx.recv() => match ev {
                       Ok(ev) => {
                           let frame = task_cookie_notification_frame(&ev);
                           if ws.send(Message::Text(frame.into())).await.is_err() {
                               break;
                           }
                       }
                       Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                           warn!(
                               target: "taiji::rpc::server",
                               lagged = n,
                               "ws subscriber lagged beyond the task-cookie event bus capacity;                                 disconnecting (bounded broadcast backpressure)"
                           );
                           let _ = ws.send(Message::Close(None)).await;
                           break;
                       }
                       Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                   },
                   msg = ws.recv() => match msg {
                       None | Some(Ok(Message::Close(_))) => break,
                       Some(Err(_)) => break,
                       Some(Ok(Message::Text(text))) => {
                           if !ws_handle_text(&mut ws, &state, ip, &text).await {
                               break;
                           }
                       }
                       Some(Ok(Message::Ping(p))) => {
                           if ws.send(Message::Pong(p)).await.is_err() {
                               break;
                           }
                       }
                       Some(Ok(_)) => {} // binary/pong: the aria2 WS face consumes text frames only.
                   },
               }
    }
    info!(target: "taiji::rpc::server", "ws session down");
}

/// WS text-message handling (shared exit for the gate's first message and
/// regular messages): over-limit/parse failure → -32700; a valid payload
/// is dispatched and answered. Returns false = session over (shutdown
/// interrupted the delay or the reply failed) — the caller breaks.
async fn ws_handle_text(ws: &mut WebSocket, state: &AppState, ip: IpAddr, text: &str) -> bool {
    // Over-limit: drop the bytes → parse failure → -32700 (mirrors
    // WebSocketSession.cc's drop-bytes behavior). Defense-in-depth second
    // layer: the protocol layer already rejects most oversized messages at
    // upgrade (`max_request_size + 1`, Capacity → disconnect); this
    // app-layer check catches configuration drift and exactly-over
    // boundary messages.
    let reply = if text.len() > state.max_request_size {
        parse_error_response().encode()
    } else {
        match serde_json::from_str::<serde_json::Value>(text) {
            Err(_) => parse_error_response().encode(),
            Ok(v) => {
                let outcome = handle_payload(state, &v, Some(ip)).await;
                // Hardening: the unauthorized delay is consumed like the
                // HTTP path — WS previously dropped the unauthorized flag,
                // letting one connection bypass the DelayedCommand 1s and
                // guess tokens fast. On shutdown, disconnect (halt
                // abandons the response).
                if outcome.unauthorized && !unauthorized_delay(state).await {
                    let _ = ws.send(Message::Close(None)).await;
                    return false;
                }
                outcome.body
            }
        }
    };
    ws.send(Message::Text(reply.to_string().into()))
        .await
        .is_ok()
}

/// First-message auth gate: the precondition for bus subscription in the
/// gated form ([`listen_all_secret_only`]) — the first **Text** message
/// must carry a valid token (`strip_token` + `validate`, constant-time;
/// same semantics as the RPC token first parameter). Returns `Some(text)`
/// = pass (the text goes back through regular handling); `None` =
/// disconnect (invalid/tokenless first message, connection error, or
/// shutdown). Non-Text frames are not auth carriers (Ping → Pong as
/// usual; binary is dropped while waiting).
async fn ws_first_message_gate(ws: &mut WebSocket, state: &AppState, ip: IpAddr) -> Option<String> {
    loop {
        tokio::select! {
                   biased;
                   _ = state.shutdown.cancelled() => {
                       let _ = ws.send(Message::Close(None)).await;
                       return None;
                   }
                   msg = ws.recv() => match msg {
                       None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return None,
                       Some(Ok(Message::Ping(p))) => {
                           if ws.send(Message::Pong(p)).await.is_err() {
                               return None;
                           }
                       }
                       Some(Ok(Message::Text(text))) => {
                           if !ws_first_token_valid(state, ip, &text).await {
        // Same failure face as the token gate: 1s delay +
        // disconnect with no JSON-RPC reply (a bare
        // disconnect would skip the delay and allow fast
        // token guessing across reconnects); shutdown
        // abandons.
                               if !unauthorized_delay(state).await {
                                   return None;
                               }
                               let _ = ws.send(Message::Close(None)).await;
                               return None;
                           }
                           return Some(text.as_str().to_owned());
                       }
                       Some(Ok(_)) => {} // binary/pong: waiting for the first Text message.
                   }
               }
    }
}

/// First-message token check: parse JSON → clone params → `strip_token` →
/// [`crate::auth::validate`] (constant-time, fixed-length digests). Ledger
/// discipline matches the dispatch-layer token gate: wait while a window
/// is armed (even valid credentials), clear on success, count and warn on
/// failure (credentials never logged). Non-object payloads or missing
/// params = no token, fail closed.
async fn ws_first_token_valid(state: &AppState, ip: IpAddr, text: &str) -> bool {
    let params = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("params").and_then(|p| p.as_array()).cloned());
    let token = params.and_then(|mut p| crate::auth::strip_token(&mut p));
    state.auth_backoff.wait(Some(ip)).await;
    let ok = crate::auth::validate(state.secret(), token.as_deref());
    if ok {
        state.auth_backoff.note_success(Some(ip));
    } else {
        state.session.metrics().note_rpc_auth_fail();
        if let Some(window) = state.auth_backoff.note_failure(Some(ip)) {
            warn!(
                target: "taiji::rpc::server",
                ?ip,
                window_secs = window.as_secs(),
                "auth failure backoff window armed"
            );
        }
    }
    ok
}

/// Test helper: run a JSON text straight through the dispatcher (no peer
/// address — the backoff ledger does not bookkeep).
#[cfg(test)]
pub(crate) async fn process_text(st: &AppState, text: &str) -> Result<serde_json::Value, ()> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    Ok(handle_payload(st, &v, None).await.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use taiji_core::session::EventKind;

    /// Regression (the auth.rs invariant: secrets never appear in logs
    /// or Debug output): the hand-written redacting Debug renders the
    /// three credential fields (`secret`/`rpc_user`/`rpc_passwd`) as
    /// set/unset only — plaintext never leaks into Debug. Shape follows
    /// auth.rs `debug_never_contains_secrets`.
    #[test]
    fn rpc_config_debug_never_contains_secrets() {
        let cfg = RpcConfig {
            secret: Some("s3cret-rpc-secret".into()),
            rpc_user: Some("alice".into()),
            rpc_passwd: Some("s3cret-basic-passwd".into()),
            ..Default::default()
        };
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("s3cret-rpc-secret"),
            "leaked: {rendered}"
        );
        assert!(!rendered.contains("alice"), "leaked: {rendered}");
        assert!(
            !rendered.contains("s3cret-basic-passwd"),
            "leaked: {rendered}"
        );
        // Set face rendered verbatim for all three credential fields.
        assert!(rendered.contains("secret: <set>"), "{rendered}");
        assert!(rendered.contains("rpc_user: <set>"), "{rendered}");
        assert!(rendered.contains("rpc_passwd: <set>"), "{rendered}");

        // Unset face (defaults): all three credential slots unset.
        let rendered = format!("{:?}", RpcConfig::default());
        assert!(rendered.contains("secret: <unset>"), "{rendered}");
        assert!(rendered.contains("rpc_user: <unset>"), "{rendered}");
        assert!(rendered.contains("rpc_passwd: <unset>"), "{rendered}");
        // Non-credential fields stay verbatim (redaction is scoped to
        // the credential fields only).
        assert!(rendered.contains("port: 6800"), "{rendered}");
    }

    fn app_state(secret: Option<&str>) -> AppState {
        let (session, _join) = taiji_core::session::SessionActor::spawn();
        AppState {
            session: Arc::new(session),
            secret: secret.map(str::to_string),
            basic: None,
            allow_origin_all: false,
            max_request_size: 1 << 20,
            shutdown: CancellationToken::new(),
            aria2_compat: false,
            listen_all: false,
            conn: Arc::new(crate::guards::ConnLedger::new(
                crate::guards::DEFAULT_MAX_TOTAL_CONNS,
                crate::guards::DEFAULT_MAX_PER_IP_CONNS,
            )),
            auth_backoff: Arc::new(crate::guards::AuthBackoff::new(
                crate::guards::DEFAULT_AUTH_FAIL_THRESHOLD,
            )),
        }
    }

    #[tokio::test]
    async fn dispatch_text_roundtrip_and_transport_parse_error() {
        // Drive the dispatch entry directly: a valid request returns result;
        // bad JSON takes the -32700 path.
        let st = Arc::new(app_state(None));
        let ok = process_text(&st, r#"{"id":3,"method":"getVersion"}"#)
            .await
            .unwrap_or_else(|()| panic!("fixture must parse"));
        let version = ok["result"]["version"].as_str().unwrap_or("");
        assert!(version.starts_with("taiji/"), "got {version}");

        let bad = process_text(&st, "not json").await;
        assert!(
            bad.is_err(),
            "transport-level parse failure surfaces -32700"
        );
    }

    #[tokio::test]
    async fn unauthorized_delay_is_one_second_and_abortable() {
        // The delay constant mirrors DelayedCommand 1_s; the shutdown token cancels the wait.
        let st = Arc::new(app_state(Some("s")));
        let t0 = Instant::now();
        let v: serde_json::Value = serde_json::from_str(r#"{"id":1,"method":"getVersion"}"#)
            .unwrap_or_else(|_| panic!("fixture"));
        let outcome = handle_payload(&st, &v, None).await;
        assert!(outcome.unauthorized);
        tokio::select! {
            _ = tokio::time::sleep(UNAUTHORIZED_DELAY) => {}
            _ = st.shutdown.cancelled() => panic!("must not cancel before sleep"),
        }
        assert!(t0.elapsed() >= Duration::from_millis(900));
        // Cancel path: token cancelled first → select takes the abandon branch immediately.
        st.shutdown.cancel();
        let t1 = Instant::now();
        tokio::select! {
            _ = tokio::time::sleep(UNAUTHORIZED_DELAY) => panic!("should have been aborted"),
            _ = st.shutdown.cancelled() => {}
        }
        assert!(t1.elapsed() < UNAUTHORIZED_DELAY);
    }

    // ---- Event notifications: envelope snapshots + WS push e2e ----

    /// Six-event text-frame snapshots (both faces): envelope per
    /// WebSocketSessionMan.cc (`{jsonrpc,method,params:[{gid}]}`); event
    /// names canonical `taiji.onXxx` / compat `aria2.onXxx`
    /// (frozen names); params is exactly one single-key element, gid hex16,
    /// no id key (notification, not response).
    #[test]
    fn notification_frames_match_reference_envelope() {
        let cases: &[(EventKind, &str, &str)] = &[
            (
                EventKind::Start,
                "taiji.onDownloadStart",
                "aria2.onDownloadStart",
            ),
            (
                EventKind::Pause,
                "taiji.onDownloadPause",
                "aria2.onDownloadPause",
            ),
            (
                EventKind::Stop,
                "taiji.onDownloadStop",
                "aria2.onDownloadStop",
            ),
            (
                EventKind::Complete,
                "taiji.onDownloadComplete",
                "aria2.onDownloadComplete",
            ),
            (
                EventKind::Error,
                "taiji.onDownloadError",
                "aria2.onDownloadError",
            ),
            (
                EventKind::BtComplete,
                "taiji.onBtDownloadComplete",
                "aria2.onBtDownloadComplete",
            ),
        ];
        let gid = taiji_core::gid::Gid::from_u64(0x8000_0000_0000_0042);
        for (kind, canonical, compat) in cases {
            for (aria2_compat, method) in [(false, *canonical), (true, *compat)] {
                let frame = notification_frame(aria2_compat, &SessionEvent { gid, kind: *kind });
                let v: serde_json::Value = serde_json::from_str(&frame)
                    .unwrap_or_else(|e| panic!("frame must be valid JSON: {e}"));
                let obj = v.as_object().unwrap_or_else(|| panic!("dict: {frame}"));
                assert_eq!(obj.len(), 3, "exactly jsonrpc/method/params: {frame}");
                assert_eq!(v["jsonrpc"], "2.0");
                assert_eq!(v["method"], *method, "face method for {kind:?}");
                let params = v["params"]
                    .as_array()
                    .unwrap_or_else(|| panic!("params list: {frame}"));
                assert_eq!(params.len(), 1, "params = [{gid}] (cc:76-82)");
                let entry = params
                    .first()
                    .and_then(|e| e.as_object())
                    .unwrap_or_else(|| panic!("params[0] dict: {frame}"));
                assert_eq!(entry.len(), 1, "single gid key: {frame}");
                let got_gid = entry
                    .get("gid")
                    .and_then(|g| g.as_str())
                    .unwrap_or_default();
                assert_eq!(got_gid, gid.to_string(), "gid hex16");
                assert_eq!(gid.to_string().len(), 16, "hex16");
                assert!(
                    obj.get("id").is_none(),
                    "notification carries no id: {frame}"
                );
            }
        }
    }

    /// Dual-state e2e carrier: a real WS upgrade → addTorrent activates →
    /// the client receives the onDownloadStart text frame. The client is a
    /// hand-written minimal RFC 6455 face (fixed handshake headers +
    /// server-frame parsing; server frames are never masked).
    /// `aria2_compat` picks the event-name face.
    async fn ws_start_notification_e2e(aria2_compat: bool, expect_method: &str) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let session = Arc::new(session);
        let session_for_rpc = Arc::clone(&session);
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                aria2_compat,
                ..Default::default()
            },
            session,
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));

        let mut sock = tokio::net::TcpStream::connect(server.local_addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        // Minimal handshake (the RFC 6455 example Sec-WebSocket-Key value suffices).
        let req = "GET /jsonrpc HTTP/1.1\r\n\
                   Host: localhost\r\n\
                   Upgrade: websocket\r\n\
                   Connection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                   Sec-WebSocket-Version: 13\r\n\r\n";
        sock.write_all(req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("handshake write: {e}"));
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = sock
                .read(&mut byte)
                .await
                .unwrap_or_else(|e| panic!("handshake read: {e}"));
            if n == 0 {
                panic!("connection closed during handshake");
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        assert!(head.starts_with("HTTP/1.1 101"), "upgrade response: {head}");

        // Upgrade handling (on_upgrade → ws_loop subscription) is async
        // with the 101 write — leave a window so the subscription lands
        // before the first event.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Trigger Start: a dead-tracker torrent publishes onDownloadStart on activation.
        let dir =
            std::env::temp_dir().join(format!("bh-p36-ws-{}-{aria2_compat}", std::process::id()));
        let torrent = minimal_v1_torrent();
        let add = process_call_via_session(
            &session_for_rpc,
            serde_json::json!([base64_of(&torrent), [], {"dir": dir.display().to_string()}]),
        )
        .await;
        let gid = match add {
            Ok(s) => s,
            Err(e) => panic!("addTorrent failed: {e}"),
        };
        let frame = read_ws_text_frame(&mut sock).await;
        let v: serde_json::Value =
            serde_json::from_str(&frame).unwrap_or_else(|e| panic!("frame json: {e}"));
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], expect_method);
        assert_eq!(v["params"][0]["gid"], serde_json::json!(gid));
        assert!(v.get("id").is_none(), "notification has no id: {frame}");

        // Shutdown wind-down (the shutdown arm closes the connection).
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Event-name face (e2e): the default canonical face.
    #[tokio::test]
    async fn ws_upgrade_receives_canonical_start_notification() {
        ws_start_notification_e2e(false, "taiji.onDownloadStart").await;
    }

    /// Event-name face (e2e): the compat aria2.onXxx face (the drop-in
    /// contract for external aria2 frontends).
    #[tokio::test]
    async fn ws_upgrade_receives_aria2_start_notification_in_compat_mode() {
        ws_start_notification_e2e(true, "aria2.onDownloadStart").await;
    }

    // ---- Security hardening regressions (transport-layer e2e) ----

    /// Raw HTTP/1.1 round-trip (test helper; `Connection: close` ensures
    /// EOF). Returns (status, header block, body).
    async fn http_roundtrip(addr: SocketAddr, req: &str) -> (u16, String, String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        sock.write_all(req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        let raw = String::from_utf8_lossy(&buf).into_owned();
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("malformed response: {raw:?}"));
        let status: u16 = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or_else(|| panic!("no status line: {head:?}"));
        (status, head.to_string(), body.to_string())
    }

    fn post_jsonrpc(body: &str, addr: SocketAddr, extra: &str) -> String {
        format!(
            "POST /jsonrpc HTTP/1.1\r\nHost: {addr}\r\n\
             Content-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n{extra}\r\n{body}",
            body.len()
        )
    }

    /// Minimal WS handshake (`extra` = additional headers, each line
    /// `\r\n`-terminated). Returns the raw response header text (the
    /// caller asserts 101/403). The connection stays open on success.
    async fn ws_handshake_raw(addr: SocketAddr, extra: &str) -> (tokio::net::TcpStream, String) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut sock = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        let req = format!(
            "GET /jsonrpc HTTP/1.1\r\nHost: {addr}\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n{extra}\r\n"
        );
        sock.write_all(req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("handshake write: {e}"));
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = sock
                .read(&mut byte)
                .await
                .unwrap_or_else(|e| panic!("handshake read: {e}"));
            if n == 0 {
                panic!("connection closed during handshake");
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        (sock, String::from_utf8_lossy(&head).into_owned())
    }

    /// Client → server masked text-frame bytes (RFC 6455: client frames
    /// must be masked); built but not written — shared by the full-write
    /// and best-effort paths.
    fn masked_text_frame_bytes(text: &str) -> Vec<u8> {
        let payload = text.as_bytes();
        let mask: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x81); // FIN + text
        let len = payload.len();
        if len <= 125 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        frame
    }

    /// Client → server masked text frame (RFC 6455: client frames must be masked).
    async fn write_masked_text_frame(sock: &mut tokio::net::TcpStream, text: &str) {
        use tokio::io::AsyncWriteExt as _;
        let frame = masked_text_frame_bytes(text);
        sock.write_all(&frame)
            .await
            .unwrap_or_else(|e| panic!("frame write: {e}"));
    }

    /// Best-effort frame write (for the over-limit PoC): a peer rejected
    /// at the frame header never reads the payload — RST on close with
    /// unread data or EPIPE mid-write are part of the disconnect shape, not
    /// assertion points (the assertions cover downlink content / the
    /// disconnect itself).
    async fn write_frame_best_effort(sock: &mut tokio::net::TcpStream, frame: &[u8]) {
        use tokio::io::AsyncWriteExt as _;
        let mut off = 0;
        while off < frame.len() {
            match sock.write(&frame[off..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => off += n,
            }
        }
    }

    /// Transport regression: a WS unauthorized message consumes the same
    /// 1s delay as the HTTP path — the wrong-token reply takes ≥900ms (WS
    /// previously dropped the unauthorized flag, allowing thousands of
    /// token guesses per second per connection); a valid token answers
    /// immediately.
    #[tokio::test]
    async fn ws_unauthorized_message_consumes_one_second_delay() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                secret: Some("sekrit".to_string()),
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;
        let (mut sock, head) = ws_handshake_raw(addr, "").await;
        assert!(head.starts_with("HTTP/1.1 101"), "upgrade: {head}");
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Wrong token → 1s delay, then Unauthorized.
        let t0 = Instant::now();
        write_masked_text_frame(
            &mut sock,
            r#"{"id":1,"method":"getVersion","params":["token:wrong"]}"#,
        )
        .await;
        let frame = read_ws_text_frame(&mut sock).await;
        assert!(t0.elapsed() >= Duration::from_millis(900), "delay consumed");
        assert!(frame.contains("Unauthorized"), "reply: {frame}");

        // Valid token → immediate (no delay).
        let t1 = Instant::now();
        write_masked_text_frame(
            &mut sock,
            r#"{"id":2,"method":"getVersion","params":["token:sekrit"]}"#,
        )
        .await;
        let frame = read_ws_text_frame(&mut sock).await;
        assert!(
            t1.elapsed() < Duration::from_millis(900),
            "valid token must not be delayed: {frame}"
        );
        assert!(frame.contains("taiji/"), "reply: {frame}");

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// Transport regression: the WS per-message cap matches the HTTP face
    /// — protocol-level `max_message_size`/`max_frame_size` =
    /// `max_request_size + 1` (same value; the frame cap rejects at the
    /// frame header without reading the payload), so an oversized message
    /// fails at the protocol layer with Capacity → the server disconnects
    /// and does **not** answer -32700 (the same attack over HTTP is stopped
    /// by the `to_bytes` limit; previously only the WS face exposed
    /// tungstenite's default 64MiB per-connection whole-message buffering —
    /// an unauthenticated OOM face in credential-free deployments). The
    /// payload is `2 × max_request_size` (defect state buffers fully and
    /// answers -32700 → red; fixed state rejects at the protocol layer →
    /// green). A frame-header rejection closes the server socket with
    /// unread data (RST/EPIPE shape) — writes are best-effort and a
    /// read-side RST counts as disconnect.
    #[tokio::test]
    async fn ws_oversized_message_closes_connection_without_parse_error() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                max_request_size: 64 * 1024,
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;
        // No credentials + no Origin = the minimal unauthenticated attack
        // shape (basic_gate passes).
        let (mut sock, head) = ws_handshake_raw(addr, "").await;
        assert!(head.starts_with("HTTP/1.1 101"), "upgrade: {head}");
        tokio::time::sleep(Duration::from_millis(150)).await;

        // One oversized text message: 128 KiB > the 64 KiB cap.
        let oversized = "x".repeat(128 * 1024);
        write_frame_best_effort(&mut sock, &masked_text_frame_bytes(&oversized)).await;

        // Assert: the server closes (EOF) and never sends a -32700 reply.
        let (downlink, closed) = read_until_eof_within(&mut sock, Duration::from_secs(5)).await;
        assert!(
            !downlink.windows(6).any(|w| w == b"-32700"),
            "oversized message must be rejected at protocol layer, got reply: {}",
            String::from_utf8_lossy(&downlink)
        );
        assert!(
            closed,
            "connection must be closed by server, downlink: {}",
            String::from_utf8_lossy(&downlink)
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// Transport regression: the WS upgrade Origin gate — cross-origin
    /// 403; same-origin / no Origin pass; `--rpc-allow-origin-all` allows
    /// all.
    #[tokio::test]
    async fn ws_upgrade_rejects_cross_origin_unless_same_origin_or_opt_out() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;

        // Cross-origin Origin (the browser-drives-loopback face) → 403.
        let (_, head) = ws_handshake_raw(addr, "Origin: http://evil.example\r\n").await;
        assert!(head.starts_with("HTTP/1.1 403"), "cross origin: {head}");
        // Sandboxed Origin: null → no matchable Host → 403.
        let (_, head) = ws_handshake_raw(addr, "Origin: null\r\n").await;
        assert!(head.starts_with("HTTP/1.1 403"), "null origin: {head}");
        // Same origin (Origin authority == Host) → 101.
        let (sock, head) = ws_handshake_raw(addr, &format!("Origin: http://{addr}\r\n")).await;
        assert!(head.starts_with("HTTP/1.1 101"), "same origin: {head}");
        // No Origin (curl/aria2 CLI and other non-browsers) → 101.
        let (sock2, head) = ws_handshake_raw(addr, "").await;
        assert!(head.starts_with("HTTP/1.1 101"), "no origin: {head}");
        drop(sock);
        drop(sock2);

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;

        // allow-origin-all: explicit allow-all (the user's explicit CORS-consistent opt-in).
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                allow_origin_all: true,
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let (_, head) =
            ws_handshake_raw(server.local_addr, "Origin: http://evil.example\r\n").await;
        assert!(head.starts_with("HTTP/1.1 101"), "opt-out: {head}");
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// E2E: with no secret, a simple HTTP request (text/plain needs no
    /// preflight) driving a write → explicit refusal; read-only methods
    /// pass.
    #[tokio::test]
    async fn http_unauthenticated_write_is_refused_end_to_end() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;

        // Write (text/plain simple-request shape) → 400 + frozen text.
        let (status, _, body) = http_roundtrip(
            addr,
            &post_jsonrpc(
                r#"{"id":1,"method":"addUri","params":[["http://127.0.0.1:1/f"],{"dir":"/tmp/x"}]}"#,
                addr,
                "",
            ),
        )
        .await;
        assert_eq!(status, 400, "write gate: {body}");
        assert!(
            body.contains("unauthenticated write requires --rpc-secret"),
            "frozen message: {body}"
        );

        // Read-only passes (including a batch carrier).
        let (status, _, body) = http_roundtrip(
            addr,
            &post_jsonrpc(r#"{"id":2,"method":"getVersion"}"#, addr, ""),
        )
        .await;
        assert_eq!(status, 200, "read-only: {body}");
        assert!(body.contains("taiji/"), "getVersion: {body}");

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// Transport regression: /metrics sits behind the same Basic gate as
    /// /jsonrpc — with credentials configured, anonymous is 401 (the
    /// WWW-Authenticate face) and correct credentials get 200.
    #[tokio::test]
    async fn metrics_requires_same_basic_gate_as_jsonrpc() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                rpc_user: Some("u".to_string()),
                rpc_passwd: Some("p".to_string()),
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;

        // Anonymous → 401 + WWW-Authenticate (the HttpServerCommand.cc face).
        let (status, head, body) = http_roundtrip(
            addr,
            &format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 401, "anonymous metrics: {body}");
        assert!(
            // hyper lowercases outbound header names; the value is untouched.
            head.to_ascii_lowercase()
                .contains("www-authenticate: basic realm=\"aria2\""),
            "challenge header: {head}"
        );

        // Correct Basic credentials → 200 metrics text.
        let (status, head, body) = http_roundtrip(
            addr,
            &format!(
                "GET /metrics HTTP/1.1\r\nHost: {addr}\r\n\
                 Authorization: Basic {}\r\nConnection: close\r\n\r\n",
                base64_of(b"u:p")
            ),
        )
        .await;
        assert_eq!(status, 200, "authorized metrics: {body}");
        assert!(head.contains("text/plain"), "content type: {head}");
        assert!(body.contains("taiji_"), "prometheus body: {body}");

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// Minimal v1 metainfo (single 32B file / 1 piece, placeholder pieces
    /// — the parser does not check hash consistency; same construction as
    /// the dispatch tests).
    fn minimal_v1_torrent() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(
            b"d8:announce27:http://127.0.0.1:1/announce4:infod6:lengthi32e4:name5:w.bin12:piece lengthi16384e6:pieces20:",
        );
        v.extend_from_slice(&[0xAB; 20]);
        v.extend_from_slice(b"ee");
        v
    }

    /// Standard base64 (encodes the addTorrent first parameter; test-only implementation).
    fn base64_of(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// Dispatch addTorrent via the session handle (returns the gid hex16 string).
    async fn process_call_via_session(
        session: &SessionHandle,
        params: serde_json::Value,
    ) -> Result<String, String> {
        let arr = params
            .as_array()
            .cloned()
            .ok_or_else(|| "params must be array".to_string())?;
        let torrent = arr
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| "missing torrent".to_string())?
            .to_string();
        let options = arr.get(2).cloned().unwrap_or_else(|| serde_json::json!({}));
        let mut map = std::collections::BTreeMap::new();
        if let Some(obj) = options.as_object() {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    map.insert(k.clone(), s.to_string());
                }
            }
        }
        match session
            .call(taiji_core::session::SessionCommand::AddTorrent {
                torrent: crate::base64::decode(&torrent).ok_or_else(|| "bad base64".to_string())?,
                options: map,
                position: None,
            })
            .await
        {
            Ok(taiji_core::session::CommandReply::Gid(g)) => Ok(g.to_string()),
            Ok(other) => Err(format!("unexpected reply: {other:?}")),
            Err(e) => Err(format!("{e:?}")),
        }
    }

    /// Read one server text frame (RFC 6455: opcode 1, FIN, unmasked).
    async fn read_ws_text_frame(sock: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt as _;
        let mut hdr = [0u8; 2];
        sock.read_exact(&mut hdr)
            .await
            .unwrap_or_else(|e| panic!("frame header: {e}"));
        assert_eq!(hdr[0] & 0x0f, 0x1, "text frame opcode");
        assert_eq!(hdr[0] & 0x80, 0x80, "FIN set");
        assert_eq!(hdr[1] & 0x80, 0, "server frames are unmasked");
        let len = match (hdr[1] & 0x7f) as usize {
            126 => {
                let mut b = [0u8; 2];
                sock.read_exact(&mut b)
                    .await
                    .unwrap_or_else(|e| panic!("len16: {e}"));
                u16::from_be_bytes(b) as usize
            }
            127 => {
                let mut b = [0u8; 8];
                sock.read_exact(&mut b)
                    .await
                    .unwrap_or_else(|e| panic!("len64: {e}"));
                u64::from_be_bytes(b) as usize
            }
            n => n,
        };
        let mut payload = vec![0u8; len];
        sock.read_exact(&mut payload)
            .await
            .unwrap_or_else(|e| panic!("payload: {e}"));
        String::from_utf8(payload).unwrap_or_else(|e| panic!("utf8: {e}"))
    }

    /// Read until EOF or the deadline window (returns the accumulated
    /// downlink bytes and whether EOF was seen). EOF = the server
    /// disconnected (including close-frame-then-close, and RST — when the
    /// protocol-layer frame cap rejects at the frame header the server
    /// socket closes with unread data and the peer sees ConnectionReset;
    /// same disconnect semantics). Still readable at the deadline =
    /// connection open. The over-limit PoC assertions rely on this
    /// distinction.
    async fn read_until_eof_within(
        sock: &mut tokio::net::TcpStream,
        window: Duration,
    ) -> (Vec<u8>, bool) {
        use tokio::io::AsyncReadExt as _;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + window;
        loop {
            match tokio::time::timeout_at(deadline, sock.read(&mut chunk)).await {
                // Deadline reached: the connection is still open (no EOF).
                Err(_elapsed) => return (buf, false),
                // RST from closing with unread data: disconnected (downlink already accumulated).
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    return (buf, true);
                }
                Ok(Err(e)) => panic!("read: {e}"),
                Ok(Ok(0)) => return (buf, true),
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    // ---- Exposure-surface guards: conn caps, auth backoff, weak-secret warning ----

    /// Guard-injection e2e helper: serve_with_guards + its own session/shutdown token.
    async fn spawn_guarded(
        cfg: RpcConfig,
        guards: crate::guards::RpcGuards,
    ) -> (ServerHandle, tokio::task::JoinHandle<()>, CancellationToken) {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve_with_guards(cfg, Arc::new(session), shutdown.clone(), guards)
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        (server, actor_join, shutdown)
    }

    /// GET /metrics as text (no auth when Basic is unconfigured; Connection: close).
    async fn get_metrics_text(addr: SocketAddr) -> (u16, String) {
        let (status, _, body) = http_roundtrip(
            addr,
            &format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        (status, body)
    }

    /// e2e (total-cap half): inject total 4 / per-IP 32 — with 4 concurrent
    /// WS sessions held, the 5th HTTP request and WS upgrade both 503
    /// (scope=total counter); after releasing one, re-entry works (the
    /// server notices disconnects with a lag — bounded retry, no hard
    /// sleeps).
    #[tokio::test]
    async fn conn_total_cap_rejects_fifth_and_readmits_after_release() {
        let (server, actor_join, shutdown) = spawn_guarded(
            RpcConfig {
                port: 0,
                ..Default::default()
            },
            crate::guards::RpcGuards {
                max_total_conns: 4,
                max_per_ip_conns: 32,
                auth_fail_threshold: 5,
            },
        )
        .await;
        let addr = server.local_addr;

        // Hold 4 concurrent connections (each WS session holds one transferred lease).
        let mut held: Vec<tokio::net::TcpStream> = Vec::new();
        for _ in 0..4 {
            let (sock, head) = ws_handshake_raw(addr, "").await;
            assert!(head.starts_with("HTTP/1.1 101"), "hold conn: {head}");
            held.push(sock);
        }
        // 5th (HTTP) → 503.
        let (status, _, body) = http_roundtrip(
            addr,
            &post_jsonrpc(r#"{"id":1,"method":"getVersion"}"#, addr, ""),
        )
        .await;
        assert_eq!(status, 503, "fifth concurrent conn over total cap: {body}");
        // 5th (WS) → rejected before the upgrade (no 101 sent).
        let (_, head) = ws_handshake_raw(addr, "").await;
        assert!(
            head.starts_with("HTTP/1.1 503"),
            "ws upgrade rejected: {head}"
        );

        // Release one → the counter is readable (at full capacity the
        // metrics GET itself would 503) and re-entry works.
        held.pop();
        let (status, body) = get_metrics_text(addr).await;
        assert_eq!(status, 200, "metrics readable after release: {body}");
        assert!(
            body.lines()
                .any(|l| l == "taiji_rpc_conn_rejected_total{scope=\"total\"} 2"),
            "rejected counter (http + ws): {body}"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let (sock, head) = ws_handshake_raw(addr, "").await;
            if head.starts_with("HTTP/1.1 101") {
                held.push(sock);
                break;
            }
            assert!(
                head.starts_with("HTTP/1.1 503"),
                "readmit attempts must 503 until release lands: {head}"
            );
            assert!(
                tokio::time::Instant::now() < deadline,
                "readmit after release never happened"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// e2e (per-IP half): inject total 64 / per-IP 2 — the 3rd connection
    /// from the same source (tests always source 127.0.0.1) gets 503
    /// (scope=per_ip counter); the other-source half is covered by the unit
    /// test `ledger_enforces_per_ip_cap_and_aggregates_per_source` (e2e
    /// cannot change the source address); re-entry works after a release.
    #[tokio::test]
    async fn conn_per_ip_cap_rejects_third_from_same_source() {
        let (server, actor_join, shutdown) = spawn_guarded(
            RpcConfig {
                port: 0,
                ..Default::default()
            },
            crate::guards::RpcGuards {
                max_total_conns: 64,
                max_per_ip_conns: 2,
                auth_fail_threshold: 5,
            },
        )
        .await;
        let addr = server.local_addr;

        let mut held: Vec<tokio::net::TcpStream> = Vec::new();
        for _ in 0..2 {
            let (sock, head) = ws_handshake_raw(addr, "").await;
            assert!(head.starts_with("HTTP/1.1 101"), "hold conn: {head}");
            held.push(sock);
        }
        // 3rd from the same source → 503 (scope=per_ip counter; the
        // counter assertion waits until after a release, since at full
        // capacity the metrics GET is rejected by the same gate).
        let (status, _, body) = http_roundtrip(
            addr,
            &post_jsonrpc(r#"{"id":1,"method":"getVersion"}"#, addr, ""),
        )
        .await;
        assert_eq!(status, 503, "third from one source over per-ip cap: {body}");

        // Release one → read-only requests re-enter (bounded retry).
        held.pop();
        let (status, body) = get_metrics_text(addr).await;
        assert_eq!(status, 200, "metrics readable after release: {body}");
        assert!(
            body.lines()
                .any(|l| l == "taiji_rpc_conn_rejected_total{scope=\"per_ip\"} 1"),
            "per-ip rejected counter: {body}"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let (status, _, body) = http_roundtrip(
                addr,
                &post_jsonrpc(r#"{"id":2,"method":"getVersion"}"#, addr, ""),
            )
            .await;
            if status == 200 {
                assert!(body.contains("taiji/"), "{body}");
                break;
            }
            assert_eq!(status, 503, "unexpected status, body: {body}");
            assert!(
                tokio::time::Instant::now() < deadline,
                "readmit after release never happened"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// e2e: inject threshold 3 — after 3 bad secrets, the 4th request
    /// (valid credentials) is delayed ≥ 0.8× the window (first window 1s;
    /// the lower bound leaves margin against flakes); one success clears
    /// the count (the 5th is immediate).
    ///
    /// Timing: a bad request's 1s unauthorized delay eats the window tail —
    /// the 3rd failure is counted before its response (note_failure → 1s
    /// delay), so the test polls the /metrics counter to sync on "3
    /// counted" before sending the valid request, ensuring it arrives in
    /// window.
    #[tokio::test]
    async fn auth_backoff_window_delays_valid_credentials_then_success_resets() {
        let secret = "p87-backoff-secret";
        let (server, actor_join, shutdown) = spawn_guarded(
            RpcConfig {
                port: 0,
                secret: Some(secret.to_string()),
                ..Default::default()
            },
            crate::guards::RpcGuards {
                auth_fail_threshold: 3,
                ..Default::default()
            },
        )
        .await;
        let addr = server.local_addr;
        let good = format!(r#"{{"id":1,"method":"getVersion","params":["token:{secret}"]}}"#);
        let bad = r#"{"id":1,"method":"getVersion","params":["token:wrong"]}"#.to_string();

        // Baseline: with no failures, valid credentials are immediate.
        let t = Instant::now();
        let (status, _, body) = http_roundtrip(addr, &post_jsonrpc(&good, addr, "")).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            t.elapsed() < Duration::from_millis(800),
            "baseline must be fast: {:?}",
            t.elapsed()
        );

        // Two bad secrets (each response carries its own ~1s unauthorized delay).
        for _ in 0..2 {
            let (status, _, body) = http_roundtrip(addr, &post_jsonrpc(&bad, addr, "")).await;
            assert_eq!(status, 400, "{body}");
            assert!(body.contains("Unauthorized"), "{body}");
        }

        // 3rd bad secret in flight; poll the counter until it lands.
        let third =
            tokio::spawn(async move { http_roundtrip(addr, &post_jsonrpc(&bad, addr, "")).await });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (status, body) = get_metrics_text(addr).await;
            assert_eq!(status, 200, "{body}");
            if body.lines().any(|l| l == "taiji_rpc_auth_fail_total 3") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "auth fail counter never hit 3: {body}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // 4th (valid credentials): arrives in window → delayed ≥ 0.8×1s, still succeeds.
        let t = Instant::now();
        let (status, _, body) = http_roundtrip(addr, &post_jsonrpc(&good, addr, "")).await;
        let elapsed = t.elapsed();
        assert_eq!(status, 200, "valid credentials still succeed: {body}");
        assert!(
            elapsed >= Duration::from_millis(800),
            "in-window valid credentials must be delayed ~1s: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "delay must stay bounded: {elapsed:?}"
        );
        let (status, _, body) = third
            .await
            .unwrap_or_else(|e| panic!("third request task: {e}"));
        assert_eq!(status, 400, "third bad request still 400: {body}");

        // Success clears the count: the 5th valid request is immediate; the
        // backoff gauge returns to 0.
        let t = Instant::now();
        let (status, _, body) = http_roundtrip(addr, &post_jsonrpc(&good, addr, "")).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            t.elapsed() < Duration::from_millis(800),
            "post-success must be fast: {:?}",
            t.elapsed()
        );
        let (status, body) = get_metrics_text(addr).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            body.lines().any(|l| l == "taiji_rpc_auth_backoff_active 0"),
            "backoff gauge cleared after success: {body}"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// Minimal capture subscriber (test face, no new dependencies —
    /// implements the `tracing` facade's [`tracing::Subscriber`]): WARN and
    /// above events are collected as `target: message [field=…]` text
    /// lines. Not installed globally (thread-local `with_default`).
    struct CaptureSubscriber(Arc<std::sync::Mutex<Vec<String>>>);

    impl tracing::Subscriber for CaptureSubscriber {
        // Spans are not needed (events only) — a single placeholder Id suffices.
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() > tracing::Level::WARN {
                return; // Capture WARN/ERROR only (the weak-credential warning face).
            }
            struct TextVisit(String);
            impl tracing::field::Visit for TextVisit {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0.push_str(&format!("{value:?}"));
                    } else {
                        self.0.push_str(&format!(" { }={value:?}", field.name()));
                    }
                }
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "message" {
                        self.0.push_str(value);
                    } else {
                        self.0.push_str(&format!(" { }={value}", field.name()));
                    }
                }
            }
            let mut visit = TextVisit(String::new());
            event.record(&mut visit);
            let line = format!("{}: {}", event.metadata().target(), visit.0);
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(line);
        }
    }

    /// Dedicated-thread log capture (test face): a current-thread runtime +
    /// `with_default` thread-local subscriber — the global default is
    /// untouched, so in-process parallel tests are unaffected (a global
    /// capture would race across parallel tests). Returns (captured text,
    /// closure result) — assertions run on the calling thread (readable
    /// panic semantics).
    fn run_with_log_capture<F, Fut, T>(f: F) -> (String, T)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let lines: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber(Arc::clone(&lines));
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| panic!("runtime: {e}"));
            tracing::subscriber::with_default(subscriber, || rt.block_on(f()))
        });
        let result = handle
            .join()
            .unwrap_or_else(|_| panic!("capture thread panicked"));
        let text = lines.lock().unwrap_or_else(|e| e.into_inner()).join("\n");
        (text, result)
    }

    /// e2e: a weak secret (<16 chars) logs one startup warn (text names
    /// the suggested length) without refusing startup (the service works);
    /// the secret itself is never logged. Contrast: 16+ chars, no warning.
    #[test]
    fn weak_secret_warns_at_startup_without_refusing() {
        let weak = "p87-weak-sec".to_string();
        let weak_in = weak.clone();
        let (logs, (status, body)) = run_with_log_capture(move || async move {
            let (session, _actor) = taiji_core::session::SessionActor::spawn();
            let shutdown = CancellationToken::new();
            let server = serve(
                RpcConfig {
                    port: 0,
                    secret: Some(weak_in),
                    ..Default::default()
                },
                Arc::new(session),
                shutdown.clone(),
            )
            .await
            .unwrap_or_else(|e| panic!("serve: {e}"));
            // Startup not refused: a normal token call works.
            let (status, _, body) = http_roundtrip(
                server.local_addr,
                &post_jsonrpc(
                    r#"{"id":1,"method":"getVersion","params":["token:p87-weak-sec"]}"#,
                    server.local_addr,
                    "",
                ),
            )
            .await;
            shutdown.cancel();
            (status, body)
        });
        assert_eq!(status, 200, "weak secret must not refuse startup: {body}");
        assert!(body.contains("taiji/"), "{body}");
        assert!(
            logs.contains("--rpc-secret is shorter than 16 characters"),
            "warn line missing: {logs}"
        );
        assert!(!logs.contains(&weak), "secret leaked into logs: {logs}");

        // Contrast: 16+ chars, no warning.
        let strong = "p87-strong-secret-0123456789".to_string();
        let (logs, _) = run_with_log_capture(move || async move {
            let (session, _actor) = taiji_core::session::SessionActor::spawn();
            let shutdown = CancellationToken::new();
            let server = serve(
                RpcConfig {
                    port: 0,
                    secret: Some(strong),
                    ..Default::default()
                },
                Arc::new(session),
                shutdown.clone(),
            )
            .await
            .unwrap_or_else(|e| panic!("serve: {e}"));
            shutdown.cancel();
            (server.local_addr, ())
        });
        assert!(
            !logs.contains("shorter than 16"),
            "strong secret must not warn: {logs}"
        );
    }

    /// e2e (zero regression): localhost without credentials — the frozen
    /// write-gate text, read-only faces, and no new delay; a normal
    /// single-client localhost flow with a proper secret runs addUri →
    /// tellStatus unchanged (the default guards never trigger in normal
    /// use).
    #[tokio::test]
    async fn localhost_flow_unchanged_under_default_guards() {
        // Half one: the no-credential form (default guards) — existing semantics unchanged.
        let (server, actor_join, shutdown) = spawn_guarded(
            RpcConfig {
                port: 0,
                ..Default::default()
            },
            crate::guards::RpcGuards::default(),
        )
        .await;
        let addr = server.local_addr;
        // addUri (write face) → frozen-text 400 (the pre-existing gate).
        let t = Instant::now();
        let (status, _, body) = http_roundtrip(
            addr,
            &post_jsonrpc(
                r#"{"id":1,"method":"addUri","params":[["http://127.0.0.1:1/f"]]}"#,
                addr,
                "",
            ),
        )
        .await;
        assert_eq!(status, 400, "{body}");
        assert!(
            body.contains("unauthenticated write requires --rpc-secret"),
            "frozen write-gate message: {body}"
        );
        assert!(
            t.elapsed() < Duration::from_millis(800),
            "no new delay on the no-credential write gate: {:?}",
            t.elapsed()
        );
        // Read-only face unchanged, no delay.
        let t = Instant::now();
        let (status, _, body) = http_roundtrip(
            addr,
            &post_jsonrpc(r#"{"id":2,"method":"getVersion"}"#, addr, ""),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("taiji/"), "{body}");
        assert!(
            t.elapsed() < Duration::from_millis(800),
            "read-only must stay fast: {:?}",
            t.elapsed()
        );
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;

        // Half two: normal single-client localhost (16+ secret, default
        // guards) — addUri → tellStatus unchanged.
        let secret = "p87-localhost-normal-secret";
        let (server, actor_join, shutdown) = spawn_guarded(
            RpcConfig {
                port: 0,
                secret: Some(secret.to_string()),
                ..Default::default()
            },
            crate::guards::RpcGuards::default(),
        )
        .await;
        let addr = server.local_addr;
        let dir = std::env::temp_dir().join(format!("recheck-flow-{}", std::process::id()));
        let add = format!(
            r#"{{"id":1,"method":"addUri","params":["token:{secret}",["http://127.0.0.1:1/f"],{{"dir":"{}"}}]}}"#,
            dir.display()
        );
        let t = Instant::now();
        let (status, _, body) = http_roundtrip(addr, &post_jsonrpc(&add, addr, "")).await;
        assert_eq!(status, 200, "addUri: {body}");
        assert!(
            t.elapsed() < Duration::from_millis(800),
            "no backoff/cap interference on normal use: {:?}",
            t.elapsed()
        );
        let gid = serde_json::from_str::<serde_json::Value>(&body)
            .unwrap_or_else(|e| panic!("addUri reply json: {e}"))["result"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert_eq!(gid.len(), 16, "gid hex16: {body}");
        let tell =
            format!(r#"{{"id":2,"method":"tellStatus","params":["token:{secret}","{gid}"]}}"#);
        let (status, _, body) = http_roundtrip(addr, &post_jsonrpc(&tell, addr, "")).await;
        assert_eq!(status, 200, "tellStatus: {body}");
        assert!(body.contains(&gid), "status of the new task: {body}");

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Blank/whitespace rpc-secret normalization + listen-all guard tightening ----

    /// Direct test of the normalizer: unset/empty/whitespace → None;
    /// non-empty → the trimmed value (aria2 "empty = unset"; whitespace
    /// tightened to match).
    #[test]
    fn normalize_secret_maps_blank_and_whitespace_to_unset() {
        assert_eq!(normalize_secret(None), None);
        assert_eq!(normalize_secret(Some(String::new())), None);
        assert_eq!(normalize_secret(Some("   \t".to_string())), None);
        assert_eq!(
            normalize_secret(Some("  s3cr3t  ".to_string())),
            Some("s3cr3t".to_string())
        );
    }

    /// Guard tightening: listen_all + an empty/whitespace --rpc-secret
    /// refuses to start. Defect shape: a guard checking only
    /// `secret.is_none` lets Some("") bind all interfaces, and after
    /// strip_token removes the `token:` prefix,
    /// validate(Some(""), Some("")) is always true → the whole write
    /// surface opens remotely (aria2's "empty = unset" semantics bypassed
    /// by a misconfiguration).
    #[tokio::test]
    async fn listen_all_blank_or_whitespace_secret_is_refused_at_startup() {
        for blank in ["", "   "] {
            let (session, _actor) = taiji_core::session::SessionActor::spawn();
            let err = serve(
                RpcConfig {
                    port: 0,
                    listen_all: true,
                    secret: Some(blank.to_string()),
                    ..Default::default()
                },
                Arc::new(session),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("listen_all + blank secret {blank:?} must refuse to start"));
            let msg = err.to_string();
            assert!(msg.contains("--rpc-listen-all"), "names the switch: {msg}");
            assert!(msg.contains("--rpc-secret"), "names the fix path: {msg}");
            assert!(
                msg.contains("loopback"),
                "names the loopback fallback: {msg}"
            );
        }
    }

    /// Guard tightening: listen_all + user-only Basic (--rpc-user set,
    /// --rpc-passwd unset → the password slot is None and unchecked;
    /// knowing the user name alone passes the Basic gate) → refuses to
    /// start (not a usable credential).
    #[tokio::test]
    async fn listen_all_user_only_basic_is_refused_at_startup() {
        let (session, _actor) = taiji_core::session::SessionActor::spawn();
        let err = serve(
            RpcConfig {
                port: 0,
                listen_all: true,
                rpc_user: Some("u".to_string()),
                ..Default::default()
            },
            Arc::new(session),
            CancellationToken::new(),
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("listen_all + user-only basic must refuse to start"));
        let msg = err.to_string();
        assert!(msg.contains("--rpc-listen-all"), "names the switch: {msg}");
        assert!(
            msg.contains("--rpc-passwd"),
            "names the missing credential half: {msg}"
        );
    }

    /// Normalization: non-listen_all + an empty secret behaves as unset —
    /// loopback bind; the unauthenticated write gate still refuses (defect
    /// shape: Some("") made validate(Some(""), _) always true and the write
    /// gate treated it as set, so an empty token could write).
    #[tokio::test]
    async fn non_listen_all_blank_secret_behaves_as_unset() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                secret: Some(String::new()),
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("blank secret must still serve on loopback: {e}"));
        assert!(
            server.local_addr.ip().is_loopback(),
            "blank secret = unset (loopback): {}",
            server.local_addr
        );
        let addr = server.local_addr;
        // Tokenless write → frozen-text 400 (same as unset secret).
        let (status, _, body) = http_roundtrip(
            addr,
            &post_jsonrpc(
                r#"{"id":1,"method":"addUri","params":[["http://127.0.0.1:1/f"]]}"#,
                addr,
                "",
            ),
        )
        .await;
        assert_eq!(
            status, 400,
            "write gate treats blank secret as unset: {body}"
        );
        assert!(
            body.contains("unauthenticated write requires --rpc-secret"),
            "frozen write-gate message: {body}"
        );
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// Contrast (zero regression): listen_all + a normal secret starts and
    /// binds all interfaces (normalization only affects the credential
    /// decision; the bind axis only looks at listen_all — the axes stay
    /// decoupled).
    #[tokio::test]
    async fn listen_all_normal_secret_still_binds_all_interfaces() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                listen_all: true,
                secret: Some("listen-all-normal-secret-16".to_string()),
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("normal secret + listen_all must start: {e}"));
        assert!(
            server.local_addr.ip().is_unspecified(),
            "listen_all binds all interfaces: {}",
            server.local_addr
        );
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    // ---- Tightening the /metrics and WS event-stream anonymous faces under listen-all ----

    /// Shared secret for the gated form (≥16 chars, clear of the weak-credential warning).
    const SEC03_SECRET: &str = "sec03-listen-all-secret";

    /// Gated-form config: listen_all + secret-only (no Basic) — the fix
    /// path recommended by the combined-guard error text (the Basic gate is
    /// always-true in this form).
    fn sec03_listen_all_secret_cfg() -> RpcConfig {
        RpcConfig {
            port: 0,
            listen_all: true,
            secret: Some(SEC03_SECRET.to_string()),
            ..Default::default()
        }
    }

    /// E2E access address: listen_all binds 0.0.0.0:port — connect via the
    /// loopback address to the same listener (a test process cannot make a
    /// real remote connection; the credential/event gates do not special-
    /// case the source, so loopback meets the same gate).
    fn loopback_of(server: &ServerHandle) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server.local_addr.port())
    }

    /// Torrent variant with a different pieces marker → a different
    /// infohash (a second add of the same identity is refused as a
    /// duplicate download; triggering a second event needs a distinct
    /// task).
    fn minimal_v1_torrent_with_pieces(marker: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(
            b"d8:announce27:http://127.0.0.1:1/announce4:infod6:lengthi32e4:name5:w.bin12:piece lengthi16384e6:pieces20:",
        );
        v.extend_from_slice(&[marker; 20]);
        v.extend_from_slice(b"ee");
        v
    }

    /// listen_all + secret-only: /metrics requires `Authorization: Bearer
    /// <secret>` — anonymous gets 401 (defect shape: metrics_gate only
    /// mounted basic_gate, always true when basic=None → anonymous 200,
    /// leaking exact versions, task counts, and method usage on 0.0.0.0);
    /// the correct Bearer gets 200.
    #[tokio::test]
    async fn metrics_bearer_gate_in_listen_all_secret_only_form() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            sec03_listen_all_secret_cfg(),
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("listen_all + secret must start: {e}"));
        let addr = loopback_of(&server);

        // Anonymous → 401 + Bearer challenge.
        let (status, head, body) = http_roundtrip(
            addr,
            &format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 401, "anonymous metrics over listen-all: {body}");
        assert!(
            head.to_ascii_lowercase()
                .contains("www-authenticate: bearer"),
            "bearer challenge: {head}"
        );

        // Correct Bearer → 200 metrics text.
        let (status, head, body) = http_roundtrip(
            addr,
            &format!(
                "GET /metrics HTTP/1.1\r\nHost: {addr}\r\n\
                 Authorization: Bearer {SEC03_SECRET}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(status, 200, "bearer metrics: {body}");
        assert!(head.contains("text/plain"), "content type: {head}");
        assert!(body.contains("taiji_"), "prometheus body: {body}");

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// listen_all + secret-only: WS event-stream subscription waits for
    /// the first Text message with a valid token — after upgrading without
    /// a token, no event frame may arrive (defect shape: subscribing at
    /// upgrade let anonymous connections keep receiving
    /// onDownloadStart/Error frames — a download-behavior profile); after a
    /// valid token, delivery resumes.
    #[tokio::test]
    async fn ws_event_stream_gated_until_first_valid_token() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let session = Arc::new(session);
        let session_for_rpc = Arc::clone(&session);
        let shutdown = CancellationToken::new();
        let server = serve(
            sec03_listen_all_secret_cfg(),
            Arc::clone(&session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("listen_all + secret must start: {e}"));
        let addr = loopback_of(&server);
        // The anonymous upgrade still passes (no Origin + no Basic) — the
        // event stream is the face being tightened.
        let (mut sock, head) = ws_handshake_raw(addr, "").await;
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "upgrade passes origin+basic face: {head}"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Trigger an event (activate a torrent via the session handle →
        // onDownloadStart) — no frame may arrive without a token.
        let dir = std::env::temp_dir().join(format!("sec03-ws-{}", std::process::id()));
        let torrent = minimal_v1_torrent();
        let _gid = process_call_via_session(
            &session_for_rpc,
            serde_json::json!([base64_of(&torrent), [], {"dir": dir.display().to_string()}]),
        )
        .await
        .unwrap_or_else(|e| panic!("addTorrent failed: {e}"));
        let (downlink, closed) = read_until_eof_within(&mut sock, Duration::from_millis(800)).await;
        assert!(
            downlink.is_empty(),
            "no event frame before first valid token: {}",
            String::from_utf8_lossy(&downlink)
        );
        assert!(!closed, "connection stays open while awaiting token");

        // First valid-token message → through the gate (subscription +
        // regular reply; event frames and the reply may interleave —
        // converge on the getVersion string).
        write_masked_text_frame(
            &mut sock,
            &format!(r#"{{"id":1,"method":"getVersion","params":["token:{SEC03_SECRET}"]}}"#),
        )
        .await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let frame = read_ws_text_frame(&mut sock).await;
            if frame.contains("taiji/") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "first message answer never arrived, got: {frame}"
            );
        }

        // Subscription active: new events are received again (variant
        // infohash — an independent second task).
        let torrent2 = minimal_v1_torrent_with_pieces(0xAC);
        let _gid2 = process_call_via_session(
            &session_for_rpc,
            serde_json::json!([
                base64_of(&torrent2),
                [],
                {"dir": dir.join("second").display().to_string()}
            ]),
        )
        .await
        .unwrap_or_else(|e| panic!("second addTorrent failed: {e}"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let frame = read_ws_text_frame(&mut sock).await;
            if frame.contains("taiji.onDownloadStart") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "event frame after auth never arrived, got: {frame}"
            );
        }

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Disconnect face: in the gated form an invalid first-token message
    /// consumes the 1s unauthorized delay, then disconnects with no JSON-RPC
    /// reply (a bare disconnect must not bypass the delay —
    /// reconnect-and-guess is still throttled to 1s per attempt).
    #[tokio::test]
    async fn ws_invalid_first_token_disconnects_in_gated_form() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            sec03_listen_all_secret_cfg(),
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("listen_all + secret must start: {e}"));
        let addr = loopback_of(&server);
        let (mut sock, head) = ws_handshake_raw(addr, "").await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        tokio::time::sleep(Duration::from_millis(150)).await;

        let t0 = Instant::now();
        write_masked_text_frame(
            &mut sock,
            r#"{"id":1,"method":"getVersion","params":["token:wrong"]}"#,
        )
        .await;
        let (downlink, closed) = read_until_eof_within(&mut sock, Duration::from_secs(5)).await;
        assert!(
            closed,
            "invalid first token must disconnect, downlink: {}",
            String::from_utf8_lossy(&downlink)
        );
        assert!(
            !String::from_utf8_lossy(&downlink).contains("Unauthorized"),
            "no JSON-RPC reply on gated disconnect: {}",
            String::from_utf8_lossy(&downlink)
        );
        assert!(
            t0.elapsed() >= Duration::from_millis(900),
            "1s unauthorized delay consumed before close: {:?}",
            t0.elapsed()
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// Contrast (zero regression): non-listen_all (loopback) + secret-only
    /// — /metrics stays anonymously 200 and WS subscribes at upgrade (no
    /// token needed; current behavior kept, matching aria2).
    #[tokio::test]
    async fn loopback_secret_only_keeps_anonymous_metrics_and_ws_events() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let session = Arc::new(session);
        let session_for_rpc = Arc::clone(&session);
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                secret: Some(SEC03_SECRET.to_string()),
                ..Default::default()
            },
            Arc::clone(&session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;

        // /metrics anonymous 200 (loopback behavior kept).
        let (status, body) = get_metrics_text(addr).await;
        assert_eq!(status, 200, "loopback metrics stays anonymous: {body}");
        assert!(body.contains("taiji_"), "{body}");

        // WS subscribes at upgrade: event frames arrive without any message sent.
        let (mut sock, head) = ws_handshake_raw(addr, "").await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        tokio::time::sleep(Duration::from_millis(150)).await;
        let dir = std::env::temp_dir().join(format!("sec03-lo-{}", std::process::id()));
        let torrent = minimal_v1_torrent();
        let _gid = process_call_via_session(
            &session_for_rpc,
            serde_json::json!([base64_of(&torrent), [], {"dir": dir.display().to_string()}]),
        )
        .await
        .unwrap_or_else(|e| panic!("addTorrent failed: {e}"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let frame = read_ws_text_frame(&mut sock).await;
            if frame.contains("taiji.onDownloadStart") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "loopback event frame without token never arrived"
            );
        }

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Gated-form predicate covers user-only Basic + WS frame-cap alignment ----

    /// Shared secret for the gated form (≥16 chars, clear of the weak-credential warning).
    const SEC23_SECRET: &str = "sec23-user-only-secret";

    /// Gated-form config: listen_all + secret + user-only Basic
    /// (--rpc-user set, --rpc-passwd unset → the password slot is None and
    /// unchecked, auth.rs authorize's `password_tag.is_none_or`). Startup
    /// passes (the secret counts as a usable credential for the combined
    /// guard), but the defect-state `listen_all_secret_only` required
    /// `basic.is_none` — in this form /metrics and the WS event stream
    /// were not guarded by the secret.
    fn sec23_listen_all_user_only_cfg() -> RpcConfig {
        RpcConfig {
            port: 0,
            listen_all: true,
            secret: Some(SEC23_SECRET.to_string()),
            rpc_user: Some("u".to_string()),
            ..Default::default()
        }
    }

    /// listen_all + secret + user-only Basic: the only /metrics gate is
    /// Bearer<secret> — user-only Basic alone (knowing the user name passes
    /// the Basic transport gate, the password is unchecked; names like
    /// admin/u are low-entropy guessable) → 401 (defect state: the
    /// predicate required basic.is_none, so the Bearer gate never armed
    /// and returned 200); the correct Bearer → 200 (defect state: the Basic
    /// gate 401'd it on scheme).
    #[tokio::test]
    async fn metrics_bearer_gate_in_listen_all_user_only_basic_form() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            sec23_listen_all_user_only_cfg(),
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("listen_all + secret + user-only basic must start: {e}"));
        let addr = loopback_of(&server);

        // user-only Basic alone (any password — the slot is unchecked) → 401.
        let (status, head, body) = http_roundtrip(
            addr,
            &format!(
                "GET /metrics HTTP/1.1\r\nHost: {addr}\r\n\
                 Authorization: Basic {}\r\nConnection: close\r\n\r\n",
                base64_of(b"u:guessed-wrong-password")
            ),
        )
        .await;
        assert_eq!(status, 401, "user-only basic must not open metrics: {body}");
        assert!(
            head.to_ascii_lowercase()
                .contains("www-authenticate: bearer"),
            "bearer challenge: {head}"
        );

        // Correct Bearer → 200 metrics text.
        let (status, head, body) = http_roundtrip(
            addr,
            &format!(
                "GET /metrics HTTP/1.1\r\nHost: {addr}\r\n\
                 Authorization: Bearer {SEC23_SECRET}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(status, 200, "bearer metrics: {body}");
        assert!(head.contains("text/plain"), "content type: {head}");
        assert!(body.contains("taiji_"), "prometheus body: {body}");

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    /// Same form, WS event stream: subscription waits for the first Text
    /// message with a valid token — after a user-only Basic upgrade (the
    /// Basic transport gate passes as usual) with no token, no event frame
    /// may arrive (defect state: the predicate never armed, subscribing at
    /// upgrade — onDownloadStart/Error profile download behavior); after a
    /// valid token, delivery resumes.
    #[tokio::test]
    async fn ws_event_stream_gated_until_first_token_in_user_only_basic_form() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let session = Arc::new(session);
        let session_for_rpc = Arc::clone(&session);
        let shutdown = CancellationToken::new();
        let server = serve(
            sec23_listen_all_user_only_cfg(),
            Arc::clone(&session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("listen_all + secret + user-only basic must start: {e}"));
        let addr = loopback_of(&server);
        // The user-only Basic upgrade still passes (Basic transport gate:
        // knowing the user name suffices) — the event stream is the face
        // being tightened.
        let (mut sock, head) = ws_handshake_raw(
            addr,
            &format!("Authorization: Basic {}\r\n", base64_of(b"u:any-password")),
        )
        .await;
        assert!(
            head.starts_with("HTTP/1.1 101"),
            "upgrade passes basic face: {head}"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Trigger an event (activate a torrent via the session handle →
        // onDownloadStart) — no frame may arrive without a token.
        let dir = std::env::temp_dir().join(format!("sec23-ws-{}", std::process::id()));
        let torrent = minimal_v1_torrent();
        let _gid = process_call_via_session(
            &session_for_rpc,
            serde_json::json!([base64_of(&torrent), [], {"dir": dir.display().to_string()}]),
        )
        .await
        .unwrap_or_else(|e| panic!("addTorrent failed: {e}"));
        let (downlink, closed) = read_until_eof_within(&mut sock, Duration::from_millis(800)).await;
        assert!(
            downlink.is_empty(),
            "no event frame before first valid token: {}",
            String::from_utf8_lossy(&downlink)
        );
        assert!(!closed, "connection stays open while awaiting token");

        // First valid-token message → through the gate (subscription +
        // regular reply; event frames and the reply may interleave —
        // converge on the getVersion string).
        write_masked_text_frame(
            &mut sock,
            &format!(r#"{{"id":1,"method":"getVersion","params":["token:{SEC23_SECRET}"]}}"#),
        )
        .await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let frame = read_ws_text_frame(&mut sock).await;
            if frame.contains("taiji/") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "first message answer never arrived, got: {frame}"
            );
        }

        // Subscription active: new events are received again (variant
        // infohash — an independent second task).
        let torrent2 = minimal_v1_torrent_with_pieces(0xAD);
        let _gid2 = process_call_via_session(
            &session_for_rpc,
            serde_json::json!([
                base64_of(&torrent2),
                [],
                {"dir": dir.join("second").display().to_string()}
            ]),
        )
        .await
        .unwrap_or_else(|e| panic!("second addTorrent failed: {e}"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let frame = read_ws_text_frame(&mut sock).await;
            if frame.contains("taiji.onDownloadStart") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "event frame after auth never arrived, got: {frame}"
            );
        }

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WS upgrades also set `max_frame_size`: with
    /// `--rpc-max-request-size` > 16MiB, a single-frame 16MiB+1 message
    /// (≤ max_request_size, answered at the same size over HTTP) must reach
    /// the application layer and get the -32700 parse error, never silently
    /// disconnected by tungstenite's default 16MiB frame cap (defect state:
    /// only max_message_size was set, so the frame cap stayed default — an
    /// inter-face asymmetry). The payload is non-JSON text: past the frame
    /// cap it always answers -32700, decoupling the assertion from parse
    /// results.
    #[tokio::test]
    async fn ws_single_frame_over_16mib_within_max_request_size_is_answered() {
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                max_request_size: 17 * 1024 * 1024,
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;
        let (mut sock, head) = ws_handshake_raw(addr, "").await;
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Single frame of 16MiB+1 (> the default 16MiB frame cap, ≤ the
        // 17MiB max_request_size): best-effort write — in the defect state
        // the server disconnects at the frame header and a client-side
        // EPIPE mid-write is not an assertion point (the assertion is the
        // downlink reply).
        let payload = "x".repeat((16 << 20) + 1);
        let frame = masked_text_frame_bytes(&payload);
        write_frame_best_effort(&mut sock, &frame).await;

        // Fixed state: the frame passes the cap → app-layer parse failure
        // → a -32700 text reply. Defect state: rejected at the frame
        // header → disconnect with no reply (read_ws_text_frame panics on
        // EOF).
        let reply = read_ws_text_frame(&mut sock).await;
        assert!(
            reply.contains("-32700"),
            "single frame within --rpc-max-request-size must be answered at the \
             application layer, got: {reply}"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), actor_join).await;
    }

    // ---- recovery extension event face ----

    /// v2-only layer-missing torrent (no top-level piece layers — the
    /// parser downgrades to layer_missing; 16384 piece length × 40000B = a
    /// multi-piece file, registering recovery bookkeeping). Hand-rolled
    /// bencode (test-only implementation).
    fn minimal_v2_layer_missing_torrent() -> Vec<u8> {
        let root = [0x77u8; 32];
        let mut v = Vec::new();
        v.extend_from_slice(b"d8:announce27:http://127.0.0.1:1/announce4:infod");
        // file tree → { "v2.bin": { "": { length, pieces root } } }
        v.extend_from_slice(b"9:file treed6:v2.bind0:d6:lengthi40000e11:pieces root32:");
        v.extend_from_slice(&root);
        // Close: leaf dict + "" wrapper + file tree dict (key order
        // file tree < meta version < piece length, strict bencode order).
        v.extend_from_slice(b"eee");
        v.extend_from_slice(b"12:meta versioni2e12:piece lengthi16384e");
        v.extend_from_slice(b"ee");
        v
    }

    /// Extension event frame snapshot: same envelope as the six events;
    /// method names = the frozen taiji.* extensions; params[0] = {gid,
    /// files[, status]} — files = 1-based file-order string array (numbers
    /// as strings); completed adds status ("ready" — no failure terminal
    /// state exists); no id key (notification, not response).
    #[test]
    fn recovery_frames_match_extension_envelope() {
        let gid = taiji_core::gid::Gid::from_u64(0x8000_0000_0000_0042);
        for (kind, method, expect_status) in [
            (RecoveryEventKind::Started, "taiji.recoveryStarted", false),
            (
                RecoveryEventKind::Completed,
                "taiji.recoveryCompleted",
                true,
            ),
        ] {
            let ev = RecoveryEvent {
                gid,
                kind,
                files: vec![1, 3],
            };
            let frame = recovery_notification_frame(&ev);
            let v: serde_json::Value = serde_json::from_str(&frame)
                .unwrap_or_else(|e| panic!("frame must be valid JSON: {e}"));
            let obj = v.as_object().unwrap_or_else(|| panic!("dict: {frame}"));
            assert_eq!(obj.len(), 3, "exactly jsonrpc/method/params: {frame}");
            assert_eq!(v["jsonrpc"], "2.0");
            assert_eq!(v["method"], method, "extension event name for {kind:?}");
            assert!(method.starts_with("taiji."), "namespace policy: {method}");
            let params = v["params"]
                .as_array()
                .unwrap_or_else(|| panic!("params list: {frame}"));
            assert_eq!(params.len(), 1, "params = a single-element [dict]");
            let entry = params
                .first()
                .and_then(|e| e.as_object())
                .unwrap_or_else(|| panic!("params[0] dict: {frame}"));
            assert_eq!(
                entry.get("gid").and_then(|g| g.as_str()),
                Some(gid.to_string().as_str())
            );
            let files = entry
                .get("files")
                .and_then(|f| f.as_array())
                .unwrap_or_else(|| panic!("files array: {frame}"));
            assert_eq!(
                files,
                &vec![json!("1"), json!("3")],
                "files = a string array in 1-based client file order: {frame}"
            );
            let got_status = entry.get("status").and_then(|s| s.as_str());
            if expect_status {
                assert_eq!(
                    got_status,
                    Some("ready"),
                    "completed carries a status: {frame}"
                );
            } else {
                assert!(got_status.is_none(), "started has no status key: {frame}");
            }
            assert!(
                obj.get("id").is_none(),
                "notification carries no id: {frame}"
            );
        }
    }

    /// E2E: a real WS upgrade → a layer-missing v2 torrent activates → the
    /// client receives both `taiji.onDownloadStart` (canonical six-event
    /// face) and `taiji.recoveryStarted` (extension face);
    /// getFiles projects `recoveryStatus: "layer_missing"` for the
    /// layer-missing file (visible while awaiting hash recovery).
    #[tokio::test]
    async fn ws_upgrade_receives_recovery_started_for_layer_missing_torrent() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (session, _actor_join) = taiji_core::session::SessionActor::spawn();
        let session = Arc::new(session);
        let session_for_rpc = Arc::clone(&session);
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                ..Default::default()
            },
            session,
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));

        let mut sock = tokio::net::TcpStream::connect(server.local_addr)
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        let req = "GET /jsonrpc HTTP/1.1\r\n\
                   Host: localhost\r\n\
                   Upgrade: websocket\r\n\
                   Connection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                   Sec-WebSocket-Version: 13\r\n\r\n";
        sock.write_all(req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("handshake write: {e}"));
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = sock
                .read(&mut byte)
                .await
                .unwrap_or_else(|e| panic!("handshake read: {e}"));
            if n == 0 {
                panic!("connection closed during handshake");
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        assert!(head.starts_with("HTTP/1.1 101"), "upgrade response: {head}");
        // Upgrade handling is async with the 101 write — leave a window so
        // the subscription lands first.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Activate the layer-missing v2 torrent (dead tracker — no peers
        // needed; activation emits immediately).
        let dir = std::env::temp_dir().join(format!("bh-p136-ws-{}", std::process::id()));
        let torrent = minimal_v2_layer_missing_torrent();
        let gid = match process_call_via_session(
            &session_for_rpc,
            serde_json::json!([base64_of(&torrent), [], {"dir": dir.display().to_string()}]),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => panic!("addTorrent failed: {e}"),
        };

        // Collect frames: Start (six-event face) + recoveryStarted
        // (extension face) must both arrive (emission order races between
        // the engine assembly point and the actor publish point — assert as
        // a set).
        let mut seen: Vec<String> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while !seen.contains(&"taiji.recoveryStarted".to_string())
            || !seen.contains(&"taiji.onDownloadStart".to_string())
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timeout waiting for notifications, got {seen:?}"
            );
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = match tokio::time::timeout(remaining, read_ws_text_frame(&mut sock)).await {
                Ok(f) => f,
                Err(_) => panic!("timeout waiting for notifications, got {seen:?}"),
            };
            let v: serde_json::Value = serde_json::from_str(&frame)
                .unwrap_or_else(|e| panic!("frame must be valid JSON: {e}"));
            let method = v["method"].as_str().unwrap_or_default().to_string();
            if method == "taiji.recoveryStarted" {
                // Extension envelope payload assertions (files = 1-based file order).
                let entry = &v["params"][0];
                assert_eq!(entry["gid"], json!(gid));
                assert_eq!(
                    entry["files"],
                    json!(["1"]),
                    "the layer-missing file set (1-based)"
                );
                assert!(entry.get("status").is_none(), "started has no status key");
            }
            seen.push(method);
        }

        // getFiles layer-missing projection: recoveryStatus =
        // "layer_missing" (visible while awaiting hash recovery;
        // completedLength = 0 — the gated state is rendered accurately).
        // Task activation and engine-query readiness have a window —
        // bounded retry (queried via SessionCommand; the engine snapshot is
        // the projection's single source of truth).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let reply = loop {
            match session_for_rpc
                .call(taiji_core::session::SessionCommand::GetFiles { gid: gid.clone() })
                .await
            {
                Ok(taiji_core::session::CommandReply::Files(fs)) => {
                    let projected = fs.iter().any(|f| f.recovery.is_some());
                    if projected {
                        break fs;
                    }
                }
                Ok(other) => panic!("getFiles unexpected reply: {other:?}"),
                Err(e) => panic!("getFiles failed: {e:?}"),
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timeout waiting for getFiles recovery projection"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(reply.len(), 1, "single-file task");
        let f = &reply[0];
        assert_eq!(f.index, 1);
        assert_eq!(
            f.recovery,
            Some("layer_missing"),
            "layer-missing projection: {f:?}"
        );
        assert_eq!(
            f.completed_length, 0,
            "the gated layer-missing file reports zero completed (honestly)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- --rpc-secure TLS listener (domain B) ----

    /// Test certificates issued by a local mini-CA (the same generation
    /// scheme as the taiji-http mtls_mock — ECDSA P-256, SAN
    /// localhost/127.0.0.1/::1, not real credentials; copies live in
    /// `tests/fixtures/tls/`, with the include resolving one level up from
    /// src/).
    const TLS_CA_PEM: &[u8] = include_bytes!("../tests/fixtures/tls/ca_cert.pem");
    const TLS_SERVER_CERT_PEM: &[u8] = include_bytes!("../tests/fixtures/tls/server_cert.pem");
    const TLS_SERVER_KEY_PEM: &[u8] = include_bytes!("../tests/fixtures/tls/server_key.pem");

    fn tls_fixture_paths(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("taiji-rpc-tls-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let cert = dir.join("server_cert.pem");
        let key = dir.join("server_key.pem");
        std::fs::write(&cert, TLS_SERVER_CERT_PEM).unwrap_or_else(|e| panic!("write cert: {e}"));
        std::fs::write(&key, TLS_SERVER_KEY_PEM).unwrap_or_else(|e| panic!("write key: {e}"));
        (cert, key)
    }

    /// TLS client connection (tokio-rustls; roots = the test CA — the
    /// server certificate SAN covers 127.0.0.1, so an IP ServerName
    /// connects directly). Returns (TLS stream, peer address).
    async fn tls_connect(
        addr: SocketAddr,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        use rustls_pki_types::ServerName;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_client_config()));
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect: {e}"));
        // The server certificate SAN covers IP:127.0.0.1 — an IP
        // ServerName connects directly (pki-types
        // `From<std::net::IpAddr> for ServerName`).
        let name = ServerName::from(addr.ip());
        connector
            .connect(name, tcp)
            .await
            .unwrap_or_else(|e| panic!("tls connect: {e}"))
    }

    /// TLS client config (roots = the test CA; no client certificate —
    /// one-way server authentication, the same shape as the production
    /// face).
    fn tls_client_config() -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(TLS_CA_PEM) {
            roots
                .add(cert.unwrap_or_else(|e| panic!("root ca: {e}")))
                .unwrap_or_else(|e| panic!("add root: {e}"));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|e| panic!("versions: {e}"))
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    /// e2e: the `--rpc-secure` shape — TLS handshake -> a JSON-RPC POST
    /// round trip equivalent to the plaintext one (auth gates / method
    /// faces unchanged across transports) -> graceful shutdown drains and
    /// exits.
    #[tokio::test]
    async fn rpc_secure_tls_jsonrpc_roundtrip_and_graceful_shutdown() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (cert, key) = tls_fixture_paths("e2e");
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                secure: true,
                certificate: Some(cert),
                private_key: Some(key),
                ..Default::default()
            },
            Arc::new(session),
            shutdown.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;

        let mut tls = tls_connect(addr).await;
        let body = r#"{"id":7,"method":"getVersion"}"#;
        let req = format!(
            "POST /jsonrpc HTTP/1.1\r\nHost: {addr}\r\n\
             Content-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
        let resp = String::from_utf8_lossy(&resp);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "got {resp}");
        let v: serde_json::Value =
            serde_json::from_str(resp.split("\r\n\r\n").nth(1).unwrap_or(""))
                .unwrap_or_else(|e| panic!("body must be json: {e}"));
        assert_eq!(v["id"], json!(7));
        assert!(
            v["result"]["version"]
                .as_str()
                .unwrap_or("")
                .starts_with("taiji/"),
            "getVersion round-trips over TLS: {v}"
        );
        drop(tls);

        // Shutdown semantics are identical across transports: token cancel
        // -> the TLS accept loop exits -> join drains.
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), server.join())
            .await
            .unwrap_or_else(|_| panic!("tls server join timed out"))
            .unwrap_or_else(|e| panic!("join: {e}"));
        actor_join.abort();
    }

    /// WS upgrade fidelity across transports: an RFC6455 handshake over
    /// TLS plus one getVersion text-frame round trip (the upgrade branch
    /// of `serve_connection_with_upgrades` — the TLS listener does not
    /// shrink the WS face).
    #[tokio::test]
    async fn rpc_secure_tls_websocket_upgrade_roundtrip() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let (cert, key) = tls_fixture_paths("ws");
        let (session, actor_join) = taiji_core::session::SessionActor::spawn();
        let shutdown = CancellationToken::new();
        let server = serve(
            RpcConfig {
                port: 0,
                secure: true,
                certificate: Some(cert),
                private_key: Some(key),
                ..Default::default()
            },
            Arc::new(session),
            shutdown,
        )
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = server.local_addr;

        let mut tls = tls_connect(addr).await;
        let req = format!(
            "GET /jsonrpc HTTP/1.1\r\nHost: {addr}\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        tls.write_all(req.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = tls
                .read(&mut byte)
                .await
                .unwrap_or_else(|e| panic!("handshake read: {e}"));
            if n == 0 {
                panic!("connection closed during ws handshake");
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"),
            "the WS upgrade must complete over TLS: {}",
            String::from_utf8_lossy(&head)
        );
        // One masked text frame (getVersion) -> an unmasked frame reply
        // (server frames carry no mask).
        let text = r#"{"id":1,"method":"getVersion"}"#;
        let mut frame = Vec::new();
        frame.push(0x81);
        frame.push(0x80 | text.len() as u8);
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        frame.extend(
            text.bytes()
                .enumerate()
                .map(|(i, b)| b ^ [0x11, 0x22, 0x33, 0x44][i % 4]),
        );
        tls.write_all(&frame)
            .await
            .unwrap_or_else(|e| panic!("frame write: {e}"));
        // Read one server text frame (RFC6455; the three length states are
        // the same as read_ws_text_frame — the getVersion reply carries
        // enabledFeatures, so past 125B the 16-bit extended length
        // applies).
        let mut hdr = [0u8; 2];
        tls.read_exact(&mut hdr)
            .await
            .unwrap_or_else(|e| panic!("frame header: {e}"));
        assert_eq!(hdr[0] & 0x0f, 0x1, "text frame opcode");
        assert_eq!(hdr[0] & 0x80, 0x80, "FIN set");
        assert_eq!(hdr[1] & 0x80, 0, "server frames are unmasked");
        let len = match (hdr[1] & 0x7f) as usize {
            126 => {
                let mut b = [0u8; 2];
                tls.read_exact(&mut b)
                    .await
                    .unwrap_or_else(|e| panic!("len16: {e}"));
                u16::from_be_bytes(b) as usize
            }
            127 => {
                let mut b = [0u8; 8];
                tls.read_exact(&mut b)
                    .await
                    .unwrap_or_else(|e| panic!("len64: {e}"));
                u64::from_be_bytes(b) as usize
            }
            n => n,
        };
        let mut payload = vec![0u8; len];
        tls.read_exact(&mut payload)
            .await
            .unwrap_or_else(|e| panic!("payload read: {e}"));
        let v: serde_json::Value =
            serde_json::from_slice(&payload).unwrap_or_else(|e| panic!("ws frame json: {e}"));
        assert_eq!(v["id"], json!(1));
        assert!(
            v["result"]["version"]
                .as_str()
                .unwrap_or("")
                .starts_with("taiji/"),
            "WS over TLS round-trips: {v}"
        );
        actor_join.abort();
    }

    /// Pairing-guard arms (fail-closed): secure with the certificate or
    /// the private key missing is refused; certificate/private key given
    /// while secure is off is refused; the plaintext default shape is
    /// unaffected (the existing suite is a full regression).
    #[tokio::test]
    async fn rpc_tls_pairing_guards_fail_closed() {
        let (session, _actor_join) = taiji_core::session::SessionActor::spawn();
        let session = Arc::new(session);
        let shutdown = CancellationToken::new();
        let (cert, key) = tls_fixture_paths("guards");

        // secure=true with the certificate missing -> refuse.
        let err = match serve(
            RpcConfig {
                port: 0,
                secure: true,
                private_key: Some(key.clone()),
                ..Default::default()
            },
            Arc::clone(&session),
            shutdown.clone(),
        )
        .await
        {
            Ok(_) => panic!("a missing certificate must be refused"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("--rpc-certificate"),
            "the message must point at the missing half: {err}"
        );

        // secure=true with the private key missing -> refuse.
        let err = match serve(
            RpcConfig {
                port: 0,
                secure: true,
                certificate: Some(cert.clone()),
                ..Default::default()
            },
            Arc::clone(&session),
            shutdown.clone(),
        )
        .await
        {
            Ok(_) => panic!("a missing private key must be refused"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("--rpc-private-key"),
            "the message must point at the missing half: {err}"
        );

        // Certificate/private key given while secure is off -> refuse
        // (silently ignoring security material violates explicitness).
        let err = match serve(
            RpcConfig {
                port: 0,
                secure: false,
                certificate: Some(cert.clone()),
                private_key: Some(key.clone()),
                ..Default::default()
            },
            Arc::clone(&session),
            shutdown.clone(),
        )
        .await
        {
            Ok(_) => panic!("certificates given without secure must be refused"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("--rpc-secure"),
            "the message must point at enabling secure: {err}"
        );

        // Bad PEM (a garbage file) -> the loading arm refuses.
        let bad_dir =
            std::env::temp_dir().join(format!("taiji-rpc-tls-bad-{}", std::process::id()));
        let bad = bad_dir.join("garbage.pem");
        std::fs::create_dir_all(&bad_dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        std::fs::write(&bad, "not a pem").unwrap_or_else(|e| panic!("write: {e}"));
        let err = match serve(
            RpcConfig {
                port: 0,
                secure: true,
                certificate: Some(bad),
                private_key: Some(key),
                ..Default::default()
            },
            Arc::clone(&session),
            shutdown,
        )
        .await
        {
            Ok(_) => panic!("a bad PEM must be refused"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
