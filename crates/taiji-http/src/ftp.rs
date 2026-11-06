//! FTP/FTPS transport adapter — the [`SegmentTransport`] implementation
//! for `ftp://` sources, built on suppaftp.
//!
//! Each extent fetch runs on one control connection (pooled checkout or
//! new): `REST <offset>` + `RETR <path>`, with the data channel via
//! PASV (IPv4) or EPSV (forced for IPv6 — PASV has no IPv6 semantics,
//! RFC 2428). A `REST 0` probe rejection (5xx) sets
//! [`FtpProbe::resume_supported`] = false and the scheduler degrades to
//! a single stream ([`crate::degraded::DegradedReason::FtpNoResume`]);
//! an offset fetch hitting a REST rejection returns
//! [`HttpError::FtpResumeUnsupported`]. TLS is explicit by default:
//! upgrade only when FEAT advertises `AUTH TLS` (AUTH TLS + PBSZ 0 +
//! PROT P, RFC 4217) — a server without the advertisement stays in
//! plaintext with a warning (capability negotiation, not a silent
//! downgrade); implicit TLS (port 990) via [`FtpTlsMode::Implicit`].
//! PASV/EPSV reply addresses are never trusted as dial targets
//! ([`PasvAddressPolicy`], SSRF hardening). Control connections are
//! pooled across extents (`--ftp-reuse-connection`, default true) and
//! get a NOOP liveness probe before checkout; a mid-extent truncation
//! drains the completion reply and demotes a desynced connection to
//! single-use.
//!
//! The transport only writes bytes into the sink and does no block
//! accounting — `complete_block` is the ExtentCoordinator's single
//! serial decision point and the transport has no authority to call
//! it; `SegId` is a zero placeholder (the frozen trait signature has
//! no identity parameter).
//!
//! Upstream anchor mapping: docs/design/http.md

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use futures::future::BoxFuture;
use rustls_platform_verifier::Verifier;
use suppaftp::Status;
use suppaftp::rustls;
use suppaftp::rustls::DigitallySignedStruct;
use suppaftp::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use suppaftp::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use suppaftp::tokio::{AsyncRustlsConnector, AsyncRustlsFtpStream, AsyncRustlsStream};
use suppaftp::tokio_rustls::TlsConnector;
use suppaftp::types::{FileType, FtpError, Mode};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::error::{HttpError, Result};
use crate::traits::{AuthScheme, RequestCtx, ResumeValidator, SegmentSink, SegmentTransport};
use taiji_io::dns::{ResolveError, SharedDns};

/// Single data-channel read chunk (64 KiB; the sink write granularity,
/// not the persisted block-grid size).
pub const DATA_CHUNK: usize = 64 * 1024;
/// Default FTP port (RFC 959).
pub const DEFAULT_FTP_PORT: u16 = 21;
/// Implicit FTPS port.
pub const IMPLICIT_FTPS_PORT: u16 = 990;
/// Idle-pool cap: idle connections beyond this are dropped.
pub const MAX_IDLE_POOL: usize = 8;

/// Data-channel stream type (one associated type for plaintext and TLS
/// sessions; whether suppaftp wraps the data channel in TLS is decided
/// by the session's `tls_ctx`, transparent to the read side).
type DataStream = suppaftp::tokio::TransferStream<AsyncRustlsStream>;

/// FTPS mode (`--ftp-ssl=none|auth (default)|implicit`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FtpTlsMode {
    /// Plaintext FTP.
    None,
    /// Explicit TLS (default): upgrade only when FEAT advertises `AUTH TLS`.
    #[default]
    Explicit,
    /// Implicit TLS: handshake on connect (default port 990).
    Implicit,
}

/// PASV/EPSV data-connection address policy (SSRF hardening).
///
/// Motivation: suppaftp 12 by default dials the 227 reply's IP:port
/// directly with no peer-consistency check — a malicious or MITM'd FTP
/// source can point the client at any host:port (including the
/// cloud-metadata endpoint 169.254.169.254). The EPSV path is immune
/// (suppaftp synthesizes the address from the control-peer IP plus the
/// reply port).
///
/// Option surface: `--ftp-pasv-address-check=peer|strict|off` (default
/// peer; value grammar in this enum's `FromStr`). Wiring: the config
/// carries [`FtpConfig::pasv_policy`] into every
/// [`FtpTransport::for_uri`] construction site (the task side projects
/// through taiji-core `HttpTaskOpts::to_ftp_config`);
/// [`FtpTransport::with_pasv_policy`] is the explicit override.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PasvAddressPolicy {
    /// Dial only the control connection's peer: the reply IP is
    /// replaced by the control peer, the reply port kept (default).
    /// Matches aria2 (`FtpNegotiationCommand.cc` `preparePasvConnect`:
    /// data endpoint = control peer address + PASV port) and suppaftp
    /// `set_passive_nat_workaround(true)`. Cost: deployments whose data
    /// egress differs from the control peer (asymmetric NAT) do not
    /// work — switch to [`PasvAddressPolicy::DenyPrivate`].
    #[default]
    AlignPeer,
    /// Accept the reply IP, but reject private/loopback/link-local
    /// replies that differ from the control peer (the asymmetric-NAT
    /// face: cross-egress data connections pass, intranet/metadata
    /// redirects are rejected).
    DenyPrivate,
    /// No rewriting (the `off` escape hatch): the 227 reply IP:port is
    /// dialed as-is (suppaftp 12's native behavior). The whole peer
    /// decision face (intranet/metadata redirect defense) is off — a
    /// malicious or MITM'd reply can point the client anywhere; for
    /// trusted networks, explicitly chosen only.
    ReplyAsIs,
}

/// Option value grammar (`--ftp-pasv-address-check`) -> policy:
/// `peer`/`strict`/`off` exact lowercase match; out-of-domain values
/// are rejected with the canonical `taiji.option.invalid` (always
/// rejected, never truncated).
impl std::str::FromStr for PasvAddressPolicy {
    type Err = HttpError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "peer" => Ok(Self::AlignPeer),
            "strict" => Ok(Self::DenyPrivate),
            "off" => Ok(Self::ReplyAsIs),
            other => Err(HttpError::OptionInvalid {
                option: "--ftp-pasv-address-check",
                value: other.into(),
            }),
        }
    }
}

/// The PASV/EPSV reply-address decision: returns the actual dial
/// target; `Err` = a violating reply (a restricted-target redirect
/// under DenyPrivate).
pub fn resolve_data_target(
    policy: PasvAddressPolicy,
    reply: SocketAddr,
    peer: SocketAddr,
) -> std::result::Result<SocketAddr, FtpError> {
    match policy {
        PasvAddressPolicy::AlignPeer => Ok(SocketAddr::new(peer.ip(), reply.port())),
        PasvAddressPolicy::DenyPrivate => {
            if reply.ip() != peer.ip() && is_restricted_addr(reply.ip()) {
                return Err(FtpError::ConnectionError(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("passive reply target {reply} rejected (private/link-local redirect)"),
                )));
            }
            Ok(reply)
        }
        PasvAddressPolicy::ReplyAsIs => Ok(reply),
    }
}

/// Restricted address families (the DenyPrivate reject set): RFC 1918
/// private, loopback, link-local (169.254/16, fe80::/10), ULA
/// (fc00::/7), unspecified. A reply equal to the control peer is
/// already allowed at the call site (a peer legitimately living on an
/// intranet).
fn is_restricted_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_restricted_addr(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

/// FTP transport config (assembled at creation; the transport-side
/// projection of the option surface).
#[derive(Clone, Debug)]
pub struct FtpConfig {
    /// TLS mode (default explicit).
    pub tls: FtpTlsMode,
    /// Reuse the control connection across extents
    /// (`--ftp-reuse-connection`, default true).
    pub reuse_connection: bool,
    /// Connect timeout (`--connect-timeout`, default 60s; shared by DNS
    /// resolution, the control dial, and the data-connection dial).
    pub connect_timeout: Duration,
    /// Read idle timeout (`--timeout`, default 60s; control-plane
    /// commands and data-plane chunk reads share the same idle
    /// semantics).
    pub read_idle_timeout: Duration,
    /// Certificate verification on (`--check-certificate`, default
    /// true; disabling warns explicitly).
    pub check_certificate: bool,
    /// Task-level trusted CA certificates (DER; non-empty **replaces**
    /// the platform roots — aria2 `--ca-certificate` replacement
    /// semantics). Producer = taiji-core's DER snapshot at option
    /// parsing (`load_ca_certificates_der`, the PEM face); tests inject
    /// through the same slot (a self-signed test CA).
    pub extra_ca_certs_der: Vec<Vec<u8>>,
    /// PASV/EPSV data-connection address policy
    /// (`--ftp-pasv-address-check`, default
    /// [`PasvAddressPolicy::AlignPeer`]). Placed on the transport
    /// instance by `for_uri` at creation time; the single value-grammar
    /// source is [`PasvAddressPolicy`]'s `FromStr` (taiji-core
    /// `HttpTaskOpts::to_ftp_config` projects into the same slot).
    pub pasv_policy: PasvAddressPolicy,
}

impl Default for FtpConfig {
    fn default() -> Self {
        Self {
            tls: FtpTlsMode::Explicit,
            reuse_connection: true,
            connect_timeout: Duration::from_secs(60),
            read_idle_timeout: Duration::from_secs(60),
            check_certificate: true,
            extra_ca_certs_der: Vec::new(),
            pasv_policy: PasvAddressPolicy::default(),
        }
    }
}

/// Parsed FTP source URI (resolved once at [`FtpTransport::for_uri`]
/// creation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FtpUrl {
    /// Host (IP literal or domain; bracketed IPv6 already stripped).
    pub host: String,
    /// Port (an explicit URI port wins; default 21 — implicit TLS's 990
    /// is applied at dial time, the parse layer keeps the URI as
    /// written).
    pub port: u16,
    /// Directory part (empty = the login directory; absolute/relative
    /// form preserved).
    pub dir: String,
    /// File name (percent-decoding + charset fallback applied here).
    pub file: String,
    /// URI userinfo username (takes priority over `RequestCtx.auth`).
    pub user: Option<String>,
    /// URI userinfo password.
    pub password: Option<String>,
}

/// Parse `ftp://[user[:pass]@]host[:port][/path]` (ftp scheme only;
/// FTPS is expressed via [`FtpConfig::tls`], not a separate scheme).
///
/// Path split: everything before the last `/` is the directory, after
/// it the file name; a directory form (empty file name) has no RETR
/// target and is rejected at task level.
pub fn parse_ftp_url(uri: &str) -> Result<FtpUrl> {
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| HttpError::Ftp("uri missing scheme".into()))?;
    if !scheme.eq_ignore_ascii_case("ftp") {
        return Err(HttpError::Ftp(format!(
            "unsupported scheme {scheme:?} for ftp transport"
        )));
    }
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, String::new()),
    };
    // Userinfo is split at the last `@` (the host part allows no bare
    // `@`; IPv6 goes in brackets).
    let (user, password, hostport) = match authority.rsplit_once('@') {
        Some((creds, hp)) => {
            let (u, p) = match creds.split_once(':') {
                Some((u, p)) => (decode_ftp_path(u), decode_ftp_path(p)),
                None => (decode_ftp_path(creds), String::new()),
            };
            (Some(u), Some(p), hp)
        }
        None => (None, None, authority),
    };
    let (host, port) = split_host_port(hostport)?;
    if host.is_empty() {
        return Err(HttpError::Ftp("uri missing host".into()));
    }
    let (dir, file) = match path.rsplit_once('/') {
        Some((d, f)) => (decode_ftp_path(d), decode_ftp_path(f)),
        None => (String::new(), decode_ftp_path(&path)),
    };
    if file.is_empty() {
        return Err(HttpError::Ftp("uri path has no file component".into()));
    }
    Ok(FtpUrl {
        host,
        port: port.unwrap_or(DEFAULT_FTP_PORT),
        dir,
        file,
        user,
        password,
    })
}

/// Host/port split (bracketed IPv6 and bare multi-colon IPv6 forms).
fn split_host_port(hostport: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| HttpError::Ftp("unterminated ipv6 literal in ftp uri".into()))?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().map_err(|_| bad_port(p))?),
            None => None,
        };
        return Ok((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        // A multi-colon unbracketed "host:port" is unparseable — treat
        // it as bare IPv6.
        Some((_h, _p)) if _h.contains(':') => Ok((hostport.to_string(), None)),
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| bad_port(p))?;
            Ok((h.to_string(), Some(port)))
        }
        None => Ok((hostport.to_string(), None)),
    }
}

fn bad_port(p: &str) -> HttpError {
    HttpError::Ftp(format!("invalid port {p:?} in ftp uri"))
}

/// Percent-decoding (byte-faithful; `%XX` two hex digits, a stray `%`
/// kept literally).
pub fn percent_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            match bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                Some(b) => {
                    out.push(b);
                    i += 3;
                    continue;
                }
                None => out.push(bytes[i]),
            }
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    out
}

/// Bytes -> protocol-level String: UTF-8 first, Latin-1 fallback (fork
/// behavior). When the fallback fires, the wire bytes may deviate from
/// the original bytes via UTF-8 re-encoding (a known boundary).
pub fn decode_ftp_path_bytes(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::info!(target: "taiji::http::ftp",
                "ftp path is not valid utf-8; falling back to latin-1 interpretation");
            raw.iter().map(|&b| b as char).collect()
        }
    }
}

/// Percent-decoding + charset fallback in one step.
pub fn decode_ftp_path(raw: &str) -> String {
    decode_ftp_path_bytes(&percent_decode(raw))
}

/// Probe output: the validation verdict plus the scheduler routing
/// input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FtpProbe {
    /// Resume validation: the SIZE length is the authoritative total;
    /// `last_modified` is filled from MDTM (RFC 3659) in the same
    /// HTTP-date format as the HTTP Last-Modified (a single source for
    /// `--remote-time` parsing); FTP has no content-encoding concept,
    /// so `encoding_ok` is always true. SIZE unsupported (5xx family) =
    /// no authoritative total -> the
    /// [`crate::degraded::DegradedReason::NoTotalLength`] form.
    pub validator: ResumeValidator,
    /// The `REST 0` probe passed; false = REST rejected ->
    /// [`crate::degraded::
    /// DegradedReason::FtpNoResume`] (single-stream degradation, no
    /// bitmap, resume from zero).
    pub resume_supported: bool,
    /// The server's FEAT advertises UTF8.
    pub utf8: bool,
}

/// Idle-timeout wrapper for control-plane commands: timeouts and
/// protocol errors return in separate layers (the 5xx classification
/// for REST/SIZE happens at call sites, not through this error
/// mapping).
async fn timed<T>(
    budget: Duration,
    fut: impl std::future::Future<Output = std::result::Result<T, FtpError>>,
) -> std::result::Result<std::result::Result<T, FtpError>, HttpError> {
    match tokio::time::timeout(budget, fut).await {
        Ok(r) => Ok(r),
        Err(_) => {
            let e = HttpError::Ftp("read idle timeout".into());
            crate::error::note_http_error(&e);
            Err(e)
        }
    }
}

/// suppaftp error -> engine error. The payload keeps only the numeric
/// status code (reply bodies may echo paths or server banners and are
/// never passed through). Classification-seam feed point: the
/// connection/reset/TLS classes count into `taiji_http_errors_total`
/// via [`crate::error::note_http_error`] (protocol reply errors are not
/// counted — `error_class` returns None, and an uncounted class creates
/// no metric).
fn map_ftp_error(e: FtpError) -> HttpError {
    let mapped = match e {
        FtpError::UnexpectedResponse(resp) => {
            HttpError::Ftp(format!("unexpected server reply ({})", resp.status.code()))
        }
        FtpError::ConnectionError(io) => HttpError::Ftp(format!("connection: {io}")),
        FtpError::SecureError(detail) => HttpError::Ftp(format!("tls: {detail}")),
        FtpError::BadResponse => HttpError::Ftp("malformed control reply".into()),
        other => HttpError::Ftp(format!("ftp: {other}")),
    };
    crate::error::note_http_error(&mapped);
    mapped
}

/// Login failure (530 etc.) -> the unified auth-failure code (HTTP,
/// FTP, and SFTP failures share `taiji.auth.failed`).
fn map_login_error(e: FtpError) -> HttpError {
    match &e {
        FtpError::UnexpectedResponse(resp) if resp.status.code() == 530 => {
            HttpError::AuthFailed("ftp login rejected (530)".into())
        }
        _ => map_ftp_error(e),
    }
}

/// A server 5xx rejection (the REST-unsupported / SIZE-unsupported
/// predicate).
fn server_rejected(e: &FtpError) -> Option<u32> {
    match e {
        FtpError::UnexpectedResponse(resp) if resp.status.code() >= 500 => Some(resp.status.code()),
        _ => None,
    }
}

/// FTP transport instance: one instance is bound to one source URI (the
/// frozen trait signature takes no URL — transports are assembled per
/// source, and a multi-source task holds one each) and owns that
/// source's control-connection reuse pool.
pub struct FtpTransport {
    cfg: FtpConfig,
    url: FtpUrl,
    /// PASV/EPSV data-connection address policy (default peer
    /// alignment; configurable at assembly).
    pasv_policy: PasvAddressPolicy,
    /// Shared resolver (consumed by the resolve path; the process
    /// default instance carries the resolver stack's TTL cache + 30s
    /// resolve timeout, shared with the HTTP transport/tracker face —
    /// see the `taiji_io::dns` module docs. Tests inject a stub via
    /// [`Self::with_dns`] for offline coverage of DNS failure/timeout
    /// paths — real DNS is forbidden in tests).
    dns: Arc<SharedDns>,
    /// Idle control-connection pool (short critical sections; the lock
    /// is never held across an await).
    idle: Mutex<Vec<AsyncRustlsFtpStream>>,
}

impl std::fmt::Debug for FtpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FtpTransport")
            .field("url", &self.url)
            .field("pasv_policy", &self.pasv_policy)
            .finish()
    }
}

impl FtpTransport {
    /// Assemble: parse and freeze the source URI (once at creation).
    /// The PASV address policy lands from [`FtpConfig::pasv_policy`]
    /// (default peer alignment; the task-side wiring is taiji-core
    /// `HttpTaskOpts::to_ftp_config` projecting
    /// `--ftp-pasv-address-check`, value grammar in
    /// [`PasvAddressPolicy`]); the builder [`Self::with_pasv_policy`] is
    /// the explicit override.
    pub fn for_uri(cfg: FtpConfig, uri: &str) -> Result<Self> {
        Ok(Self {
            // The Copy read happens before the move of `cfg` (struct
            // literal fields evaluate in source order).
            pasv_policy: cfg.pasv_policy,
            cfg,
            url: parse_ftp_url(uri)?,
            dns: SharedDns::shared_default(),
            idle: Mutex::new(Vec::new()),
        })
    }

    /// Assembly point: the shared resolver instance (default = the
    /// process-level [`SharedDns::shared_default`]; tests inject a
    /// `SharedDns::with_resolver` stub — cache isolation and offline
    /// reproduction of DNS failure/timeout paths; real DNS is forbidden
    /// in tests).
    pub fn with_dns(mut self, dns: Arc<SharedDns>) -> Self {
        self.dns = dns;
        self
    }

    /// Assembly point: the PASV/EPSV data-connection address policy,
    /// all three states settable (`peer`/`strict`/`off` grammar in
    /// [`PasvAddressPolicy`]'s `FromStr`; the normal production path
    /// carries it via [`FtpConfig::pasv_policy`] — this builder is the
    /// explicit post-construction override).
    pub fn with_pasv_policy(mut self, policy: PasvAddressPolicy) -> Self {
        self.pasv_policy = policy;
        self
    }

    /// FTP probe: login -> TYPE I -> CWD -> SIZE -> `REST 0` probe ->
    /// FEAT (UTF8 recorded) -> MDTM (the `--remote-time` face). The
    /// dedicated connection never returns to the reuse pool (probing is
    /// low-frequency; closed with QUIT).
    pub async fn probe(&self, ctx: &RequestCtx) -> Result<FtpProbe> {
        let mut conn = self.dial().await?;
        let (user, pass) = self.credentials(ctx);
        let probe = async {
            timed(self.cfg.read_idle_timeout, conn.login(&user, &pass))
                .await?
                .map_err(map_login_error)?;
            timed(
                self.cfg.read_idle_timeout,
                conn.transfer_type(FileType::Binary),
            )
            .await?
            .map_err(map_ftp_error)?;
            self.change_dir(&mut conn).await?;
            let total = match timed(
                self.cfg.read_idle_timeout,
                conn.size(self.url.file.as_str()),
            )
            .await?
            {
                Ok(n) => Some(
                    u64::try_from(n)
                        .map_err(|_| HttpError::Ftp("SIZE reply exceeds 64-bit range".into()))?,
                ),
                Err(e) if is_size_unsupported(&e) => None,
                Err(e) => return Err(map_ftp_error(e)),
            };
            // REST 0 probe: 5xx = unsupported -> single-stream
            // degradation with no bitmap (resume from zero).
            let resume_supported =
                match timed(self.cfg.read_idle_timeout, conn.resume_transfer(0usize)).await? {
                    Ok(()) => true,
                    Err(e) => match server_rejected(&e) {
                        Some(code) => {
                            tracing::info!(target: "taiji::http::ftp", host = %self.url.host,
                            code, "server rejected REST 0; ftp source degrades to single stream");
                            false
                        }
                        None => return Err(map_ftp_error(e)),
                    },
                };
            // UTF8 is recorded for diagnostics only; path byte semantics
            // live in the module docs' charset section.
            let utf8 = timed(self.cfg.read_idle_timeout, utf8_feat(&mut conn))
                .await
                .unwrap_or(Ok(false))
                .unwrap_or(false);
            // MDTM (RFC 3659): the `--remote-time` FTP face (the HTTP
            // side goes through Last-Modified). A 213 timestamp
            // normalizes to the same HTTP-date format as the HTTP
            // `last_modified` (a single parser); 550, unknown codes,
            // timeout, or an unparseable body = best-effort skip, never
            // a probe failure.
            let last_modified = match timed(
                self.cfg.read_idle_timeout,
                conn.custom_command(format!("MDTM {}", self.url.file), &[Status::File]),
            )
            .await
            {
                Ok(Ok(resp)) => resp
                    .as_string()
                    .ok()
                    .and_then(|body| crate::remotetime::mdtm_http_date(&body)),
                _ => None,
            };
            Ok(FtpProbe {
                validator: ResumeValidator {
                    final_url_path: format!("{}/{}", self.url.dir, self.url.file),
                    total_len: total,
                    last_modified,
                    encoding_ok: true,
                    ..ResumeValidator::default()
                },
                resume_supported,
                utf8,
            })
        };
        let result = probe.await;
        // The probe connection is always closed (QUIT best-effort,
        // never masking the probe result).
        let _ = timed(self.cfg.read_idle_timeout, conn.quit()).await;
        result
    }

    /// Lock face for the idle-connection pool (short critical sections;
    /// the lock is never held across an await). Poisoning is fatal per
    /// the crate-wide lock policy (see [`crate::lock`]): a panic inside
    /// a sync section means a pool invariant may be lost, and recovery
    /// via `into_inner` is no longer permitted.
    fn lock_pool(&self) -> std::sync::MutexGuard<'_, Vec<AsyncRustlsFtpStream>> {
        crate::lock(&self.idle)
    }

    /// Checkout from the reuse pool, or connect fresh when empty. A
    /// pooled connection gets a NOOP liveness probe first:
    /// server-side timeout reclamation, half-closed connections, and
    /// desync from leftover replies are dropped and replaced here — a
    /// stale connection's first-fetch failure no longer surfaces as an
    /// extent failure (the consecutive-failure ledger counts real
    /// transfer failures only; a probe-failed drop never pollutes the
    /// source ledger). Returns `(connection, from_pool)`; the pool flag
    /// feeds the stale-retry criterion at the call site.
    async fn checkout(&self, ctx: &RequestCtx) -> Result<(AsyncRustlsFtpStream, bool)> {
        // Pop from the pool before probing (the guard never spans an
        // await).
        let pooled = self.lock_pool().pop();
        if let Some(mut conn) = pooled {
            if let Ok(Ok(())) = timed(self.cfg.read_idle_timeout, conn.noop()).await {
                return Ok((conn, true));
            }
            // Dead or desynced connection: QUIT is pointless — drop
            // closes the TCP socket (the server reclaims the session)
            // and a fresh one is built.
        }
        Ok((self.connect_logged_in(ctx).await?, false))
    }

    /// Open a new control connection and log in (dial + login; the
    /// fresh path of checkout).
    async fn connect_logged_in(&self, ctx: &RequestCtx) -> Result<AsyncRustlsFtpStream> {
        let mut conn = self.dial().await?;
        self.login(&mut conn, ctx).await?;
        Ok(conn)
    }

    async fn login(&self, conn: &mut AsyncRustlsFtpStream, ctx: &RequestCtx) -> Result<()> {
        let (user, pass) = self.credentials(ctx);
        timed(self.cfg.read_idle_timeout, conn.login(&user, &pass))
            .await?
            .map_err(map_login_error)
    }

    fn recycle(&self, conn: AsyncRustlsFtpStream) {
        let mut idle = self.lock_pool();
        if idle.len() < MAX_IDLE_POOL {
            idle.push(conn);
        }
        // Over the cap: drop = close the TCP socket; the server
        // reclaims the session.
    }

    /// Credential resolution: URI userinfo > `RequestCtx.auth` >
    /// anonymous/anonymous@.
    fn credentials(&self, ctx: &RequestCtx) -> (String, String) {
        if let (Some(u), Some(p)) = (self.url.user.clone(), self.url.password.clone()) {
            return (u, p);
        }
        if let Some(auth) = &ctx.auth {
            let (u, p) = match auth {
                AuthScheme::Basic { user, passwd } | AuthScheme::Digest { user, passwd } => {
                    (user.clone(), passwd.clone())
                }
            };
            return (u, p);
        }
        ("anonymous".into(), "anonymous@".into())
    }

    /// Directory change. Absolute paths use a single CWD (idempotent,
    /// tolerant of leftover directory state on a reused connection);
    /// relative paths CWD segment by segment — not idempotent, returns
    /// false marking the connection single-use (never returned to the
    /// reuse pool).
    async fn change_dir(&self, conn: &mut AsyncRustlsFtpStream) -> Result<bool> {
        let dir = self.url.dir.as_str();
        if dir.is_empty() || dir == "/" {
            return Ok(true);
        }
        if let Some(abs) = dir.strip_prefix('/') {
            timed(self.cfg.read_idle_timeout, conn.cwd(&format!("/{abs}")))
                .await?
                .map_err(map_ftp_error)?;
            return Ok(true);
        }
        for part in dir.split('/').filter(|s| !s.is_empty()) {
            timed(self.cfg.read_idle_timeout, conn.cwd(part))
                .await?
                .map_err(map_ftp_error)?;
        }
        Ok(false)
    }

    /// New control connection: resolve -> TCP (connect timeout) ->
    /// implicit TLS direct, or the explicit-TLS FEAT-gated upgrade.
    /// Login is performed by the caller ([`Self::checkout`]/probe).
    async fn dial(&self) -> Result<AsyncRustlsFtpStream> {
        // Implicit TLS default-port placement (an explicit URI port
        // wins).
        let port = match self.cfg.tls {
            FtpTlsMode::Implicit if self.url.port == DEFAULT_FTP_PORT => IMPLICIT_FTPS_PORT,
            _ => self.url.port,
        };
        let addr = self.resolve(port).await?;
        tracing::debug!(target: "taiji::http::ftp", host = %self.url.host, port,
            tls = ?self.cfg.tls, "ftp dial");
        match self.cfg.tls {
            FtpTlsMode::Implicit => {
                let connector = self.tls_connector()?;
                let mut stream = tokio::time::timeout(
                    self.cfg.connect_timeout,
                    AsyncRustlsFtpStream::connect_secure_implicit(
                        addr,
                        connector,
                        self.url.host.as_str(),
                    ),
                )
                .await
                .map_err(|_| HttpError::Ftp("connect timed out".into()))?
                .map_err(map_ftp_error)?;
                stream.set_mode(if addr.is_ipv6() {
                    Mode::ExtendedPassive
                } else {
                    Mode::Passive
                });
                let mut stream = self.with_data_connect(stream, addr);
                // RFC 4217: an implicit-TLS session's data channel
                // defaults to Clear — only after PBSZ 0 + PROT P does
                // suppaftp wrap the data connection in TLS per tls_ctx.
                for (cmd, expected) in [
                    ("PBSZ 0", &[Status::CommandOk][..]),
                    ("PROT P", &[Status::CommandOk][..]),
                ] {
                    timed(
                        self.cfg.read_idle_timeout,
                        stream.custom_command(cmd, expected),
                    )
                    .await?
                    .map_err(map_ftp_error)?;
                }
                Ok(stream)
            }
            mode => {
                // One T = AsyncRustlsStream: the plaintext phase holds a
                // Tcp data channel; after the upgrade an Ssl one (with
                // automatic PROT P wrapping of data connections).
                let mut plain =
                    AsyncRustlsFtpStream::connect_timeout(addr, self.cfg.connect_timeout)
                        .await
                        .map_err(map_ftp_error)?;
                // PASV has no IPv6 semantics: a resolved v6 address
                // forces EPSV (RFC 2428).
                plain.set_mode(if addr.is_ipv6() {
                    Mode::ExtendedPassive
                } else {
                    Mode::Passive
                });
                let mut plain = self.with_data_connect(plain, addr);
                if mode == FtpTlsMode::Explicit {
                    // FEAT gate: upgrade only when AUTH TLS is
                    // advertised. A FEAT failure itself counts as no TLS
                    // capability (an old server -> plaintext, capability
                    // negotiation); the downgrade warns explicitly,
                    // never silently.
                    let advertised =
                        timed(self.cfg.read_idle_timeout, auth_tls_advertised(&mut plain))
                            .await
                            .unwrap_or(Ok(false))
                            .unwrap_or(false);
                    if advertised {
                        let connector = self.tls_connector()?;
                        tracing::debug!(target: "taiji::http::ftp", host = %self.url.host,
                            "upgrading control channel with AUTH TLS");
                        // into_secure consumes the session by value
                        // (AUTH TLS -> TLS handshake -> PBSZ 0 -> PROT P
                        // -> the secured session).
                        plain = timed(
                            self.cfg.read_idle_timeout,
                            plain.into_secure(connector, self.url.host.as_str()),
                        )
                        .await?
                        .map_err(map_ftp_error)?;
                    } else {
                        tracing::warn!(target: "taiji::http::ftp", host = %self.url.host,
                            "ftp server does not advertise AUTH TLS; control and data channels continue in plaintext (--ftp-ssl=auth is upgrade-on-advertisement, not mandatory)");
                    }
                }
                Ok(plain)
            }
        }
    }

    /// Resolve the control-connection peer via the shared resolver
    /// [`SharedDns::resolve_for_transport`] (the only bridge — IP
    /// literal passthrough, the TTL cache, and the 30s resolve timeout
    /// all live in the resolver stack); take the first address (its
    /// family decides the PASV/EPSV choice). Resolution and dial share
    /// `--connect-timeout` (a hung resolve = a failed connection, never
    /// an unbounded wait — the outer wrapper's semantics; two layers:
    /// the inner 30s backstop usually fires first). DNS failures are
    /// typed as [`HttpError::FtpDns`] (carrying `ResolveError`
    /// unchanged; the `taiji.http.ftp` string code / numeric code 21
    /// face is unchanged).
    async fn resolve(&self, port: u16) -> Result<SocketAddr> {
        let addrs = tokio::time::timeout(
            self.cfg.connect_timeout,
            self.dns.resolve_for_transport(&self.url.host, port),
        )
        .await
        // The outer connect_timeout deadline (the arm where the inner
        // 30s does not fire first; tests prove it with a hanging stub
        // and a short connect_timeout).
        .map_err(|_| {
            let e = HttpError::FtpDns(ResolveError::Timeout(self.cfg.connect_timeout));
            crate::error::note_http_error(&e);
            e
        })?
        .map_err(|e| {
            let e = HttpError::FtpDns(e);
            crate::error::note_http_error(&e);
            e
        })?;
        addrs.into_iter().next().ok_or_else(|| {
            // Defensive arm: the bridge's Ok path is non-empty by
            // construction (a literal yields one entry; a resolver
            // returning an empty list is Err) — this guards against
            // future implementation drift.
            let e = HttpError::FtpDns(ResolveError::Failed("no address resolved".into()));
            crate::error::note_http_error(&e);
            e
        })
    }

    /// Install the data-connection establishment policy (the PASV/EPSV
    /// reply address is decided here — see the module docs' PASV
    /// section): suppaftp's default builder dials the reply address
    /// directly with no timeout — this hook closes both the SSRF
    /// surface and the data-channel connect timeout
    /// (`--connect-timeout`). `into_secure` preserves the installed
    /// hook (a direct field move in suppaftp), so one installation
    /// covers the explicit-upgrade path too.
    fn with_data_connect(
        &self,
        stream: AsyncRustlsFtpStream,
        peer: SocketAddr,
    ) -> AsyncRustlsFtpStream {
        let policy = self.pasv_policy;
        let connect_timeout = self.cfg.connect_timeout;
        stream.passive_stream_builder(move |reply| {
            Box::pin(async move {
                let target = resolve_data_target(policy, reply, peer)?;
                match tokio::time::timeout(connect_timeout, TcpStream::connect(target)).await {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(e)) => Err(FtpError::ConnectionError(e)),
                    Err(_) => Err(FtpError::ConnectionError(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "data connection connect timed out",
                    ))),
                }
            })
        })
    }

    /// The rustls client connector (ring provider; with verification
    /// on, roots = the platform trust store, and task-level CAs
    /// **replace** them — aria2 `--ca-certificate` replacement
    /// semantics, not append; `check_certificate=false` disables
    /// explicitly with a warning — the TLS baseline verification face).
    fn tls_connector(&self) -> Result<AsyncRustlsConnector> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| HttpError::Ftp(format!("tls config: {e}")))?;
        let config = if self.cfg.check_certificate {
            if self.cfg.extra_ca_certs_der.is_empty() {
                // Platform trust store (rustls-platform-verifier;
                // follows OS updates, matching the fork's OpenSSL
                // system-store semantics; task-level replacement is the
                // options ca-certificate path).
                let verifier = Verifier::new(provider)
                    .map_err(|e| HttpError::Ftp(format!("tls verifier: {e}")))?;
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth()
            } else {
                let mut roots = rustls::RootCertStore::empty();
                for der in &self.cfg.extra_ca_certs_der {
                    let cert = CertificateDer::from(der.clone());
                    roots
                        .add(cert)
                        .map_err(|e| HttpError::Ftp(format!("ca certificate: {e}")))?;
                }
                builder.with_root_certificates(roots).with_no_client_auth()
            }
        } else {
            tracing::warn!(target: "taiji::http::ftp", host = %self.url.host,
                "certificate verification disabled (--check-certificate=false)");
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
                .with_no_client_auth()
        };
        Ok(AsyncRustlsConnector::from(TlsConnector::from(Arc::new(
            config,
        ))))
    }
}

/// Whether FEAT advertises `AUTH TLS` (suppaftp keys the FEAT list by
/// first token: " AUTH TLS" -> key "AUTH", value "TLS"; an SSL-only
/// server's "AUTH SSL" is not grounds to upgrade — `into_secure` sends
/// AUTH TLS specifically, and a wrong upgrade fails hard).
async fn auth_tls_advertised(
    conn: &mut AsyncRustlsFtpStream,
) -> std::result::Result<bool, FtpError> {
    Ok(conn
        .feat()
        .await?
        .get("AUTH")
        .is_some_and(|v| v.as_deref() == Some("TLS")))
}

async fn utf8_feat(conn: &mut AsyncRustlsFtpStream) -> std::result::Result<bool, FtpError> {
    Ok(conn.feat().await?.contains_key("UTF8"))
}

/// SIZE unsupported (500 family) -> no authoritative total; 550 (no
/// such file) is not this form and stays a task-level error.
fn is_size_unsupported(e: &FtpError) -> bool {
    matches!(e, FtpError::UnexpectedResponse(resp)
        if (500..=504).contains(&resp.status.code()))
}

/// The explicit skip-verifier for `--check-certificate=false` (default
/// is to verify).
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl SegmentTransport for FtpTransport {
    fn fetch<'a>(
        &'a self,
        seg: &'a crate::traits::Extent,
        ctx: &'a RequestCtx,
        sink: &'a dyn SegmentSink,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.fetch_extent(seg, ctx, sink).await })
    }
}

impl FtpTransport {
    /// Extent fetch executor (the orchestration face): CWD -> TYPE I ->
    /// (REST offset) -> EPSV/PASV + RETR -> stream into the sink ->
    /// 226 close-out -> recycle/QUIT.
    ///
    /// Writes bytes only, no accounting (`complete_block` belongs to
    /// the ExtentCoordinator's single decision point); SegId is a zero
    /// placeholder (see the module docs' scheduling boundary). The
    /// transferred byte count is reconciled strictly against the
    /// extent: short or over-long transfers are server violations and
    /// fail explicitly (EOF detection reads until the data channel
    /// closes, never cutting early at the expected length — the 226
    /// close-out requires the data connection to close first).
    ///
    /// A stale pooled connection failing before the first byte retries
    /// once on a fresh connection immediately: although the pooled
    /// connection passed the checkout liveness probe, a race window
    /// remains between probe and first fetch — that shape is connection
    /// staleness, not a source fault, so the retry failure never spills
    /// into the source's failure ledger.
    async fn fetch_extent(
        &self,
        seg: &crate::traits::Extent,
        ctx: &RequestCtx,
        sink: &dyn SegmentSink,
    ) -> Result<()> {
        if seg.is_empty() {
            return Ok(());
        }
        let seg_id = crate::traits::SegId {
            source: 0,
            extent: 0,
        };
        let (mut conn, from_pool) = self.checkout(ctx).await?;
        let (mut result, written) = self.attempt(&mut conn, seg, seg_id, sink).await;
        // Stale-retry criterion: a pooled connection with zero bytes
        // written on the first cut (the error string is taken in a
        // separate phase to avoid overlapping borrows; this covers the
        // race window between probe and first fetch).
        let stale_first_cut = match &result {
            Err(error) if from_pool && written == 0 => Some(error.to_string()),
            _ => None,
        };
        if let Some(first_error) = stale_first_cut {
            tracing::debug!(target: "taiji::http::ftp", host = %self.url.host,
                error = %first_error,
                "pooled control connection failed before first byte; retrying once on a fresh connection");
            let _ = timed(self.cfg.read_idle_timeout, conn.quit()).await;
            if let Ok(mut fresh) = self.connect_logged_in(ctx).await {
                let (retry, _) = self.attempt(&mut fresh, seg, seg_id, sink).await;
                conn = fresh;
                result = retry;
            }
            // If the fresh dial fails: the original error propagates
            // (the root cause is the first-fetch failure; a retry dial
            // failure is usually the same fault — do not mask it).
        }
        match (&result, self.cfg.reuse_connection) {
            (Ok(true), true) => self.recycle(conn),
            // Failed / single-use / reuse-disabled connections: close
            // out with QUIT.
            _ => {
                let _ = timed(self.cfg.read_idle_timeout, conn.quit()).await;
            }
        }
        result.map(|_: bool| ())
    }

    /// One fetch attempt (connection already checked out): CWD -> TYPE
    /// I -> (REST) -> read the data channel to the extent's end.
    /// Returns `(disposition, bytes_written)`: disposition `true` = the
    /// connection may return to the reuse pool (idempotent directory
    /// and a control plane resynchronized via reply checks);
    /// bytes_written feeds the stale-retry criterion (0 = nothing
    /// landed on the first cut).
    async fn attempt(
        &self,
        conn: &mut AsyncRustlsFtpStream,
        seg: &crate::traits::Extent,
        seg_id: crate::traits::SegId,
        sink: &dyn SegmentSink,
    ) -> (Result<bool>, u64) {
        let end = seg.end();
        let mut written = 0u64;
        let result: Result<bool> = async {
            // Segment-by-segment CWD for a relative dir is not
            // idempotent: such connections are single-use.
            let mut reusable_dir = self.change_dir(conn).await?;
            timed(
                self.cfg.read_idle_timeout,
                conn.transfer_type(FileType::Binary),
            )
            .await?
            .map_err(map_ftp_error)?;
            if seg.start > 0 {
                // The probe ([`FtpProbe::resume_supported`]) already
                // routes REST-rejecting sources into single-stream
                // degradation; a rejection here means an offset fetch
                // hit a REST-less server (a scheduler-contract
                // violation) and fails explicitly.
                let offset = usize::try_from(seg.start)
                    .map_err(|_| HttpError::Ftp("extent offset exceeds address width".into()))?;
                if let Err(e) =
                    timed(self.cfg.read_idle_timeout, conn.resume_transfer(offset)).await?
                {
                    return Err(match server_rejected(&e) {
                        Some(_) => HttpError::FtpResumeUnsupported,
                        None => map_ftp_error(e),
                    });
                }
            }
            let mut stream: DataStream = timed(
                self.cfg.read_idle_timeout,
                conn.retr_as_stream(self.url.file.as_str()),
            )
            .await?
            .map_err(map_ftp_error)?;
            // The extent is the hard read bound (the RETR stream serves
            // the REST offset to EOF; an extent is a slice of the file
            // — never read past its end).
            let mut off = seg.start;
            let mut buf = vec![0u8; DATA_CHUNK];
            let mut natural_eof = false;
            loop {
                let cap = ((end - off) as usize).min(DATA_CHUNK);
                let n = match tokio::time::timeout(
                    self.cfg.read_idle_timeout,
                    stream.read(&mut buf[..cap]),
                )
                .await
                {
                    Ok(r) => r.map_err(|e| HttpError::Ftp(format!("data channel: {e}")))?,
                    Err(_) => return Err(HttpError::Ftp("data read idle timeout".into())),
                };
                if n == 0 {
                    natural_eof = true;
                    break;
                }
                sink.write_at(seg_id, off, Bytes::copy_from_slice(&buf[..n]))
                    .await?;
                off += n as u64;
                written = off - seg.start;
                if off == end {
                    break;
                }
            }
            if off != end {
                return Err(HttpError::Ftp(format!(
                    "short transfer: got {off} of {end} bytes at offset {}",
                    seg.start
                )));
            }
            if natural_eof {
                // The extent reached file EOF: the data channel closes
                // naturally; read the 226/250 close-out (server-side
                // errors surface here).
                timed(self.cfg.read_idle_timeout, stream.finish())
                    .await?
                    .map_err(map_ftp_error)?;
            } else {
                // The extent is a mid-file slice (the RETR tail keeps
                // flowing): the data channel is closed here. One
                // completion reply is drained explicitly (suppaftp's
                // drop semantics leave the reply for the next command
                // and swallow 4xx replies): under the RFC 959
                // single-reply contract drain + NOOP restores
                // control-plane sync; on servers that send a 426+226
                // pair the leftover tail makes NOOP read non-2xx —
                // control-plane desync, so the connection is demoted to
                // single-use and never returned to the pool (the tail
                // can no longer pollute the next extent; boundary notes
                // in the module docs' reuse section).
                drop(stream);
                match timed(self.cfg.read_idle_timeout, conn.noop()).await {
                    Ok(Ok(())) => {}
                    _ => reusable_dir = false,
                }
            }
            Ok(reusable_dir)
        }
        .await;
        (result, written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ftp_url_matrix() {
        let u = parse_ftp_url("ftp://example.com/dir/file.bin")
            .unwrap_or_else(|e| panic!("plain: {e}"));
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port, 21);
        assert_eq!(u.dir, "/dir");
        assert_eq!(u.file, "file.bin");
        assert!(u.user.is_none());

        let u = parse_ftp_url("ftp://u:p@host.example:990/f.tar.gz")
            .unwrap_or_else(|e| panic!("creds: {e}"));
        assert_eq!(u.user.as_deref(), Some("u"));
        assert_eq!(u.password.as_deref(), Some("p"));
        assert_eq!(u.port, 990);
        assert_eq!(u.dir, "");
        assert_eq!(u.file, "f.tar.gz");

        let u = parse_ftp_url("ftp://[2001:db8::1]:2121/a/b/c.dat")
            .unwrap_or_else(|e| panic!("v6: {e}"));
        assert_eq!(u.host, "2001:db8::1");
        assert_eq!(u.port, 2121);
        assert_eq!(u.dir, "/a/b");
        assert_eq!(u.file, "c.dat");

        let u = parse_ftp_url("ftp://2001:db8::1/file").unwrap_or_else(|e| panic!("bare v6: {e}"));
        assert_eq!(u.host, "2001:db8::1");
        assert_eq!(u.port, 21);

        let u = parse_ftp_url("ftp://h/%E6%96%87%E4%BB%B6.txt")
            .unwrap_or_else(|e| panic!("percent path: {e}"));
        assert_eq!(u.file, "文件.txt");

        // Negative: non-ftp scheme, no scheme, directory form, bad
        // port, empty host.
        assert!(parse_ftp_url("http://h/f").is_err());
        assert!(parse_ftp_url("example.com/f").is_err());
        assert!(parse_ftp_url("ftp://h/dir/").is_err());
        assert!(parse_ftp_url("ftp://h:notaport/f").is_err());
        assert!(parse_ftp_url("ftp://").is_err());
        assert!(parse_ftp_url("ftp://[::1/f").is_err());
    }

    #[test]
    fn percent_decode_keeps_stray_percent_literal() {
        assert_eq!(percent_decode("a%41%2"), b"aA%2");
        assert_eq!(percent_decode("%zz"), b"%zz");
        assert_eq!(percent_decode("plain"), b"plain");
    }

    #[test]
    fn charset_fallback_utf8_first_then_latin1() {
        // Valid UTF-8 bytes pass through unchanged.
        assert_eq!(decode_ftp_path("a%20b"), "a b");
        assert_eq!(decode_ftp_path("%E6%96%87"), "文");
        // Non-UTF-8 bytes (%E9 = the Latin-1 single byte for é) ->
        // Latin-1 transcoding.
        assert_eq!(decode_ftp_path("%E9.txt"), "é.txt");
        assert_eq!(decode_ftp_path_bytes(&[0xE9, b'.', b't']), "é.t");
    }

    #[test]
    fn ftp_config_defaults_follow_spec() {
        let cfg = FtpConfig::default();
        // --ftp-ssl defaults to auth (explicit);
        // --ftp-reuse-connection defaults to true.
        assert_eq!(cfg.tls, FtpTlsMode::Explicit);
        assert!(cfg.reuse_connection);
        assert!(cfg.check_certificate);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(60));
    }

    /// PASV/EPSV reply-address policy: malicious replies are rejected
    /// or rewritten. AlignPeer overrides any reply IP with the control
    /// peer; DenyPrivate rejects restricted redirects (including the
    /// 169.254.169.254 metadata endpoint and v4-mapped normalization)
    /// and allows public replies and replies matching the peer.
    #[test]
    fn pasv_target_policy_overrides_and_rejects_malicious_replies() {
        let parse = |s: &str| -> SocketAddr {
            s.parse()
                .unwrap_or_else(|e| panic!("socket addr {s:?}: {e}"))
        };
        let peer = parse("127.0.0.1:21");

        // AlignPeer (default): malicious/MITM'd replies (TEST-NET-3
        // public + the metadata endpoint) are always overridden with
        // the control peer; only the reply port is kept.
        for malicious in ["203.0.113.7:40000", "169.254.169.254:80"] {
            let reply = parse(malicious);
            let target = resolve_data_target(PasvAddressPolicy::AlignPeer, reply, peer)
                .unwrap_or_else(|e| panic!("align {malicious}: {e}"));
            assert_eq!(
                target,
                SocketAddr::new(peer.ip(), reply.port()),
                "AlignPeer {malicious}"
            );
        }

        // DenyPrivate: restricted redirects are rejected (a
        // connection-level violation, raised explicitly).
        for malicious in [
            "169.254.169.254:80",
            "10.0.0.5:8080",
            "192.168.1.9:6969",
            "127.0.0.5:9999",
            "[::ffff:10.0.0.5]:40000",
        ] {
            let err =
                match resolve_data_target(PasvAddressPolicy::DenyPrivate, parse(malicious), peer) {
                    Err(err) => err,
                    Ok(target) => panic!("deny private {malicious} must reject, dialed {target}"),
                };
            assert!(
                matches!(err, FtpError::ConnectionError(_)),
                "deny private {malicious}: {err}"
            );
        }
        // DenyPrivate: public replies pass (the asymmetric-NAT face); a
        // reply equal to the peer passes (a peer legitimately on an
        // intranet).
        let public = parse("203.0.113.7:40000");
        let target = resolve_data_target(PasvAddressPolicy::DenyPrivate, public, peer)
            .unwrap_or_else(|e| panic!("deny private public: {e}"));
        assert_eq!(target, public);
        let lan_peer = parse("10.1.2.3:21");
        let lan_reply = parse("10.1.2.3:40000");
        let target = resolve_data_target(PasvAddressPolicy::DenyPrivate, lan_reply, lan_peer)
            .unwrap_or_else(|e| panic!("deny private lan: {e}"));
        assert_eq!(target, lan_reply);
    }

    /// `--ftp-pasv-address-check` value grammar and the three-state
    /// decision matrix: strict rejects a malicious reply, off dials the
    /// same reply as-is (the escape hatch = suppaftp's native
    /// behavior), peer overrides it with the control peer;
    /// out-of-domain values are rejected as `taiji.option.invalid`.
    #[test]
    fn pasv_address_check_grammar_and_three_state_matrix() {
        // Value grammar: three states, exact lowercase match.
        assert_eq!(
            "peer".parse::<PasvAddressPolicy>(),
            Ok(PasvAddressPolicy::AlignPeer)
        );
        assert_eq!(
            "strict".parse::<PasvAddressPolicy>(),
            Ok(PasvAddressPolicy::DenyPrivate)
        );
        assert_eq!(
            "off".parse::<PasvAddressPolicy>(),
            Ok(PasvAddressPolicy::ReplyAsIs)
        );
        // Negative: case variants, aliases, whitespace, and empty
        // values are all rejected (never truncated, never guessed).
        for bad in ["", "PEER", "align", "deny-private", "off ", "disabled"] {
            let err = match bad.parse::<PasvAddressPolicy>() {
                Ok(policy) => panic!("value {bad:?} must be rejected, got {policy:?}"),
                Err(err) => err,
            };
            assert_eq!(err.code(), "taiji.option.invalid", "value {bad:?}");
        }

        let parse = |s: &str| -> SocketAddr {
            s.parse()
                .unwrap_or_else(|e| panic!("socket addr {s:?}: {e}"))
        };
        let peer = parse("127.0.0.1:21");
        let malicious = parse("169.254.169.254:80");

        // strict: a malicious reply (the cloud-metadata redirect) is
        // rejected.
        assert!(
            resolve_data_target(PasvAddressPolicy::DenyPrivate, malicious, peer).is_err(),
            "strict must reject the metadata-endpoint redirect"
        );
        // off: the same malicious reply dials as-is (the escape hatch —
        // the whole decision face is off; the dial target is the reply
        // itself).
        let target = resolve_data_target(PasvAddressPolicy::ReplyAsIs, malicious, peer)
            .unwrap_or_else(|e| panic!("off must dial as-is: {e}"));
        assert_eq!(target, malicious);
        // off adopts public replies as-is too.
        let public = parse("203.0.113.7:40000");
        let target = resolve_data_target(PasvAddressPolicy::ReplyAsIs, public, peer)
            .unwrap_or_else(|e| panic!("off public reply: {e}"));
        assert_eq!(target, public);
        // peer: the same malicious reply is overridden with the control
        // peer (only the reply port is kept).
        let target = resolve_data_target(PasvAddressPolicy::AlignPeer, malicious, peer)
            .unwrap_or_else(|e| panic!("peer override: {e}"));
        assert_eq!(target, parse("127.0.0.1:80"));
    }

    /// The production assembly site ([`FtpTransport::for_uri`]) pins
    /// the default peer alignment (a regression guard against default
    /// drift); the assembly builder can override with any of the three
    /// states (the config-carrier face is
    /// [`for_uri_carries_config_pasv_policy`]).
    #[test]
    fn for_uri_pins_default_policy_and_builder_overrides() {
        let t = FtpTransport::for_uri(FtpConfig::default(), "ftp://example.com/f")
            .unwrap_or_else(|e| panic!("for_uri: {e}"));
        assert_eq!(
            t.pasv_policy,
            PasvAddressPolicy::AlignPeer,
            "the production assembly default must pin AlignPeer"
        );
        let t = t.with_pasv_policy(PasvAddressPolicy::ReplyAsIs);
        assert_eq!(t.pasv_policy, PasvAddressPolicy::ReplyAsIs);
        let t = FtpTransport::for_uri(FtpConfig::default(), "ftp://example.com/f")
            .unwrap_or_else(|e| panic!("for_uri: {e}"))
            .with_pasv_policy(PasvAddressPolicy::DenyPrivate);
        assert_eq!(t.pasv_policy, PasvAddressPolicy::DenyPrivate);
    }

    /// Wiring (`--ftp-pasv-address-check`): value grammar (single
    /// source = `FromStr`) -> [`FtpConfig::pasv_policy`] -> lands at
    /// the [`FtpTransport::for_uri`] construction site — all three
    /// states reach the constructor through the config carrier (the
    /// task side projects through taiji-core
    /// `HttpTaskOpts::to_ftp_config`).
    #[test]
    fn for_uri_carries_config_pasv_policy() {
        let cases = [
            ("peer", PasvAddressPolicy::AlignPeer),
            ("strict", PasvAddressPolicy::DenyPrivate),
            ("off", PasvAddressPolicy::ReplyAsIs),
        ];
        for (value, policy) in cases {
            let cfg = FtpConfig {
                pasv_policy: value
                    .parse::<PasvAddressPolicy>()
                    .unwrap_or_else(|e| panic!("parse {value:?}: {e}")),
                ..FtpConfig::default()
            };
            let t = FtpTransport::for_uri(cfg, "ftp://example.com/f")
                .unwrap_or_else(|e| panic!("for_uri {value:?}: {e}"));
            assert_eq!(
                t.pasv_policy, policy,
                "option value {value:?} must reach the construction site"
            );
        }
    }

    #[test]
    fn credentials_precedence_uri_over_ctx_over_anonymous() {
        let t = FtpTransport::for_uri(FtpConfig::default(), "ftp://uriuser:uripass@example.com/f")
            .unwrap_or_else(|e| panic!("uri: {e}"));
        assert_eq!(
            t.credentials(&RequestCtx::default()),
            ("uriuser".into(), "uripass".into())
        );

        let t = FtpTransport::for_uri(FtpConfig::default(), "ftp://example.com/f")
            .unwrap_or_else(|e| panic!("plain: {e}"));
        let ctx = RequestCtx {
            auth: Some(AuthScheme::Digest {
                user: "digestuser".into(),
                passwd: "dp".into(),
            }),
            ..RequestCtx::default()
        };
        assert_eq!(t.credentials(&ctx), ("digestuser".into(), "dp".into()));
        // The anonymous default matches aria2.
        assert_eq!(
            t.credentials(&RequestCtx::default()),
            ("anonymous".into(), "anonymous@".into())
        );
    }

    #[tokio::test]
    async fn empty_extent_fetch_is_noop() {
        let t = FtpTransport::for_uri(FtpConfig::default(), "ftp://127.0.0.1:1/f")
            .unwrap_or_else(|e| panic!("uri: {e}"));
        let sink = crate::traits::NoopSink::default();
        let extent = crate::traits::Extent { start: 4, len: 0 };
        t.fetch(&extent, &RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("empty extent is noop: {e}"));
        assert_eq!(sink.written_bytes(), 0);
    }
}
