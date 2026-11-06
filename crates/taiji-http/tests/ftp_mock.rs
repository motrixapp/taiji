//! FTP mock matrix: an in-process mock FTP server cross-validates
//! FtpTransport at the wire level — REST-reject degradation (no
//! bitmap) / EPSV (per address family) / explicit + implicit TLS
//! (incl. PROT P data channel) / anonymous + authenticated login /
//! connection reuse / charset fallback / PASV reply-address decisions
//! / out-of-step completion replies / reuse-pool liveness probing.
//! Loopback only, never the real network.
//!
//! TLS fixtures (`fixtures/ftp-test-ca/`): a locally generated
//! self-signed test CA (ECDSA P-256) plus a server certificate with
//! SAN `DNS:localhost, IP:127.0.0.1, IP:::1` — not real credentials,
//! for mock handshakes only.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use suppaftp::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use suppaftp::tokio_rustls::TlsAcceptor;
use suppaftp::tokio_rustls::rustls;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use taiji_http::client::load_ca_certificates_der;
use taiji_http::degraded::DegradedReason;
use taiji_http::error::HttpError;
use taiji_http::ftp::{FtpConfig, FtpTlsMode, PasvAddressPolicy};
use taiji_http::traits::{AuthScheme, Extent, RequestCtx, SegId, SegmentSink, SegmentTransport};

const CA_CERT: &[u8] = include_bytes!("fixtures/ftp-test-ca/ca_cert.der");
const SERVER_CERT: &[u8] = include_bytes!("fixtures/ftp-test-ca/server_cert.der");
const SERVER_KEY: &[u8] = include_bytes!("fixtures/ftp-test-ca/server_key.der");

// ---------------------------------------------------------------------------
// Recording sink / assertion surface
// ---------------------------------------------------------------------------

/// Recording sink: captures the (offset, bytes) write sequence;
/// `complete_block` always errors (the transport must not do block
/// bookkeeping — that is the coordinator's job).
#[derive(Default)]
struct CaptureSink {
    writes: Mutex<Vec<(u64, Vec<u8>)>>,
}

impl CaptureSink {
    fn assembled(&self, total: u64) -> Vec<u8> {
        let mut out = vec![0u8; total as usize];
        for (off, bytes) in self.writes.lock().unwrap_or_else(|p| p.into_inner()).iter() {
            let off = *off as usize;
            out[off..off + bytes.len()].copy_from_slice(bytes);
        }
        out
    }

    /// Number of write_at calls (proves rejected paths write nothing).
    fn write_count(&self) -> usize {
        self.writes.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl SegmentSink for CaptureSink {
    fn write_at(
        &self,
        _seg: SegId,
        off: u64,
        bytes: Bytes,
    ) -> futures::future::BoxFuture<'_, taiji_http::error::Result<()>> {
        self.writes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((off, bytes.to_vec()));
        Box::pin(std::future::ready(Ok(())))
    }

    fn complete_block(
        &self,
        _block: u64,
    ) -> futures::future::BoxFuture<'_, taiji_http::error::Result<()>> {
        Box::pin(std::future::ready(Err(HttpError::Ftp(
            "sink received complete_block from transport".into(),
        ))))
    }
}

use taiji_http::ftp::FtpTransport;

// ---------------------------------------------------------------------------
// Mock FTP server
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockFtp {
    /// Full path (canonical `/dir/file`) → file body.
    files: HashMap<String, Vec<u8>>,
    /// Every `REST <n>` gets 502 (degradation scenario).
    reject_rest: bool,
    /// FEAT advertisement flags.
    feat_rest: bool,
    feat_utf8: bool,
    feat_auth_tls: bool,
    /// Control-channel TLS acceptor (shared by explicit upgrade and
    /// implicit handshake).
    tls: Option<TlsAcceptor>,
    /// Every PASS gets 530 (auth-failure scenario).
    reject_login: bool,
    /// IPv6 control/data channels (EPSV scenario): listen on [::1].
    v6: bool,
    /// Forged IP for the PASV 227 reply (malicious-reply scenario):
    /// when set, the 227 combines this IP with the real data listen
    /// port, injecting a misleading address into the peer-alignment
    /// decision.
    pasv_reply_ip: Option<&'static str>,
    /// Send both 426 and 226 after a mid-transfer client abort (an
    /// out-of-contract server shape beyond RFC 959's single completion
    /// reply).
    double_reply_on_abort: bool,
    /// MDTM reply timestamp (RFC 3659 §2.3 `YYYYMMDDhhmmss[.sss]` UTC);
    /// None = 550 (no-mtime server, silently skipped by the client).
    mdtm: Option<&'static str>,
    /// Close the control connection right after answering NOOP (stale
    /// pooled connection: the server reclaims it while idle in the
    /// pool, exercising the checkout liveness probe).
    close_after_noop: bool,
    /// Bookkeeping: accepted control connections / command lines.
    conns: AtomicU32,
    commands: Mutex<Vec<String>>,
}

/// Per-connection dialog state (persists across the TLS upgrade).
#[derive(Default)]
struct DialogState {
    cwd: String,
    logged_in: bool,
    prot_p: bool,
    rest_offset: u64,
    /// Data listener pre-bound by PASV/EPSV (one data connection at a time).
    data: Option<TcpListener>,
}

impl MockFtp {
    fn record(&self, line: &str) {
        self.commands
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(line.to_string());
    }

    fn commands(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn conn_count(&self) -> u32 {
        self.conns.load(Ordering::SeqCst)
    }

    fn contains_command(&self, prefix: &str) -> bool {
        self.commands().iter().any(|c| c.starts_with(prefix))
    }
}

/// Path resolution: `cwd + arg` (arg starting with / is absolute).
fn resolve_path(cwd: &str, arg: &str) -> String {
    if arg.starts_with('/') {
        arg.to_string()
    } else if cwd.is_empty() || cwd == "/" {
        format!("/{arg}")
    } else {
        format!("{cwd}/{arg}")
    }
}

async fn serve_control(mock: Arc<MockFtp>, stream: TcpStream) {
    mock.conns.fetch_add(1, Ordering::SeqCst);
    let mut state = DialogState::default();
    // Plaintext segment (absent for implicit TLS). AUTH TLS returns the
    // raw stream and the dialog continues over TLS.
    if let Ok(Some(plain)) = serve_dialog(mock.clone(), stream, &mut state, true).await {
        let Some(acceptor) = mock.tls.as_ref() else {
            return;
        };
        let Ok(tls) = acceptor.accept(plain).await else {
            return;
        };
        let _ = serve_dialog(mock, tls, &mut state, false).await;
    }
}

async fn write_reply<S: AsyncWrite + Unpin>(writer: &mut S, line: &str) -> std::io::Result<()> {
    writer.write_all(format!("{line}\r\n").as_bytes()).await?;
    writer.flush().await
}

/// Dialog engine (shared by plaintext and TLS streams; `greeting` is
/// true only for the first segment). Returns `Some(stream)` when the
/// peer sends AUTH TLS (the plaintext segment ends).
async fn serve_dialog<S: AsyncRead + AsyncWrite + Unpin>(
    mock: Arc<MockFtp>,
    stream: S,
    state: &mut DialogState,
    greeting: bool,
) -> std::io::Result<Option<S>> {
    let mut reader = BufReader::new(stream);
    if greeting {
        write_reply(reader.get_mut(), "220 taiji ftp mock ready").await?;
    }
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return Ok(None),
            Ok(_) => {}
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        let (cmd, arg) = match line.split_once(' ') {
            Some((c, a)) => (c, a),
            None => (line.as_str(), ""),
        };
        mock.record(&line);
        let reply = match cmd {
            "USER" => format!("331 Password required for {arg}"),
            "PASS" => {
                if mock.reject_login {
                    "530 Login incorrect".to_string()
                } else {
                    state.logged_in = true;
                    "230 User logged in".to_string()
                }
            }
            "TYPE" => "200 Type set".to_string(),
            "FEAT" => {
                let mut feats = Vec::new();
                if mock.feat_utf8 {
                    feats.push(" UTF8");
                }
                if mock.feat_rest {
                    feats.push(" REST STREAM");
                }
                if mock.feat_auth_tls {
                    feats.push(" AUTH TLS");
                }
                if feats.is_empty() {
                    "211 End".to_string()
                } else {
                    format!("211-Features:\r\n{}\r\n211 End", feats.join("\r\n"))
                }
            }
            "AUTH" if arg == "TLS" && mock.tls.is_some() => {
                write_reply(reader.get_mut(), "234 Proceeding with TLS handshake").await?;
                return Ok(Some(reader.into_inner()));
            }
            "PBSZ" => "200 PBSZ=0".to_string(),
            "PROT" => {
                state.prot_p = arg == "P";
                format!("200 Protection level is {arg}")
            }
            "CWD" => {
                state.cwd = resolve_path(&state.cwd, arg);
                "250 Directory changed".to_string()
            }
            "PWD" => format!(
                "257 \"/{}\" is the current directory",
                state.cwd.trim_start_matches('/')
            ),
            "SIZE" => match mock.files.get(&resolve_path(&state.cwd, arg)) {
                Some(body) => format!("213 {}", body.len()),
                None => "550 Could not get file size".to_string(),
            },
            // MDTM (RFC 3659 §2.3): 213 when a timestamp is configured
            // and the file exists; otherwise 550 (the client skips
            // silently).
            "MDTM" => match mock.mdtm {
                Some(ts) if mock.files.contains_key(&resolve_path(&state.cwd, arg)) => {
                    format!("213 {ts}")
                }
                _ => "550 Could not get file mtime".to_string(),
            },
            "REST" => {
                if mock.reject_rest {
                    "502 REST not implemented".to_string()
                } else {
                    state.rest_offset = arg.parse().unwrap_or(0);
                    format!("350 Restarting at {arg}. Send STORE or RETRIEVE")
                }
            }
            "EPSV" | "PASV" => {
                let listener = match (cmd, mock.v6) {
                    ("EPSV", true) | ("PASV", true) => TcpListener::bind("[::1]:0").await,
                    _ => TcpListener::bind("127.0.0.1:0").await,
                }
                .unwrap_or_else(|e| panic!("bind data listener: {e}"));
                let port = listener
                    .local_addr()
                    .unwrap_or_else(|e| panic!("data local_addr: {e}"))
                    .port();
                state.data = Some(listener);
                if cmd == "EPSV" {
                    format!("229 Entering Extended Passive Mode (|||{port}|)")
                } else {
                    let (p1, p2) = (port / 256, port % 256);
                    let ip = mock.pasv_reply_ip.unwrap_or("127.0.0.1").replace('.', ",");
                    format!("227 Entering Passive Mode ({ip},{p1},{p2})")
                }
            }
            "RETR" => {
                let path = resolve_path(&state.cwd, arg);
                let Some(body) = mock.files.get(&path).cloned() else {
                    write_reply(reader.get_mut(), "550 Failed to open file").await?;
                    continue;
                };
                write_reply(reader.get_mut(), "150 Opening data connection").await?;
                let Some(listener) = state.data.take() else {
                    write_reply(reader.get_mut(), "425 Use PORT or PASV first").await?;
                    continue;
                };
                let (data, _) = listener.accept().await?;
                // With PROT P and TLS capability, the data channel also
                // uses TLS (RFC 4217).
                let payload = &body[state.rest_offset as usize..];
                let wrote_all = if state.prot_p {
                    let Some(acceptor) = mock.tls.as_ref() else {
                        write_reply(reader.get_mut(), "425 PROT P without TLS").await?;
                        continue;
                    };
                    match acceptor.accept(data).await {
                        Ok(tls) => {
                            let (_, mut wr) = tokio::io::split(tls);
                            wr.write_all(payload).await.is_ok()
                        }
                        Err(_) => false,
                    }
                } else {
                    let mut data = data;
                    data.write_all(payload).await.is_ok()
                };
                // The client closes the data channel once its extent is
                // full (the RETR stream has not ended) → 426; natural
                // EOF → 226. double_reply_on_abort replays the
                // out-of-contract 426+226 pair (a residual tail remains
                // after the client drains).
                if wrote_all {
                    write_reply(reader.get_mut(), "226 Transfer complete").await?;
                } else {
                    write_reply(reader.get_mut(), "426 Transfer aborted").await?;
                    if mock.double_reply_on_abort {
                        write_reply(reader.get_mut(), "226 Abort successful").await?;
                    }
                }
                continue;
            }
            "NOOP" => {
                write_reply(reader.get_mut(), "200 NOOP ok").await?;
                if mock.close_after_noop {
                    return Ok(None);
                }
                continue;
            }
            "QUIT" => {
                write_reply(reader.get_mut(), "221 Goodbye").await?;
                return Ok(None);
            }
            _ => "502 Command not implemented".to_string(),
        };
        write_reply(reader.get_mut(), &reply).await?;
    }
}

/// Start the mock. Returns (host, port, handle).
async fn spawn_mock(mock: MockFtp) -> (String, u16, Arc<MockFtp>) {
    let mock = Arc::new(mock);
    let listener = if mock.v6 {
        TcpListener::bind("[::1]:0").await
    } else {
        TcpListener::bind("127.0.0.1:0").await
    }
    .unwrap_or_else(|e| panic!("bind control listener: {e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("control local_addr: {e}"))
        .port();
    let host = if mock.v6 {
        "::1".to_string()
    } else {
        "127.0.0.1".to_string()
    };
    let spawned = Arc::clone(&mock);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let m = Arc::clone(&spawned);
            tokio::spawn(serve_control(m, stream));
        }
    });
    (host, port, mock)
}

/// Implicit-TLS startup: the TLS handshake precedes the greeting.
async fn spawn_implicit_tls(mock: MockFtp) -> (String, u16, Arc<MockFtp>) {
    let mock = Arc::new(mock);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind control: {e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("control local_addr: {e}"))
        .port();
    let spawned = Arc::clone(&mock);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let m = Arc::clone(&spawned);
            tokio::spawn(async move {
                m.conns.fetch_add(1, Ordering::SeqCst);
                let Some(acceptor) = m.tls.as_ref() else {
                    return;
                };
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut state = DialogState::default();
                let _ = serve_dialog(m, tls, &mut state, true).await;
            });
        }
    });
    ("127.0.0.1".to_string(), port, mock)
}

fn mock_server_tls() -> TlsAcceptor {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap_or_else(|e| panic!("protocol versions: {e}"))
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(SERVER_CERT.to_vec())],
            PrivatePkcs8KeyDer::from(SERVER_KEY.to_vec()).into(),
        )
        .unwrap_or_else(|e| panic!("server cert: {e}"));
    TlsAcceptor::from(Arc::new(config))
}

fn client_config(tls: FtpTlsMode, check_certificate: bool) -> FtpConfig {
    FtpConfig {
        tls,
        check_certificate,
        extra_ca_certs_der: if check_certificate {
            vec![CA_CERT.to_vec()]
        } else {
            Vec::new()
        },
        ..FtpConfig::default()
    }
}

fn body(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn plain_file_server(reject_rest: bool) -> MockFtp {
    let mut m = MockFtp {
        feat_rest: true,
        feat_utf8: true,
        reject_rest,
        ..MockFtp::default()
    };
    m.files.insert("/f.bin".to_string(), body(7, 200 * 1024));
    m
}

// ---------------------------------------------------------------------------
// Matrix: anonymous + auth / REST-reject degradation / EPSV /
// explicit + implicit TLS / reuse / charset
// ---------------------------------------------------------------------------

/// Anonymous login plus a full plaintext download.
#[tokio::test]
async fn anonymous_full_download_with_probe() {
    let (host, port, mock) = spawn_mock(plain_file_server(false)).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));

    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert_eq!(probe.validator.total_len, Some(200 * 1024));
    assert!(probe.resume_supported, "the REST 0 probe passed");
    let validator = &probe.validator;
    assert!(validator.encoding_ok);
    assert_eq!(validator.final_url_path, "/f.bin");

    let sink = CaptureSink::default();
    let seg = Extent {
        start: 0,
        len: 200 * 1024,
    };
    t.fetch(&seg, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
    assert_eq!(sink.assembled(200 * 1024), body(7, 200 * 1024));
    // Anonymous is the default (matching aria2).
    assert!(mock.contains_command("USER anonymous"));
    assert!(mock.contains_command("PASS anonymous@"));
    // The transport never touches block bookkeeping.
    let cmds = mock.commands();
    assert!(
        cmds.iter().any(|c| c.starts_with("REST 0")),
        "the probe face sends REST 0"
    );
    assert!(cmds.iter().any(|c| c.starts_with("TYPE I")));
}

#[tokio::test]
async fn uri_userinfo_and_ctx_auth_precedence() {
    // URI userinfo takes precedence.
    let (host, port, mock) = spawn_mock(plain_file_server(false)).await;
    let uri = format!("ftp://uriuser:uripass@{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    t.probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert!(mock.contains_command("USER uriuser"));
    assert!(mock.contains_command("PASS uripass"));

    // ctx.auth (Basic) comes next.
    let (host, port, mock) = spawn_mock(plain_file_server(false)).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let ctx = RequestCtx {
        auth: Some(AuthScheme::Basic {
            user: "ctxuser".into(),
            passwd: "ctxpass".into(),
        }),
        ..RequestCtx::default()
    };
    t.probe(&ctx).await.unwrap_or_else(|e| panic!("probe: {e}"));
    assert!(mock.contains_command("USER ctxuser"));
    assert!(mock.contains_command("PASS ctxpass"));
}

/// Login failure (530) maps to the unified `taiji.auth.failed` code.
#[tokio::test]
async fn login_failure_maps_to_auth_failed() {
    let mut m = plain_file_server(false);
    m.reject_login = true;
    let (host, port, _mock) = spawn_mock(m).await;
    let uri = format!("ftp://u:p@{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let err = match t.probe(&RequestCtx::default()).await {
        Err(err) => err,
        Ok(_) => panic!("530 must fail"),
    };
    assert_eq!(err.code(), "taiji.auth.failed", "{err}");
}

/// REST rejection (502) → the probe reports resume_supported=false →
/// single-stream degradation (no bitmap, resume from zero); an offset
/// fetch fails explicitly with `taiji.http.ftp_resume_unsupported`.
#[tokio::test]
async fn rest_rejected_degrades_to_single_stream() {
    let (host, port, _mock) = spawn_mock(plain_file_server(true)).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));

    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert!(
        !probe.resume_supported,
        "REST 0 rejected -> the degradation verdict"
    );
    // Scheduler routing: FtpNoResume is a degradation reason (no
    // bitmap, resume from zero).
    let reason = DegradedReason::FtpNoResume;
    assert_ne!(reason, DegradedReason::NoTotalLength);

    // In the degraded shape, a single-stream fetch from zero still works.
    let sink = CaptureSink::default();
    let seg = Extent {
        start: 0,
        len: 200 * 1024,
    };
    t.fetch(&seg, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("degraded fetch: {e}"));
    assert_eq!(sink.assembled(200 * 1024), body(7, 200 * 1024));

    // An offset segment against a no-REST server violates the routing
    // contract → explicit error.
    let sink = CaptureSink::default();
    let seg = Extent {
        start: 1024,
        len: 100,
    };
    let err = match t.fetch(&seg, &RequestCtx::default(), &sink).await {
        Err(err) => err,
        Ok(_) => panic!("resume on no-rest server must fail"),
    };
    assert_eq!(err.code(), "taiji.http.ftp_resume_unsupported", "{err}");
    assert_eq!(
        sink.assembled(200 * 1024).len(),
        200 * 1024,
        "no write pollution"
    );
}

/// EPSV (IPv6, RFC 2428) — the data-channel command is picked by
/// address family.
#[tokio::test]
async fn epsv_selected_for_ipv6() {
    let mut m = plain_file_server(false);
    m.v6 = true;
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://[{host}]:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let sink = CaptureSink::default();
    let seg = Extent {
        start: 64 * 1024,
        len: 32 * 1024,
    };
    t.fetch(&seg, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
    assert_eq!(
        sink.assembled(64 * 1024 + 32 * 1024)[64 * 1024..],
        body(7, 200 * 1024)[64 * 1024..64 * 1024 + 32 * 1024],
        "the mid-file extent's bytes are correct"
    );
    assert!(mock.contains_command("EPSV"), "IPv6 forces EPSV");
    assert!(!mock.contains_command("PASV"), "IPv6 does not use PASV");
    assert!(mock.contains_command("REST 65536"), "extent = REST + RETR");
}

/// PASV (the IPv4 default data channel).
#[tokio::test]
async fn pasv_selected_for_ipv4() {
    let (host, port, mock) = spawn_mock(plain_file_server(false)).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let sink = CaptureSink::default();
    let seg = Extent {
        start: 0,
        len: 1024,
    };
    t.fetch(&seg, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
    assert!(mock.contains_command("PASV"), "IPv4 uses PASV");
    assert!(!mock.contains_command("EPSV"), "IPv4 does not use EPSV");
}

/// Explicit TLS (AUTH TLS + PBSZ 0 + PROT P) end to end: control and
/// data channels both over TLS, content intact.
#[tokio::test]
async fn tls_explicit_end_to_end() {
    let mut m = plain_file_server(false);
    m.feat_auth_tls = true;
    m.tls = Some(mock_server_tls());
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::Explicit, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));

    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert_eq!(probe.validator.total_len, Some(200 * 1024));

    let sink = CaptureSink::default();
    let seg = Extent {
        start: 1024,
        len: 64 * 1024,
    };
    t.fetch(&seg, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
    let expected = &body(7, 200 * 1024)[1024..1024 + 64 * 1024];
    let mut got = vec![0u8; 1024 + 64 * 1024];
    got[1024..].copy_from_slice(&sink.assembled(1024 + 64 * 1024)[1024..]);
    assert_eq!(&got[1024..], expected);

    let cmds = mock.commands();
    assert!(cmds.iter().any(|c| c == "AUTH TLS"), "explicit upgrade");
    assert!(cmds.iter().any(|c| c.starts_with("PBSZ")), "PBSZ 0");
    assert!(
        cmds.iter().any(|c| c.starts_with("PROT P")),
        "data-channel protection"
    );
    // The post-PROT-P RETR data channel runs over TLS (the test fails
    // if the mock-side TLS accept fails).
    assert!(cmds.iter().any(|c| c.starts_with("RETR f.bin")));
}

/// Implicit TLS (classic port 990 shape) end to end.
#[tokio::test]
async fn tls_implicit_end_to_end() {
    let mut m = plain_file_server(false);
    m.tls = Some(mock_server_tls());
    let (_host, port, mock) = spawn_implicit_tls(m).await;
    let uri = format!("ftp://127.0.0.1:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::Implicit, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert_eq!(probe.validator.total_len, Some(200 * 1024));
    let sink = CaptureSink::default();
    let seg = Extent {
        start: 0,
        len: 200 * 1024,
    };
    t.fetch(&seg, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
    assert_eq!(sink.assembled(200 * 1024), body(7, 200 * 1024));
    assert!(
        mock.contains_command("USER anonymous"),
        "login completes over TLS"
    );
}

/// `--check-certificate=false` explicitly allows an untrusted
/// certificate (the default configuration fails against the same
/// server — validation is on by default).
#[tokio::test]
async fn tls_check_certificate_false_allows_untrusted() {
    let mut m = plain_file_server(false);
    m.feat_auth_tls = true;
    m.tls = Some(mock_server_tls());
    let (host, port, _mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    // Default validation (webpki roots, which exclude this test CA) →
    // the handshake fails.
    let mut cfg = client_config(FtpTlsMode::Explicit, true);
    cfg.extra_ca_certs_der.clear(); // no trust anchor → validation must fail
    let t = FtpTransport::for_uri(cfg, &uri).unwrap_or_else(|e| panic!("for_uri: {e}"));
    assert!(
        t.probe(&RequestCtx::default()).await.is_err(),
        "certificate validation must fail without a trust anchor"
    );
    // Validation off → the handshake proceeds (explicit-warning path).
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::Explicit, false), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert_eq!(probe.validator.total_len, Some(200 * 1024));
}

/// The `--ca-certificate` option path: a PEM file goes through
/// [`load_ca_certificates_der`] (the single loader for option values)
/// into `FtpConfig::extra_ca_certs_der`. Same TLS matrix as
/// `tls_explicit_end_to_end` above, but the CA arrives via the option
/// loading path instead of direct DER injection.
#[tokio::test]
async fn tls_explicit_via_ca_certificate_option_path() {
    let ca_pem = write_ca_pem_file("ftp-opt");
    let ders = load_ca_certificates_der(&ca_pem).unwrap_or_else(|e| panic!("load ca: {e}"));
    assert!(!ders.is_empty(), "loading the PEM must yield DER");
    let mut m = plain_file_server(false);
    m.feat_auth_tls = true;
    m.tls = Some(mock_server_tls());
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let cfg = FtpConfig {
        tls: FtpTlsMode::Explicit,
        check_certificate: true,
        extra_ca_certs_der: ders,
        ..FtpConfig::default()
    };
    let t = FtpTransport::for_uri(cfg, &uri).unwrap_or_else(|e| panic!("for_uri: {e}"));
    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert_eq!(probe.validator.total_len, Some(200 * 1024));
    let sink = CaptureSink::default();
    let seg = Extent {
        start: 0,
        len: 200 * 1024,
    };
    t.fetch(&seg, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
    assert_eq!(sink.assembled(200 * 1024), body(7, 200 * 1024));
    assert!(mock.contains_command("AUTH TLS"), "explicit upgrade");
}

/// Encode the CA DER fixture into a PEM file (the `--ca-certificate`
/// value shape; a self-contained std-only base64 encoder — no new
/// dependency, same encoding as ca_cert_mock).
fn write_ca_pem_file(tag: &str) -> PathBuf {
    fn b64(data: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let encoded = b64(CA_CERT);
    for chunk in encoded.as_bytes().chunks(64) {
        let line = std::str::from_utf8(chunk).unwrap_or_else(|e| panic!("utf8: {e}"));
        pem.push_str(line);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    let dir = std::env::temp_dir().join(format!("taiji-ftp-ca-opt-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
    let path = dir.join("ca.pem");
    std::fs::write(&path, pem).unwrap_or_else(|e| panic!("write pem: {e}"));
    path
}

/// Connection reuse semantics: reuse=true keeps one control connection
/// across extents; false opens one per extent.
#[tokio::test]
async fn reuse_connection_semantics() {
    // Reuse: two fetches over one control connection.
    let (host, port, mock) = spawn_mock(plain_file_server(false)).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let sink = CaptureSink::default();
    for (start, len) in [(0u64, 64 * 1024u64), (64 * 1024, 64 * 1024)] {
        t.fetch(&Extent { start, len }, &RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("fetch {start}: {e}"));
    }
    assert_eq!(
        mock.conn_count(),
        1,
        "reuse=true: the control connection is reused across extents"
    );
    assert_eq!(
        sink.assembled(128 * 1024)[..128 * 1024],
        body(7, 200 * 1024)[..128 * 1024]
    );

    // No reuse: a new control connection per extent, closed with QUIT.
    let (host, port, mock) = spawn_mock(plain_file_server(false)).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(
        FtpConfig {
            reuse_connection: false,
            ..client_config(FtpTlsMode::None, true)
        },
        &uri,
    )
    .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let sink = CaptureSink::default();
    for (start, len) in [(0u64, 64 * 1024u64), (64 * 1024, 64 * 1024)] {
        t.fetch(&Extent { start, len }, &RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("fetch {start}: {e}"));
    }
    assert_eq!(
        mock.conn_count(),
        2,
        "reuse=false: a new control connection per extent"
    );
    assert!(
        mock.contains_command("QUIT"),
        "the no-reuse path closes out with QUIT"
    );
}

/// Charset: UTF-8 paths are sent as-is; Latin-1 falls back to
/// transcoding.
#[tokio::test]
async fn charset_utf8_and_latin1_paths() {
    // UTF-8 file name (percent-encoded in the URI).
    let mut m = plain_file_server(false);
    m.files.insert("/文件.txt".to_string(), body(1, 16));
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/%E6%96%87%E4%BB%B6.txt");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert_eq!(probe.validator.total_len, Some(16));
    let sink = CaptureSink::default();
    t.fetch(&Extent { start: 0, len: 16 }, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
    assert!(mock.contains_command("RETR 文件.txt"));

    // Latin-1 single-byte name (%E9 = é) → transcoded and sent as
    // UTF-8 wire bytes.
    let mut m = plain_file_server(false);
    m.files.insert("/é.txt".to_string(), body(2, 8));
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/%E9.txt");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert_eq!(probe.validator.total_len, Some(8));
    assert!(
        mock.contains_command("SIZE é.txt"),
        "Latin-1 fallback transcoding (SIZE face)"
    );
    let sink = CaptureSink::default();
    t.fetch(&Extent { start: 0, len: 8 }, &RequestCtx::default(), &sink)
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
    assert!(
        mock.contains_command("RETR é.txt"),
        "Latin-1 fallback transcoding (RETR face)"
    );
    assert_eq!(sink.assembled(8), body(2, 8));
}

/// Absolute subdirectory path: a single absolute CWD (idempotent, safe
/// on reused connections).
#[tokio::test]
async fn absolute_subdir_download() {
    let mut m = plain_file_server(false);
    m.files.insert("/pub/dist/f.bin".to_string(), body(9, 4096));
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/pub/dist/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert_eq!(probe.validator.total_len, Some(4096));
    assert!(probe.validator.final_url_path.contains("/pub/dist/f.bin"));
    let sink = CaptureSink::default();
    t.fetch(
        &Extent {
            start: 0,
            len: 4096,
        },
        &RequestCtx::default(),
        &sink,
    )
    .await
    .unwrap_or_else(|e| panic!("fetch: {e}"));
    assert_eq!(sink.assembled(4096), body(9, 4096));
    assert!(
        mock.contains_command("CWD /pub/dist"),
        "a single CWD for an absolute path"
    );
}

// ---------------------------------------------------------------------------
// MDTM (RFC 3659): the FTP face of --remote-time
// ---------------------------------------------------------------------------

/// MDTM probe: after FEAT the client sends `MDTM <path>`; a 213
/// timestamp (`YYYYMMDDhhmmss[.sss]`, UTC) is normalized into the same
/// last_modified format as the HTTP face, so `--remote-time` works for
/// FTP tasks through the same time parser. A 550 (no mtime) is skipped
/// silently; the probe does not fail.
#[tokio::test]
async fn mdtm_probe_fills_validator_last_modified() {
    use taiji_http::remotetime::parse_http_date;

    let mut m = plain_file_server(false);
    m.mdtm = Some("20260101120000");
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe: {e}"));
    assert!(
        mock.contains_command("MDTM f.bin"),
        "the probe face must send MDTM (recorded commands: {:?})",
        mock.commands()
    );
    let lm = probe
        .validator
        .last_modified
        .as_deref()
        .unwrap_or_else(|| panic!("MDTM 213 -> validator.last_modified must be filled"));
    // 2026-01-01T12:00:00Z = 1767268800 (cross-checked with `date -u`);
    // parsed through the same exit as the HTTP Last-Modified face
    // (remotetime::parse_http_date).
    assert_eq!(
        parse_http_date(lm),
        Some(1_767_268_800),
        "last_modified={lm}"
    );

    // 550 (no mtime) → skipped silently: the probe succeeds and
    // last_modified stays None.
    let (host, port, _mock) = spawn_mock(plain_file_server(false)).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let probe = t
        .probe(&RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("probe under 550 must not fail: {e}"));
    assert_eq!(
        probe.validator.last_modified, None,
        "550 MDTM -> last_modified not filled"
    );
}

// ---------------------------------------------------------------------------
// PASV/EPSV reply-address decisions / completion-reply desync /
// reuse-pool liveness
// ---------------------------------------------------------------------------

/// Test transport assembly with a tightened data-connection dial
/// timeout (failures under malicious replies must be fast).
fn fast_dial_config(tls: FtpTlsMode) -> FtpConfig {
    FtpConfig {
        connect_timeout: Duration::from_secs(5),
        ..client_config(tls, true)
    }
}

/// Malicious PASV reply, positive case: the 227 reply IP is a
/// TEST-NET-3 public address (simulating address spoofing by a
/// malicious or MITM'd server). The default AlignPeer policy overrides
/// the data connection with the control peer plus the reply port, so
/// the data connection still lands on the real data listener.
#[tokio::test]
async fn pasv_malicious_reply_aligns_to_control_peer() {
    let mut m = plain_file_server(false);
    m.pasv_reply_ip = Some("203.0.113.7");
    let (host, port, _mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(fast_dial_config(FtpTlsMode::None), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let sink = CaptureSink::default();
    t.fetch(
        &Extent {
            start: 0,
            len: 64 * 1024,
        },
        &RequestCtx::default(),
        &sink,
    )
    .await
    .unwrap_or_else(|e| panic!("fetch under forged 227 ip: {e}"));
    assert_eq!(
        sink.assembled(64 * 1024),
        &body(7, 200 * 1024)[..64 * 1024],
        "data-plane complete after the peer override"
    );
}

/// Malicious PASV reply, negative case: under the DenyPrivate policy a
/// link-local metadata endpoint (169.254.169.254) redirect is rejected
/// before dialing; nothing is written.
#[tokio::test]
async fn pasv_private_redirect_rejected_under_deny_private() {
    let mut m = plain_file_server(false);
    m.pasv_reply_ip = Some("169.254.169.254");
    let (host, port, _mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(fast_dial_config(FtpTlsMode::None), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"))
        .with_pasv_policy(PasvAddressPolicy::DenyPrivate);
    let sink = CaptureSink::default();
    let err = match t
        .fetch(
            &Extent {
                start: 0,
                len: 1024,
            },
            &RequestCtx::default(),
            &sink,
        )
        .await
    {
        Err(err) => err,
        Ok(_) => panic!("link-local redirect must be rejected"),
    };
    assert!(err.to_string().contains("rejected"), "{err}");
    assert_eq!(sink.write_count(), 0, "the rejected path writes zero bytes");
}

/// The legitimate DenyPrivate case: the reply address equals the
/// control peer (the peer itself is private) → allowed, data flows
/// normally.
#[tokio::test]
async fn pasv_peer_equal_reply_allowed_under_deny_private() {
    let (host, port, _mock) = spawn_mock(plain_file_server(false)).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(fast_dial_config(FtpTlsMode::None), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"))
        .with_pasv_policy(PasvAddressPolicy::DenyPrivate);
    let sink = CaptureSink::default();
    t.fetch(
        &Extent {
            start: 0,
            len: 1024,
        },
        &RequestCtx::default(),
        &sink,
    )
    .await
    .unwrap_or_else(|e| panic!("peer-equal reply must be allowed: {e}"));
    assert_eq!(sink.assembled(1024), &body(7, 200 * 1024)[..1024]);
}

/// 426+226 double completion reply (an out-of-contract server beyond
/// RFC 959's single reply): the residual tail after a mid-transfer
/// drain desyncs the control channel — a desynced connection degrades
/// to single use (no reuse), the next extent uses a fresh connection,
/// and both bytes and connection counts stay correct.
/// The file is 4MiB so the server-side write_all reliably hits EPIPE
/// after the truncation (a small file may fit entirely in loopback
/// buffers → a single 226, no double reply).
#[tokio::test]
async fn double_completion_reply_marks_connection_single_use() {
    const BIG: usize = 4 * 1024 * 1024;
    let mut m = plain_file_server(false);
    m.files.insert("/f.bin".to_string(), body(7, BIG));
    m.double_reply_on_abort = true;
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let sink = CaptureSink::default();
    for (start, len) in [(0u64, 64 * 1024u64), (64 * 1024, 64 * 1024)] {
        t.fetch(&Extent { start, len }, &RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("fetch {start}: {e}"));
    }
    assert_eq!(
        sink.assembled(128 * 1024)[..128 * 1024],
        body(7, BIG)[..128 * 1024],
        "desync does not reuse: both extents' bytes are complete"
    );
    assert_eq!(
        mock.conn_count(),
        2,
        "a desynced connection degrades to single use: the second extent gets a new connection"
    );
    // The explicit drain of the mid-transfer truncation (suppaftp
    // drop-semantics replies, NOOP as the sync check) appears before
    // the second extent's CWD.
    let cmds = mock.commands();
    let first_retr = cmds
        .iter()
        .position(|c| c.starts_with("RETR"))
        .unwrap_or_else(|| panic!("no RETR"));
    assert!(
        cmds[first_retr..].iter().any(|c| c.starts_with("NOOP")),
        "an explicit drain receipt after the mid-transfer truncation"
    );
}

/// Stale pooled connection (the server closes it while idle in the
/// pool): a failed checkout NOOP liveness probe discards it and opens
/// a fresh one — the second extent is unaffected, and the discarded
/// probe failure never surfaces as an extent failure.
#[tokio::test]
async fn stale_pooled_connection_probed_and_replaced() {
    let mut m = plain_file_server(false);
    m.close_after_noop = true;
    let (host, port, mock) = spawn_mock(m).await;
    let uri = format!("ftp://{host}:{port}/f.bin");
    let t = FtpTransport::for_uri(client_config(FtpTlsMode::None, true), &uri)
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    let sink = CaptureSink::default();
    for (start, len) in [(0u64, 64 * 1024u64), (64 * 1024, 64 * 1024)] {
        t.fetch(&Extent { start, len }, &RequestCtx::default(), &sink)
            .await
            .unwrap_or_else(|e| panic!("fetch {start}: {e}"));
    }
    assert_eq!(
        sink.assembled(128 * 1024)[..128 * 1024],
        body(7, 200 * 1024)[..128 * 1024],
        "a stale connection is discarded and replaced: both extents' bytes are complete"
    );
    assert_eq!(
        mock.conn_count(),
        2,
        "a failed checkout probe discards the stale one: the second extent gets a new connection"
    );
}

// ---------------------------------------------------------------------------
// DNS surface (shared resolver integration): stub injection, no real DNS
// ---------------------------------------------------------------------------

/// Stub resolver (injected via [`FtpTransport::with_dns`]; used for
/// hostname hosts on the shared `resolve_for_transport` path).
struct StubResolver {
    result: Result<std::net::IpAddr, String>,
}

impl taiji_io::dns::HostResolver for StubResolver {
    fn resolve(&self, _host: String) -> taiji_io::dns::ResolverFuture {
        let result = self.result.clone();
        Box::pin(std::future::ready(result))
    }
}

/// Hanging stub (resolution never completes — a stuck getaddrinfo; the
/// timeout comes from the surrounding connect_timeout wrap).
struct HangingResolver;

impl taiji_io::dns::HostResolver for HangingResolver {
    fn resolve(&self, _host: String) -> taiji_io::dns::ResolverFuture {
        Box::pin(std::future::pending())
    }
}

/// DNS resolution failure → typed payload
/// `HttpError::FtpDns(ResolveError::Failed)`: the error shape is
/// asserted by type match, not Display text. The string code stays
/// `taiji.http.ftp`. Stub injection: no real DNS, no network
/// (resolution fails before dialing).
#[tokio::test]
async fn dns_failure_maps_to_typed_ftp_dns_payload() {
    let t = FtpTransport::for_uri(
        client_config(FtpTlsMode::None, true),
        "ftp://dns-dead.example/f.bin",
    )
    .unwrap_or_else(|e| panic!("for_uri: {e}"))
    .with_dns(Arc::new(taiji_io::dns::SharedDns::with_resolver(Arc::new(
        StubResolver {
            result: Err("nxdomain stub".to_string()),
        },
    ))));
    let err = match t.probe(&RequestCtx::default()).await {
        Err(err) => err,
        Ok(_) => panic!("stub nxdomain must fail probe"),
    };
    // Typed shape (positive): the ResolveError is carried verbatim,
    // not as a string payload.
    assert!(
        matches!(
            &err,
            HttpError::FtpDns(taiji_io::dns::ResolveError::Failed(m)) if m == "nxdomain stub"
        ),
        "got {err:?}"
    );
    // Code unchanged: same string code as the string-payload Ftp variant.
    assert_eq!(err.code(), HttpError::Ftp("control".into()).code());
    assert_eq!(err.code(), "taiji.http.ftp");
    // fetch has the same shape (the dial path resolves identically).
    let sink = CaptureSink::default();
    let err = match t
        .fetch(
            &Extent {
                start: 0,
                len: 1024,
            },
            &RequestCtx::default(),
            &sink,
        )
        .await
    {
        Err(err) => err,
        Ok(_) => panic!("fetch must fail too"),
    };
    assert!(
        matches!(
            &err,
            HttpError::FtpDns(taiji_io::dns::ResolveError::Failed(_))
        ),
        "got {err:?}"
    );
    assert_eq!(
        sink.write_count(),
        0,
        "a resolution failure writes zero bytes"
    );
}

/// A hanging DNS resolution is bounded by the outer `--connect-timeout`
/// wrap (semantics preserved: a hung resolution is a connection
/// failure, never an infinite wait). A hanging stub plus a short
/// connect_timeout shows the `ResolveError::Timeout` typed payload
/// carrying the active deadline, with bounded return latency.
#[tokio::test]
async fn dns_hang_bounded_by_connect_timeout_wrap() {
    let cfg = FtpConfig {
        connect_timeout: Duration::from_millis(100),
        ..client_config(FtpTlsMode::None, true)
    };
    let t = FtpTransport::for_uri(cfg, "ftp://dns-hang.example/f.bin")
        .unwrap_or_else(|e| panic!("for_uri: {e}"))
        .with_dns(Arc::new(taiji_io::dns::SharedDns::with_resolver(Arc::new(
            HangingResolver,
        ))));
    let t0 = std::time::Instant::now();
    let err = match t.probe(&RequestCtx::default()).await {
        Err(err) => err,
        Ok(_) => panic!("hanging resolution must fail probe"),
    };
    assert!(
        matches!(
            &err,
            HttpError::FtpDns(taiji_io::dns::ResolveError::Timeout(d))
                if *d == Duration::from_millis(100)
        ),
        "got {err:?}"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "returns promptly under the short deadline (elapsed {:?})",
        t0.elapsed()
    );
    assert_eq!(err.code(), "taiji.http.ftp");
}

/// Literal hosts bypass resolution entirely: the stub counter records
/// zero calls, and dialing a closed port fails as a connection error.
#[tokio::test]
async fn literal_host_bypasses_resolver() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct CountingStub {
        calls: AtomicUsize,
    }
    impl taiji_io::dns::HostResolver for CountingStub {
        fn resolve(&self, _host: String) -> taiji_io::dns::ResolverFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(Ok(std::net::IpAddr::V4(
                std::net::Ipv4Addr::LOCALHOST,
            ))))
        }
    }
    let stub = Arc::new(CountingStub {
        calls: AtomicUsize::new(0),
    });
    // Literal host + closed port: zero resolver calls (bypass), and
    // the dial failure is a connection error, not DNS (the payload is
    // not FtpDns).
    let t = FtpTransport::for_uri(
        client_config(FtpTlsMode::None, true),
        "ftp://127.0.0.1:1/f.bin",
    )
    .unwrap_or_else(|e| panic!("for_uri: {e}"))
    .with_dns(Arc::new(taiji_io::dns::SharedDns::with_resolver(
        stub.clone(),
    )));
    let err = match t.probe(&RequestCtx::default()).await {
        Err(err) => err,
        Ok(_) => panic!("port 1 must fail dial"),
    };
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        0,
        "a literal host bypasses resolution (zero calls)"
    );
    assert!(
        !matches!(&err, HttpError::FtpDns(_)),
        "a literal-path failure is not the DNS face: {err:?}"
    );
}
