//! `--ca-certificate` task-level CA mock matrix: the self-signed CA
//! replace semantics (HTTPS wire level) / default rejection without
//! the option (platform roots do not trust the self-signed CA — a
//! status-quo regression lock) / `--check-certificate=false` winning
//! when both are set / bad path and bad PEM = client build errors
//! (never a silent pass). Built directly via the library face
//! [`ClientConfig`]. Loopback only, never the real network.
//!
//! TLS fixtures (`fixtures/ftp-test-ca/`): the local self-signed test
//! CA shared with ftp_mock (ECDSA P-256) plus a server certificate
//! with SAN `DNS:localhost, IP:127.0.0.1, IP:::1` — not real
//! credentials, for mock handshakes only. Platform trust stores never
//! contain this CA: test (a) can only succeed through the option file
//! root — a falsifiable construction of the replace semantics.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use suppaftp::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use suppaftp::tokio_rustls::TlsAcceptor;
use suppaftp::tokio_rustls::rustls;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use taiji_http::client::{ClientConfig, HttpClient, load_ca_certificates_der};
use taiji_http::traits::RequestCtx;

const CA_CERT: &[u8] = include_bytes!("fixtures/ftp-test-ca/ca_cert.der");
const SERVER_CERT: &[u8] = include_bytes!("fixtures/ftp-test-ca/server_cert.der");
const SERVER_KEY: &[u8] = include_bytes!("fixtures/ftp-test-ca/server_key.der");

const PAYLOAD: &[u8] = b"ca-cert-mock-payload";

// ---------------------------------------------------------------------------
// Mock HTTPS server (TLS termination + single-response HTTP/1.1)
// ---------------------------------------------------------------------------

/// Self-signed mock HTTPS server: after the per-connection TLS
/// handshake, read one request head block and reply 200 + [`PAYLOAD`]
/// with a fixed length (Connection: close, a single round — each case
/// issues one GET).
async fn spawn_https() -> (String, u16) {
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
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|e| panic!("bind: {e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("local_addr: {e}"))
        .port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Reply once the request head ends (GET has no body).
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    PAYLOAD.len()
                );
                if tls.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let _ = tls.write_all(PAYLOAD).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    ("127.0.0.1".to_string(), port)
}

// ---------------------------------------------------------------------------
// CA PEM file assembly (the option value shape)
// ---------------------------------------------------------------------------

/// CA DER fixture → PEM file (the `--ca-certificate` value shape).
/// Returns the file path.
fn write_ca_pem(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("taiji-ca-cert-mock-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    let path = dir.join("ca.pem");
    std::fs::write(&path, pem_of(CA_CERT)).unwrap_or_else(|e| panic!("write pem: {e}"));
    path
}

/// DER → PEM (self-contained std base64 — no new dependency; the same
/// encoding as auth_mock).
fn pem_of(der: &[u8]) -> String {
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
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    let encoded = b64(der);
    for chunk in encoded.as_bytes().chunks(64) {
        let line = std::str::from_utf8(chunk).unwrap_or_else(|e| panic!("utf8: {e}"));
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

// ---------------------------------------------------------------------------
// Matrix: replace success / reject without option /
// check-certificate=false wins / bad path, bad PEM
// ---------------------------------------------------------------------------

/// a. Self-signed server + `--ca-certificate=<self-signed CA PEM>` →
/// download succeeds. Platform roots never contain the test CA, so
/// success proves the file root replaced the defaults (aria2 replace
/// semantics, not append; an append would be indistinguishable from a
/// platform-root union in this construction, hence the "platform roots
/// must not contain the CA" criterion — the contrast half is test b).
#[tokio::test]
async fn ca_certificate_file_replaces_platform_roots() {
    let (host, port) = spawn_https().await;
    let url = format!("https://{host}:{port}/f.bin");
    let cfg = ClientConfig {
        ca_cert_path: Some(write_ca_pem("ok")),
        ..ClientConfig::default()
    };
    let client = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let followed = client
        .get(&url, &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    assert_eq!(followed.hops, 0);
    let body = followed
        .response
        .text()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"));
    assert_eq!(body.as_bytes(), PAYLOAD);
}

/// b. Self-signed server without the option → rejected (platform roots
/// do not trust it — a status-quo regression lock; the contrast half
/// of test a).
#[tokio::test]
async fn self_signed_rejected_without_option() {
    let (host, port) = spawn_https().await;
    let url = format!("https://{host}:{port}/f.bin");
    let client = HttpClient::new(ClientConfig::default()).unwrap_or_else(|e| panic!("client: {e}"));
    assert!(
        client.get(&url, &RequestCtx::default()).await.is_err(),
        "platform roots do not trust self-signed — must fail"
    );
}

/// c. `--ca-certificate` + `--check-certificate=false` together → the
/// latter wins: validation is off and the CA file is ignored, not even
/// read. Proof by construction: the path points at a nonexistent file,
/// the transport still builds and the download succeeds — if the CA
/// file were still loaded the build would fail (a strong precedence
/// assertion; the same rule as aria2's "ignore when
/// check-certificate=false").
#[tokio::test]
async fn check_certificate_false_wins_over_ca_file() {
    let (host, port) = spawn_https().await;
    let url = format!("https://{host}:{port}/f.bin");
    let cfg = ClientConfig {
        accept_invalid_certs: true,
        ca_cert_path: Some(PathBuf::from("/nonexistent/taiji-ca.pem")),
        ..ClientConfig::default()
    };
    let client = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    let followed = client
        .get(&url, &RequestCtx::default())
        .await
        .unwrap_or_else(|e| panic!("get: {e}"));
    let body = followed
        .response
        .text()
        .await
        .unwrap_or_else(|e| panic!("body: {e}"));
    assert_eq!(body.as_bytes(), PAYLOAD);
}

/// d. Bad path / bad PEM → client build error (never a silent pass).
/// Checked at both layers: the loader helper
/// ([`load_ca_certificates_der`], the single loader behind the option,
/// HTTP, and FTP faces) and [`HttpClient`] construction.
#[tokio::test]
async fn bad_path_and_bad_pem_fail_client_build() {
    // Bad path: the build rejects it.
    let cfg = ClientConfig {
        ca_cert_path: Some(PathBuf::from("/nonexistent/taiji-ca.pem")),
        ..ClientConfig::default()
    };
    assert!(
        HttpClient::new(cfg).is_err(),
        "a bad path must fail the build"
    );
    assert!(load_ca_certificates_der(Path::new("/nonexistent/taiji-ca.pem")).is_err());

    // Bad PEM: a CERTIFICATE section with a corrupt body (not base64)
    // → parse error.
    let dir = std::env::temp_dir().join(format!("taiji-ca-cert-mock-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
    let bad_body = dir.join("bad-body.pem");
    std::fs::write(
        &bad_body,
        "-----BEGIN CERTIFICATE-----\n@@not-base64@@\n-----END CERTIFICATE-----\n",
    )
    .unwrap_or_else(|e| panic!("write: {e}"));
    assert!(
        load_ca_certificates_der(&bad_body).is_err(),
        "a bad PEM body must be rejected"
    );
    let cfg = ClientConfig {
        ca_cert_path: Some(bad_body),
        ..ClientConfig::default()
    };
    assert!(
        HttpClient::new(cfg).is_err(),
        "a bad PEM must fail the build"
    );

    // Bad PEM: a valid-base64 body that is not X.509 (webpki rejects
    // it at parse — a build-time failure, matching aria2's "failed to
    // load certificate").
    let garbage = dir.join("garbage.pem");
    std::fs::write(&garbage, pem_of(b"not-a-certificate")).unwrap_or_else(|e| panic!("write: {e}"));
    assert!(
        HttpClient::new(ClientConfig {
            ca_cert_path: Some(garbage),
            ..ClientConfig::default()
        })
        .is_err(),
        "a non-X.509 CERTIFICATE section must fail the build"
    );

    // Empty file (no CERTIFICATE section) → rejected.
    let empty = dir.join("empty.pem");
    std::fs::write(&empty, "").unwrap_or_else(|e| panic!("write: {e}"));
    assert!(
        load_ca_certificates_der(&empty).is_err(),
        "an empty file must be rejected"
    );
}

/// Loader value domain: a PEM with one or many certificates → a DER
/// sequence (the shape fed to the FTP face; the replace semantics live
/// at the consumer — this only proves loading).
#[tokio::test]
async fn loader_parses_pem_single_and_bundle() {
    let path = write_ca_pem("loader");
    let ders = load_ca_certificates_der(&path).unwrap_or_else(|e| panic!("load: {e}"));
    assert_eq!(ders.len(), 1);
    assert_eq!(ders[0], CA_CERT);

    // A multi-certificate PEM (CA + server certificate back to back)
    // → one DER per section, order preserved.
    let dir =
        std::env::temp_dir().join(format!("taiji-ca-cert-mock-bundle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
    let bundle = dir.join("bundle.pem");
    std::fs::write(
        &bundle,
        format!("{}{}", pem_of(CA_CERT), pem_of(SERVER_CERT)),
    )
    .unwrap_or_else(|e| panic!("write: {e}"));
    let ders = load_ca_certificates_der(&bundle).unwrap_or_else(|e| panic!("load: {e}"));
    assert_eq!(ders.len(), 2);
    assert_eq!(ders[0], CA_CERT);
    assert_eq!(ders[1], SERVER_CERT);
}
