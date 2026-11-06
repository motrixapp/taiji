//! Wire-level mock matrix for the client mTLS identity + TLS minimum
//! version (domain B `--certificate`/`--private-key`/`--min-tls-version`
//! transport faces):
//!
//! a. the server **requires** client certificates
//! (`with_client_cert_verifier`) + the client presents its identity
//! ([`ClientConfig::identity_cert_path`]/[`identity_key_path`] ->
//! reqwest `Identity::from_pem`) -> the handshake succeeds and the
//! download completes — success can only come from presenting the
//! identity (the no-identity control half must fail, a falsifiable
//! construction);
//! b. the same server without an identity -> refused at the TLS handshake
//! (certificate required alert);
//! c. one side given (only the certificate or only the key) -> a **client
//! build error** (not a silent run without identity); bad PEM takes
//! the same face;
//! d. `--min-tls-version`: the server locks TLS1.2 + a client floor of
//! tls1.3 -> negotiation fails; a client floor of tls1.2 -> succeeds
//! (real wire evidence for the version floor).
//!
//! TLS fixtures (`fixtures/mtls-test-ca/`): a local mini-CA dedicated to
//! these tests (ECDSA P-256, self-signed) + the two leaf certificates it
//! issued — the server certificate (serverAuth EKU + SAN
//! `DNS:localhost, IP:127.0.0.1, IP:::1`) and the **client identity
//! certificate** (clientAuth EKU — the ftp-test-ca server certificate's
//! EKU carries only serverAuth, which `WebPkiClientVerifier` rejects as a
//! client identity, hence the dedicated pair). Not real credentials,
//! mock-handshake material only; the platform trust store never contains
//! this CA.

use std::path::{Path, PathBuf};

use suppaftp::rustls::pki_types::pem::PemObject;
use suppaftp::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use suppaftp::tokio_rustls::TlsAcceptor;
use suppaftp::tokio_rustls::rustls;
use taiji_http::client::{ClientConfig, HttpClient, MinTlsVersion, load_client_identity_pem};
use taiji_http::traits::RequestCtx;

const CA_CERT_PEM: &[u8] = include_bytes!("fixtures/mtls-test-ca/ca_cert.pem");
const SERVER_CERT_PEM: &[u8] = include_bytes!("fixtures/mtls-test-ca/server_cert.pem");
const SERVER_KEY_PEM: &[u8] = include_bytes!("fixtures/mtls-test-ca/server_key.pem");
const CLIENT_CERT_PEM: &[u8] = include_bytes!("fixtures/mtls-test-ca/client_cert.pem");
const CLIENT_KEY_PEM: &[u8] = include_bytes!("fixtures/mtls-test-ca/client_key.pem");

const PAYLOAD: &[u8] = b"mtls-mock-payload";

// ---------------------------------------------------------------------------
// mock HTTPS server (TLS termination + optional required client cert + one HTTP/1.1 response)
// ---------------------------------------------------------------------------

/// Self-signed mock HTTPS server. With `require_client_cert = true` a
/// [`rustls::server::WebPkiClientVerifier`] is wired in (roots = the test
/// CA) — a client presenting no verifiable certificate fails the
/// handshake (the control half of case b); `protocol_versions` locks the
/// server-side negotiation set (the version floor of case d). After each
/// connection's TLS handshake it reads one request header block and
/// replies 200 + [`PAYLOAD`] (Connection: close, single shot, discarded).
async fn spawn_https_mtls(require_client_cert: bool, tls12_only: bool) -> (String, u16) {
    use rustls::server::WebPkiClientVerifier;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(CA_CERT_PEM) {
        roots
            .add(cert.unwrap_or_else(|e| panic!("root ca: {e}")))
            .unwrap_or_else(|e| panic!("add root: {e}"));
    }
    let server_cert = CertificateDer::pem_slice_iter(SERVER_CERT_PEM)
        .next()
        .unwrap_or_else(|| panic!("server cert missing"))
        .unwrap_or_else(|e| panic!("server cert: {e}"));
    let server_key = PrivateKeyDer::pem_slice_iter(SERVER_KEY_PEM)
        .next()
        .unwrap_or_else(|| panic!("server key missing"))
        .unwrap_or_else(|e| panic!("server key: {e}"));
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12_only {
        &[&rustls::version::TLS12]
    } else {
        rustls::ALL_VERSIONS
    };
    let config = match require_client_cert {
        true => {
            let verifier =
                WebPkiClientVerifier::builder_with_provider(roots.into(), provider.clone())
                    .build()
                    .unwrap_or_else(|e| panic!("client verifier: {e}"));
            rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(versions)
                .unwrap_or_else(|e| panic!("protocol versions: {e}"))
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![server_cert], server_key)
                .unwrap_or_else(|e| panic!("server cert: {e}"))
        }
        false => rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .unwrap_or_else(|e| panic!("protocol versions: {e}"))
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
            .unwrap_or_else(|e| panic!("server cert: {e}")),
    };
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
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

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// PEM file assembly (DER fixture -> arbitrary-tag PEM; the ca_cert_mock encoding face)
// ---------------------------------------------------------------------------

/// DER -> PEM (tag parameterized: `CERTIFICATE` / `PRIVATE KEY`). Writes
/// into a temp directory and returns the path.
fn write_pem(tag: &str, name: &str, label: &str, der: &[u8]) -> PathBuf {
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
    let mut text = format!("-----BEGIN {label}-----\n");
    let encoded = b64(der);
    for chunk in encoded.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(chunk).unwrap_or_else(|e| panic!("utf8: {e}")));
        text.push('\n');
    }
    text.push_str(&format!("-----END {label}-----\n"));
    let dir = std::env::temp_dir().join(format!("taiji-mtls-mock-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    path
}

fn write_client_identity(tag: &str) -> (PathBuf, PathBuf) {
    (
        write_pem_text(tag, "client-cert.pem", CLIENT_CERT_PEM),
        write_pem_text(tag, "client-key.pem", CLIENT_KEY_PEM),
    )
}

/// Writes the bytes to disk as-is (the fixture is already PEM text).
fn write_pem_text(tag: &str, name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("taiji-mtls-mock-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    path
}

/// Test CA PEM (root face: an explicit file root goes through the rustls
/// webpki verification path — the platform trust-store verifier is
/// stricter with certificates this test CA issued (the serial compliance
/// face), and "trust comes from the option file root" keeps the
/// assertions dependent only on the trust domain this file assembles).
fn write_ca_pem(tag: &str) -> PathBuf {
    write_pem_text(tag, "ca.pem", CA_CERT_PEM)
}

fn identity_config(cert: PathBuf, key: PathBuf, ca: PathBuf) -> ClientConfig {
    ClientConfig {
        identity_cert_path: Some(cert),
        identity_key_path: Some(key),
        ca_cert_path: Some(ca),
        ..ClientConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Matrix: mTLS success / no-identity refusal / one-side refusal / bad PEM refusal / version floor
// ---------------------------------------------------------------------------

/// a. A server requiring client certificates + the client identity ->
/// handshake success + download complete. The server verifier roots =
/// the test CA — the presented identity (the certificate pair loaded
/// via `Identity::from_pem`) passing verification is the only path to
/// success.
#[tokio::test]
async fn mtls_identity_presented_and_verified() {
    let (host, port) = spawn_https_mtls(true, false).await;
    let url = format!("https://{host}:{port}/f.bin");
    let (cert, key) = write_client_identity("ok");
    let client = HttpClient::new(identity_config(cert, key, write_ca_pem("ok")))
        .unwrap_or_else(|e| panic!("client: {e}"));
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

/// b. The same server without an identity -> the request fails (the
/// server's certificate required alert, refused at the handshake) —
/// the control half of case a: success can only come from the identity
/// face.
#[tokio::test]
async fn mtls_server_rejects_client_without_identity() {
    let (host, port) = spawn_https_mtls(true, false).await;
    let url = format!("https://{host}:{port}/f.bin");
    // The server trust face also goes through the option file root (the
    // rustls webpki verification path) — this case's failure may only
    // come from "the client presented no certificate" (the server's
    // certificate required alert), not from a server certificate
    // verification failure (control-half purity).
    let cfg = ClientConfig {
        ca_cert_path: Some(write_ca_pem("no-identity")),
        ..ClientConfig::default()
    };
    let client = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    assert!(
        client.get(&url, &RequestCtx::default()).await.is_err(),
        "a server requiring client certificates must reject an identity-less handshake"
    );
}

/// c. One side given -> a client build error (explicit refusal, not a
/// silent run without identity — a TLS client identity with half of it
/// missing fails at the handshake for sure; expose that early at build
/// time).
#[tokio::test]
async fn mtls_half_configured_identity_fails_client_build() {
    let (cert, key) = write_client_identity("half");
    let cert_only = ClientConfig {
        identity_cert_path: Some(cert),
        ..ClientConfig::default()
    };
    assert!(
        HttpClient::new(cert_only).is_err(),
        "certificate only must fail the build"
    );
    let key_only = ClientConfig {
        identity_key_path: Some(key),
        ..ClientConfig::default()
    };
    assert!(
        HttpClient::new(key_only).is_err(),
        "key only must fail the build"
    );
}

/// d. Bad path / bad PEM -> explicit errors at both layers, the load
/// helper and the client build (never silently allowed through; error
/// messages carry only the path and the failure stage, no file
/// content).
#[tokio::test]
async fn mtls_bad_paths_and_bad_pem_fail_loudly() {
    // Bad path (each of the two files).
    let missing_cert = Path::new("/nonexistent/taiji-mtls-cert.pem");
    let missing_key = Path::new("/nonexistent/taiji-mtls-key.pem");
    assert!(load_client_identity_pem(missing_cert, missing_key).is_err());

    // Certificate file without a CERTIFICATE section -> an explicit error
    // pinpointing the certificate file.
    let (cert, key) = write_client_identity("badcert");
    let garbage_cert = write_pem("badcert", "garbage.pem", "GARBAGE", b"junk");
    assert!(
        load_client_identity_pem(&garbage_cert, &key).is_err(),
        "a missing CERTIFICATE section must be rejected"
    );

    // Key file without a private key section -> an explicit error
    // pinpointing the key file.
    let garbage_key = write_pem("badkey", "garbage-key.pem", "GARBAGE", b"junk");
    assert!(
        load_client_identity_pem(&cert, &garbage_key).is_err(),
        "a missing private-key section must be rejected"
    );

    // Broken structure (a non-base64 section body) -> refused at the
    // reqwest Identity::from_pem build surface.
    let broken_key = std::env::temp_dir().join(format!(
        "taiji-mtls-mock-broken-{}-broken-key.pem",
        std::process::id()
    ));
    std::fs::write(
        &broken_key,
        "-----BEGIN PRIVATE KEY-----\n@@not-base64@@\n-----END PRIVATE KEY-----\n",
    )
    .unwrap_or_else(|e| panic!("write: {e}"));
    let pem = load_client_identity_pem(&cert, &broken_key).unwrap_or_else(|e| panic!("load: {e}"));
    assert!(
        reqwest::Identity::from_pem(&pem).is_err(),
        "a corrupt section body must be rejected by Identity parsing"
    );
}

/// e. The `--min-tls-version` version floor (wire level): the server
/// locks TLS1.2; a client floor of tls1.3 -> negotiation fails; a
/// client floor of tls1.2 -> succeeds.
#[tokio::test]
async fn min_tls_version_floor_is_enforced_on_wire() {
    let (host, port) = spawn_https_mtls(false, true).await;
    let url = format!("https://{host}:{port}/f.bin");

    // A tls1.3 floor vs a TLS1.2-only server -> no common version, the
    // handshake must fail.
    let cfg = ClientConfig {
        min_tls_version: Some(MinTlsVersion::Tls13),
        ca_cert_path: Some(write_ca_pem("tls13")),
        ..ClientConfig::default()
    };
    let client = HttpClient::new(cfg).unwrap_or_else(|e| panic!("client: {e}"));
    assert!(
        client.get(&url, &RequestCtx::default()).await.is_err(),
        "a tls1.3 floor must fail against a TLS1.2-only server"
    );

    // A tls1.2 floor -> compatible with the TLS1.2-only server, success.
    let cfg = ClientConfig {
        min_tls_version: Some(MinTlsVersion::Tls12),
        ca_cert_path: Some(write_ca_pem("tls12")),
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

/// Single value-range point: `MinTlsVersion::from_value` = the CLI/conf
/// shared domain `tls1.2|tls1.3`; outside the domain None.
#[test]
fn min_tls_version_value_domain() {
    assert_eq!(
        MinTlsVersion::from_value("tls1.2"),
        Some(MinTlsVersion::Tls12)
    );
    assert_eq!(
        MinTlsVersion::from_value("tls1.3"),
        Some(MinTlsVersion::Tls13)
    );
    for junk in ["", "TLSv1.2", "tls1.1", "tls1.0", "ssl3", "1.2"] {
        assert_eq!(
            MinTlsVersion::from_value(junk),
            None,
            "junk {junk:?} must be rejected"
        );
    }
}
