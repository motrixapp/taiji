//! FTP container interop matrix (local lab): the in-process mock matrix
//! (`ftp_mock.rs`) cross-validated against real FTP servers (vsftpd +
//! proftpd). Fixtures, the vsftpd listen-mode defect, the skip policy,
//! and the mock-row mapping live in docs/design/http.md.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;

use taiji_http::error::HttpError;
use taiji_http::ftp::{FtpConfig, FtpProbe, FtpTlsMode, FtpTransport};
use taiji_http::traits::{Extent, RequestCtx, SegId, SegmentSink, SegmentTransport};

/// Container-matrix self-signed test certificate (SAN
/// `DNS:localhost, IP:127.0.0.1`; not real credentials; separate from
/// the mock matrix's EC test CA — the container server uses the common
/// RSA shape).
const CONTAINER_SERVER_CERT: &[u8] =
    include_bytes!("fixtures/ftp-test-ca/container_server_cert.der");

const VSFTPD_IMAGE_DEFAULT: &str = "taiji-ftp-it-vsftpd:matrix";
const PROFTPD_IMAGE_DEFAULT: &str = "taiji-ftp-it-proftpd:matrix";

/// Matrix baseline file (server content root): full-download / extent
/// baseline, same pattern as the mock.
const MATRIX_FILE: &str = "f200k.bin";
const MATRIX_LEN: u64 = 200 * 1024;
/// UTF-8 file name (direct-send row, percent-encoded in the URI).
const UTF8_FILE_ENCODED: &str = "%E6%96%87%E4%BB%B6.txt";
const UTF8_FILE: &str = "文件.txt";
/// Latin-1 single-byte file name (fallback re-encode row): URI `%A3` →
/// Latin-1 £ → UTF-8 wire bytes.
const LATIN1_FILE_ENCODED: &str = "%A3.txt";
const LATIN1_FILE: &str = "£.txt";

const READY_DEADLINE: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// docker execution (blocking; the pool build runs inside
// spawn_blocking, no lock held across await)
// ---------------------------------------------------------------------------

fn run_docker(args: &[String], timeout: Duration) -> Result<Output, String> {
    let label = args.first().map(String::as_str).unwrap_or("");
    let mut child = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn docker {label}: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().map_err(|e| e.to_string()),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                return Err(format!("docker {label} timed out after {timeout:?}"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn docker_stdout(args: &[String], timeout: Duration) -> Result<String, String> {
    let out = run_docker(args, timeout)?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// Skip marker. Printed on the spawn_blocking thread (libtest output
/// capture is thread-local, so this stderr reaches the terminal by
/// default); under `TAIJI_FTP_IT_REQUIRE=1` the caller panics on the
/// test thread instead.
fn note_skip(reason: &str) {
    eprintln!("SKIP(taiji.ftp.container-matrix): {reason}");
}

/// The REQUIRE decision runs on the test thread after the pool build
/// returns (a panic turns the test red).
fn matrix_disabled() -> bool {
    std::env::var("TAIJI_FTP_IT_OFF").is_ok_and(|v| v == "1")
}

fn image_ref(env_key: &str, default: &str) -> String {
    std::env::var(env_key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

// ---------------------------------------------------------------------------
// Content dir (generated once per process; non-ASCII file names
// survive the bind mount)
// ---------------------------------------------------------------------------

static PUB_DIR: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

fn lock_or_recover<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Deterministic content pattern (same as ftp_mock.rs).
fn body(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn build_pub_dir() -> Result<std::path::PathBuf, String> {
    let mut guard = lock_or_recover(&PUB_DIR);
    if let Some(dir) = guard.as_ref() {
        return Ok(dir.clone());
    }
    let dir = std::env::temp_dir().join(format!("taiji-ftp-it-pub-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("pub dir: {e}"))?;
    std::fs::write(dir.join(MATRIX_FILE), body(7, MATRIX_LEN as usize))
        .map_err(|e| format!("pub file {MATRIX_FILE}: {e}"))?;
    std::fs::write(dir.join(UTF8_FILE), body(1, 16)).map_err(|e| format!("pub file utf8: {e}"))?;
    std::fs::write(dir.join(LATIN1_FILE), body(2, 8))
        .map_err(|e| format!("pub file latin1: {e}"))?;
    *guard = Some(dir.clone());
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Shared container pool (four instances: vsftpd plaintext/implicit +
// proftpd plaintext/implicit; shared across cases in one test binary,
// torn down when the last reference drops)
// ---------------------------------------------------------------------------

struct Endpoint {
    name: &'static str,
    /// Host-side control port.
    port: u16,
    /// Container-side control port (plaintext 21 / implicit 990).
    container_port: u16,
    /// PASV/EPSV port range (published 1:1 host=container; distinct
    /// per instance).
    pasv: (u16, u16),
    conf: &'static str,
    mount_target: &'static str,
    image_env: &'static str,
    image_default: &'static str,
    /// Dockerfile used to build the image when missing (relative to
    /// tests/fixtures).
    build: Option<&'static str>,
    /// Extra run args (the vsftpd implicit instance injects its inetd
    /// listen port via INETD_PORT).
    extra_run_args: &'static [&'static str],
    auth_user: bool,
}

const VSFTPD: Endpoint = Endpoint {
    name: "taiji-ftp-it-vsftpd",
    port: 12121,
    container_port: 21,
    pasv: (50100, 50199),
    conf: "fixtures/ftp-container/vsftpd.conf",
    mount_target: "/etc/vsftpd/taiji.conf",
    image_env: "TAIJI_FTP_IT_IMAGE_VSFTPD",
    image_default: VSFTPD_IMAGE_DEFAULT,
    build: Some("local-build/vsftpd.Dockerfile"),
    extra_run_args: &[],
    auth_user: true,
};

const VSFTPD_IMPLICIT: Endpoint = Endpoint {
    name: "taiji-ftp-it-vsftpd-implicit",
    port: 12123,
    container_port: 990,
    pasv: (51100, 51199),
    conf: "fixtures/ftp-container/vsftpd-implicit.conf",
    mount_target: "/etc/vsftpd/taiji.conf",
    image_env: "TAIJI_FTP_IT_IMAGE_VSFTPD",
    image_default: VSFTPD_IMAGE_DEFAULT,
    build: Some("local-build/vsftpd.Dockerfile"),
    extra_run_args: &["-e", "INETD_PORT=990"],
    auth_user: false,
};

const PROFTPD: Endpoint = Endpoint {
    name: "taiji-ftp-it-proftpd",
    port: 12122,
    container_port: 21,
    pasv: (52100, 52199),
    conf: "fixtures/ftp-container/proftpd.conf",
    mount_target: "/etc/proftpd/proftpd.conf",
    image_env: "TAIJI_FTP_IT_IMAGE_PROFTPD",
    image_default: PROFTPD_IMAGE_DEFAULT,
    build: Some("local-build/proftpd.Dockerfile"),
    extra_run_args: &[],
    auth_user: true,
};

const PROFTPD_IMPLICIT: Endpoint = Endpoint {
    name: "taiji-ftp-it-proftpd-implicit",
    port: 12124,
    container_port: 990,
    pasv: (53100, 53199),
    conf: "fixtures/ftp-container/proftpd-implicit.conf",
    mount_target: "/etc/proftpd/proftpd.conf",
    image_env: "TAIJI_FTP_IT_IMAGE_PROFTPD",
    image_default: PROFTPD_IMAGE_DEFAULT,
    build: Some("local-build/proftpd.Dockerfile"),
    extra_run_args: &[],
    auth_user: false,
};

const ENDPOINTS: [&Endpoint; 4] = [&VSFTPD, &VSFTPD_IMPLICIT, &PROFTPD, &PROFTPD_IMPLICIT];

struct Pool;

impl Drop for Pool {
    fn drop(&mut self) {
        // Tear down containers. Crash leftovers are also handled by the
        // rm -f before the next pool build; the content temp dir is left
        // for OS temp cleanup — the pool may be rebuilt in this process,
        // so it cannot be deleted early.
        for ep in ENDPOINTS {
            let _ = run_docker(
                &["rm".into(), "-f".into(), ep.name.to_string()],
                Duration::from_secs(60),
            );
        }
    }
}

static POOL: Mutex<Option<Weak<Pool>>> = Mutex::new(None);

fn pool_alive() -> Option<Arc<Pool>> {
    lock_or_recover(&POOL).as_ref().and_then(Weak::upgrade)
}

/// Matrix entry: return the shared container pool; None = the matrix
/// is explicitly skipped (SKIP marker already printed).
async fn pool() -> Option<Arc<Pool>> {
    if let Some(alive) = pool_alive() {
        return Some(alive);
    }
    let built = tokio::task::spawn_blocking(|| {
        let mut guard = lock_or_recover(&POOL);
        if let Some(alive) = guard.as_ref().and_then(Weak::upgrade) {
            return Ok(alive);
        }
        match build_pool() {
            Ok(pool) => {
                let arc = Arc::new(pool);
                *guard = Some(Arc::downgrade(&arc));
                Ok(arc)
            }
            Err(reason) => {
                // The builder thread's stderr is not captured by
                // libtest: the SKIP marker is visible by default.
                note_skip(&reason);
                Err(reason)
            }
        }
    })
    .await;
    match built {
        Ok(Ok(arc)) => Some(arc),
        Ok(Err(reason)) => {
            if std::env::var("TAIJI_FTP_IT_REQUIRE").is_ok_and(|v| v == "1") {
                panic!(
                    "FTP container matrix required (TAIJI_FTP_IT_REQUIRE=1) but unavailable: {reason}"
                );
            }
            None
        }
        Err(join) => {
            note_skip(&format!("pool builder join error: {join}"));
            None
        }
    }
}

fn docker_env_ready() -> Result<(), String> {
    if matrix_disabled() {
        return Err("disabled by TAIJI_FTP_IT_OFF=1".into());
    }
    let probe = run_docker(
        &["info".into(), "--format".into(), "ok".into()],
        Duration::from_secs(30),
    );
    if !probe.as_ref().is_ok_and(|o| o.status.success()) {
        let detail = probe
            .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
            .unwrap_or_else(|e| e);
        return Err(format!(
            "docker daemon unavailable (docker info failed): {detail}"
        ));
    }
    Ok(())
}

/// Image handling: build from the fixtures Dockerfile when the default
/// reference is not cached (native multi-arch); fall back to
/// `docker pull` when an env-overridden reference is missing (external
/// registry etc.).
fn ensure_image(ep: &Endpoint) -> Result<(), String> {
    let reference = image_ref(ep.image_env, ep.image_default);
    let inspect = run_docker(
        &["image".into(), "inspect".into(), reference.clone()],
        Duration::from_secs(30),
    );
    if inspect.as_ref().is_ok_and(|o| o.status.success()) {
        return Ok(());
    }
    if image_ref(ep.image_env, ep.image_default) == ep.image_default {
        if let Some(dockerfile) = ep.build {
            let manifest_dir = env!("CARGO_MANIFEST_DIR");
            let dockerfile_path = std::path::Path::new(manifest_dir)
                .join("tests/fixtures/ftp-container")
                .join(dockerfile);
            let build_dir = dockerfile_path
                .parent()
                .map_or_else(|| Err("dockerfile has no parent dir".to_string()), Ok)?;
            return docker_stdout(
                &[
                    "build".into(),
                    "-f".into(),
                    dockerfile_path.display().to_string(),
                    "-t".into(),
                    reference,
                    build_dir.display().to_string(),
                ],
                Duration::from_secs(600),
            )
            .map(|_| ())
            .map_err(|e| format!("image build failed ({}): {e}", ep.image_default));
        }
    }
    docker_stdout(&["pull".into(), reference], Duration::from_secs(600))
        .map(|_| ())
        .map_err(|e| format!("image pull failed ({}): {e}", ep.image_default))
}

fn build_pool() -> Result<Pool, String> {
    docker_env_ready()?;
    let pub_dir = build_pub_dir()?;
    for ep in ENDPOINTS {
        ensure_image(ep)?;
    }
    // Remove same-name containers left over by a previous crashed run.
    for ep in ENDPOINTS {
        let _ = docker_stdout(
            &["rm".into(), "-f".into(), ep.name.to_string()],
            Duration::from_secs(60),
        );
    }
    for ep in ENDPOINTS {
        // Port publishing can lag briefly after rm (userland forwarder
        // reclamation); on failure, tear down and retry once.
        if let Err(first) = start_endpoint(ep, &pub_dir) {
            let _ = docker_stdout(
                &["rm".into(), "-f".into(), ep.name.to_string()],
                Duration::from_secs(60),
            );
            std::thread::sleep(Duration::from_millis(1500));
            start_endpoint(ep, &pub_dir)
                .map_err(|second| format!("start ({}) retry failed: {first}; {second}", ep.name))?;
        }
        if ep.auth_user {
            provision_auth_user(ep.name)?;
        }
    }
    Ok(Pool)
}

fn provision_auth_user(name: &str) -> Result<(), String> {
    docker_stdout(
        &[
            "exec".into(),
            name.to_string(),
            "sh".into(),
            "-c".into(),
            "id taiji >/dev/null 2>&1 || useradd -d /srv/ftp/pub -s /bin/sh taiji; \
             echo 'taiji:taijipass' | chpasswd"
                .into(),
        ],
        Duration::from_secs(60),
    )
    .map(|_| ())
    .map_err(|e| format!("auth user provisioning ({name}): {e}"))
}

fn start_endpoint(ep: &Endpoint, pub_dir: &std::path::Path) -> Result<(), String> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let tests_dir = std::path::Path::new(manifest_dir).join("tests");
    let ca_dir = tests_dir.join("fixtures/ftp-test-ca");
    let mut args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        ep.name.to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{}:{}", ep.port, ep.container_port),
        "-p".to_string(),
        format!(
            "127.0.0.1:{}-{}:{}-{}",
            ep.pasv.0, ep.pasv.1, ep.pasv.0, ep.pasv.1
        ),
        "-v".to_string(),
        format!("{}:/srv/ftp/pub:ro", pub_dir.display()),
        "-v".to_string(),
        format!(
            "{}:{}:ro",
            tests_dir.join(ep.conf).display(),
            ep.mount_target
        ),
        "-v".to_string(),
        format!(
            "{}:/etc/ssl/taiji/server.pem:ro",
            ca_dir.join("container_server_cert.pem").display()
        ),
        "-v".to_string(),
        format!(
            "{}:/etc/ssl/taiji/server.key:ro",
            ca_dir.join("container_server_key.pem").display()
        ),
    ];
    args.extend(ep.extra_run_args.iter().map(|s| (*s).to_string()));
    args.push(image_ref(ep.image_env, ep.image_default));
    docker_stdout(&args, Duration::from_secs(120))
        .map(|_| ())
        .map_err(|e| format!("container start ({}): {e}", ep.name))
}

// ---------------------------------------------------------------------------
// Transport-under-test assembly (sink/assertions mirroring the mock
// matrix)
// ---------------------------------------------------------------------------

/// Recording sink (as in the mock matrix; `complete_block` always
/// errors — the transport must not do block bookkeeping).
#[derive(Default)]
struct CaptureSink {
    writes: Mutex<Vec<(u64, Vec<u8>)>>,
}

impl CaptureSink {
    fn assembled(&self, total: u64) -> Vec<u8> {
        let mut out = vec![0u8; total as usize];
        for (off, bytes) in lock_or_recover(&self.writes).iter() {
            let off = *off as usize;
            out[off..off + bytes.len()].copy_from_slice(bytes);
        }
        out
    }
}

impl SegmentSink for CaptureSink {
    fn write_at(
        &self,
        _seg: SegId,
        off: u64,
        bytes: Bytes,
    ) -> futures::future::BoxFuture<'_, taiji_http::error::Result<()>> {
        lock_or_recover(&self.writes).push((off, bytes.to_vec()));
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

/// Container-matrix client config: the added trust anchor is the
/// self-signed test certificate (validation on by default — the
/// explicit TLS rows exercise it); timeouts are tightened so readiness
/// retries cycle fast.
fn client_config(tls: FtpTlsMode) -> FtpConfig {
    FtpConfig {
        tls,
        connect_timeout: Duration::from_secs(5),
        read_idle_timeout: Duration::from_secs(30),
        extra_ca_certs_der: vec![CONTAINER_SERVER_CERT.to_vec()],
        ..FtpConfig::default()
    }
}

fn matrix_uri(port: u16, userinfo: Option<(&str, &str)>, path: &str) -> String {
    let creds = userinfo
        .map(|(u, p)| format!("{u}:{p}@"))
        .unwrap_or_default();
    format!("ftp://{creds}127.0.0.1:{port}/{path}")
}

/// Pool assembly: the container pool (None = SKIP already printed)
/// plus a transport aimed at the endpoint's file.
async fn matrix_transport(
    ep: &'static Endpoint,
    tls: FtpTlsMode,
    path: &str,
) -> Option<(Arc<Pool>, FtpTransport)> {
    let pool = pool().await?;
    let transport = FtpTransport::for_uri(client_config(tls), &matrix_uri(ep.port, None, path))
        .unwrap_or_else(|e| panic!("for_uri: {e}"));
    Some((pool, transport))
}

/// Pool assembly with credentials (URI userinfo has top precedence).
async fn matrix_transport_with_creds(
    ep: &'static Endpoint,
    user: &str,
    password: &str,
) -> Option<(Arc<Pool>, FtpTransport)> {
    let pool = pool().await?;
    let uri = matrix_uri(ep.port, Some((user, password)), MATRIX_FILE);
    let transport = FtpTransport::for_uri(client_config(FtpTlsMode::None), &uri)
        .unwrap_or_else(|e| panic!("for_uri creds: {e}"));
    Some((pool, transport))
}

/// Readiness probe: loop the transport's probe until success or the
/// deadline (the last failure is carried into the panic message).
async fn wait_ready(transport: &FtpTransport, who: &str) -> FtpProbe {
    let start = Instant::now();
    let mut last_err = String::from("no attempt");
    while start.elapsed() < READY_DEADLINE {
        match transport.probe(&RequestCtx::default()).await {
            Ok(probe) => return probe,
            Err(e) => {
                last_err = e.to_string();
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    panic!("{who} not ready within {READY_DEADLINE:?}: {last_err}");
}

async fn fetch_extent(transport: &FtpTransport, start: u64, len: u64, sink: &CaptureSink) {
    transport
        .fetch(&Extent { start, len }, &RequestCtx::default(), sink)
        .await
        .unwrap_or_else(|e| panic!("fetch extent {start}+{len}: {e}"));
}

// ---------------------------------------------------------------------------
// Matrix: vsftpd (12121 plaintext + explicit TLS; 12123 implicit TLS)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vsftpd_anonymous_download_and_probe() {
    let Some((_pool, transport)) = matrix_transport(&VSFTPD, FtpTlsMode::None, MATRIX_FILE).await
    else {
        return;
    };
    let probe = wait_ready(&transport, "vsftpd").await;
    assert_eq!(
        probe.validator.total_len,
        Some(MATRIX_LEN),
        "SIZE is the authoritative total length"
    );
    assert!(
        probe.resume_supported,
        "the REST 0 probe passed (resume supported)"
    );

    let sink = CaptureSink::default();
    fetch_extent(&transport, 0, MATRIX_LEN, &sink).await;
    assert_eq!(sink.assembled(MATRIX_LEN), body(7, MATRIX_LEN as usize));
}

#[tokio::test]
async fn vsftpd_authenticated_download_and_530_mapping() {
    let Some((_pool, transport)) = matrix_transport_with_creds(&VSFTPD, "taiji", "taijipass").await
    else {
        return;
    };
    // Readiness and authenticated download together (URI userinfo
    // credentials).
    let probe = wait_ready(&transport, "vsftpd authed").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));
    let sink = CaptureSink::default();
    fetch_extent(&transport, 0, MATRIX_LEN, &sink).await;
    assert_eq!(sink.assembled(MATRIX_LEN), body(7, MATRIX_LEN as usize));

    // Wrong password → 530 → `taiji.auth.failed` (unified auth code).
    let bad = FtpTransport::for_uri(
        client_config(FtpTlsMode::None),
        &matrix_uri(VSFTPD.port, Some(("taiji", "WRONG")), MATRIX_FILE),
    )
    .unwrap_or_else(|e| panic!("for_uri bad: {e}"));
    let err = match bad.probe(&RequestCtx::default()).await {
        Err(err) => err,
        Ok(_) => panic!("wrong password must be rejected"),
    };
    assert_eq!(err.code(), "taiji.auth.failed", "{err}");
}

#[tokio::test]
async fn vsftpd_rest_chunked_extents() {
    let Some((_pool, transport)) = matrix_transport(&VSFTPD, FtpTlsMode::None, MATRIX_FILE).await
    else {
        return;
    };
    let probe = wait_ready(&transport, "vsftpd").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));

    // extent = REST <offset> + RETR: three segments cover the whole
    // file (the control connection is reused by default).
    let sink = CaptureSink::default();
    for (start, len) in [
        (0, 64 * 1024),
        (64 * 1024, 64 * 1024),
        (128 * 1024, MATRIX_LEN - 128 * 1024),
    ] {
        fetch_extent(&transport, start, len, &sink).await;
    }
    assert_eq!(sink.assembled(MATRIX_LEN), body(7, MATRIX_LEN as usize));
}

#[tokio::test]
async fn vsftpd_explicit_tls_end_to_end() {
    let Some((_pool, transport)) =
        matrix_transport(&VSFTPD, FtpTlsMode::Explicit, MATRIX_FILE).await
    else {
        return;
    };
    // A successful probe = AUTH TLS upgrade + rustls validation against
    // the self-signed anchor.
    let probe = wait_ready(&transport, "vsftpd explicit tls").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));

    let sink = CaptureSink::default();
    let (start, len) = (1024u64, 64 * 1024u64);
    fetch_extent(&transport, start, len, &sink).await;
    assert_eq!(
        sink.assembled(start + len)[start as usize..],
        body(7, MATRIX_LEN as usize)[start as usize..(start + len) as usize],
        "PROT P data-plane bytes correct"
    );
}

#[tokio::test]
async fn vsftpd_implicit_tls_end_to_end() {
    let Some((_pool, transport)) =
        matrix_transport(&VSFTPD_IMPLICIT, FtpTlsMode::Implicit, MATRIX_FILE).await
    else {
        return;
    };
    let probe = wait_ready(&transport, "vsftpd implicit tls").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));
    let sink = CaptureSink::default();
    fetch_extent(&transport, 0, MATRIX_LEN, &sink).await;
    assert_eq!(sink.assembled(MATRIX_LEN), body(7, MATRIX_LEN as usize));
}

#[tokio::test]
async fn vsftpd_epsv_raw_dialog() {
    let Some(_pool) = pool().await else { return };
    let got = raw_epsv_fetch(VSFTPD.port);
    assert_eq!(
        got,
        body(7, MATRIX_LEN as usize)[65536..],
        "EPSV data-plane bytes"
    );
}

#[tokio::test]
async fn vsftpd_charset_utf8_and_latin1_paths() {
    let Some((_pool, utf8_transport)) =
        matrix_transport(&VSFTPD, FtpTlsMode::None, UTF8_FILE_ENCODED).await
    else {
        return;
    };
    let probe = wait_ready(&utf8_transport, "vsftpd utf8").await;
    assert_eq!(probe.validator.total_len, Some(16));
    let sink = CaptureSink::default();
    fetch_extent(&utf8_transport, 0, 16, &sink).await;
    assert_eq!(sink.assembled(16), body(1, 16));

    let Some((_pool, latin1_transport)) =
        matrix_transport(&VSFTPD, FtpTlsMode::None, LATIN1_FILE_ENCODED).await
    else {
        return;
    };
    // %A3 = Latin-1 £: a non-UTF-8 byte → fallback transcoding →
    // UTF-8 wire bytes hit the server file (same re-encode boundary as
    // the mock matrix).
    let probe = wait_ready(&latin1_transport, "vsftpd latin1").await;
    assert_eq!(probe.validator.total_len, Some(8));
    let sink = CaptureSink::default();
    fetch_extent(&latin1_transport, 0, 8, &sink).await;
    assert_eq!(sink.assembled(8), body(2, 8));
}

// ---------------------------------------------------------------------------
// Matrix: proftpd (12122 plaintext + explicit TLS; 12124 implicit TLS)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proftpd_anonymous_download_and_probe() {
    let Some((_pool, transport)) = matrix_transport(&PROFTPD, FtpTlsMode::None, MATRIX_FILE).await
    else {
        return;
    };
    let probe = wait_ready(&transport, "proftpd").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));
    assert!(
        probe.resume_supported,
        "the REST 0 probe passed (resume supported)"
    );

    let sink = CaptureSink::default();
    fetch_extent(&transport, 0, MATRIX_LEN, &sink).await;
    assert_eq!(sink.assembled(MATRIX_LEN), body(7, MATRIX_LEN as usize));
}

#[tokio::test]
async fn proftpd_authenticated_download_and_530_mapping() {
    let Some((_pool, transport)) =
        matrix_transport_with_creds(&PROFTPD, "taiji", "taijipass").await
    else {
        return;
    };
    let probe = wait_ready(&transport, "proftpd authed").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));
    let sink = CaptureSink::default();
    fetch_extent(&transport, 0, MATRIX_LEN, &sink).await;
    assert_eq!(sink.assembled(MATRIX_LEN), body(7, MATRIX_LEN as usize));

    let bad = FtpTransport::for_uri(
        client_config(FtpTlsMode::None),
        &matrix_uri(PROFTPD.port, Some(("taiji", "WRONG")), MATRIX_FILE),
    )
    .unwrap_or_else(|e| panic!("for_uri bad: {e}"));
    let err = match bad.probe(&RequestCtx::default()).await {
        Err(err) => err,
        Ok(_) => panic!("wrong password must be rejected"),
    };
    assert_eq!(err.code(), "taiji.auth.failed", "{err}");
}

#[tokio::test]
async fn proftpd_rest_chunked_extents() {
    let Some((_pool, transport)) = matrix_transport(&PROFTPD, FtpTlsMode::None, MATRIX_FILE).await
    else {
        return;
    };
    let probe = wait_ready(&transport, "proftpd").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));

    let sink = CaptureSink::default();
    for (start, len) in [
        (0, 64 * 1024),
        (64 * 1024, 64 * 1024),
        (128 * 1024, MATRIX_LEN - 128 * 1024),
    ] {
        fetch_extent(&transport, start, len, &sink).await;
    }
    assert_eq!(sink.assembled(MATRIX_LEN), body(7, MATRIX_LEN as usize));
}

#[tokio::test]
async fn proftpd_explicit_tls_end_to_end() {
    let Some((_pool, transport)) =
        matrix_transport(&PROFTPD, FtpTlsMode::Explicit, MATRIX_FILE).await
    else {
        return;
    };
    let probe = wait_ready(&transport, "proftpd explicit tls").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));

    let sink = CaptureSink::default();
    let (start, len) = (1024u64, 64 * 1024u64);
    fetch_extent(&transport, start, len, &sink).await;
    assert_eq!(
        sink.assembled(start + len)[start as usize..],
        body(7, MATRIX_LEN as usize)[start as usize..(start + len) as usize],
        "PROT P data-plane bytes correct"
    );
}

#[tokio::test]
async fn proftpd_implicit_tls_end_to_end() {
    let Some((_pool, transport)) =
        matrix_transport(&PROFTPD_IMPLICIT, FtpTlsMode::Implicit, MATRIX_FILE).await
    else {
        return;
    };
    let probe = wait_ready(&transport, "proftpd implicit tls").await;
    assert_eq!(probe.validator.total_len, Some(MATRIX_LEN));
    let sink = CaptureSink::default();
    fetch_extent(&transport, 0, MATRIX_LEN, &sink).await;
    assert_eq!(sink.assembled(MATRIX_LEN), body(7, MATRIX_LEN as usize));
}

#[tokio::test]
async fn proftpd_epsv_raw_dialog() {
    let Some(_pool) = pool().await else { return };
    let got = raw_epsv_fetch(PROFTPD.port);
    assert_eq!(
        got,
        body(7, MATRIX_LEN as usize)[65536..],
        "EPSV data-plane bytes"
    );
}

#[tokio::test]
async fn proftpd_charset_utf8_and_latin1_paths() {
    let Some((_pool, utf8_transport)) =
        matrix_transport(&PROFTPD, FtpTlsMode::None, UTF8_FILE_ENCODED).await
    else {
        return;
    };
    let probe = wait_ready(&utf8_transport, "proftpd utf8").await;
    assert_eq!(probe.validator.total_len, Some(16));
    let sink = CaptureSink::default();
    fetch_extent(&utf8_transport, 0, 16, &sink).await;
    assert_eq!(sink.assembled(16), body(1, 16));

    let Some((_pool, latin1_transport)) =
        matrix_transport(&PROFTPD, FtpTlsMode::None, LATIN1_FILE_ENCODED).await
    else {
        return;
    };
    let probe = wait_ready(&latin1_transport, "proftpd latin1").await;
    assert_eq!(probe.validator.total_len, Some(8));
    let sink = CaptureSink::default();
    fetch_extent(&latin1_transport, 0, 8, &sink).await;
    assert_eq!(sink.assembled(8), body(2, 8));
}

// ---------------------------------------------------------------------------
// Raw EPSV dialog (synchronous/blocking; the client's per-address-family
// EPSV/PASV selection is covered by the mock matrix — here we verify
// the real server's EPSV 229 + REST + RETR data-plane bytes)
// ---------------------------------------------------------------------------

fn raw_epsv_fetch(port: u16) -> Vec<u8> {
    let offset: u64 = 64 * 1024;
    let control = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("epsv control connect: {e}"));
    control
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap_or_else(|e| panic!("set read timeout: {e}"));
    let clone = control.try_clone().unwrap_or_else(|e| panic!("clone: {e}"));
    let mut reader = BufReader::new(clone);
    let mut control = control;

    expect_reply(&mut reader, "220", "greeting");
    send_line(&mut control, "USER anonymous");
    expect_reply(&mut reader, "331", "user");
    send_line(&mut control, "PASS anonymous@");
    expect_reply(&mut reader, "230", "pass");
    send_line(&mut control, "TYPE I");
    expect_reply(&mut reader, "200", "type");
    send_line(&mut control, "EPSV");
    let epsv = expect_reply(&mut reader, "229", "epsv");
    let data_port = parse_epsv_port(&epsv);
    let mut data = TcpStream::connect(("127.0.0.1", data_port))
        .unwrap_or_else(|e| panic!("epsv data connect ({data_port}): {e}"));
    data.set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap_or_else(|e| panic!("set data timeout: {e}"));
    send_line(&mut control, &format!("REST {offset}"));
    expect_reply(&mut reader, "350", "rest");
    send_line(&mut control, &format!("RETR {MATRIX_FILE}"));
    expect_reply(&mut reader, "150", "retr");

    let mut got = Vec::new();
    data.read_to_end(&mut got)
        .unwrap_or_else(|e| panic!("epsv data read: {e}"));
    expect_reply(&mut reader, "226", "transfer complete");
    got
}

fn send_line(stream: &mut TcpStream, line: &str) {
    stream
        .write_all(format!("{line}\r\n").as_bytes())
        .unwrap_or_else(|e| panic!("control write {line:?}: {e}"));
}

fn expect_reply(reader: &mut BufReader<TcpStream>, prefix: &str, what: &str) -> String {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .unwrap_or_else(|e| panic!("control read ({what}): {e}"));
    let line = line.trim_end_matches(['\r', '\n']).to_string();
    assert!(
        line.starts_with(prefix),
        "expected {prefix} for {what}, got {line:?}"
    );
    line
}

/// Data port inside an RFC 2428 EPSV reply `(|||port|)`.
fn parse_epsv_port(reply: &str) -> u16 {
    let inner = reply
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(inner, _)| inner)
        .unwrap_or_else(|| panic!("no parenthesized body in EPSV reply: {reply:?}"));
    let fields: Vec<&str> = inner.split('|').collect();
    fields
        .get(3)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no port in EPSV reply: {reply:?}"))
}
