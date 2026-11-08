//! End-to-end integration tests for the `taiji http` subcommand (real
//! binary, same shape as import_flow): completion closeout (default and
//! custom incomplete suffix), `--checksum` final-verdict pass/mismatch
//! paths, and kill -9 interruption -> restart with bitmap resume (mock
//! origin of >= 1 GiB; the data plane is the in-process mock origin).

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Test-only Result unwrap helper (lints ban unwrap/expect).
fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{what}: {e}"),
    }
}

/// Unique temp directory.
fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "tj-http-e2e-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|x| x.subsec_nanos())
            .unwrap_or(0)
    ));
    ok(std::fs::create_dir_all(&d), "mkdir");
    d
}

/// Content pattern: byte(i) = (i % 251), deterministic. The mock origin
/// and the expected-content comparison share the pattern, so any Range
/// slice needs no materialization and 1-GiB-scale content never lands
/// in memory. Rotation period + memcpy repeat keeps the fill at memory
/// bandwidth even in debug builds.
fn fill_pattern(buf: &mut [u8], start: u64) {
    const PERIOD: usize = 251;
    let off = (start % PERIOD as u64) as usize;
    let mut rot = [0u8; PERIOD];
    for (k, b) in rot.iter_mut().enumerate() {
        *b = ((off + k) % PERIOD) as u8;
    }
    let mut done = 0usize;
    while done + PERIOD <= buf.len() {
        buf[done..done + PERIOD].copy_from_slice(&rot);
        done += PERIOD;
    }
    let tail = buf.len() - done;
    buf[done..].copy_from_slice(&rot[..tail]);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// sha-256 of the pattern content (streamed; the full-length buffer is
/// never materialized).
fn pattern_sha256(len: u64) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut off = 0u64;
    while off < len {
        let n = (buf.len() as u64).min(len - off) as usize;
        fill_pattern(&mut buf[..n], off);
        sha2::Digest::update(&mut h, &buf[..n]);
        off += n as u64;
    }
    hex(&h.finalize())
}

fn file_sha256(p: &Path) -> String {
    use sha2::Digest;
    let f = ok(std::fs::File::open(p), "open for hash");
    let mut h = sha2::Sha256::new();
    let mut reader = std::io::BufReader::new(f);
    // digest 0.11 removed the hasher's io::Write impl: feed via an explicit 64 KiB read loop.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = ok(std::io::Read::read(&mut reader, &mut buf), "hash read");
        if n == 0 {
            break;
        }
        sha2::Digest::update(&mut h, &buf[..n]);
    }
    hex(&h.finalize())
}

/// Streamed byte-for-byte comparison of a file against pattern(len)
/// (the 1-GiB-scale integrity check: pinning bit-exact content is as
/// strong as a hash check, and a memcpy compare is far cheaper than
/// sha2 compression in debug builds).
fn file_matches_pattern(p: &Path, len: u64) -> bool {
    let Ok(f) = std::fs::File::open(p) else {
        return false;
    };
    let Ok(meta) = f.metadata() else {
        return false;
    };
    if meta.len() != len {
        return false;
    }
    let mut reader = std::io::BufReader::new(f);
    let mut got = vec![0u8; 1024 * 1024];
    let mut want = vec![0u8; 1024 * 1024];
    let mut off = 0u64;
    while off < len {
        let n = (got.len() as u64).min(len - off) as usize;
        if reader.read_exact(&mut got[..n]).is_err() {
            return false;
        }
        fill_pattern(&mut want[..n], off);
        if got[..n] != want[..n] {
            return false;
        }
        off += n as u64;
    }
    true
}

/// Mock origin (in-process std threads): 206 with the full
/// `Content-Range: bytes s-e/TOTAL` form, plus a 200 full-body
/// fallback. Records data Ranges tagged by phase (the 0-0 probe is not
/// counted); supports a pre-response delay (suffix visibility window)
/// and per-chunk throttling (widens the kill window).
struct Mock {
    url_base: String,
    /// (phase, start, end_incl) sequence of data Ranges.
    ranges: Arc<Mutex<Vec<(usize, u64, u64)>>>,
    phase: Arc<AtomicUsize>,
}

fn spawn_mock(total: u64, data_delay: Duration, chunk_sleep: Duration) -> Mock {
    spawn_mock_mode(total, data_delay, chunk_sleep, false)
}

/// Degraded-form mock: every request gets 200 + Content-Length full
/// body (Range ignored — the shape that forces single-connection
/// degradation); serves the degraded-path checksum tests.
fn spawn_mock_degraded(total: u64) -> Mock {
    spawn_mock_mode(total, Duration::ZERO, Duration::ZERO, true)
}

fn spawn_mock_mode(total: u64, data_delay: Duration, chunk_sleep: Duration, degrade: bool) -> Mock {
    let listener = ok(TcpListener::bind("127.0.0.1:0"), "bind mock");
    let port = ok(listener.local_addr(), "local_addr").port();
    let ranges = Arc::new(Mutex::new(Vec::new()));
    let phase = Arc::new(AtomicUsize::new(0));
    let ranges_t = Arc::clone(&ranges);
    let phase_t = Arc::clone(&phase);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { break };
            let ranges = Arc::clone(&ranges_t);
            let phase = Arc::clone(&phase_t);
            std::thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    // Read one request head (\r\n\r\n delimited; GET has no body).
                    let head = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..pos + 4).collect();
                            break String::from_utf8_lossy(&head).into_owned();
                        }
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let range = if degrade {
                        // Degraded form: Range is always ignored.
                        None
                    } else {
                        head.to_ascii_lowercase()
                            .split("\r\n")
                            .find_map(|l| l.strip_prefix("range: bytes="))
                            .and_then(|v| {
                                let (s, e) = v.trim().split_once('-')?;
                                Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                            })
                    };
                    match range {
                        // Probe (single GET bytes=0-0): 1-byte body.
                        Some((0, 0)) => {
                            let mut body = [0u8; 1];
                            fill_pattern(&mut body, 0);
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes 0-0/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Content-Length: 1\r\n\
                                 Connection: keep-alive\r\n\r\n"
                            );
                            sock.write_all(resp.as_bytes()).ok();
                            sock.write_all(&body).ok();
                        }
                        Some((s, e)) => {
                            if let Ok(mut g) = ranges.lock() {
                                g.push((phase.load(Ordering::Relaxed), s, e));
                            }
                            if !data_delay.is_zero() {
                                std::thread::sleep(data_delay);
                            }
                            let end = e.min(total.saturating_sub(1));
                            let len = end.saturating_sub(s) + 1;
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes {s}-{end}/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Content-Length: {len}\r\n\
                                 Connection: keep-alive\r\n\r\n"
                            );
                            if sock.write_all(resp.as_bytes()).is_err() {
                                return;
                            }
                            let mut chunk = vec![0u8; 256 * 1024];
                            let mut off = s;
                            while off <= end {
                                let n = (chunk.len() as u64).min(end - off + 1) as usize;
                                fill_pattern(&mut chunk[..n], off);
                                if sock.write_all(&chunk[..n]).is_err() {
                                    return;
                                }
                                off += n as u64;
                                if !chunk_sleep.is_zero() {
                                    std::thread::sleep(chunk_sleep);
                                }
                            }
                        }
                        None => {
                            // Range-less full GET (degraded form; body is the full length).
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Connection: keep-alive\r\n\r\n"
                            );
                            sock.write_all(resp.as_bytes()).ok();
                            let mut chunk = vec![0u8; 256 * 1024];
                            let mut off = 0u64;
                            while off < total {
                                let n = (chunk.len() as u64).min(total - off) as usize;
                                fill_pattern(&mut chunk[..n], off);
                                if sock.write_all(&chunk[..n]).is_err() {
                                    return;
                                }
                                off += n as u64;
                            }
                        }
                    }
                }
            });
        }
    });
    Mock {
        url_base: format!("http://127.0.0.1:{port}"),
        ranges,
        phase,
    }
}

/// Spawn `taiji http` (stdout/stderr captured; RUST_LOG=info so
/// task-level log lines are present).
fn http_child(args: &[String]) -> std::process::Child {
    ok(
        Command::new(env!("CARGO_BIN_EXE_taiji"))
            .arg("http")
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn(),
        "spawn taiji http",
    )
}

/// Run to exit; returns (exit code, stdout).
fn run_http(args: &[String]) -> (i32, String) {
    let out = ok(http_child(args).wait_with_output(), "run taiji http");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Run to exit; returns (exit code, stdout+stderr combined) — the
/// assertion surface for guard-rejection messages (tracing writes to
/// stdout, but asserting over both streams is robust).
fn run_http_capture(args: &[String]) -> (i32, String) {
    let out = ok(http_child(args).wait_with_output(), "run taiji http");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// All `state` values in the http_task table (read-only; guard/rejection assertions).
fn http_task_states(db: &Path) -> Vec<String> {
    let conn = ok(
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY),
        "open db ro",
    );
    let mut st = ok(conn.prepare("SELECT state FROM http_task"), "prepare");
    let rows = ok(st.query_map([], |r| r.get::<_, String>(0)), "query states");
    rows.filter_map(|r| r.ok()).collect()
}

/// Poll the session db read-only: wait until an http_task bitmap
/// snapshot holds >= min_blocks done blocks (the kill trigger point —
/// the 2 s snapshot debounce means the first snapshot certifies that
/// the on-disk half-finished state exists).
fn wait_bitmap_blocks(db: &Path, min_blocks: u32, timeout: Duration) -> u32 {
    let t0 = Instant::now();
    loop {
        if let Ok(conn) =
            rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        {
            let sums: Vec<u32> = conn
                .prepare("SELECT block_bitmap FROM http_task WHERE block_bitmap IS NOT NULL")
                .and_then(|mut st| {
                    st.query_map([], |r| r.get::<_, Vec<u8>>(0)).map(|it| {
                        it.filter_map(|r| r.ok())
                            .map(|b| b.iter().map(|x| x.count_ones()).sum::<u32>())
                            .collect()
                    })
                })
                .unwrap_or_default();
            if let Some(&s) = sums.iter().find(|&&s| s >= min_blocks) {
                return s;
            }
        }
        if t0.elapsed() > timeout {
            panic!("bitmap snapshot with >= {min_blocks} blocks not reached in time");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Common args (fresh tmp dir/db per test; output file name fixed to f.bin).
fn cli_args(url: &str, root: &Path, extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        url.to_string(),
        "-d".to_string(),
        root.join("dl").display().to_string(),
        "--sqlite3-db-path".to_string(),
        root.join("taiji.sqlite3").display().to_string(),
        "-o".to_string(),
        "f.bin".to_string(),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

/// 1 GiB mock source + targeted kill -9 -> `.part`/bitmap snapshot
/// survive -> restart with the same args -> bootstrap rebuild + bitmap
/// resume (block 0 is never refetched) -> file is bit-identical.
#[test]
fn kill9_resume_completes_1gib() {
    const TOTAL: u64 = 1024 * 1024 * 1024;
    let root = tmp_dir("kill9");
    let dl = root.join("dl");
    let db = root.join("taiji.sqlite3");
    // ~4 ms per 256 KiB chunk throttling: the first snapshot (2 s
    // debounce) lands while the task is still in flight (a full-speed
    // 1 GiB would finish before the kill).
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::from_millis(4));
    let url = format!("{}/f.bin", mock.url_base);
    let args = cli_args(&url, &root, &[]);

    let mut child = http_child(&args);
    let done_blocks = wait_bitmap_blocks(&db, 8, Duration::from_secs(30));
    println!("kill -9 at snapshot with {done_blocks} done blocks");
    ok(child.kill(), "kill -9");
    let _ = child.wait();
    assert!(
        dl.join("f.bin.part").exists(),
        "after kill -9 the .part half-written state must survive"
    );
    assert!(
        !dl.join("f.bin").exists(),
        "after kill -9 there must be no final file"
    );

    // Restart with the same args: bootstrap rebuild -> resume to completion.
    mock.phase.store(1, Ordering::Relaxed);
    let (code, out) = run_http(&args);
    assert_eq!(code, 0, "resume run failed: {out}");
    assert!(
        out.contains("resuming in-flight"),
        "the restart must resume (not re-create the task): {out}"
    );
    assert!(
        !dl.join("f.bin.part").exists(),
        "after completion .part must be renamed"
    );
    assert!(
        file_matches_pattern(&dl.join("f.bin"), TOTAL),
        "after resume the file must be bit-identical"
    );

    // Resume evidence: phase1 fetched from 0 (fresh start); phase2
    // fetched only remaining extents (start > 0; {done_blocks} blocks
    // were done at the snapshot).
    let rs = mock
        .ranges
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let phase1 = rs.iter().filter(|(ph, _, _)| *ph == 0).collect::<Vec<_>>();
    let phase2 = rs.iter().filter(|(ph, _, _)| *ph == 1).collect::<Vec<_>>();
    assert!(
        phase1.iter().any(|(_, s, _)| *s == 0),
        "the first run must fetch from 0: {phase1:?}"
    );
    assert!(
        !phase2.is_empty(),
        "the resume must actually fetch the remaining data"
    );
    assert!(
        phase2.iter().all(|(_, s, _)| *s > 0),
        "the resume must not re-fetch block 0 (bitmap resume): {phase2:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `--checksum` failure path = task error (exit 1 + `.part` left on
/// disk + no final file); rerunning with the correct digest completes.
#[test]
fn checksum_mismatch_fails_task_and_correct_digest_passes() {
    const TOTAL: u64 = 1024 * 1024;
    let root = tmp_dir("checksum");
    let dl = root.join("dl");
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
    let url = format!("{}/f.bin", mock.url_base);
    let good = pattern_sha256(TOTAL);
    let wrong = "a".repeat(64);

    let bad_args = cli_args(&url, &root, &["--checksum", &format!("sha-256={wrong}")]);
    let (code, out) = run_http(&bad_args);
    assert_eq!(code, 1, "a checksum mismatch must fail the task: {out}");
    assert!(
        out.contains("checksum mismatch"),
        "the error surface must carry the mismatch detail: {out}"
    );
    assert!(
        !dl.join("f.bin").exists(),
        "a final verdict failure before rename = no final file"
    );
    assert!(
        dl.join("f.bin.part").exists(),
        ".part left on disk for inspection"
    );

    let good_args = cli_args(&url, &root, &["--checksum", &format!("sha-256={good}")]);
    let (code, out) = run_http(&good_args);
    assert_eq!(code, 0, "the correct digest must pass: {out}");
    assert!(dl.join("f.bin").exists());
    assert_eq!(file_sha256(&dl.join("f.bin")), good);
    assert!(!dl.join("f.bin.part").exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// `--checksum` accepts six hash schemes (RFC 1321 md5 + the FIPS
/// 180-4 SHA-2 family: md5/sha-1/sha-224/sha-256/sha-384/sha-512),
/// each exercised with a good and a bad digest — good = task completes
/// (exit 0 + final file), bad = completion-time verdict mismatch
/// (exit 1 + `checksum mismatch` + `.part` left on disk).
#[test]
fn six_hash_checksum_good_and_bad_digest_end_to_end() {
    const TOTAL: u64 = 1024 * 1024;
    // Deterministic digests of pattern(TOTAL) (byte(i) = i % 251), the mock's own pattern.
    let cases: &[(&str, &str)] = &[
        ("md5", "8f293a2f6c19b345152f7a49bb4c643c"),
        ("sha-1", "c2fc4cb20f1301a6b0dd211c19e69a13925dbe40"),
        (
            "sha-224",
            "5ea506c312141d911fb8909367ae6ecd22513c9fe337046ec36f3dde",
        ),
        (
            "sha-256",
            "631b84027d6b9e52b539c4e8373622d23032dfadc64d60af87339c9037e4f769",
        ),
        (
            "sha-384",
            "c0b5633796816dc370458921d148550ed3e490ca635324e1\
             9b86a26c500577c623a37ecc5de698c222fba72e08e0ee5b",
        ),
        (
            "sha-512",
            "67dad569eefc986a3b2424f5516d5a0284bb53d7b52d75f5ed881a6830a95765\
             ccc82bc48752fb693422579f11dc9a400561ec1885af9eeef703dbbd312d4fd0",
        ),
    ];
    for (scheme, good) in cases {
        let root = tmp_dir(&format!("cs6-{}", scheme.replace('-', "")));
        let dl = root.join("dl");
        let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
        let url = format!("{}/f.bin", mock.url_base);
        // Bad digest: all 'a', valid shape — the mismatch must come from
        // the completion-time compare, not create-time rejection.
        let wrong = "a".repeat(good.len());
        let bad_args = cli_args(&url, &root, &["--checksum", &format!("{scheme}={wrong}")]);
        let (code, out) = run_http(&bad_args);
        assert_eq!(
            code, 1,
            "{scheme} bad digest must fail the final verdict (exit 1): {out}"
        );
        assert!(
            out.contains("checksum mismatch"),
            "{scheme} mismatch: {out}"
        );
        assert!(
            !dl.join("f.bin").exists(),
            "{scheme} mismatch = no final file"
        );
        assert!(
            dl.join("f.bin.part").exists(),
            "{scheme} .part left on disk for inspection"
        );
        // Good digest: rerun; the errored row is not resumed, so a fresh task passes.
        let good_args = cli_args(&url, &root, &["--checksum", &format!("{scheme}={good}")]);
        let (code, out) = run_http(&good_args);
        assert_eq!(code, 0, "{scheme} good digest must pass: {out}");
        assert!(dl.join("f.bin").exists(), "{scheme} final file on disk");
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// `--http-incomplete-suffix=.motrix` end to end: the suffixed file
/// exists during the download (within the data-delay window), is gone
/// after completion, and the bytes match.
#[test]
fn incomplete_suffix_motrix_end_to_end() {
    const TOTAL: u64 = 8 * 1024 * 1024;
    let root = tmp_dir("suffix");
    let dl = root.join("dl");
    // 700 ms data delay = the `.motrix` visibility window (prealloc precedes fetching).
    let mock = spawn_mock(TOTAL, Duration::from_millis(700), Duration::ZERO);
    let url = format!("{}/f.bin", mock.url_base);
    let args = cli_args(&url, &root, &["--http-incomplete-suffix", ".motrix"]);
    let mut child = http_child(&args);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = false;
    while Instant::now() < deadline {
        if dl.join("f.bin.motrix").exists() {
            seen = true;
            break;
        }
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        seen,
        "f.bin.motrix must be visible during download (the custom suffix works)"
    );
    let out = ok(child.wait_with_output(), "wait suffix run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "suffix run failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        dl.join("f.bin").exists(),
        "after completion there must be an unsuffixed final file"
    );
    assert!(
        !dl.join("f.bin.motrix").exists(),
        "after completion .motrix must be renamed"
    );
    assert_eq!(file_sha256(&dl.join("f.bin")), pattern_sha256(TOTAL));
    let _ = std::fs::remove_dir_all(&root);
}

/// Option-value rejection (`taiji.option.invalid`): checksum schemes
/// outside the six-hash domain, malformed digests, and suffix names
/// outside the naming domain all exit 2 without creating a task.
#[test]
fn invalid_option_values_are_rejected() {
    let root = tmp_dir("invalid");
    let url = "http://127.0.0.1:9/f.bin"; // rejected at add time; no live source needed.
    for bad in [
        "sha3-256=0123456789abcdef",
        "md4=00",
        "no-delimiter",
        "sha-256=zz",
    ] {
        let args = cli_args(url, &root, &["--checksum", bad]);
        let (code, out) = run_http(&args);
        assert_eq!(code, 2, "bad checksum {bad} must exit 2: {out}");
    }
    let args = cli_args(url, &root, &["--http-incomplete-suffix", "nodot"]);
    let (code, out) = run_http(&args);
    assert_eq!(code, 2, "bad suffix must exit 2: {out}");
    assert!(
        out.contains("taiji.option.invalid") || out.contains("http-incomplete-suffix"),
        "the error surface must name the invalid option: {out}"
    );
    // Scheduler-group domains: max-connection-per-server must be in
    // 1..=16 (aria2-native domain, no clamping); split >= 1;
    // http-stall-window >= 3 (several heartbeat periods);
    // min-split-size must parse as a size.
    for (flag, val) in [
        ("--max-connection-per-server", "0"),
        ("--max-connection-per-server", "17"),
        ("--split", "0"),
        ("--http-stall-window", "0"),
        ("--min-split-size", "4X"),
    ] {
        let args = cli_args(url, &root, &[flag, val]);
        let (code, out) = run_http(&args);
        assert_eq!(code, 2, "bad {flag} {val} must exit 2: {out}");
        assert!(
            out.contains("taiji.option.invalid"),
            "the error surface must be taiji.option.invalid: {out}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Concurrency guard: two concurrent processes, same db, same args —
/// the second must fail explicitly (lockfile guard) and must not
/// bootstrap-rebuild into co-writing the same `.part`: no extra task
/// row, the bitmap is untouched, and the first process still
/// completes with a bit-identical file.
#[test]
fn concurrent_second_process_is_rejected_not_cowritten() {
    const TOTAL: u64 = 64 * 1024 * 1024;
    let root = tmp_dir("concurrent");
    let dl = root.join("dl");
    let db = root.join("taiji.sqlite3");
    // Throttle (~17 MiB/s: ~3.8 s to finish) so the 2 s-debounce
    // snapshot lands before completion. Single connection pinned
    // explicitly — the snapshot/kill timing is calibrated for the
    // single-connection shape.
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::from_millis(15));
    let url = format!("{}/f.bin", mock.url_base);
    let args = cli_args(&url, &root, &["--max-connection-per-server", "1"]);

    let first = http_child(&args);
    let _done_blocks = wait_bitmap_blocks(&db, 4, Duration::from_secs(30));
    let part_len_at_kill = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    let before = part_len_at_kill(&dl.join("f.bin.part"));

    // Second process, same db/args: the lock guard fails fast and clearly.
    let started = Instant::now();
    let (code, out) = run_http_capture(&args);
    let elapsed = started.elapsed();
    assert_eq!(code, 1, "the concurrent second process must exit 1: {out}");
    assert!(
        out.contains("held by another taiji process"),
        "the rejection must name the session-db occupancy: {out}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the guard must fail fast (not queue): {elapsed:?}"
    );
    // No co-writing: no second task row; the `.part` was not truncated.
    let states = http_task_states(&db);
    assert_eq!(
        states.len(),
        1,
        "the concurrent second process must not add a task row: {states:?}"
    );
    let after = part_len_at_kill(&dl.join("f.bin.part"));
    assert!(
        after >= before,
        "the second process must not truncate the in-flight `.part`: {before} -> {after}"
    );

    // First process completes (the guard does not disturb the live session).
    let out = ok(first.wait_with_output(), "wait first");
    assert_eq!(
        out.status.code(),
        Some(0),
        "first run failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        file_matches_pattern(&dl.join("f.bin"), TOTAL),
        "the guard must not disturb the first process's output"
    );
    assert_eq!(http_task_states(&db), vec!["done".to_string()]);
    let _ = std::fs::remove_dir_all(&root);
}

/// Degraded path: a `--checksum` mismatch must not leave a corrupt
/// final file. Single-connection degradation (200 + Content-Length,
/// Range ignored) renames first -> verdict mismatch -> the final file
/// rolls back to `.part` for inspection; rerunning with the correct
/// digest starts a fresh task (the errored row is not resumed) and
/// completes.
#[test]
fn degraded_checksum_mismatch_rolls_back_final_file() {
    const TOTAL: u64 = 1024 * 1024;
    let root = tmp_dir("deg-cs");
    let dl = root.join("dl");
    let mock = spawn_mock_degraded(TOTAL);
    let url = format!("{}/f.bin", mock.url_base);
    let good = pattern_sha256(TOTAL);
    let wrong = "c".repeat(64);

    let bad_args = cli_args(&url, &root, &["--checksum", &format!("sha-256={wrong}")]);
    let (code, out) = run_http(&bad_args);
    assert_eq!(
        code, 1,
        "the degraded-path checksum mismatch must fail the task: {out}"
    );
    assert!(out.contains("checksum mismatch"), "{out}");
    assert!(
        !dl.join("f.bin").exists(),
        "a mismatch must not leave a corrupt final file"
    );
    assert!(
        dl.join("f.bin.part").exists(),
        "the data rolls back to .part for inspection"
    );
    assert_eq!(
        std::fs::metadata(dl.join("f.bin.part"))
            .map(|m| m.len())
            .unwrap_or(0),
        TOTAL,
        "the rollback preserves every received byte"
    );

    // Correct-digest rerun: the errored row is not resumed (no
    // attach); degradation always restarts from zero -> completes.
    let good_args = cli_args(&url, &root, &["--checksum", &format!("sha-256={good}")]);
    let (code, out) = run_http(&good_args);
    assert_eq!(code, 0, "the correct-digest rerun must close out: {out}");
    assert!(
        !out.contains("resuming in-flight"),
        "an error row does not attach (the terminal state is outside the recovery read): {out}"
    );
    assert!(dl.join("f.bin").exists());
    assert_eq!(file_sha256(&dl.join("f.bin")), good);
    assert!(!dl.join("f.bin.part").exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// Degraded path (single-connection sequential stream; the digest is
/// consumed pipelined through the tee), md5 good/bad digest — bad =
/// mismatch rolls back to `.part`, good = completes. Same coverage as
/// `degraded_checksum_mismatch_rolls_back_final_file` (sha-256) on the
/// md5 algorithm (RFC 1321).
#[test]
fn degraded_md5_checksum_verdict_end_to_end() {
    const TOTAL: u64 = 1024 * 1024;
    let root = tmp_dir("deg-cs-md5");
    let dl = root.join("dl");
    let mock = spawn_mock_degraded(TOTAL);
    let url = format!("{}/f.bin", mock.url_base);
    let good = "8f293a2f6c19b345152f7a49bb4c643c"; // md5 of pattern(1 MiB)
    let wrong = "0".repeat(32);

    let bad_args = cli_args(&url, &root, &["--checksum", &format!("md5={wrong}")]);
    let (code, out) = run_http(&bad_args);
    assert_eq!(
        code, 1,
        "the degraded-path md5 mismatch must fail the task: {out}"
    );
    assert!(out.contains("checksum mismatch"), "{out}");
    assert!(
        dl.join("f.bin.part").exists(),
        "the data rolls back to .part for inspection"
    );

    let good_args = cli_args(&url, &root, &["--checksum", &format!("md5={good}")]);
    let (code, out) = run_http(&good_args);
    assert_eq!(
        code, 0,
        "the degraded-path md5 good digest must close out: {out}"
    );
    assert!(dl.join("f.bin").exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// Attach option comparison, end to end: after kill -9, a rerun with
/// a different `--checksum` is refused attach (exit 1, no new task
/// row, `.part` not truncated); rerunning with the persisted value
/// attaches, resumes, and completes with the file hash equal to the
/// pattern digest.
#[test]
fn attach_checksum_conflict_rejected_then_matching_digest_resumes() {
    // 384 MiB so the run (~8 s over loopback at the default connection
    // cap) leaves ample snapshot-to-kill margin (~4 blocks, ~0.4 s) —
    // a shorter run can finish before the kill, leaving no active row
    // and making the conflict rerun create a spurious task.
    const TOTAL: u64 = 384 * 1024 * 1024;
    let root = tmp_dir("attach-cs");
    let dl = root.join("dl");
    let db = root.join("taiji.sqlite3");
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::from_millis(12));
    let url = format!("{}/f.bin", mock.url_base);
    let good = pattern_sha256(TOTAL);
    let wrong = "b".repeat(64);

    let args_good = cli_args(&url, &root, &["--checksum", &format!("sha-256={good}")]);
    let mut child = http_child(&args_good);
    let _done_blocks = wait_bitmap_blocks(&db, 4, Duration::from_secs(30));
    let part_len = std::fs::metadata(dl.join("f.bin.part"))
        .map(|m| m.len())
        .unwrap_or(0);
    ok(child.kill(), "kill -9");
    let _ = child.wait();

    // Conflicting-digest rerun: refused (no attach, no new row, no truncation).
    let args_conflict = cli_args(&url, &root, &["--checksum", &format!("sha-256={wrong}")]);
    let (code, out) = run_http_capture(&args_conflict);
    assert_eq!(code, 1, "a checksum conflict must refuse attach: {out}");
    assert!(
        out.contains("refusing to attach"),
        "the rejection must be explicit: {out}"
    );
    assert_eq!(
        http_task_states(&db),
        vec!["downloading".to_string()],
        "the rejection path must not add a task row"
    );
    assert_eq!(
        std::fs::metadata(dl.join("f.bin.part"))
            .map(|m| m.len())
            .unwrap_or(0),
        part_len,
        "the rejection path must not truncate the in-flight `.part`"
    );

    // Persisted-value rerun: attach -> bitmap resume -> final verification passes.
    mock.phase.store(1, Ordering::Relaxed);
    let (code, out) = run_http(&args_good);
    assert_eq!(code, 0, "the persisted-value rerun must close out: {out}");
    assert!(
        out.contains("resuming in-flight"),
        "the persisted-value rerun must attach: {out}"
    );
    assert_eq!(file_sha256(&dl.join("f.bin")), good);
    assert!(!dl.join("f.bin.part").exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// Graceful SIGTERM end to end: the signal is acknowledged and the
/// process exits within the shutdown budget (snapshot closed out, no
/// final file) -> rerun attaches and resumes via the bitmap (block 0
/// never refetched) -> bit-identical file.
#[cfg(unix)]
#[test]
fn sigterm_graceful_closeout_exit_and_resume() {
    const TOTAL: u64 = 64 * 1024 * 1024;
    let root = tmp_dir("sigterm");
    let dl = root.join("dl");
    let db = root.join("taiji.sqlite3");
    // ~17 MiB/s: completes in ~3.8 s so SIGTERM lands after the
    // snapshot settles but before completion. Single connection
    // pinned explicitly — the SIGTERM/snapshot timing is calibrated
    // for that shape.
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::from_millis(15));
    let url = format!("{}/f.bin", mock.url_base);
    let args = cli_args(&url, &root, &["--max-connection-per-server", "1"]);

    let child = http_child(&args);
    let done_blocks = wait_bitmap_blocks(&db, 4, Duration::from_secs(30));
    // SIGTERM (the graceful path, in contrast to kill -9).
    let t0 = Instant::now();
    ok(
        Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status(),
        "send SIGTERM",
    );
    let out = ok(child.wait_with_output(), "wait sigterm run");
    let elapsed = t0.elapsed();
    assert_eq!(out.status.code(), Some(1), "the interrupt exits 1");
    assert!(
        elapsed < Duration::from_secs(4),
        "graceful shutdown must exit within budget scale \
         (the §7.5 1s budget + scheduling slack): {elapsed:?}"
    );
    assert!(
        dl.join("f.bin.part").exists(),
        "after the interrupt the `.part` half-written state survives"
    );
    assert!(
        !dl.join("f.bin").exists(),
        "after the interrupt there must be no final file"
    );

    // Rerun: attach -> bitmap resume to completion.
    mock.phase.store(1, Ordering::Relaxed);
    let (code, out) = run_http(&args);
    assert_eq!(code, 0, "resume run failed: {out}");
    assert!(
        out.contains("resuming in-flight"),
        "the rerun must attach the in-flight task: {out}"
    );
    assert!(file_matches_pattern(&dl.join("f.bin"), TOTAL));
    let rs = mock
        .ranges
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let phase2 = rs.iter().filter(|(ph, _, _)| *ph == 1).collect::<Vec<_>>();
    assert!(
        phase2.iter().all(|(_, s, _)| *s > 0),
        "the resume must not re-fetch block 0 \
         ({done_blocks} blocks were done at the snapshot): {phase2:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Connection-concurrency-observing mock (x16 fixture): same shape as
/// `spawn_mock` plus a peak counter over simultaneously in-flight
/// data requests (the 0-0 probe is not counted; per-chunk throttling
/// per connection caps per-connection bandwidth — the shape in which
/// AIMD gains scale with connection count). Returns
/// (url, peak, inflight); `inflight` lets the next run wait for the
/// server-side count to drain after kill -9 so a killed process's
/// leaked count cannot pollute the peak assertion.
fn spawn_mock_tracked(
    total: u64,
    chunk_sleep: Duration,
) -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = ok(TcpListener::bind("127.0.0.1:0"), "bind mock");
    let port = ok(listener.local_addr(), "local_addr").port();
    let inflight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let inflight_t = Arc::clone(&inflight);
    let peak_t = Arc::clone(&peak);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { break };
            let inflight = Arc::clone(&inflight_t);
            let peak = Arc::clone(&peak_t);
            std::thread::spawn(move || {
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    let head = loop {
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head: Vec<u8> = buf.drain(..pos + 4).collect();
                            break String::from_utf8_lossy(&head).into_owned();
                        }
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let range = head
                        .to_ascii_lowercase()
                        .split("\r\n")
                        .find_map(|l| l.strip_prefix("range: bytes="))
                        .and_then(|v| {
                            let (s, e) = v.trim().split_once('-')?;
                            Some((s.parse::<u64>().ok()?, e.parse::<u64>().ok()?))
                        });
                    match range {
                        // Probe (bytes=0-0): 1-byte body, not counted in-flight.
                        Some((0, 0)) => {
                            let mut body = [0u8; 1];
                            fill_pattern(&mut body, 0);
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes 0-0/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Content-Length: 1\r\n\
                                 Connection: keep-alive\r\n\r\n"
                            );
                            sock.write_all(resp.as_bytes()).ok();
                            sock.write_all(&body).ok();
                        }
                        Some((s, e)) => {
                            // Count data requests as in-flight (concurrency observation).
                            let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(cur, Ordering::SeqCst);
                            let end = e.min(total.saturating_sub(1));
                            let len = end.saturating_sub(s) + 1;
                            let resp = format!(
                                "HTTP/1.1 206 Partial Content\r\n\
                                 Content-Range: bytes {s}-{end}/{total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Content-Length: {len}\r\n\
                                 Connection: keep-alive\r\n\r\n"
                            );
                            if sock.write_all(resp.as_bytes()).is_err() {
                                inflight.fetch_sub(1, Ordering::SeqCst);
                                return;
                            }
                            let mut chunk = vec![0u8; 256 * 1024];
                            let mut off = s;
                            while off <= end {
                                let n = (chunk.len() as u64).min(end - off + 1) as usize;
                                fill_pattern(&mut chunk[..n], off);
                                if sock.write_all(&chunk[..n]).is_err() {
                                    break;
                                }
                                off += n as u64;
                                if !chunk_sleep.is_zero() {
                                    std::thread::sleep(chunk_sleep);
                                }
                            }
                            inflight.fetch_sub(1, Ordering::SeqCst);
                        }
                        None => {
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\n\
                                 Accept-Ranges: bytes\r\n\
                                 Connection: keep-alive\r\n\r\n"
                            );
                            sock.write_all(resp.as_bytes()).ok();
                            let mut chunk = vec![0u8; 256 * 1024];
                            let mut off = 0u64;
                            while off < total {
                                let n = (chunk.len() as u64).min(total - off) as usize;
                                fill_pattern(&mut chunk[..n], off);
                                if sock.write_all(&chunk[..n]).is_err() {
                                    break;
                                }
                                off += n as u64;
                            }
                        }
                    }
                }
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), peak, inflight)
}

/// `--http-scheduler=static` end to end (taiji extension option: the
/// scheduling mode is selectable through the CLI/addUri option
/// surface): static fixed splitting (split=4) completes with
/// bit-identical bytes; an unknown scheduler value is rejected
/// (`taiji.option.invalid`, exit 2).
#[test]
fn http_scheduler_static_completes_and_unknown_value_rejected() {
    const TOTAL: u64 = 24 * 1024 * 1024;
    let root = tmp_dir("sched");
    let dl = root.join("dl");
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
    let url = format!("{}/f.bin", mock.url_base);

    // static mode: split=4 fixed splitting (24 MiB / 4 = 6 MiB per
    // segment); --min-split-size 4M is passed explicitly so all 4
    // segments stand. Completes with bit-identical bytes.
    let args = cli_args(
        &url,
        &root,
        &[
            "--http-scheduler",
            "static",
            "--split",
            "4",
            "--min-split-size",
            "4M",
        ],
    );
    let (code, out) = run_http(&args);
    assert_eq!(code, 0, "static download failed: {out}");
    assert!(
        file_matches_pattern(&dl.join("f.bin"), TOTAL),
        "static download bytes must round-trip"
    );

    // Unknown scheduler value: rejected (no clamping, no default fallback; taiji.option.invalid).
    let bad = cli_args(&url, &root, &["--http-scheduler", "guided"]);
    let (code, out) = run_http(&bad);
    assert_eq!(code, 2, "unknown scheduler value must exit 2: {out}");
    assert!(
        out.contains("taiji.option.invalid") && out.contains("http-scheduler"),
        "the error surface must name the invalid --http-scheduler value: {out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `--http-block-size` end to end (taiji extension option: the block
/// grid granularity is configurable at creation; domain = powers of
/// two, 256KiB..16MiB): a 256KiB block completes with bit-identical
/// bytes; out-of-domain values are rejected
/// (`taiji.option.invalid`, exit 2).
#[test]
fn http_block_size_wiring_domain_and_completion() {
    const TOTAL: u64 = 8 * 1024 * 1024;
    let root = tmp_dir("bs");
    let dl = root.join("dl");
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
    let url = format!("{}/f.bin", mock.url_base);

    let args = cli_args(&url, &root, &["--http-block-size", "256K"]);
    let (code, out) = run_http(&args);
    assert_eq!(code, 0, "256K block download failed: {out}");
    assert!(
        file_matches_pattern(&dl.join("f.bin"), TOTAL),
        "block-size download bytes must round-trip"
    );

    for bad in ["300K", "128K", "32M"] {
        let args = cli_args(&url, &root, &["--http-block-size", bad]);
        let (code, out) = run_http(&args);
        assert_eq!(code, 2, "bad block size {bad} must exit 2: {out}");
        assert!(
            out.contains("taiji.option.invalid") && out.contains("http-block-size"),
            "the error surface must name the invalid --http-block-size value: {out}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// `--max-connection-per-server 16` capability proof: the connection
/// executor really opens 16 connections. After AIMD slow start
/// (min(2,16) at start; per-connection bandwidth constant, so each
/// window's gain grows geometrically toward the cap), the peak number
/// of concurrently in-flight data requests observed by the server is
/// exactly 16 (capped; the default per-host cap of 32 does not bind).
/// Full download + bit-identical bytes also verifies
/// single-writer-per-block correctness under 16 concurrent writers.
#[test]
fn max_connection_per_server_16_establishes_sixteen_connections() {
    let total: u64 = 512 * 1024 * 1024;
    // Per-connection throttle: 256 KiB / 80 ms ~= 3.2 MiB/s. During
    // growth (2->4->8->16) each 5 s window aggregates
    // 32/64/128/256 MiB, so the 512 MiB total leaves >= 4 AIMD
    // evaluation windows of growth headroom plus surplus at the cap.
    let (url, peak, _inflight) = spawn_mock_tracked(total, Duration::from_millis(80));
    let root = tmp_dir("x16");
    let args = cli_args(
        &url,
        &root,
        &[
            "--max-connection-per-server",
            "16",
            "--http-stall-window",
            "15",
        ],
    );
    let (code, out) = run_http(&args);
    assert_eq!(code, 0, "x16 download failed: {out}");
    assert!(
        file_matches_pattern(&root.join("dl").join("f.bin"), total),
        "x16 download bytes must round-trip"
    );
    let seen = peak.load(Ordering::SeqCst);
    assert_eq!(
        seen, 16,
        "server must observe 16 concurrent data connections (AIMD cap), saw {seen}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// e2e for the CLI attach half (the core half lives in the taiji-core
/// session-actor tests): `--http-max-per-host` must take effect via
/// session HostCap initialization — in the attach-resume shape (rerun
/// after kill -9; no addUri is issued; the task row already exists),
/// SessionOptions initialization is the only channel that can carry
/// the CLI cap (before closeout the value would be silently dropped
/// and the session cap would stay at its default). Shape: two runs
/// with the same args (split/cap=16 intent + `--http-max-per-host=2`)
/// — the first run goes through addUri with cap 2 and is killed after
/// the bitmap snapshot; the rerun attaches (asserts "resuming
/// in-flight") and its concurrency peak must stay clamped at 2 (under
/// the default caps the 16-intent would exceed 2, so peak <= 2 is
/// direct evidence of the initialization wiring). Completion +
/// bit-identical bytes.
#[test]
fn cli_http_max_per_host_wires_into_session_hostcap_on_attach_resume() {
    const TOTAL: u64 = 32 * 1024 * 1024;
    let root = tmp_dir("p76-attach-cap");
    let dl = root.join("dl");
    let db = root.join("taiji.sqlite3");
    // 80 ms per 256 KiB per connection (~3.2 MiB/s): with cap 2 the
    // first run takes ~5 s (2.8 s to the first snapshot + kill
    // margin) and the resume leg ~3.7 s (< the 5 s AIMD evaluation
    // window, so connections stay at the capped start intent — a
    // stable peak).
    let (url, peak, inflight) = spawn_mock_tracked(TOTAL, Duration::from_millis(80));
    let extra = [
        "--http-max-per-host",
        "2",
        "--split",
        "16",
        "--max-connection-per-server",
        "16",
    ];
    let args = cli_args(&url, &root, &extra);

    // First run: kill -9 once the bitmap snapshot settles (2 blocks).
    let mut child = http_child(&args);
    let done_blocks = wait_bitmap_blocks(&db, 2, Duration::from_secs(30));
    println!("kill -9 at snapshot with {done_blocks} done blocks");
    ok(child.kill(), "kill -9");
    let _ = child.wait();
    assert!(
        dl.join("f.bin.part").exists(),
        "after kill -9 the .part half-written state must survive"
    );
    // Drain the server-side in-flight counter (after the kill each
    // server thread exits on a write error within one throttle period
    // and returns its count) so the first run's leaked count cannot
    // pollute the resume-leg peak assertion.
    let drain_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while inflight.load(Ordering::SeqCst) > 0 {
        assert!(
            std::time::Instant::now() < drain_deadline,
            "after kill -9 the server-side in-flight requests must drain within 5s"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // Rerun with the same args: attach matches (same url/dir/out) ->
    // no addUri — session HostCap initialization is the only channel
    // the CLI cap can flow through.
    let (code, out) = run_http(&args);
    assert_eq!(code, 0, "attach resume run failed: {out}");
    assert!(
        out.contains("resuming in-flight"),
        "the rerun must recover via attach (no addUri issued): {out}"
    );
    assert!(
        file_matches_pattern(&dl.join("f.bin"), TOTAL),
        "after recovery the file must be bit-identical"
    );
    let seen = peak.load(Ordering::SeqCst);
    assert!(
        seen > 1 && seen <= 2,
        "in the attach form the concurrency peak must stay clamped by the CLI \
         --http-max-per-host=2 (the first run's addUri and the rerun's initialization \
         share the same cap; >2 = an initialization wiring-seam regression), got {seen}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ---- Platform filename sanitization e2e ----

/// The `out` column of http_task rows (read-only connection; the
/// persisted assertion surface for the actual-name round-trip —
/// tellStatus files[0].path reads from the same column).
fn http_task_outs(db: &Path) -> Vec<String> {
    let conn = ok(
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY),
        "open db ro",
    );
    let mut st = ok(conn.prepare("SELECT out FROM http_task"), "prepare");
    let rows = ok(st.query_map([], |r| r.get::<_, String>(0)), "query outs");
    rows.filter_map(|r| r.ok()).collect()
}

/// Args without `--out` (URL-derived names = the entry to full sanitization).
fn cli_args_url_named(url: &str, root: &Path, extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        url.to_string(),
        "-d".to_string(),
        root.join("dl").display().to_string(),
        "--sqlite3-db-path".to_string(),
        root.join("taiji.sqlite3").display().to_string(),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

/// URL-derived-name full sanitization matrix (table driven): illegal
/// characters/control codes/separators -> `_`; reserved names get a
/// suffix while keeping the extension; trailing dots/spaces are
/// stripped; 254-byte truncation keeps the extension; an empty name
/// falls back to `download`. Each row asserts four faces: the actual
/// on-disk name, `.part` closeout, the row's `out` column (the
/// persisted actual-name round-trip), and the path in the stdout
/// completion log.
#[test]
fn url_derived_names_are_sanitized_end_to_end() {
    const TOTAL: u64 = 256 * 1024;
    // (trailing URL segment, percent-encoded; expected on-disk name; why)
    let cases: &[(&str, &str, &str)] = &[
        (
            "fi%3Cle%3Ena%3Ame%22.txt",
            "fi_le_na_me_.txt",
            "illegal characters < > : \" -> _",
        ),
        (
            "path%2Finject.txt",
            "path_inject.txt",
            "separators restored by percent-decode -> _ (the single-component invariant)",
        ),
        ("a%01b%2Ebin", "a_b.bin", "control codes -> _"),
        (
            "con.tar.gz",
            "con_.tar.gz",
            "reserved-name stem gets a suffix, keeping the extension",
        ),
        ("lpt9", "lpt9_", "reserved name without an extension"),
        (
            "evil%2E%20",
            "evil",
            "trailing dot/space stripped (after decode+trim: evil.)",
        ),
        (
            "%E8%B5%84%E6%96%99.tar.gz",
            "资料.tar.gz",
            "a healthy multibyte name passes through",
        ),
    ];
    for (i, (segment, expected, why)) in cases.iter().enumerate() {
        let root = tmp_dir(&format!("p79full{i}"));
        let dl = root.join("dl");
        let db = root.join("taiji.sqlite3");
        let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
        let url = format!("{}/{segment}", mock.url_base);
        let (code, out) = run_http(&cli_args_url_named(&url, &root, &[]));
        assert_eq!(code, 0, "case `{segment}` ({why}) failed: {out}");
        let file = dl.join(expected);
        assert!(
            file.is_file(),
            "case `{segment}` ({why}): the actual on-disk name must be {expected} \
             (the actual name round-trips)"
        );
        assert!(
            file_matches_pattern(&file, TOTAL),
            "case `{segment}`: content must be bit-identical"
        );
        assert!(
            !dl.join(format!("{expected}.part")).exists(),
            "case `{segment}`: .part must be renamed to close out"
        );
        let outs = http_task_outs(&db);
        assert_eq!(
            outs,
            vec![expected.to_string()],
            "case `{segment}` ({why}): the row's out must be the actual on-disk name \
             (the query/recovery surfaces share one source)"
        );
        assert!(
            out.contains(expected),
            "case `{segment}` ({why}): the completion log must carry the actual name: {out}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Truncation and fallback: a 300-byte URL name is truncated to the
/// engine budget (254 - suffix 5 - candidate marker 2 = 247) keeping
/// the extension, so `<final>.part` and `<final>.1.part` shapes stay
/// <= 254 <= NAME_MAX; an empty trailing URL segment falls back to
/// the name `download`.
#[test]
fn url_derived_name_truncation_and_fallback() {
    const TOTAL: u64 = 256 * 1024;
    // 300 'L' + ".bin" -> stem truncated to 243 + ".bin" = 247 bytes (engine budget).
    let long_segment = format!("{}.bin", "L".repeat(300));
    let expected_long = format!("{}.bin", "L".repeat(243));
    assert_eq!(expected_long.len(), 247);

    let root = tmp_dir("p79trunc");
    let dl = root.join("dl");
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
    let url = format!("{}/{}", mock.url_base, long_segment);
    let (code, out) = run_http(&cli_args_url_named(&url, &root, &[]));
    assert_eq!(code, 0, "truncation run failed: {out}");
    assert!(
        dl.join(&expected_long).is_file(),
        "an over-long URL name must be truncated to 254 bytes keeping the extension: {}",
        dl.display()
    );
    assert_eq!(
        http_task_outs(&root.join("taiji.sqlite3")),
        vec![expected_long.clone()]
    );
    let _ = std::fs::remove_dir_all(&root);

    // Empty trailing URL segment (trailing `/`) -> derive None -> fallback `download`.
    let root = tmp_dir("p79fallback");
    let dl = root.join("dl");
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
    let url = format!("{}/", mock.url_base);
    let (code, out) = run_http(&cli_args_url_named(&url, &root, &[]));
    assert_eq!(code, 0, "fallback run failed: {out}");
    assert!(
        dl.join("download").is_file(),
        "an empty trailing segment must fall back to download"
    );
    assert_eq!(
        http_task_outs(&root.join("taiji.sqlite3")),
        vec!["download".to_string()]
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// User-supplied `--out` name length layering: the acceptance face
/// (`sanitize_out_option`) caps names at 255 bytes, matching the
/// taiji-bt filetree component cap. Within the cap, a 250-byte name
/// is truncated by the engine-level light channel to the 247-byte
/// engine budget, keeping the extension (no character replacement);
/// over the cap, a 300-byte name is rejected wholesale at add time
/// (`taiji.option.invalid`, exit 2, no task row).
#[test]
fn user_out_name_length_clamped_by_light_channel() {
    const TOTAL: u64 = 256 * 1024;
    let root = tmp_dir("p79light");
    let dl = root.join("dl");
    let db = root.join("taiji.sqlite3");
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
    let url = format!("{}/f.bin", mock.url_base);

    // Within the cap (250 <= 255) but over the 247 budget: light-channel truncation.
    let in_cap_out = format!("{}.zip", "u".repeat(246)); // 250 bytes
    let expected = format!("{}.zip", "u".repeat(243)); // 243 + ".zip" = 247 (engine budget)
    let mut args = cli_args_url_named(&url, &root, &[]);
    args.extend(["-o".to_string(), in_cap_out.clone()]);
    let (code, out) = run_http(&args);
    assert_eq!(code, 0, "light channel run failed: {out}");
    assert!(
        dl.join(&expected).is_file(),
        "a within-cap over-budget user name must be truncated to the engine budget \
         by the light channel, keeping the extension"
    );
    assert!(
        !dl.join(&in_cap_out).exists(),
        "must not land on disk under the over-budget name (the engine-level fallback)"
    );
    assert_eq!(http_task_outs(&db), vec![expected.clone()]);

    // Over the cap (300 > 255): rejected at add time, no task row.
    let over_cap = format!("{}.zip", "u".repeat(296)); // 300 bytes
    let mut args = cli_args_url_named(&url, &root, &[]);
    args.extend(["-o".to_string(), over_cap]);
    let (code, out) = run_http(&args);
    assert_eq!(
        code, 2,
        "an over-cap basename must be rejected at the add face with exit 2: {out}"
    );
    assert!(
        out.contains("taiji.option.invalid"),
        "the error surface must be taiji.option.invalid: {out}"
    );
    assert_eq!(
        http_task_outs(&db),
        vec![expected],
        "the rejected add must not leave a task row"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Sanitization interacts with auto-file-renaming candidate
/// generation: the conflict namespace is the post-sanitization name.
/// URL `con.txt` sanitizes to `con_.txt`; when that name and `.1` are
/// both taken, the aria2 candidate algorithm lands on `con_.2.txt`,
/// and the actual name (with the candidate suffix) is written back to
/// the row's `out`. Existing files are never overwritten.
#[test]
fn sanitized_name_feeds_auto_rename_candidates() {
    const TOTAL: u64 = 256 * 1024;
    let root = tmp_dir("p79rename");
    let dl = root.join("dl");
    let db = root.join("taiji.sqlite3");
    ok(std::fs::create_dir_all(&dl), "mkdir dl");
    // Pre-take the sanitized final name and the first candidate (aria2 `fn.1.ext` order).
    ok(
        std::fs::write(dl.join("con_.txt"), b"seed-con"),
        "seed con_",
    );
    ok(
        std::fs::write(dl.join("con_.1.txt"), b"seed-con1"),
        "seed con_.1",
    );

    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
    let url = format!("{}/con.txt", mock.url_base);
    let (code, out) = run_http(&cli_args_url_named(&url, &root, &[]));
    assert_eq!(code, 0, "auto-rename run failed: {out}");
    let landed = dl.join("con_.2.txt");
    assert!(
        landed.is_file(),
        "when the sanitized name is taken, the sanitized-domain candidate \
         con_.2.txt must be used: {}",
        dl.display()
    );
    assert!(
        file_matches_pattern(&landed, TOTAL),
        "the candidate file's content must be this download's data"
    );
    assert_eq!(
        ok(std::fs::read(dl.join("con_.txt")), "read seed con_"),
        b"seed-con",
        "the pre-existing file must not be overwritten"
    );
    assert_eq!(
        ok(std::fs::read(dl.join("con_.1.txt")), "read seed con_.1"),
        b"seed-con1",
        "the first candidate file must not be overwritten"
    );
    assert_eq!(
        http_task_outs(&db),
        vec!["con_.2.txt".to_string()],
        "the actual name (with the auto-rename candidate suffix) must round-trip into the row's out"
    );
    assert!(
        out.contains("con_.2.txt"),
        "the completion log must carry the candidate's actual name: {out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

// ----------------------------------------------------------------------
// Windows long-path (>260 chars) download full-flow e2e, gated by
// cfg(windows) (compiled out on other platforms). The CI shape keeps
// the LongPathsEnabled registry policy off (the default): the
// conversion layer is policy-independent and long paths are admitted
// only via the `\\?\` verbatim prefix.
// ----------------------------------------------------------------------
#[cfg(windows)]
mod winpath_long_path {
    use super::*;
    use std::os::windows::ffi::OsStrExt as _;

    /// Length in UTF-16 units (the Windows test measure).
    fn utf16_len(p: &Path) -> usize {
        p.as_os_str().encode_wide().count()
    }

    /// Build a nested directory deeper than 260 UTF-16 units. The
    /// fixture creates directories via [`taiji_io::winpath::to_fs_path`]
    /// — a bare `create_dir_all` on a long directory also hits
    /// `ERROR_PATH_NOT_FOUND`; production-side creation goes through
    /// the binary's wiring.
    fn deep_dir(root: &Path) -> PathBuf {
        // 6 segments x 60 'a' ~= 360+ UTF-16 units (far beyond 260).
        let mut p = root.to_path_buf();
        for _ in 0..6 {
            p = p.join("a".repeat(60));
        }
        p
    }

    /// Small file, full flow, inside a >260-char directory: open
    /// (create_dir_all along the way + open + prealloc set_len) ->
    /// positioned write -> fsync -> rename closeout, every step
    /// through the verbatim conversion; the landing spot is correct
    /// and the bytes match. The row's `out` (the same source RPC
    /// echoes as files[0].path) and stdout carry no `\\?\` prefix
    /// (the user-visible surface stays prefix-free).
    #[test]
    fn long_path_download_completes_without_prefix_leak() {
        const TOTAL: u64 = 64 * 1024;
        let root = tmp_dir("winpath");
        let deep = deep_dir(&root);
        // Fixture dir creation (same conversion inside the test process).
        ok(
            std::fs::create_dir_all(taiji_io::winpath::to_fs_path(&deep)),
            "mkdir long dir",
        );
        // Pin the depth: >260 UTF-16 units (outside MAX_PATH).
        assert!(
            utf16_len(&deep) > 260,
            "the fixture depth must exceed MAX_PATH: {}",
            deep.display()
        );

        let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
        let url = format!("{}/f.bin", mock.url_base);
        // root = deep: cli_args derives dir = deep/dl and db =
        // deep/taiji.sqlite3 (covering the sqlite open point's
        // conversion too); -o pins the file name.
        let args = cli_args(&url, &deep, &[]);
        let dl = deep.join("dl");
        let db = deep.join("taiji.sqlite3");

        let (code, out) = run_http(&args);
        assert_eq!(code, 0, "the long-path download must complete: {out}");

        // Landing spot and content (probed and read back through the
        // conversion — the shared helpers' bare open fails on >260
        // paths).
        let final_path = dl.join("f.bin");
        let part_path = dl.join("f.bin.part");
        assert!(
            taiji_io::winpath::to_fs_path(&final_path).is_file(),
            "the final file must land at the long path"
        );
        assert!(
            !taiji_io::winpath::to_fs_path(&part_path).exists(),
            "after completion .part must be renamed to close out"
        );
        let f = ok(
            std::fs::File::open(taiji_io::winpath::to_fs_path(&final_path)),
            "open long final file",
        );
        let mut body = Vec::new();
        ok(std::io::Read::read_to_end(&mut f, &mut body), "read final");
        let mut want = vec![0u8; TOTAL as usize];
        fill_pattern(&mut want, 0);
        assert_eq!(
            body, want,
            "the long-path on-disk content must be bit-identical"
        );

        // Zero prefix on user-visible surfaces: the row's `out` (same
        // source as tellStatus files[0].path) and the stdout
        // completion log must not carry `\\?\`.
        let conn = ok(
            rusqlite::Connection::open_with_flags(
                taiji_io::winpath::to_fs_path(&db),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ),
            "open db ro (long path)",
        );
        let mut st = ok(conn.prepare("SELECT out FROM http_task"), "prepare");
        let outs: Vec<String> = ok(st.query_map([], |r| r.get::<_, String>(0)), "query outs")
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(
            outs,
            vec![final_path.display().to_string()],
            "the row's out must be the original (prefix-free) path"
        );
        assert!(
            !out.contains(r"\\?\"),
            "the stdout user-visible surface must not leak the verbatim prefix: {out}"
        );

        let _ = std::fs::remove_dir_all(&taiji_io::winpath::to_fs_path(&root));
    }
}

/// Top-level positional URL form exercises the full http-subcommand
/// pipeline (attach/bitmap resume/exit codes): the mock download
/// completes, on-disk content verifies, exit code 0.
#[test]
fn positional_url_downloads_via_http_pipeline() {
    const TOTAL: u64 = 512 * 1024;
    let root = tmp_dir("w1-pos");
    let dl = root.join("dl");
    let mock = spawn_mock(TOTAL, Duration::ZERO, Duration::ZERO);
    let url = format!("{}/f.bin", mock.url_base);
    // Top-level form: positional URL + --dir (no http subcommand).
    let out = ok(
        Command::new(env!("CARGO_BIN_EXE_taiji"))
            .arg(&url)
            .arg("--dir")
            .arg(dl.display().to_string())
            .arg("--sqlite3-db-path")
            .arg(root.join("taiji.sqlite3").display().to_string())
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
        "run taiji <url>",
    );
    let code = out.status.code().unwrap_or(-1);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        code, 0,
        "the top-level URL one-shot download exits 0; output:\n{combined}"
    );
    assert!(
        file_matches_pattern(&dl.join("f.bin"), TOTAL),
        "the on-disk content must be bit-identical"
    );
    let _ = std::fs::remove_dir_all(&root);
}
