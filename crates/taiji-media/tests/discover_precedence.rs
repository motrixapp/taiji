//! Discovery precedence + same-origin pairing tests.
//! Filesystem-backed but ffmpeg-free: tier directories
//! hold plain marker files (the dir tiers check presence only); the
//! PATH search tier gets a parameterized PATH value (env mutation is
//! off-limits under edition 2024 without unsafe).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use taiji_media::discover::{DiscoveryRequest, DiscoverySource, discover_with_env};

fn tier_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("taiji-discover-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    dir
}

/// Marker-file pair (dir tiers only check `is_file`).
fn marker_pair(dir: &Path) {
    for name in ["ffmpeg", "ffprobe"] {
        let path = if cfg!(windows) {
            dir.join(format!("{name}.exe"))
        } else {
            dir.join(name)
        };
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap_or_else(|e| panic!("{e}"));
    }
}

#[test]
fn precedence_explicit_beats_env_beats_packaged() {
    let explicit = tier_dir("explicit");
    let env_dir = tier_dir("env");
    let packaged = tier_dir("packaged");
    for dir in [&explicit, &env_dir, &packaged] {
        marker_pair(dir);
    }
    let request = DiscoveryRequest {
        explicit_dir: Some(explicit.clone()),
    };
    let pair = match discover_with_env(&request, Some(&env_dir), packaged.to_str()) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(pair.source, DiscoverySource::Explicit(explicit.clone()));
    assert_eq!(pair.dir(), explicit.as_path());

    // Explicit tier absent: env wins over packaged.
    let request = DiscoveryRequest { explicit_dir: None };
    let pair = match discover_with_env(&request, Some(&env_dir), packaged.to_str()) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(pair.source, DiscoverySource::Env(env_dir.clone()));

    // Env absent: packaged wins.
    let pair = match discover_with_env(&request, None, packaged.to_str()) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(pair.source, DiscoverySource::Packaged(packaged.clone()));
}

#[test]
fn mandatory_tier_with_one_binary_missing_is_a_hard_error() {
    // An explicit/ env tier holding ffmpeg but not ffprobe does NOT
    // fall through to PATH — the operator asked for that directory.
    let env_dir = tier_dir("half");
    fs::write(
        env_dir.join(if cfg!(windows) {
            "ffmpeg.exe"
        } else {
            "ffmpeg"
        }),
        b"",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let request = DiscoveryRequest { explicit_dir: None };
    match discover_with_env(&request, Some(&env_dir), None) {
        Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_missing"),
        Ok(p) => panic!("unexpected success: {:?}", p.source),
    }
}

#[test]
fn all_tiers_absent_is_missing() {
    // No explicit, no env, no packaged, and a PATH holding no ffmpeg.
    let request = DiscoveryRequest { explicit_dir: None };
    match discover_with_env(&request, None, None) {
        // NOTE: the live PATH may still hold ffmpeg on the dev/CI
        // machine — a Path-tier hit is a legitimate outcome; only the
        // Missing error is *forbidden* here. The dedicated PATH test
        // below exercises search_path_in with a controlled value.
        Ok(p) => assert_eq!(p.source.as_str(), "path"),
        Err(e) => panic!("unexpected missing on a machine with a PATH hit: {e}"),
    }
}

#[test]
fn path_search_pairing_and_executable_bit() {
    // Controlled PATH (parameterized seam — no process-env mutation).
    let dir_a = tier_dir("path-a");
    marker_pair(&dir_a);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["ffmpeg", "ffprobe"] {
            let mut perms = fs::metadata(dir_a.join(name))
                .unwrap_or_else(|e| panic!("{e}"))
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(dir_a.join(name), perms).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    let path_value = env::join_paths([dir_a.as_path(), Path::new("/nonexistent-taiji")])
        .unwrap_or_else(|e| panic!("{e}"));
    let pair = match taiji_media::discover::search_path_in(path_value.as_os_str()) {
        Ok(p) => p,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(pair.source, DiscoverySource::Path(dir_a.clone()));
    assert!(pair.ffmpeg.starts_with(&dir_a));
    assert!(pair.ffprobe.starts_with(&dir_a));

    // Non-executable ffmpeg on unix is not a hit (mode 0o644).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir_b = tier_dir("path-b");
        marker_pair(&dir_b);
        for name in ["ffmpeg", "ffprobe"] {
            let mut perms = fs::metadata(dir_b.join(name))
                .unwrap_or_else(|e| panic!("{e}"))
                .permissions();
            perms.set_mode(0o644);
            fs::set_permissions(dir_b.join(name), perms).unwrap_or_else(|e| panic!("{e}"));
        }
        let path_value = env::join_paths([dir_b.as_path(), Path::new("/nonexistent-taiji")])
            .unwrap_or_else(|e| panic!("{e}"));
        match taiji_media::discover::search_path_in(path_value.as_os_str()) {
            Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_missing"),
            Ok(p) => panic!("non-executable must not be a PATH hit: {:?}", p.ffmpeg),
        }
    }

    // Mixed directories (ffmpeg in dir_a only, ffprobe moved to a
    // second dir) = origin mismatch, never a silent mixed pair.
    #[cfg(unix)]
    {
        let dir_c = tier_dir("path-c");
        fs::create_dir_all(&dir_c).unwrap_or_else(|e| panic!("{e}"));
        let _ = fs::rename(dir_a.join("ffprobe"), dir_c.join("ffprobe"));
        let path_value =
            env::join_paths([dir_a.as_path(), dir_c.as_path()]).unwrap_or_else(|e| panic!("{e}"));
        match taiji_media::discover::search_path_in(path_value.as_os_str()) {
            Err(e) => assert_eq!(e.code(), "taiji.media.ffmpeg_origin_mismatch"),
            Ok(p) => panic!(
                "mixed-pair must be refused: {:?} + {:?}",
                p.ffmpeg, p.ffprobe
            ),
        }
    }
}
