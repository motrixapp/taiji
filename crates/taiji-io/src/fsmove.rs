//! Storage-migration primitives for `taiji.moveStorage` (SPEC §8.2
//! deferred extension): move a task's on-disk payload to a new
//! directory with same-volume atomic rename, a cross-volume
//! (EXDEV) copy fallback, and crash safety by idempotent redo.
//!
//! Crash-safety contract (the `finalize.rs` rename-journal discipline,
//! applied to moves):
//!
//! - **The source is never destroyed before the commit lands.** Rename
//!   mode commits in one atomic `rename(2)`; copy mode commits by
//!   renaming a fully-written, fsynced temp file (`<dst>.taiji-move-
//!   <tag>.tmp`) over the destination — only then is the source
//!   unlinked. Every intermediate state therefore still holds either
//!   the intact source, the committed destination, or both.
//! - **Redo is idempotent.** Re-running a move after a kill at any
//!   point converges: absent source = already committed; source and
//!   destination both present with equal length = commit landed before
//!   the source unlink (finish by removing the source); unequal length
//!   = a foreign file owns the destination namespace slot.
//! - **Tree moves are two-pass**: the walk copies/renames every file
//!   into place but defers the source unlinks to one
//!   `remove_dir_all` after the whole tree has committed — a mid-tree
//!   failure leaves the source tree complete (the redo re-copies or
//!   skips per equal-length file), never split across directories.
//! - Directory moves walk the tree (deterministic sorted order) and
//!   apply the same per-file discipline; the source subtree is removed
//!   only after every file has committed. Same-volume directory moves
//!   take the single atomic `rename(2)` instead of the walk.
//!
//! Like `publication_fs`, the equal-length committed-destination rule
//! assumes an application-managed download namespace: an externally
//! planted same-length file at a destination slot is indistinguishable
//! from our own commit and is treated as the commit.
//!
//! `MoveMode::ForceCopy` forces the copy path on any filesystem — the
//! cross-volume simulation arm for tests (no real EXDEV exists inside a
//! temp-dir test sandbox); it is not exposed on the RPC face.
//!
//! Blocking discipline: callers run these on `spawn_blocking` (the
//! repo-wide rule for disk IO).
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::winpath;

/// How the move executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveMode {
    /// `rename(2)` first; on EXDEV fall back to copy + commit + unlink.
    Auto,
    /// Always take the copy path (tests' cross-volume arm).
    ForceCopy,
}

/// What a single [`move_path`] call did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveOutcome {
    /// Atomic `rename(2)` committed the move.
    Renamed,
    /// Copy fallback committed the move (payload bytes copied).
    Copied { bytes: u64 },
    /// A prior commit already landed; the leftover source was removed.
    CommitFinished,
    /// Source absent and destination present (fully committed earlier).
    SrcAbsent,
}

/// Occupied-directory rename failure detection (the fall-through arm
/// of the directory move): ENOTEMPTY on Unix (39 Linux / 66 macOS),
/// EEXIST/AlreadyExists elsewhere. Such a destination is walked file
/// by file — equal-length files are adopted as prior partial commits,
/// anything else is a foreign slot and refuses.
fn is_occupied_dir(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::AlreadyExists {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(error.raw_os_error(), Some(17 | 39 | 66))
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Temporary sibling name for an in-flight copy (`<dst>.taiji-move-<tag>.tmp`).
fn temp_sibling(dst: &Path, tag: &str) -> PathBuf {
    let mut name = dst.as_os_str().to_os_string();
    name.push(format!(".taiji-move-{tag}.tmp"));
    dst.with_file_name(name)
}

/// Remove a stale temp sibling from an interrupted attempt, if any.
/// Best-effort: a leftover temp never blocks the redo (it is replaced
/// by the fresh copy), but tidying keeps the namespace clean.
fn clear_temp(dst: &Path, tag: &str) {
    let tmp = temp_sibling(dst, tag);
    if let Err(error) = fs::remove_file(winpath::to_fs_path(&tmp)) {
        if error.kind() != io::ErrorKind::NotFound {
            tracing::debug!(%error, tmp = ?tmp, "stale move temp survived cleanup");
        }
    }
}

/// Best-effort directory fsync (rename/unlink durability). Errors are
/// swallowed: filesystems that reject directory fsync (some network
/// mounts) still get the data-level fsync from the copy path.
#[cfg(unix)]
fn fsync_dir(dir: &Path) {
    let f = match File::open(winpath::to_fs_path(dir)) {
        Ok(f) => f,
        Err(_) => return,
    };
    let _ = f.sync_all();
}
#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) {}

/// EXDEV (cross-device link) detection: errno 18 on Unix,
/// ERROR_NOT_SAME_DEVICE (17) on Windows. `io::ErrorKind` has no
/// stable crosses-devices variant, so the raw errno is matched here.
fn is_cross_device(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(18)
    }
    #[cfg(windows)]
    {
        error.raw_os_error() == Some(17)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = error;
        false
    }
}

/// Move one regular file under the crash-safety contract (see module
/// docs). `tag` names the temp sibling (the gid, for identifiability).
/// `defer_unlink` (the tree-walk form) keeps the source in place after
/// the copy commits — the caller unlinks the whole source tree only
/// after every file has landed.
fn move_one_file(
    src: &Path,
    dst: &Path,
    tag: &str,
    mode: MoveMode,
    defer_unlink: bool,
) -> io::Result<MoveOutcome> {
    let src_meta = match fs::symlink_metadata(winpath::to_fs_path(src)) {
        Ok(m) => m,
        Err(_) => {
            // Absent source: committed earlier (destination present) or
            // nothing to move. The caller's journal close-out decides.
            return Ok(MoveOutcome::SrcAbsent);
        }
    };
    if !src_meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "move source is not a regular file",
        ));
    }
    // Destination already present: either our commit landed before the
    // source unlink (equal length → finish it) or a foreign file owns
    // the slot (unequal → refuse; namespace discipline).
    if let Ok(dst_meta) = fs::symlink_metadata(winpath::to_fs_path(dst)) {
        if !dst_meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "move destination is not a regular file",
            ));
        }
        if dst_meta.len() == src_meta.len() {
            if !defer_unlink {
                fs::remove_file(winpath::to_fs_path(src))?;
                fsync_dir(src.parent().unwrap_or(Path::new(".")));
            }
            return Ok(MoveOutcome::CommitFinished);
        }
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "move destination occupied by a foreign file",
        ));
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(winpath::to_fs_path(parent))?;
    }
    // Tidy a stale temp from an interrupted copy attempt regardless of
    // the path taken this round (a same-volume rename commit leaves
    // the old temp behind otherwise; the caller-serialized namespace
    // makes the clear race-free).
    clear_temp(dst, tag);
    if mode == MoveMode::Auto {
        match fs::rename(
            winpath::to_fs_path(src).as_ref(),
            winpath::to_fs_path(dst).as_ref(),
        ) {
            Ok(()) => {
                fsync_dir(dst.parent().unwrap_or(Path::new(".")));
                return Ok(MoveOutcome::Renamed);
            }
            Err(error) if is_cross_device(&error) => {}
            Err(error) => return Err(error),
        }
    }
    // Copy fallback: temp sibling → fsync → atomic rename → unlink src.
    let tmp = temp_sibling(dst, tag);
    let bytes = copy_with_fsync(src, &tmp)?;
    fs::rename(
        winpath::to_fs_path(&tmp).as_ref(),
        winpath::to_fs_path(dst).as_ref(),
    )?;
    fsync_dir(dst.parent().unwrap_or(Path::new(".")));
    if !defer_unlink {
        fs::remove_file(winpath::to_fs_path(src))?;
        fsync_dir(src.parent().unwrap_or(Path::new(".")));
    }
    Ok(MoveOutcome::Copied { bytes })
}

/// Stream `src` into `tmp` and fsync it. The temp is a fresh file, so
/// an interrupted attempt never corrupts either endpoint.
fn copy_with_fsync(src: &Path, tmp: &Path) -> io::Result<u64> {
    let mut reader = File::open(winpath::to_fs_path(src))?;
    let mut writer = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(winpath::to_fs_path(tmp))?;
    // Permission bits ride along (exec bits on torrent payloads; the
    // fresh temp would otherwise default to 0666&~umask). Best-effort:
    // a permission failure never fails the data move.
    if let Ok(meta) = reader.metadata() {
        let _ = fs::set_permissions(winpath::to_fs_path(tmp), meta.permissions());
    }
    let mut total: u64 = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buffer[..n])?;
        total += n as u64;
    }
    writer.sync_all()?;
    Ok(total)
}

/// Move a task payload — a regular file or a directory tree of regular
/// files — from `src` to `dst` under the module's crash-safety
/// contract. A nesting move (`dst` inside `src`) is refused: the walk
/// would consume its own destination.
pub fn move_path(src: &Path, dst: &Path, tag: &str, mode: MoveMode) -> io::Result<MoveOutcome> {
    if src == dst {
        return Ok(MoveOutcome::SrcAbsent);
    }
    if dst.starts_with(src) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "move destination nested inside source",
        ));
    }
    let src_meta = match fs::symlink_metadata(winpath::to_fs_path(src)) {
        Ok(m) => m,
        Err(_) => return Ok(MoveOutcome::SrcAbsent),
    };
    if src_meta.is_file() {
        return move_one_file(src, dst, tag, mode, false);
    }
    if !src_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "move source is neither file nor directory",
        ));
    }
    // Directory: same-volume atomic rename first (Auto), else the walk.
    // An occupied destination directory (a foreign tree, or the residue
    // of an interrupted walk) fails the rename with ENOTEMPTY/EEXIST —
    // not EXDEV — so those errors also fall through to the convergent
    // per-file walk instead of wedging every retry (the redo contract).
    if mode == MoveMode::Auto {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(winpath::to_fs_path(parent))?;
        }
        match fs::rename(
            winpath::to_fs_path(src).as_ref(),
            winpath::to_fs_path(dst).as_ref(),
        ) {
            Ok(()) => {
                fsync_dir(dst.parent().unwrap_or(Path::new(".")));
                return Ok(MoveOutcome::Renamed);
            }
            Err(error) if is_cross_device(&error) => {}
            Err(error) if is_occupied_dir(&error) => {}
            Err(error) => return Err(error),
        }
    }
    let mut bytes: u64 = 0;
    move_dir_tree(src, dst, tag, &mut bytes)?;
    fs::remove_dir_all(winpath::to_fs_path(src))?;
    fsync_dir(dst.parent().unwrap_or(Path::new(".")));
    Ok(MoveOutcome::Copied { bytes })
}

/// Recursive walk of a payload directory: every file commits under the
/// per-file contract **with the source unlink deferred** (the two-pass
/// discipline — [`move_path`] removes the source tree only after the
/// walk completes); empty subdirectories are recreated as walked.
fn move_dir_tree(src: &Path, dst: &Path, tag: &str, bytes: &mut u64) -> io::Result<()> {
    fs::create_dir_all(winpath::to_fs_path(dst))?;
    let mut entries: Vec<_> = fs::read_dir(winpath::to_fs_path(src))?
        .map(|e| e.map(|e| e.path()))
        .collect::<io::Result<_>>()?;
    entries.sort();
    for entry in entries {
        let Some(name) = entry.file_name() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "move source tree entry has no file name",
            ));
        };
        let target = dst.join(name);
        let meta = fs::symlink_metadata(winpath::to_fs_path(&entry))?;
        if meta.is_dir() {
            move_dir_tree(&entry, &target, tag, bytes)?;
        } else if meta.is_file() {
            if let MoveOutcome::Copied { bytes: b } =
                move_one_file(&entry, &target, tag, MoveMode::ForceCopy, true)?
            {
                *bytes += b;
            }
        } else {
            // Torrent payload trees carry no symlinks (BEP47 `.pad`
            // files never reach the disk); anything else is foreign
            // and refused rather than silently mangled.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "move source tree contains a non-regular entry",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    /// Test-side result unwrap (the repo-wide no-unwrap discipline:
    /// a labeled panic instead of `unwrap`/`expect`).
    fn ok<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("{what}: {e}"),
        }
    }

    /// Test-side expected-error unwrap.
    fn err_of<T>(r: io::Result<T>, what: &str) -> io::Error {
        match r {
            Ok(_) => panic!("{what}: expected an error"),
            Err(e) => e,
        }
    }

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            ok(fs::create_dir_all(parent), "fs op");
        }
        ok(fs::write(path, bytes), "fs op");
    }

    fn tmp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("taiji-io-fsmove")
            .join(format!("{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        ok(fs::create_dir_all(&dir), "fs op");
        dir
    }

    #[test]
    fn same_volume_rename_commits_atomically() {
        let root = tmp_root("rename");
        let src = root.join("a.part");
        write(&src, b"payload");
        let dst = root.join("b.part");
        let out = ok(move_path(&src, &dst, "g1", MoveMode::Auto), "fs op");
        assert_eq!(out, MoveOutcome::Renamed);
        assert_eq!(ok(fs::read(&dst), "fs op"), b"payload");
        assert!(!src.exists());
    }

    #[test]
    fn forced_copy_commits_and_clears_source() {
        let root = tmp_root("copy");
        let src = root.join("a.part");
        write(&src, b"0123456789");
        let dst = root.join("nest").join("b.part");
        let out = ok(move_path(&src, &dst, "g2", MoveMode::ForceCopy), "fs op");
        assert_eq!(out, MoveOutcome::Copied { bytes: 10 });
        assert_eq!(ok(fs::read(&dst), "fs op"), b"0123456789");
        assert!(!src.exists());
        // No temp sibling survives.
        assert!(!temp_sibling(&dst, "g2").exists());
    }

    #[test]
    fn directory_tree_moves_in_both_modes() {
        for mode in [MoveMode::Auto, MoveMode::ForceCopy] {
            let root = tmp_root(&format!("dir-{:?}", mode));
            let src = root.join("name-dir");
            write(&src.join("f1.bin"), b"one");
            write(&src.join("sub").join("f2.bin"), b"two-two");
            let dst = root.join("moved").join("name-dir");
            ok(move_path(&src, &dst, "g3", mode), "fs op");
            assert_eq!(ok(fs::read(dst.join("f1.bin")), "fs op"), b"one");
            assert_eq!(
                ok(fs::read(dst.join("sub").join("f2.bin")), "fs op"),
                b"two-two"
            );
            assert!(!src.exists());
        }
    }

    #[test]
    fn redo_after_commit_lands_finishes_the_unlink() {
        // Crash window: copy committed, source unlink never ran.
        let root = tmp_root("redo-commit");
        let src = root.join("a.part");
        let dst = root.join("b.part");
        write(&src, b"same");
        write(&dst, b"same");
        let out = ok(move_path(&src, &dst, "g4", MoveMode::Auto), "fs op");
        assert_eq!(out, MoveOutcome::CommitFinished);
        assert!(!src.exists());
        assert_eq!(ok(fs::read(&dst), "fs op"), b"same");
    }

    #[test]
    fn redo_from_scratch_is_idempotent() {
        // Crash window: half-copied temp sits next to the destination.
        let root = tmp_root("redo-half");
        let src = root.join("a.part");
        write(&src, b"full-payload");
        let dst = root.join("b.part");
        write(&temp_sibling(&dst, "g5"), b"hal");
        let out = ok(move_path(&src, &dst, "g5", MoveMode::ForceCopy), "fs op");
        assert_eq!(out, MoveOutcome::Copied { bytes: 12 });
        assert_eq!(ok(fs::read(&dst), "fs op"), b"full-payload");
        assert!(!src.exists());
    }

    #[test]
    fn absent_source_reports_and_keeps_destination() {
        let root = tmp_root("absent");
        let dst = root.join("b.part");
        write(&dst, b"committed");
        let out = ok(
            move_path(&root.join("a.part"), &dst, "g6", MoveMode::Auto),
            "fs op",
        );
        assert_eq!(out, MoveOutcome::SrcAbsent);
        assert_eq!(ok(fs::read(&dst), "fs op"), b"committed");
    }

    #[test]
    fn foreign_destination_is_refused_with_source_intact() {
        let root = tmp_root("foreign");
        let src = root.join("a.part");
        write(&src, b"ours");
        let dst = root.join("b.part");
        write(&dst, b"foreign-different-length");
        let err = err_of(move_path(&src, &dst, "g7", MoveMode::Auto), "foreign dst");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(ok(fs::read(&src), "fs op"), b"ours");
        assert_eq!(ok(fs::read(&dst), "fs op"), b"foreign-different-length");
    }

    #[test]
    fn nested_destination_is_refused() {
        let root = tmp_root("nested");
        let src = root.join("tree");
        write(&src.join("f"), b"x");
        let err = err_of(
            move_path(&src, &src.join("inner"), "g8", MoveMode::Auto),
            "nested dst",
        );
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn mid_tree_failure_keeps_source_tree_whole() {
        // A foreign file mid-tree fails the walk; the already-copied
        // prefix must NOT have unlinked its sources (two-pass
        // discipline: the source stays complete until the whole tree
        // commits).
        let root = tmp_root("two-pass");
        let src = root.join("tree");
        write(&src.join("a").join("f1"), b"one-one");
        write(&src.join("b").join("f2"), b"two");
        let dst = root.join("moved");
        // Foreign occupant with a different length (sorted walk hits
        // a/ before b/).
        write(&dst.join("b").join("f2"), b"foreign-different");
        let err = err_of(
            move_path(&src, &dst, "g10", MoveMode::ForceCopy),
            "mid-tree",
        );
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        // Source tree complete.
        assert!(src.join("a").join("f1").is_file());
        assert!(src.join("b").join("f2").is_file());
        assert_eq!(
            fs::read(dst.join("a").join("f1")).unwrap_or_else(|e| panic!("{e}")),
            b"one-one"
        );
    }

    #[cfg(unix)]
    #[test]
    fn copy_preserves_permission_bits() {
        let root = tmp_root("perms");
        let src = root.join("p.bin");
        write(&src, b"payload");
        fs::set_permissions(&src, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("{e}"));
        let dst = root.join("q.bin");
        move_path(&src, &dst, "g11", MoveMode::ForceCopy).unwrap_or_else(|e| panic!("move: {e}"));
        let mode = fs::metadata(&dst)
            .unwrap_or_else(|e| panic!("{e}"))
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "exec bit must ride along");
    }

    #[test]
    fn occupied_destination_directory_converges_via_walk() {
        // Rename onto a non-empty destination fails ENOTEMPTY (not
        // EXDEV); the move must fall through to the per-file walk and
        // adopt the equal-length partial as a prior commit.
        let root = tmp_root("occupied");
        let src = root.join("tree");
        write(&src.join("f1"), b"one");
        write(&src.join("sub").join("f2"), b"two");
        let dst = root.join("moved");
        // Partial prior attempt: f1 already there (equal length), the
        // rest missing.
        write(&dst.join("f1"), b"one");
        let out =
            move_path(&src, &dst, "g12", MoveMode::Auto).unwrap_or_else(|e| panic!("move: {e}"));
        assert_eq!(out, MoveOutcome::Copied { bytes: 3 });
        assert_eq!(
            fs::read(dst.join("sub").join("f2")).unwrap_or_else(|e| panic!("{e}")),
            b"two"
        );
        assert!(!src.exists());
    }

    #[test]
    fn empty_source_tree_moves_as_skeleton() {
        let root = tmp_root("empty-tree");
        let src = root.join("name-dir");
        ok(fs::create_dir_all(src.join("empty-sub")), "fs op");
        let dst = root.join("moved-name");
        let out = ok(move_path(&src, &dst, "g9", MoveMode::ForceCopy), "fs op");
        assert_eq!(out, MoveOutcome::Copied { bytes: 0 });
        assert!(dst.join("empty-sub").is_dir());
        assert!(!src.exists());
    }
}
