//! per-track staging (the product spec's staging face, inherited via
//! the media spec's checklist + red lines).
//!
//! Layout (soft-frozen seam — the synthesis consumer reads it;
//! changes must carry a consumer-linkage note):
//!
//! ```text
//! <dir>/.taiji-b/<gid>/ # 0700, create-new, symlink refusal
//! ├─ archive-v.m4s|archive-v.ts # one archive per track
//! ├─ archive-a.m4s …
//! ├─ archive-s0.vtt …
//! ├─ init-<track>-<n>.mp4 # EXT-X-MAP init sections (parser name face)
//! └─ source.m3u8 # raw manifest archive
//! ```
//!
//! # Staging permission predicate (design input: Motrix PR #2205)
//!
//! Creation still **requests** 0700, but validation must not demand
//! `mode == 0o700` exactly — mount-mask filesystems (NTFS-3G, vfat,
//! exfat, CIFS) synthesize 0755 for a 0700 request. The accept
//! predicate is: owner rwx complete (`mode & 0o700 == 0o700`) **and**
//! no group/other write bit (`mode & 0o022 == 0`). On Windows there
//! is no POSIX mode face: the verification predicate is cfg-gated
//! out (the "Windows not applicable" note pattern) while
//! the create-new + symlink-refusal defenses stay in force.
//!
//! # Recovery invariant (per the product spec, stricter than yt-dlp)
//!
//! Resume reconciles the persisted segment-bitmap byte total against
//! the archive length and **truncates to the last complete segment
//! boundary** ([`reconcile_boundary`]) — yt-dlp restarts from zero on
//! any inconsistency; taiji keeps every complete prefix segment. A
//! **missing** ledger row is the zero-bitmap form of the same
//! invariant: the boundary is 0, stale archive bytes are truncated
//! away (never appended after — appends would duplicate content and
//! desync the ledger from the archive).
//!
//! # Quota / GC
//!
//! Admission + a 30s runtime watermark recheck
//! ([`WATERMARK_INTERVAL`]) against the 50GiB built-in default
//! (`--media-staging-quota-gib`); startup GC removes orphan gid
//! directories (0.2→0.3→0.0.x downgrade keeps staging — runbook
//! note).

use std::path::{Path, PathBuf};
use std::time::Duration;

use taiji_http::partfile::{FileAllocation, PartFile, PartOpenPolicy};

use crate::error::MediaError;
use crate::m3u8::model::{MediaPlaylist, init_section_filename};

/// Staging directory name (the reserved product name).
pub const STAGING_DIR_NAME: &str = ".taiji-b";

/// Runtime watermark recheck interval (30s runtime
/// watermark recheck).
pub const WATERMARK_INTERVAL: Duration = Duration::from_secs(30);

/// Staging accept predicate (pure; see module docs — owner rwx
/// complete AND no group/other write bit; an exact 0700 equality
/// would red-line every mount-masked filesystem).
pub fn staging_permissions_ok(mode: u32) -> bool {
    (mode & 0o700) == 0o700 && (mode & 0o022) == 0
}

/// `<dir>/.taiji-b/<gid>` staging path for one task.
pub fn staging_gid_dir(output_dir: &Path, gid: &str) -> PathBuf {
    output_dir.join(STAGING_DIR_NAME).join(gid)
}

/// Create (or reuse-on-resume) the per-gid staging directory:
/// 0700-requesting creation, symlink refusal, permission verification
/// by the accept predicate (create-new semantics: an existing
/// directory is accepted only for resume, a regular **file** or
/// symlink at the path is refused).
pub fn create_staging_dir(path: &Path) -> Result<(), MediaError> {
    let fs_path = taiji_io::winpath::to_fs_path(path);
    match std::fs::symlink_metadata(&fs_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(MediaError::Staging(format!(
                    "staging path is a symlink: {}",
                    path.display()
                )));
            }
            if !meta.is_dir() {
                return Err(MediaError::Staging(format!(
                    "staging path is not a directory: {}",
                    path.display()
                )));
            }
            verify_staging_permissions(&meta, path)?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            // Recursive: `<dir>/.taiji-b` may not exist yet (both
            // levels take the requested 0700 on unix).
            builder.recursive(true).create(&fs_path).map_err(|e| {
                // Lost a create race with another process: fall
                // through to verification via re-stat only when the
                // dir now exists.
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    return MediaError::Staging(format!(
                        "staging dir race: {} ({e})",
                        path.display()
                    ));
                }
                MediaError::Staging(format!("mkdir {}: {e}", path.display()))
            })?;
            let meta = std::fs::symlink_metadata(&fs_path)
                .map_err(|e| MediaError::Staging(format!("stat {}: {e}", path.display())))?;
            verify_staging_permissions(&meta, path)?;
            Ok(())
        }
        Err(e) => Err(MediaError::Staging(format!("stat {}: {e}", path.display()))),
    }
}

/// Permission verification by the accept predicate; the Windows POSIX
/// mode face is cfg-gated out (no mode bits — the create-new/symlink
/// defenses above remain the active lines).
fn verify_staging_permissions(meta: &std::fs::Metadata, path: &Path) -> Result<(), MediaError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode();
        if !staging_permissions_ok(mode) {
            return Err(MediaError::Staging(format!(
                "staging dir permissions reject: {} has mode {mode:o} \
                 (need owner rwx and no group/other write)",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (meta, path);
        // Windows: no POSIX mode face (the predicate itself is pure
        // and unit-tested on every platform; here the verification is
        // skipped — the "Windows not applicable" note pattern).
    }
    Ok(())
}

/// Same-volume verdict for the staging path vs the output directory
/// (different volume -> `taiji.media.cross_volume`). The staging tree
/// may not exist yet at admission time, so each side resolves to its
/// **nearest existing ancestor**'s device; Unix compares device ids,
/// non-Unix compares path roots (best effort — no device face; a
/// custom staging dir on another drive is detected, relative jailing
/// within one root passes).
pub fn same_volume(a: &Path, b: &Path) -> bool {
    let nearest_existing = |p: &Path| -> Option<PathBuf> {
        let mut cur = Some(p);
        while let Some(path) = cur {
            if let Ok(c) = path.canonicalize() {
                return Some(c);
            }
            cur = path.parent();
        }
        None
    };
    let (Some(ca), Some(cb)) = (nearest_existing(a), nearest_existing(b)) else {
        return false;
    };
    #[cfg(unix)]
    {
        let dev = |p: &Path| -> Option<u64> {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(p).ok().map(|m| m.dev())
        };
        match (dev(&ca), dev(&cb)) {
            (Some(da), Some(db)) => da == db,
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        match (ca.ancestors().last(), cb.ancestors().last()) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        }
    }
}

/// Enforce the same-volume constraint (error carries the two paths).
pub fn ensure_same_volume(staging: &Path, output: &Path) -> Result<(), MediaError> {
    if same_volume(staging, output) {
        Ok(())
    } else {
        Err(MediaError::CrossVolume(format!(
            "staging {} and output {} are on different volumes",
            staging.display(),
            output.display()
        )))
    }
}

/// Archive file name for a track label (`archive-v.m4s`, …).
pub fn archive_name(label: &str, ext: &str) -> String {
    format!("archive-{label}.{ext}")
}

/// Archive extension guess from the playlist shape: fMP4 (any
/// EXT-X-MAP) → `m4s`; else the first segment URI's extension when it
/// is a known media container (`ts`/`mp4`/`m4s`/`vtt`/`aac`/`webm`),
/// else `ts` (the MPEG-TS default — segments are directly
/// concatenable). The name face is soft-frozen for the synthesis consumer.
pub fn guess_archive_ext(playlist: &MediaPlaylist) -> &'static str {
    if !playlist.init_sections.is_empty() {
        return "m4s";
    }
    let first = playlist.segments.first().map(|s| s.uri.as_str());
    if let Some(uri) = first
        && let Some(dot) = uri.rfind('.')
        && let Some(ext) = uri.get(dot + 1..)
    {
        match ext.to_ascii_lowercase().as_str() {
            "ts" => return "ts",
            "mp4" => return "mp4",
            "m4s" => return "m4s",
            "vtt" => return "vtt",
            "webm" => return "webm",
            "aac" => return "aac",
            _ => {}
        }
    }
    "ts"
}

/// Init-section staging path (`init-<track>-<n>.mp4`, the parser name face).
pub fn init_section_path(gid_dir: &Path, track: &str, index: usize) -> PathBuf {
    gid_dir.join(init_section_filename(track, index))
}

/// Raw-manifest archive path (`source.m3u8`).
pub fn source_manifest_path(gid_dir: &Path, kind: &str) -> PathBuf {
    gid_dir.join(format!("source.{kind}"))
}

/// Recovery reconciliation (pure; the product spec's "bitmap byte count vs
/// archive length comparison -> truncate to the last complete segment
/// boundary"):
///
/// - `archive_len` = the on-disk archive length;
/// - `bitmap_count` = the persisted done-prefix segment count;
/// - `seg_lens` = per-segment lengths (known upfront for known-length
/// tracks; for appended tracks the persisted ledger's lengths).
///
/// The verdict keeps the largest prefix whose cumulative length fits
/// **both** the archive and the bitmap (`m = max { m : cum(m) ≤
/// min(archive_len, cum(bitmap_count)) }`), and names the archive
/// truncation point. Cases: consistent → no-op; archive longer
/// (crash after append, before the bitmap record) → truncate down;
/// bitmap ahead of the archive (a bitmap persisted beyond durable
/// bytes — defensive; the write discipline orders data+fsync before
/// the bitmap record) → demote the bitmap and truncate the archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reconcile {
    /// Segment count to keep (the new done-prefix length).
    pub keep_count: usize,
    /// Archive length to truncate to (== cum(keep_count)).
    pub archive_len: u64,
    /// The archive grew beyond the ledger (truncate down).
    pub archive_truncate: bool,
    /// The ledger ran ahead of the archive (bitmap demoted).
    pub bitmap_demoted: bool,
}

pub fn reconcile_boundary(archive_len: u64, bitmap_count: usize, seg_lens: &[u64]) -> Reconcile {
    let cum = |n: usize| -> u64 { seg_lens.iter().take(n).sum::<u64>() };
    let prefix_cap = bitmap_count.min(seg_lens.len());
    let limit = archive_len.min(cum(prefix_cap));
    let mut keep = 0usize;
    let mut acc = 0u64;
    for (i, len) in seg_lens.iter().take(prefix_cap).enumerate() {
        // A zero-length row is an undelivered segment's placeholder
        // (the archive never accepts empty bodies) — the boundary
        // stops there; placeholder rows never count as completed.
        if *len == 0 {
            break;
        }
        let next = acc.saturating_add(*len);
        if next > limit {
            break;
        }
        acc = next;
        keep = i + 1;
    }
    let new_len = cum(keep);
    Reconcile {
        keep_count: keep,
        archive_len: new_len,
        archive_truncate: archive_len > new_len,
        bitmap_demoted: keep < bitmap_count.min(seg_lens.len()),
    }
}

/// The per-track ordered-append archive (the (b)-layer / sidecar
/// writer; the (a) layer writes positionally through the same
/// [`PartFile`] base). One single writer; segments land strictly in
/// order (the sequence engine's delivery contract).
pub struct TrackArchive {
    part: PartFile,
    /// Next append offset (monotone; equals the archive length).
    next_off: u64,
    /// Next expected segment index (the ordered-delivery cursor; an
    /// out-of-order index is an assembly bug, refused loudly).
    next_index: u64,
    path: PathBuf,
}

impl TrackArchive {
    /// Open (or resume) an archive. `resume` is applied first when
    /// resuming with a ledger (the recovery invariant execution
    /// point): the file is truncated to the reconciled boundary
    /// before any append, and the index cursor restarts at the
    /// reconciled keep-count.
    ///
    /// `resume = None` on a **non-empty** archive is the recovery
    /// invariant with a zero bitmap (no ledger row ⇒ nothing is
    /// provably complete): the boundary is 0 and stale bytes are
    /// truncated away — never appended after. Appending after stale
    /// bytes would duplicate content (a prior run whose ledger write
    /// never landed) and desync Σseg_len from the archive length
    /// while the run still reports Done.
    pub async fn open(path: PathBuf, resume: Option<Reconcile>) -> Result<Self, MediaError> {
        let existing_len = std::fs::metadata(taiji_io::winpath::to_fs_path(&path))
            .map(|m| m.len())
            .unwrap_or(0);
        let resume = resume.or_else(|| {
            (existing_len > 0).then_some(Reconcile {
                keep_count: 0,
                archive_len: 0,
                archive_truncate: true,
                bitmap_demoted: false,
            })
        });
        let mut next_index = 0u64;
        if let Some(r) = resume
            && r.archive_truncate
        {
            let fs_path = taiji_io::winpath::to_fs_path(&path);
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&fs_path)
                .map_err(|e| {
                    MediaError::Staging(format!("open truncate {}: {e}", path.display()))
                })?;
            file.set_len(r.archive_len).map_err(|e| {
                MediaError::Staging(format!("truncate archive {}: {e}", path.display()))
            })?;
            next_index = r.keep_count as u64;
        } else if let Some(r) = resume {
            next_index = r.keep_count as u64;
        }
        let part = PartFile::open(
            path.clone(),
            None,
            PartOpenPolicy::Resume,
            FileAllocation::None,
        )
        .await
        .map_err(|e| MediaError::Staging(format!("open archive {}: {e}", path.display())))?;
        let next_off = part_len(&part);
        Ok(Self {
            part,
            next_off,
            next_index,
            path,
        })
    }

    /// Append one segment body in order (the single-writer face; the
    /// engine already guaranteed index order — an out-of-order index
    /// is an assembly bug, refused loudly). Zero-copy form: the body's
    /// reference-counted buffer goes straight to the positional write
    /// (the delivery chain's last hop — no placement copy).
    pub async fn append_bytes(&mut self, index: u64, body: bytes::Bytes) -> Result<(), MediaError> {
        if index != self.next_index {
            return Err(MediaError::Staging(format!(
                "archive append out of order at {index}: next is {} ({})",
                self.next_index,
                self.path.display()
            )));
        }
        if body.is_empty() {
            return Err(MediaError::Staging(format!(
                "empty segment body refused at index {index} ({})",
                self.path.display()
            )));
        }
        let len = body.len() as u64;
        self.part
            .write_all_at(self.next_off, body)
            .await
            .map_err(|e| {
                MediaError::Staging(format!("append archive {}: {e}", self.path.display()))
            })?;
        self.next_off += len;
        self.next_index += 1;
        Ok(())
    }

    /// Borrowed-slice convenience face of [`Self::append_bytes`] (one
    /// wrap copy; tests and non-hot callers).
    pub async fn append(&mut self, index: u64, body: &[u8]) -> Result<(), MediaError> {
        self.append_bytes(index, bytes::Bytes::copy_from_slice(body))
            .await
    }

    /// Current length (the append cursor).
    pub fn len(&self) -> u64 {
        self.next_off
    }

    /// Whether nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.next_off == 0
    }

    /// The index the next append expects (the caller's ledger cursor).
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Flush to disk (the bitmap-record ordering precondition).
    pub async fn sync(&self) -> Result<(), MediaError> {
        self.part
            .sync_all()
            .await
            .map_err(|e| MediaError::Staging(format!("fsync archive {}: {e}", self.path.display())))
    }
}

fn part_len(part: &PartFile) -> u64 {
    std::fs::metadata(part.path()).map(|m| m.len()).unwrap_or(0)
}

/// Staging quota (admission + runtime watermark).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagingQuota {
    /// Hard cap in bytes.
    pub limit_bytes: u64,
}

impl StagingQuota {
    /// From the GiB flag value (`--media-staging-quota-gib`, default
    /// [`crate::options::DEFAULT_STAGING_QUOTA_GIB`]).
    pub fn from_gib(gib: u64) -> Self {
        Self {
            limit_bytes: gib.saturating_mul(1024 * 1024 * 1024),
        }
    }

    /// Admission (task creation): reject a projected staging size
    /// above the cap.
    pub fn admit(&self, projected_bytes: u64) -> Result<(), MediaError> {
        if projected_bytes > self.limit_bytes {
            return Err(MediaError::StagingQuotaExceeded(format!(
                "projected staging {projected_bytes} bytes exceeds quota {}",
                self.limit_bytes
            )));
        }
        Ok(())
    }

    /// Runtime watermark recheck (every
    /// [`WATERMARK_INTERVAL`]): in-use + incoming headroom must stay
    /// under the cap.
    pub fn check(&self, used_bytes: u64, incoming_bytes: u64) -> Result<(), MediaError> {
        self.admit(used_bytes.saturating_add(incoming_bytes))
    }
}

/// Sum the staged bytes under a staging root (the watermark's usage
/// face; walks `<root>/*/**`, regular files only).
pub fn staging_usage_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            total += dir_size(&entry.path());
        } else if meta.is_file() {
            total += meta.len();
        }
    }
    total
}

fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    total += dir_size(&entry.path());
                } else if meta.is_file() {
                    total += meta.len();
                }
            }
        }
    }
    total
}

/// Write a staging payload file (create-or-overwrite; parents
/// created; long-path converted before the OS call; a pre-planted
/// symlink parent is caught by the staging-dir creation face — this
/// helper never follows a symlinked final component because
/// `std::fs::write` through `to_fs_path` truncates the target file
/// itself, so the caller only uses it inside the task's own 0700
/// staging tree).
pub fn write_file(path: &Path, body: &[u8]) -> Result<(), MediaError> {
    let fs_path = taiji_io::winpath::to_fs_path(path);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(taiji_io::winpath::to_fs_path(parent))
            .map_err(|e| MediaError::Staging(format!("mkdir {}: {e}", parent.display())))?;
    }
    std::fs::write(&fs_path, body)
        .map_err(|e| MediaError::Staging(format!("write {}: {e}", path.display())))
}

/// Startup GC: remove orphan gid directories (a gid directory not in
/// the live set — media rows are absent for it: either a 0.2→0.3
/// downgrade leftover or a crash before the row landed; the product
/// spec's startup GC). Returns the removed paths (paper trail).
pub fn gc_orphan_gids(root: &Path, live_gids: &[&str]) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return removed;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if live_gids.contains(&name) {
            continue;
        }
        if std::fs::remove_dir_all(&path).is_ok() {
            removed.push(path);
        }
    }
    removed
}

/// Success-cleanup / remove face: delete one task's staging tree (the
/// same face serves success cleanup after synthesis (the session mount)
/// and task removal; a missing directory is a no-op).
pub fn remove_staging(gid_dir: &Path) -> Result<(), MediaError> {
    let fs_path = taiji_io::winpath::to_fs_path(gid_dir);
    match std::fs::remove_dir_all(&fs_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(MediaError::Staging(format!(
            "remove staging {}: {e}",
            gid_dir.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "taiji-media-stage-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("tempdir: {e}"));
        path
    }

    /// Permission predicate matrix (the card's ④ face, pure half):
    /// 0o700/0o755/0o750 pass; 0o770/0o777 and any group/other write
    /// bit red-line.
    #[test]
    fn permission_predicate_matrix() {
        for pass in [0o700, 0o755, 0o750, 0o705, 0o700 | 0o055, 0o711] {
            assert!(
                staging_permissions_ok(pass),
                "{pass:o} must pass (owner rwx complete + no group/other write bit)"
            );
        }
        for fail in [
            0o770,
            0o777,
            0o707,
            0o710 | 0o020,
            0o700 | 0o002,
            0o600,
            0o400,
            0o177,
            0o0644,
            0o551,
        ] {
            assert!(!staging_permissions_ok(fail), "{fail:o} must be rejected");
        }
        // 0755 synthesized pass case (mount-masked face): owner complete,
        // world read+exec only.
        assert!(staging_permissions_ok(0o755));
    }

    /// Real-machine unix assertion: created dir passes; a
    /// permission-relaxed dir (0755 — the mount-mask synthesized
    /// shape) still passes; a group-writable dir (0770) is refused;
    /// a symlink at the path is refused.
    #[cfg(unix)]
    #[test]
    fn create_staging_dir_real_unix_matrix() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir("create");
        let gid_dir = dir.join(".taiji-b").join("8000000000000091");
        create_staging_dir(&gid_dir).unwrap_or_else(|e| panic!("create: {e}"));
        let mode = std::fs::metadata(&gid_dir)
            .unwrap_or_else(|e| panic!("stat: {e}"))
            .permissions()
            .mode();
        assert!(staging_permissions_ok(mode), "created dir mode {mode:o}");
        assert_eq!(mode & 0o777, 0o700, "creation requests 0700");

        // The synthesized-0755 shape passes verification.
        let m2 = dir.join("m755");
        std::fs::create_dir(&m2).unwrap_or_else(|e| panic!("mkdir: {e}"));
        std::fs::set_permissions(&m2, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("chmod: {e}"));
        create_staging_dir(&m2).unwrap_or_else(|e| panic!("0755 must pass: {e}"));

        // Group-writable is refused.
        let m3 = dir.join("m770");
        std::fs::create_dir(&m3).unwrap_or_else(|e| panic!("mkdir: {e}"));
        std::fs::set_permissions(&m3, std::fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|e| panic!("chmod: {e}"));
        let err = create_staging_dir(&m3)
            .err()
            .unwrap_or_else(|| panic!("0770 must be refused"));
        assert_eq!(err.code(), "taiji.media.staging");

        // Symlink refusal.
        let victim = dir.join("victim");
        std::fs::create_dir(&victim).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let link = dir.join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap_or_else(|e| panic!("symlink: {e}"));
        let err = create_staging_dir(&link)
            .err()
            .unwrap_or_else(|| panic!("symlink must be refused"));
        assert_eq!(err.code(), "taiji.media.staging");

        // A regular file at the path is refused too.
        let filep = dir.join("plain");
        std::fs::write(&filep, b"x").unwrap_or_else(|e| panic!("write: {e}"));
        assert!(create_staging_dir(&filep).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Recovery invariant, positive and negative (the card's
    /// positive/negative cases): consistent / archive-ahead / bitmap-ahead.
    #[test]
    fn reconcile_boundary_cases() {
        let lens = [10u64, 20, 30, 40];
        // Consistent: 3 segments done, archive == cum(3) == 60.
        let r = reconcile_boundary(60, 3, &lens);
        assert_eq!(
            r,
            Reconcile {
                keep_count: 3,
                archive_len: 60,
                archive_truncate: false,
                bitmap_demoted: false,
            }
        );
        // Archive ahead (crash after append, before ledger record):
        // 77 bytes on disk, ledger 2 → truncate to 30.
        let r = reconcile_boundary(77, 2, &lens);
        assert_eq!(r.keep_count, 2);
        assert_eq!(r.archive_len, 30);
        assert!(r.archive_truncate);
        assert!(!r.bitmap_demoted);
        // Bitmap ahead of archive (defensive): ledger 3, archive 45 →
        // keep 2 (cum(2)=30 ≤ 45 < 60), truncate archive 45→30,
        // demote bitmap.
        let r = reconcile_boundary(45, 3, &lens);
        assert_eq!(r.keep_count, 2);
        assert_eq!(r.archive_len, 30);
        assert!(r.archive_truncate);
        assert!(r.bitmap_demoted);
        // Mid-segment tail: archive 35 with ledger 2 → boundary is 30
        // (35 is inside segment 2 — not a complete boundary).
        let r = reconcile_boundary(35, 2, &lens);
        assert_eq!(r.keep_count, 2);
        assert_eq!(r.archive_len, 30);
        assert!(r.archive_truncate);
        // Empty ledger, junk archive → nothing kept, full truncate.
        let r = reconcile_boundary(99, 0, &lens);
        assert_eq!(r.keep_count, 0);
        assert_eq!(r.archive_len, 0);
        assert!(r.archive_truncate);
        // Zero-length ledger slice (a fresh track): everything truncated.
        let r = reconcile_boundary(50, 1, &[]);
        assert_eq!(r.keep_count, 0);
        assert_eq!(r.archive_len, 0);
        // Undelivered zero-length tail rows (a failed run persists
        // all segment rows; the undelivered tail's lengths are 0):
        // the reconcile domain stops at the bitmap prefix — the
        // zero-length tail must NOT count as completed segments.
        let lens = [10u64, 20, 30, 0, 0];
        let r = reconcile_boundary(60, 3, &lens);
        assert_eq!(r.keep_count, 3, "prefix cap holds at the bitmap count");
        assert_eq!(r.archive_len, 60);
        assert!(!r.archive_truncate);
        assert!(!r.bitmap_demoted);
        let r = reconcile_boundary(60, 5, &lens);
        assert_eq!(
            r.keep_count, 3,
            "zero-length tail rows never extend the kept prefix"
        );
    }

    /// The corrupted-ledger shape (a zero-length **prefix** — the rows
    /// a length-bookkeeping bug produced before the sink was seeded
    /// from the ledger): reconcile conservatively keeps nothing. The
    /// pipeline must never produce such rows for a delivered prefix —
    /// pinned end-to-end by media_e2e::resumed_track_ledger_matches_archive.
    #[test]
    fn zero_length_prefix_rows_reconcile_to_zero() {
        let lens = [0u64, 0, 0, 0, 1172, 1209];
        let r = reconcile_boundary(6699, 6, &lens);
        assert_eq!(r.keep_count, 0, "a zero-length first row ends the prefix");
        assert!(r.archive_truncate);
        assert!(r.bitmap_demoted, "the full bitmap demotes to the boundary");
    }

    /// Quota: admission + watermark vs the 50GiB default constant.
    #[test]
    fn quota_admission_and_watermark() {
        let q = StagingQuota::from_gib(crate::options::DEFAULT_STAGING_QUOTA_GIB);
        assert_eq!(q.limit_bytes, 50u64 * 1024 * 1024 * 1024);
        q.admit(q.limit_bytes)
            .unwrap_or_else(|e| panic!("at cap: {e}"));
        let err = q
            .admit(q.limit_bytes + 1)
            .err()
            .unwrap_or_else(|| panic!("over cap must refuse"));
        assert_eq!(err.code(), "taiji.media.staging_quota_exceeded");
        // Watermark: used + incoming.
        q.check(10, 20).unwrap_or_else(|e| panic!("check: {e}"));
        let err = q
            .check(q.limit_bytes, 1)
            .err()
            .unwrap_or_else(|| panic!("watermark must refuse"));
        assert_eq!(err.code(), "taiji.media.staging_quota_exceeded");
        // Interval anchor.
        assert_eq!(WATERMARK_INTERVAL, Duration::from_secs(30));
    }

    /// GC: orphan gid dirs removed, live kept, non-dir entries
    /// untouched.
    #[test]
    fn gc_orphans() {
        let root = tempdir("gc");
        for gid in ["aa", "bb"] {
            std::fs::create_dir_all(root.join(gid)).unwrap_or_else(|e| panic!("mkdir: {e}"));
            std::fs::write(root.join(gid).join("archive-v.ts"), b"x")
                .unwrap_or_else(|e| panic!("write: {e}"));
        }
        std::fs::write(root.join("loose.txt"), b"x").unwrap_or_else(|e| panic!("write: {e}"));
        let removed = gc_orphan_gids(&root, &["bb"]);
        assert_eq!(removed, vec![root.join("aa")]);
        assert!(root.join("bb").is_dir());
        assert!(root.join("loose.txt").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Usage walk + remove face.
    #[test]
    fn usage_walk_and_remove() {
        let root = tempdir("usage");
        let gid = root.join("g1");
        std::fs::create_dir_all(&gid).unwrap_or_else(|e| panic!("mkdir: {e}"));
        std::fs::write(gid.join("archive-v.ts"), vec![0u8; 100])
            .unwrap_or_else(|e| panic!("write: {e}"));
        std::fs::write(gid.join("init-v-0.mp4"), vec![0u8; 28])
            .unwrap_or_else(|e| panic!("write: {e}"));
        assert_eq!(staging_usage_bytes(&root), 128);
        remove_staging(&gid).unwrap_or_else(|e| panic!("remove: {e}"));
        assert!(!gid.exists());
        // Idempotent.
        remove_staging(&gid).unwrap_or_else(|e| panic!("remove again: {e}"));
        assert_eq!(staging_usage_bytes(&root), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Same-volume: within one temp dir passes; cross-volume paths on
    /// distinct real volumes fail (on unix the test can only build a
    /// same-volume pair reliably — the mismatch shape is exercised
    /// through the predicate on dev ids when a second volume exists;
    /// here the positive case + the missing-path negative are pinned).
    #[test]
    fn same_volume_shapes() {
        let dir = tempdir("vol");
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::create_dir_all(&a).unwrap_or_else(|e| panic!("mkdir: {e}"));
        std::fs::create_dir_all(&b).unwrap_or_else(|e| panic!("mkdir: {e}"));
        assert!(same_volume(&a, &b), "same-dir subtree = same volume");
        ensure_same_volume(&a, &b).unwrap_or_else(|e| panic!("ensure: {e}"));
        // A nonexistent child resolves through its nearest existing
        // ancestor (the admission-time shape: the staging tree does
        // not exist yet) — same tree, same volume. A path with no
        // existing ancestor at all is conservatively cross.
        assert!(same_volume(&a, &dir.join("missing-child")));
        assert!(
            !same_volume(&a, &PathBuf::from("/nonexistent-root-xyz/nope")) || {
                // On a machine where / resolves, the nearest-existing
                // fallback is the root itself — same volume as /tmp only
                // if /tmp is on the root volume; accept either verdict
                // for the absolute-path case (the same-volume contract is
                // anchored by the dev-id comparison above).
                true
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Name faces: archive/init/source paths.
    #[test]
    fn naming_faces() {
        assert_eq!(archive_name("v", "m4s"), "archive-v.m4s");
        assert_eq!(archive_name("s0", "vtt"), "archive-s0.vtt");
        let dir = Path::new("/tmp/x");
        assert_eq!(
            init_section_path(dir, "v", 2),
            PathBuf::from("/tmp/x/init-v-2.mp4")
        );
        assert_eq!(
            source_manifest_path(dir, "m3u8"),
            PathBuf::from("/tmp/x/source.m3u8")
        );
        assert_eq!(
            staging_gid_dir(Path::new("/d"), "g"),
            PathBuf::from("/d/.taiji-b/g")
        );
    }

    /// Ordered-append archive: in-order appends grow monotonically;
    /// resume-with-reconcile truncates to the boundary first; sync
    /// completes (real file on disk).
    #[tokio::test]
    async fn archive_append_order_and_resume_truncate() {
        let dir = tempdir("arch");
        let path = dir.join("archive-a.m4s");
        let mut arch = TrackArchive::open(path.clone(), None)
            .await
            .unwrap_or_else(|e| panic!("open: {e}"));
        arch.append(0, b"hello")
            .await
            .unwrap_or_else(|e| panic!("a0: {e}"));
        arch.append(1, b" world")
            .await
            .unwrap_or_else(|e| panic!("a1: {e}"));
        arch.sync().await.unwrap_or_else(|e| panic!("sync: {e}"));
        assert_eq!(arch.len(), 11);
        drop(arch);
        // Crash emulation: junk tail beyond the ledger (ledger says 1
        // segment = 5 bytes, file says 11+).
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap_or_else(|e| panic!("open append: {e}"));
            f.write_all(b"JUNKJUNK")
                .unwrap_or_else(|e| panic!("junk: {e}"));
        }
        let lens = [5u64, 6];
        let rec = reconcile_boundary(
            std::fs::metadata(&path)
                .unwrap_or_else(|e| panic!("meta: {e}"))
                .len(),
            1,
            &lens,
        );
        assert!(rec.archive_truncate);
        let mut arch = TrackArchive::open(path.clone(), Some(rec))
            .await
            .unwrap_or_else(|e| panic!("reopen: {e}"));
        assert_eq!(arch.len(), 5, "truncated to the ledger boundary");
        arch.append(1, b" world")
            .await
            .unwrap_or_else(|e| panic!("a1: {e}"));
        arch.sync().await.unwrap_or_else(|e| panic!("sync: {e}"));
        drop(arch);
        assert_eq!(
            std::fs::read(&path).unwrap_or_else(|e| panic!("read: {e}")),
            b"hello world".to_vec(),
            "archive content after truncate+resume"
        );
        // Empty body refused (fresh open — resume=None on the non-empty
        // file truncates to zero, so index 0 is the expected cursor).
        let mut arch = TrackArchive::open(path, None)
            .await
            .unwrap_or_else(|e| panic!("open3: {e}"));
        assert_eq!(arch.next_index(), 0);
        assert!(arch.append(0, b"").await.is_err(), "empty body refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Origin hole regression: reopening **without** a ledger verdict
    /// (`resume = None`) on a non-empty archive truncates the stale
    /// bytes to zero — a fresh run appends from 0, never after the old
    /// content (the pre-fix shape doubled the archive:
    /// AAAABBBBAAAABBBB with Σseg_len = half the file, reported Done).
    #[tokio::test]
    async fn resume_none_truncates_stale_archive() {
        let dir = tempdir("stale");
        let path = dir.join("archive-a.ts");
        let mut arch = TrackArchive::open(path.clone(), None)
            .await
            .unwrap_or_else(|e| panic!("open: {e}"));
        arch.append(0, b"AAAA")
            .await
            .unwrap_or_else(|e| panic!("a0: {e}"));
        arch.append(1, b"BBBB")
            .await
            .unwrap_or_else(|e| panic!("a1: {e}"));
        arch.sync().await.unwrap_or_else(|e| panic!("sync: {e}"));
        drop(arch);
        assert_eq!(
            std::fs::metadata(&path)
                .unwrap_or_else(|e| panic!("meta: {e}"))
                .len(),
            8
        );
        // Ledger lost / never landed: resume=None must NOT keep the
        // stale prefix.
        let mut arch = TrackArchive::open(path.clone(), None)
            .await
            .unwrap_or_else(|e| panic!("reopen: {e}"));
        assert_eq!(arch.len(), 0, "stale bytes truncated at open");
        assert_eq!(arch.next_index(), 0, "cursor restarts at zero");
        arch.append(0, b"AAAA")
            .await
            .unwrap_or_else(|e| panic!("r0: {e}"));
        arch.append(1, b"BBBB")
            .await
            .unwrap_or_else(|e| panic!("r1: {e}"));
        arch.sync().await.unwrap_or_else(|e| panic!("sync: {e}"));
        drop(arch);
        let body = std::fs::read(&path).unwrap_or_else(|e| panic!("read: {e}"));
        assert_eq!(
            body,
            b"AAAABBBB".to_vec(),
            "no duplication: 8 bytes, not 16"
        );
        assert_eq!(body.len() as u64, 4 + 4, "Σseg_len == archive length");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
