//! The torrent-creation face: explicit disk paths -> [`taiji_bt::creator`]
//! generation -> the .torrent written to disk.
//!
//! This module is the wiring layer shared by the RPC
//! `taiji.createTorrent` and the CLI `create-torrent` (both entries take
//! the same parameters; the dependency direction allows cli -> core and
//! rpc -> core; creator.rs is untouched — a missing library API is
//! reported explicitly, never patched in the library). Input rules,
//! default-value freedoms, timeout and resource gates: Upstream anchor
//! mapping: docs/design/core.md.
//!
//! Hard invariants: stat/read/hash/write all run inside spawn_blocking
//! with a 600s overall response bound (timeout = an explicit Err, the
//! caller never hangs); the four input gates (pseudo-filesystem
//! rejection, the process concurrency cap, timeout does not release the
//! permit, the total-bytes budget) close before any hashing; no implicit
//! directory recursion and no implicit output-directory creation.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::spawn_blocking;

/// The target swarm form (v1-only / v2-only / hybrid). Re-exported for
/// the rpc/cli naming (rpc cannot depend on bt directly — forwarded
/// through the core facade).
pub use taiji_bt::creator::TorrentForm;
use taiji_bt::creator::{CreateFile, CreateRequest, CreatedTorrent};

/// Default piece length: 16KiB (the BEP52 floor; libtorrent's
/// `create_torrent.cpp` automatic tiering floor is the same value — see
/// the freedoms note in docs/design/core.md).
pub const DEFAULT_PIECE_LENGTH: u32 = 16 * 1024;

/// The upper bound of the synchronous contract: 600s. At hashing
/// throughputs of hundreds of MB/s this budget covers hundred-GB inputs;
/// timeout = [`CreateTorrentError::Timeout`] (the caller fails promptly,
/// never hangs).
const CREATE_TORRENT_TIMEOUT: Duration = Duration::from_secs(600);

/// Process-wide creation concurrency cap: 2. Rationale: the hash
/// pipeline is sequential reads plus CPU-bound v1/v2 double hashing; two
/// concurrent runs saturate a single client disk's sequential throughput,
/// and more concurrency only raises tail latency and squeezes seeding IO
/// (the main spawn_blocking pool consumer) — the gate targets real
/// resources (disk + CPU), it is not an arbitrary conservative number.
/// Over the cap does not queue forever: if no permit arrives within
/// [`CREATE_QUEUE_WAIT`] the result is an explicit
/// [`CreateTorrentError::Busy`].
const MAX_CONCURRENT_CREATE: usize = 2;

/// Concurrency-gate queue window: 5s. The trade-off ("queue or reject
/// explicitly"; this chooses bounded queueing then rejecting):
/// millisecond jitter and natural multicall batch queueing (batch size
/// capped by the rpc layer's `MAX_BATCH_ITEMS = 1000`) should not
/// hard-fail; still saturated after 5s = an explicit Busy (fail fast).
/// Magnitude: small creations finish in milliseconds to seconds (the
/// window leaves orders of magnitude of headroom), the worst wait is
/// clamped within 1% of [`CREATE_TORRENT_TIMEOUT`], and waiters hold no
/// blocking-pool/hash resources (pure async waiting; the pool and memory
/// are not amplified by queueing).
const CREATE_QUEUE_WAIT: Duration = Duration::from_secs(5);

/// Permit-parking grace for abandoned-but-running tasks: 600s (=
/// [`CREATE_TORRENT_TIMEOUT`]). Rationale: the timeout cancels only the
/// response while the spawn_blocking hash continues; for an abandoned
/// task that already passed the [`MAX_INPUT_TOTAL_BYTES`] budget gate,
/// its remaining hashing converges within the same budget magnitude
/// under the same throughput assumption, so the grace equals it
/// (stricter rather than looser — within the grace new calls are
/// refused, never wrongly admitted). When the grace expires the permit
/// returns naturally.
const ABANDONED_PERMIT_GRACE: Duration = CREATE_TORRENT_TIMEOUT;

/// Total input byte budget: 64GiB. Rationale: (1) a function of the
/// response budget — finishing within [`CREATE_TORRENT_TIMEOUT`] (600s)
/// needs >=109MiB/s of aggregate read+hash throughput (hybrid = SHA-1 +
/// SHA-256 over one read pass; SSDs reach hundreds of MB/s; anything
/// slower fails explicitly here, better than timing out after 600s — the
/// timeout cannot cancel the underlying hashing, so failure must happen
/// up front); (2) disk headroom — covers the common creation materials
/// (distribution ISOs, Blu-ray images, up to a few dozen GiB). No
/// separate per-file cap: each file's measured stat length counts into
/// the total, so this budget is the per-file upper bound too (no second
/// constant).
const MAX_INPUT_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// The on-disk shape of the creation output (the two states behind the
/// RPC `outputDir` / CLI `-o` faces).
#[derive(Debug, Clone)]
pub enum CreateOutput {
    /// Directory form: write `<derived name>.torrent` (see
    /// [`derive_layout`]; the RPC `outputDir` parameter — aria2 style).
    Dir(PathBuf),
    /// File form: an explicit output path (the CLI `create-torrent -o`
    /// face).
    File(PathBuf),
}

/// Creation parameters (shared by RPC/CLI; field semantics in
/// docs/design/core.md and the per-field notes).
#[derive(Debug, Clone)]
pub struct CreateTorrentParams {
    /// Explicit input file paths (disk sources; >=1, no recursive scan).
    pub files: Vec<PathBuf>,
    /// The output shape.
    pub output: CreateOutput,
    /// Piece length (bytes; a power of two and >=16KiB — the creator
    /// validates).
    pub piece_length: u32,
    /// The target form (v1|v2|hybrid).
    pub form: TorrentForm,
    /// A BEP27 private torrent (`private: 1` inside info).
    pub private: bool,
    /// The top-level `comment`.
    pub comment: Option<String>,
    /// The announce URL list (1 = top-level announce only; >=2 = announce +
    /// announce-list with one tier each; empty = neither written).
    pub announce: Vec<String>,
    /// The top-level `creation date` (unix seconds; None = not written —
    /// see the default-omission freedom in docs/design/core.md).
    pub creation_date: Option<i64>,
}

/// The creation receipt (after writing; infohashes carried per form —
/// v1-only has no v2 identity and v2-only no v1 identity (BEP52
/// transport semantics), never over-claimed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedTorrentInfo {
    /// The output path (a successful write = the file exists).
    pub output: PathBuf,
    /// The derived torrent name (= info.name).
    pub name: String,
    /// The actual form (= the requested form).
    pub form: TorrentForm,
    /// Piece length (bytes).
    pub piece_length: u32,
    /// The sum of all input file bytes (excluding pads).
    pub total_length: u64,
    /// The v1 infohash (raw 20B SHA-1); Some for v1-only/hybrid.
    pub info_hash_v1: Option<[u8; 20]>,
    /// The v2 infohash (raw 32B SHA-256); Some for v2-only/hybrid.
    pub info_hash_v2: Option<[u8; 32]>,
}

impl CreatedTorrentInfo {
    /// The wire-face form name ("v1"|"v2"|"hybrid"). TorrentForm is a
    /// foreign bt type and cannot get an inherent impl in core (E0116) —
    /// the rendered value is funneled through the receipt struct so the
    /// rpc face never names bt types (dependency direction).
    pub fn format_name(&self) -> &'static str {
        form_name(self.form)
    }
}

/// Form -> wire-face name (the CLI renders the same; one source of
/// truth).
pub fn form_name(form: TorrentForm) -> &'static str {
    match form {
        TorrentForm::V1Only => "v1",
        TorrentForm::V2Only => "v2",
        TorrentForm::Hybrid => "hybrid",
    }
}

#[derive(Debug, Error)]
pub enum CreateTorrentError {
    #[error("file list is empty")]
    EmptyFileList,
    #[error("input file {path:?}: {source}")]
    InputStat {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("input {path:?} is not a regular file")]
    NotAFile { path: PathBuf },
    #[error("input path {path:?} is not valid UTF-8")]
    InputPathUtf8 { path: PathBuf },
    #[error(
        "inputs share no common parent directory: cannot derive torrent name \
         (pass files under one directory)"
    )]
    NoCommonParent,
    #[error(
        "derived torrent-relative path of {path:?} is empty (input is a prefix of another input)"
    )]
    EmptyRelativePath { path: PathBuf },
    #[error("torrent creation failed: {0}")]
    Creator(#[from] taiji_bt::creator::CreatorError),
    #[error("output directory {dir:?} does not exist")]
    OutputDirMissing { dir: PathBuf },
    #[error("output {path:?}: {source}")]
    OutputWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "torrent creation exceeded the {secs}s budget \
         (hashing large inputs is unbounded work; shrink the input)"
    )]
    Timeout { secs: u64 },
    #[error("blocking task panicked or was cancelled")]
    TaskJoin,
    #[error(
        "createTorrent is at its process concurrency limit ({limit}); \
         retry after in-flight creations finish"
    )]
    Busy { limit: usize },
    #[error(
        "input total size {total} bytes exceeds the {limit}-byte budget \
         (hashing is unbounded work; shrink the input)"
    )]
    InputTooLarge { total: u64, limit: u64 },
    #[error(
        "input path {path:?} resolves into a pseudo-filesystem \
         (/proc, /dev, /sys); kernel/virtual files cannot be hashed"
    )]
    PseudoFsPath { path: PathBuf },
}

/// The stat probe result (collected inside spawn_blocking).
#[derive(Debug, Clone)]
struct ProbedFile {
    source: PathBuf,
    length: u64,
}

/// The derived artifact: the torrent name + a (relative path, source
/// path, length) table (sorted by relative-path components byte-wise =
/// the v1 layout order the creator requires).
#[derive(Debug)]
struct DerivedInput {
    pub name: String,
    pub files: Vec<(PathBuf, PathBuf, u64)>,
}

/// Whether the total input length exceeds the budget (a pure function;
/// the summing side uses saturating addition — proof against overflow
/// from huge stat values, and a saturated value necessarily trips the
/// gate).
fn over_budget(total: u64) -> bool {
    total > MAX_INPUT_TOTAL_BYTES
}

/// Pseudo-filesystem source rejection table: an absolute path under
/// /proc, /dev or /sys is refused. Rationale: /proc and /sys are Linux
/// kernel pseudo-filesystem mount points (entries report
/// `is_file() == true` with huge stat sizes — e.g. /proc/kcore; hashing
/// one is a meaningless multi-GB-RSS exercise); /dev hosts device files.
/// macOS dev machines have no /proc but do have /dev, so all three mount
/// points are refused uniformly to avoid platform divergence (neither
/// platform has a legitimate regular-file creation source under /dev).
/// Component-level matching rather than a byte prefix: `/provoke` and
/// the relative `proc/x` (an ordinary directory under the caller's cwd)
/// are not hit. A pure path check (zero IO): called at the async entry
/// before any stat (pseudo files can stat to huge sizes, so rejection
/// must precede probing).
fn is_pseudo_fs_source(path: &Path) -> bool {
    let mut comps = path.components();
    if !matches!(comps.next(), Some(std::path::Component::RootDir)) {
        return false;
    }
    comps
        .next()
        .is_some_and(|c| matches!(c.as_os_str().to_str(), Some("proc" | "dev" | "sys")))
}

/// stat every input (blocking — call only from spawn_blocking/sync
/// contexts).
fn probe_files(paths: &[PathBuf]) -> Result<Vec<ProbedFile>, CreateTorrentError> {
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        // stat/canonicalize OS calls go through the winpath conversion (an
        // identity borrow off Windows; error faces keep the original
        // path).
        let meta = std::fs::metadata(taiji_io::winpath::to_fs_path(p)).map_err(|source| {
            CreateTorrentError::InputStat {
                path: p.clone(),
                source,
            }
        })?;
        // Non-regular (directory/device/FIFO/socket) = an explicit Err
        // (the existing gate; device nodes themselves are intercepted
        // here — the pseudo-fs table only covers the /dev mount-point
        // prefix).
        if !meta.is_file() {
            return Err(CreateTorrentError::NotAFile { path: p.clone() });
        }
        // Pseudo-filesystem alias check: `metadata()` follows symlinks,
        // so a clean original prefix says nothing about the target
        // (tmp/link -> /proc/kcore is exactly the follow face). The
        // canonicalized target goes through the same rejection table; on
        // failure (dangling / permission race) no new error face is added
        // — the original path already passed the table and the target
        // check is best effort.
        if let Ok(resolved) = std::fs::canonicalize(taiji_io::winpath::to_fs_path(p)) {
            if is_pseudo_fs_source(&resolved) {
                return Err(CreateTorrentError::PseudoFsPath { path: p.clone() });
            }
        }
        out.push(ProbedFile {
            source: p.clone(),
            length: meta.len(),
        });
    }
    Ok(out)
}

/// Path -> UTF-8 component list (non-UTF-8 = an explicit Err; the
/// creator's write face only accepts UTF-8). The root component (`/`) is
/// excluded — otherwise any two absolute paths share at least the root
/// as a common prefix and the derived name degenerates to "/" (the root
/// is not a meaningful directory name; NoCommonParent therefore only
/// considers real directory levels).
fn utf8_components(path: &Path) -> Result<Vec<String>, CreateTorrentError> {
    let mut out = Vec::new();
    for comp in path.components() {
        if matches!(comp, std::path::Component::RootDir) {
            continue;
        }
        let s = comp
            .as_os_str()
            .to_str()
            .ok_or_else(|| CreateTorrentError::InputPathUtf8 {
                path: path.to_path_buf(),
            })?;
        out.push(s.to_string());
    }
    Ok(out)
}

/// Derive the torrent name + in-torrent relative paths (a pure function;
/// the rules in docs/design/core.md, "input rules").
///
/// One algorithm: the longest common component prefix length `cp` (a
/// single file = full length - 1, i.e. strip the file name; multiple
/// files = the common prefix of every full component list) -> relative
/// path = `comps[cp..]`; `name` = a single file takes `comps[cp]` (the
/// file name), multiple files take `comps[cp-1]` (the common directory
/// name). `cp == 0` (no common directory) = an explicit Err; an empty
/// relative path (this input is a prefix of another input, file and
/// directory at once) = an explicit Err (the creator's PathConflict
/// judges the same way).
fn derive_layout(probed: &[ProbedFile]) -> Result<DerivedInput, CreateTorrentError> {
    let full: Vec<(PathBuf, Vec<String>)> = probed
        .iter()
        .map(|f| Ok((f.source.clone(), utf8_components(&f.source)?)))
        .collect::<Result<Vec<_>, CreateTorrentError>>()?;

    let cp = if full.len() == 1 {
        full[0].1.len().saturating_sub(1)
    } else {
        let min_len = full.iter().map(|(_, c)| c.len()).min().unwrap_or(0);
        let mut cp = 0usize;
        for i in 0..min_len {
            let head = &full[0].1[i];
            if full[1..].iter().any(|(_, c)| c.get(i) != Some(head)) {
                break;
            }
            cp = i + 1;
        }
        cp
    };
    if cp == 0 {
        return Err(CreateTorrentError::NoCommonParent);
    }

    let name = if full.len() == 1 {
        full[0]
            .1
            .last()
            .ok_or_else(|| CreateTorrentError::EmptyRelativePath {
                path: full[0].0.clone(),
            })?
            .clone()
    } else {
        full[0].1[cp - 1].clone()
    };

    let mut files: Vec<(PathBuf, PathBuf, u64)> = Vec::with_capacity(full.len());
    for ((source, comps), probed) in full.iter().zip(probed) {
        if comps.len() <= cp {
            return Err(CreateTorrentError::EmptyRelativePath {
                path: source.clone(),
            });
        }
        let rel: PathBuf = comps[cp..].iter().collect();
        files.push((rel, source.clone(), probed.length));
    }
    // The v1 layout order = the lexicographic order of relative-path
    // components (BEP3 canonical; the creator inserts pads).
    files.sort_by(|a, b| rel_sort_key(&a.0).cmp(&rel_sort_key(&b.0)));
    Ok(DerivedInput { name, files })
}

/// Sort key: the relative path's component list (component-wise
/// lexicographic = the bencode path byte order).
fn rel_sort_key(rel: &Path) -> Vec<&str> {
    rel.components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect()
}

/// Announce list -> (announce, announce-list): empty = neither written;
/// 1 = the top-level announce only; >=2 = announce (the first) + one
/// independent tier per entry (the BEP12 shape). Empty-string entries
/// are dropped.
fn announce_fields(list: &[String]) -> (Option<String>, Option<Vec<Vec<String>>>) {
    let urls: Vec<String> = list.iter().filter(|u| !u.is_empty()).cloned().collect();
    match urls.as_slice() {
        [] => (None, None),
        [one] => (Some(one.clone()), None),
        _ => (
            Some(urls[0].clone()),
            Some(urls.iter().map(|u| vec![u.clone()]).collect()),
        ),
    }
}

/// Assemble the creator request (the derived result + passthroughs; attr
/// always default — the freedoms note).
fn build_request(derived: &DerivedInput, params: &CreateTorrentParams) -> CreateRequest {
    let (announce, announce_list) = announce_fields(&params.announce);
    CreateRequest {
        name: derived.name.clone(),
        files: derived
            .files
            .iter()
            .map(|(rel, source, length)| CreateFile {
                path: rel.clone(),
                source: source.clone(),
                length: *length,
                attr: taiji_bt::filetree::FileAttr::default(),
            })
            .collect(),
        piece_length: params.piece_length,
        form: params.form,
        private: params.private,
        announce,
        announce_list,
        comment: params.comment.clone(),
        creation_date: params.creation_date,
    }
}

/// Write to disk (blocking — call only from spawn_blocking/sync
/// contexts). Directory form validates existence (no implicit directory
/// creation — the "output unwritable" error face stays explicit); an
/// existing same-name output is overwritten.
fn write_output(
    output: &CreateOutput,
    name: &str,
    bytes: &[u8],
) -> Result<PathBuf, CreateTorrentError> {
    let target = match output {
        CreateOutput::Dir(dir) => {
            // The directory existence probe and the write both go through
            // the winpath conversion.
            if !taiji_io::winpath::to_fs_path(dir).is_dir() {
                return Err(CreateTorrentError::OutputDirMissing { dir: dir.clone() });
            }
            dir.join(format!("{name}.torrent"))
        }
        CreateOutput::File(path) => path.clone(),
    };
    std::fs::write(taiji_io::winpath::to_fs_path(&target), bytes).map_err(|source| {
        CreateTorrentError::OutputWrite {
            path: target.clone(),
            source,
        }
    })?;
    Ok(target)
}

/// The process-wide creation permit pool (process-wide = the rpc and cli
/// entries share one gate inside this crate; the [`OnceLock`] lazy
/// singleton matches engine/addr_hygiene.rs in-repo style).
fn create_permits() -> &'static Arc<Semaphore> {
    static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    PERMITS.get_or_init(|| Arc::new(Semaphore::const_new(MAX_CONCURRENT_CREATE)))
}

/// Gate admission: try_acquire first (the idle path); when full, queue up
/// to `queue_wait`; still full = an explicit [`CreateTorrentError::Busy`]
/// (the trade-off in [`CREATE_QUEUE_WAIT`]). `sem`/`limit` are
/// parameterized for testability only: production injects
/// [`create_permits`] and [`MAX_CONCURRENT_CREATE`] (the process gate);
/// tests inject a local pool so gate cases do not contend with
/// concurrently running existing cases over the process gate (existing
/// tests unchanged and never failing because a gate case holds the
/// gate).
async fn acquire_create_permit(
    queue_wait: Duration,
    sem: &Arc<Semaphore>,
    limit: usize,
) -> Result<OwnedSemaphorePermit, CreateTorrentError> {
    match tokio::time::timeout(queue_wait, sem.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        // This module never closes the pool (the sole holder) -> Ok(Err)
        // is unreachable; folded into Busy with the queue timeout (the
        // same capacity semantics, no invented error face).
        Ok(Err(_)) | Err(_) => Err(CreateTorrentError::Busy { limit }),
    }
}

/// Permit parking for abandoned-but-running tasks (the timeout cancels
/// only the response while the spawn_blocking hash continues — the
/// permit would be released as soon as the future is dropped, making the
/// gate lie about work still burning disk/CPU; instead a watchdog parks
/// the permit until the grace expires, the gate stays saturated, and new
/// calls are refused explicitly until it drains; see
/// [`ABANDONED_PERMIT_GRACE`]).
fn park_abandoned_permit(permit: OwnedSemaphorePermit, grace: Duration) {
    tracing::warn!(
        grace_secs = grace.as_secs(),
        "createTorrent response timed out; background hashing continues, \
         permit held until grace expires"
    );
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        drop(permit);
    });
}

/// The full creation flow (the async entry): pseudo-filesystem rejection
/// (a pure path table, zero IO) -> the process concurrency gate (bounded
/// queueing -> an explicit refusal) -> stat + the alias check + the
/// budget (spawn_blocking) -> path derivation -> creator hashing
/// (spawn_blocking inside the library, the [`CREATE_TORRENT_TIMEOUT`]
/// backstop; the timeout path hands the permit to the watchdog) -> write
/// to disk (spawn_blocking).
pub async fn create_torrent(
    params: CreateTorrentParams,
) -> Result<CreatedTorrentInfo, CreateTorrentError> {
    if params.files.is_empty() {
        return Err(CreateTorrentError::EmptyFileList);
    }
    // Pseudo-filesystem rejection precedes all IO and the gate
    // (validation errors do not queue: a caller bug fails explicitly
    // immediately without consuming concurrency capacity).
    for p in &params.files {
        if is_pseudo_fs_source(p) {
            return Err(CreateTorrentError::PseudoFsPath { path: p.clone() });
        }
    }
    // The process concurrency gate: the permit is held across
    // stat/hash/write (the whole resource-consuming span).
    let permit =
        acquire_create_permit(CREATE_QUEUE_WAIT, create_permits(), MAX_CONCURRENT_CREATE).await?;
    let paths = params.files.clone();
    let probed = spawn_blocking(move || probe_files(&paths))
        .await
        .map_err(|_| CreateTorrentError::TaskJoin)??;
    // Input budget: after stat, before disk hashing — over budget = an
    // explicit failure with zero disk reads (the saturating sum guards
    // against huge stat values; a saturated value necessarily trips the
    // gate).
    let total_length: u64 = probed
        .iter()
        .map(|f| f.length)
        .fold(0u64, |a, b| a.saturating_add(b));
    if over_budget(total_length) {
        return Err(CreateTorrentError::InputTooLarge {
            total: total_length,
            limit: MAX_INPUT_TOTAL_BYTES,
        });
    }
    let derived = derive_layout(&probed)?;

    let req = build_request(&derived, &params);
    let created: CreatedTorrent =
        match tokio::time::timeout(CREATE_TORRENT_TIMEOUT, taiji_bt::creator::create(req)).await {
            Ok(res) => res.map_err(CreateTorrentError::Creator)?,
            Err(_elapsed) => {
                // The timeout cancels only the response while hashing
                // continues: the permit goes to the watchdog, and the gate
                // stays saturated for the abandoned task until the grace
                // drains.
                park_abandoned_permit(permit, ABANDONED_PERMIT_GRACE);
                return Err(CreateTorrentError::Timeout {
                    secs: CREATE_TORRENT_TIMEOUT.as_secs(),
                });
            }
        };

    let name = derived.name.clone();
    let output = spawn_blocking(move || write_output(&params.output, &name, &created.bytes))
        .await
        .map_err(|_| CreateTorrentError::TaskJoin)??;

    let (v1, v2) = match params.form {
        TorrentForm::V1Only => (Some(created.info_hash_v1), None),
        TorrentForm::V2Only => (None, Some(created.info_hash_v2)),
        TorrentForm::Hybrid => (Some(created.info_hash_v1), Some(created.info_hash_v2)),
    };
    Ok(CreatedTorrentInfo {
        output,
        name: derived.name,
        form: params.form,
        piece_length: params.piece_length,
        total_length,
        info_hash_v1: v1,
        info_hash_v2: v2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use taiji_bt::bencode;

    /// Process-level temp root (not cleaned up — the same as the
    /// existing repo tests).
    fn temp_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bh-p108-{tag}-{}", std::process::id()))
    }

    fn write_file(path: &Path, len: usize, fill: impl Fn(usize) -> u8) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| panic!("mkdir {parent:?}: {e}"));
        }
        let data: Vec<u8> = (0..len).map(fill).collect();
        fs::write(path, &data).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
    }

    fn params(files: Vec<PathBuf>, output: CreateOutput, form: TorrentForm) -> CreateTorrentParams {
        CreateTorrentParams {
            files,
            output,
            piece_length: DEFAULT_PIECE_LENGTH,
            form,
            private: false,
            comment: None,
            announce: Vec::new(),
            creation_date: None,
        }
    }

    // ===== path derivation (the input rules) =====

    #[test]
    fn derive_single_file_uses_file_name() {
        let probed = vec![ProbedFile {
            source: PathBuf::from("/data/big.bin"),
            length: 7,
        }];
        let d = derive_layout(&probed).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.name, "big.bin");
        assert_eq!(
            d.files,
            vec![(PathBuf::from("big.bin"), PathBuf::from("/data/big.bin"), 7)]
        );
    }

    #[test]
    fn derive_multi_file_uses_common_parent_and_rel_components() {
        let probed = vec![
            ProbedFile {
                source: PathBuf::from("/data/x/a.bin"),
                length: 1,
            },
            ProbedFile {
                source: PathBuf::from("/data/x/sub/b.bin"),
                length: 2,
            },
        ];
        let d = derive_layout(&probed).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(d.name, "x");
        assert_eq!(
            d.files,
            vec![
                (PathBuf::from("a.bin"), PathBuf::from("/data/x/a.bin"), 1),
                (
                    PathBuf::from("sub").join("b.bin"),
                    PathBuf::from("/data/x/sub/b.bin"),
                    2
                ),
            ]
        );
    }

    #[test]
    fn derive_sorts_by_relative_path() {
        let probed = vec![
            ProbedFile {
                source: PathBuf::from("/data/x/z.txt"),
                length: 1,
            },
            ProbedFile {
                source: PathBuf::from("/data/x/a_dir/inner.txt"),
                length: 2,
            },
            ProbedFile {
                source: PathBuf::from("/data/x/a.bin"),
                length: 3,
            },
        ];
        let d = derive_layout(&probed).unwrap_or_else(|e| panic!("{e}"));
        let rels: Vec<PathBuf> = d.files.iter().map(|(r, _, _)| r.clone()).collect();
        assert_eq!(
            rels,
            vec![
                PathBuf::from("a.bin"),
                PathBuf::from("a_dir").join("inner.txt"),
                PathBuf::from("z.txt"),
            ]
        );
    }

    #[test]
    fn derive_error_faces() {
        // No common parent (including bare files at the root).
        let probed = vec![
            ProbedFile {
                source: PathBuf::from("/a/one.txt"),
                length: 1,
            },
            ProbedFile {
                source: PathBuf::from("/b/two.txt"),
                length: 1,
            },
        ];
        assert!(matches!(
            derive_layout(&probed),
            Err(CreateTorrentError::NoCommonParent)
        ));
        // One input is a prefix of another (file and directory) -> an
        // empty relative path.
        let probed = vec![
            ProbedFile {
                source: PathBuf::from("/data/x/a"),
                length: 1,
            },
            ProbedFile {
                source: PathBuf::from("/data/x/a/b"),
                length: 1,
            },
        ];
        assert!(matches!(
            derive_layout(&probed),
            Err(CreateTorrentError::EmptyRelativePath { .. })
        ));
        // A non-UTF-8 path component (unix).
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let bad = PathBuf::from(std::ffi::OsStr::from_bytes(b"/data/x/\xff.txt"));
            let probed = vec![ProbedFile {
                source: bad,
                length: 1,
            }];
            assert!(matches!(
                derive_layout(&probed),
                Err(CreateTorrentError::InputPathUtf8 { .. })
            ));
        }
    }

    // ===== end to end (real temp files -> generate -> a parse-face
    // roundtrip / fixture cross-check) =====

    /// The bt fixture's same material (the deterministic payload of
    /// scripts/gen_hybrid_fixture.py): a.bin 70000B + b.bin 30000B @16KiB
    /// -> the creator's auto pad 11920.
    fn hybrid_fixture_material(root: &Path) -> (PathBuf, PathBuf) {
        let dir = root.join("taiji-p01-hybrid");
        write_file(&dir.join("a.bin"), 70000, |i| ((i * 7 + 11) % 256) as u8);
        write_file(&dir.join("b.bin"), 30000, |i| ((i * 13 + 29) % 256) as u8);
        (dir.join("a.bin"), dir.join("b.bin"))
    }

    /// A byte-for-byte reproduction of the official hybrid fixture: the
    /// same material + a single announce + 16KiB pieces + no creation
    /// date (the local default omits it) => equal bytes. Deliberately fed
    /// unordered inputs: derivation sorting + the creator's pad planning
    /// must produce the fixture's v1 layout order (a.bin, .pad/11920,
    /// b.bin).
    #[tokio::test]
    async fn hybrid_fixture_material_reproduces_fixture_bytes() {
        let root = temp_root("fixture");
        let (a, b) = hybrid_fixture_material(&root);
        let mut p = params(
            vec![b, a],
            CreateOutput::Dir(root.clone()),
            TorrentForm::Hybrid,
        );
        p.announce = vec!["http://example.invalid/announce".to_string()];
        let info = create_torrent(p).await.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(info.name, "taiji-p01-hybrid");
        assert_eq!(
            info.output,
            root.join("taiji-p01-hybrid.torrent"),
            "Dir-form artifact name = <derived name>.torrent"
        );
        let got = fs::read(&info.output).unwrap_or_else(|e| panic!("{e}"));
        let fixture = include_bytes!("../../taiji-bt/tests/fixtures/hybrid_16k.torrent");
        assert_eq!(
            got.as_slice(),
            fixture.as_slice(),
            "same input material must byte-for-byte reproduce the official creator fixture"
        );
    }

    /// The end-to-end roundtrip (three forms): the artifact goes through
    /// this repo's authoritative parse face
    /// [`crate::metainfo::Metainfo`] (detect_swarm_kind + the
    /// filetree/merkle checks); kind/name/piece_length/files/the private
    /// bit/both infohashes all match; infohashes carried per form
    /// (v1-only has no v2, v2-only no v1).
    #[tokio::test]
    async fn end_to_end_roundtrip_across_forms() {
        let root = temp_root("roundtrip");
        let dir = root.join("payload");
        write_file(&dir.join("one.bin"), 50000, |i| (i % 251) as u8);
        write_file(&dir.join("two.bin"), 20000, |i| ((i * 3) % 253) as u8);
        let inputs = vec![dir.join("one.bin"), dir.join("two.bin")];

        let cases = [
            (TorrentForm::V1Only, 1usize, 0usize),
            (TorrentForm::V2Only, 0, 1),
            (TorrentForm::Hybrid, 1, 1),
        ];
        for (form, want_v1, want_v2) in cases {
            let mut p = params(inputs.clone(), CreateOutput::Dir(root.clone()), form);
            p.private = true;
            p.comment = Some("roundtrip".to_string());
            p.announce = vec!["http://a.invalid/ann".to_string()];
            let info = create_torrent(p).await.unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(info.form, form);
            assert_eq!(info.name, "payload");
            assert_eq!(info.total_length, 70000);
            assert_eq!(info.info_hash_v1.is_some(), want_v1 == 1);
            assert_eq!(info.info_hash_v2.is_some(), want_v2 == 1);

            let bytes = fs::read(&info.output).unwrap_or_else(|e| panic!("{e}"));
            let meta =
                crate::metainfo::Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("parse: {e}"));
            assert_eq!(meta.meta.kind, form);
            assert_eq!(meta.name.as_deref(), Some("payload"));
            assert_eq!(meta.meta.piece_length, DEFAULT_PIECE_LENGTH);
            assert!(meta.multi_file);
            assert!(meta.private, "private bit passed through");
            assert_eq!(meta.announce, "http://a.invalid/ann");
            assert_eq!(meta.meta.identity.v1, info.info_hash_v1);
            assert_eq!(meta.meta.identity.v2, info.info_hash_v2);
            // The parse-face file table: pads appear only in the v1-only
            // view (the v1 `files` list carries attr-p entries — BEP47
            // pads are a v1 layout concept); the v2 view (the v2-only/
            // hybrid primary view) has no pad entries. Pad length =
            // 16384 - (50000 % 16384) = 15536 (aligning the following
            // file to a piece boundary).
            let real: Vec<(u64, bool)> = meta
                .meta
                .files
                .iter()
                .map(|f| (f.length, f.padding))
                .collect();
            if form == TorrentForm::V1Only {
                assert_eq!(
                    real,
                    vec![(50000, false), (15536, true), (20000, false)],
                    "v1 view includes creator-planned pad entries"
                );
            } else {
                assert_eq!(real, vec![(50000, false), (20000, false)]);
            }
            // The v1 piece count = ceil(padded total/piece) =
            // ceil(85536/16384) = 6 (v2-only has no pieces key -> empty).
            let want_pieces = if form == TorrentForm::V2Only { 0 } else { 6 };
            assert_eq!(meta.v1_pieces.len(), want_pieces);
        }
    }

    /// announce >=2: the top-level announce (the first) + announce-list
    /// with one independent tier per entry (the BEP12 shape; read via
    /// top-level bencode keys — Metainfo exposes only the single
    /// announce).
    #[tokio::test]
    async fn multiple_announces_write_announce_list() {
        let root = temp_root("announce");
        let dir = root.join("multi");
        write_file(&dir.join("f.bin"), 100, |i| i as u8);
        let mut p = params(
            vec![dir.join("f.bin")],
            CreateOutput::Dir(root.clone()),
            TorrentForm::V1Only,
        );
        p.announce = vec![
            "http://first.invalid/a".to_string(),
            "udp://second.invalid:6969/announce".to_string(),
        ];
        p.comment = Some("hello".to_string());
        let info = create_torrent(p).await.unwrap_or_else(|e| panic!("{e}"));
        let bytes = fs::read(&info.output).unwrap_or_else(|e| panic!("{e}"));
        let (top, _) = bencode::decode_with_info_span(&bytes).unwrap_or_else(|e| panic!("{e}"));
        let get = |k: &[u8]| top.get(k);
        assert_eq!(
            get(b"comment").and_then(bencode::Value::as_bytes),
            Some(b"hello".as_slice()),
            "comment passed through (top-level key)"
        );
        assert_eq!(
            get(b"announce").and_then(bencode::Value::as_bytes),
            Some(b"http://first.invalid/a".as_slice())
        );
        let tiers = get(b"announce-list")
            .and_then(bencode::Value::as_list)
            .unwrap_or_else(|| panic!("announce-list missing"));
        assert_eq!(tiers.len(), 2);
        let second = tiers[1]
            .as_list()
            .and_then(|t| t.first())
            .and_then(bencode::Value::as_bytes);
        assert_eq!(
            second,
            Some(b"udp://second.invalid:6969/announce".as_slice())
        );
    }

    // ===== error faces (explicit Err, no faking) =====

    #[tokio::test]
    async fn error_faces_rejected() {
        let root = temp_root("errors");
        let dir = root.join("in");
        write_file(&dir.join("ok.bin"), 100, |i| i as u8);

        // An empty files list.
        assert!(matches!(
            create_torrent(params(
                vec![],
                CreateOutput::Dir(root.clone()),
                TorrentForm::Hybrid
            ))
            .await,
            Err(CreateTorrentError::EmptyFileList)
        ));
        // The path does not exist.
        let missing = dir.join("nope.bin");
        assert!(matches!(
            create_torrent(params(
                vec![missing],
                CreateOutput::Dir(root.clone()),
                TorrentForm::Hybrid
            ))
            .await,
            Err(CreateTorrentError::InputStat { .. })
        ));
        // A directory as input.
        assert!(matches!(
            create_torrent(params(
                vec![dir.clone()],
                CreateOutput::Dir(root.clone()),
                TorrentForm::Hybrid
            ))
            .await,
            Err(CreateTorrentError::NotAFile { .. })
        ));
        // No common parent (any two absolute paths on a real filesystem
        // almost always share an ancestor — this error face is covered at
        // the derivation layer with synthetic paths, see
        // derive_error_faces).
        // An illegal piece length (not a power of two — surfaced through
        // the creator's validation face).
        let mut p = params(
            vec![dir.join("ok.bin")],
            CreateOutput::Dir(root.clone()),
            TorrentForm::V1Only,
        );
        p.piece_length = 8000;
        assert!(matches!(
            create_torrent(p).await,
            Err(CreateTorrentError::Creator(
                taiji_bt::creator::CreatorError::InvalidPieceLength(_)
            ))
        ));
        // The output directory is missing (the "output unwritable" face).
        assert!(matches!(
            create_torrent(params(
                vec![dir.join("ok.bin")],
                CreateOutput::Dir(root.join("nowhere")),
                TorrentForm::V1Only
            ))
            .await,
            Err(CreateTorrentError::OutputDirMissing { .. })
        ));
        // All-empty files (a total length of 0 — the creator's
        // AllFilesEmpty).
        write_file(&dir.join("zero.bin"), 0, |_| 0);
        assert!(matches!(
            create_torrent(params(
                vec![dir.join("zero.bin")],
                CreateOutput::Dir(root.clone()),
                TorrentForm::V1Only
            ))
            .await,
            Err(CreateTorrentError::Creator(
                taiji_bt::creator::CreatorError::AllFilesEmpty
            ))
        ));
    }

    /// File form: the CLI `-o` face — the artifact is written exactly at
    /// the given path.
    #[tokio::test]
    async fn file_output_form_writes_exact_path() {
        let root = temp_root("fileout");
        let dir = root.join("thing");
        write_file(&dir.join("x.bin"), 1000, |i| i as u8);
        let out = root.join("custom-name.torrent");
        let info = create_torrent(params(
            vec![dir.join("x.bin")],
            CreateOutput::File(out.clone()),
            TorrentForm::Hybrid,
        ))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(info.output, out);
        // Single-file form: the name = the file name (the creator's
        // single-file constraint; no directory name involved).
        assert_eq!(info.name, "x.bin");
        assert!(out.is_file());
    }

    // ===== resource gates and the input budget =====

    /// The case temp root (not cleaned up — the same as the existing repo
    /// tests).
    fn temp_root_p126(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("bh-p126-{tag}-{}", std::process::id()))
    }

    /// Gate policy constants pinned (each constant carries its local
    /// rationale; changing a value = a policy change that must re-review
    /// the constant's rationale, guarding against casual retuning).
    #[test]
    fn policy_constants_pinned() {
        assert_eq!(MAX_CONCURRENT_CREATE, 2);
        assert_eq!(CREATE_QUEUE_WAIT, Duration::from_secs(5));
        assert_eq!(MAX_INPUT_TOTAL_BYTES, 64 * 1024 * 1024 * 1024);
        assert_eq!(ABANDONED_PERMIT_GRACE, CREATE_TORRENT_TIMEOUT);
    }

    /// The pseudo-filesystem rejection table (table-driven): mount-point
    /// prefix hits; component-level matching does not hit byte-similar
    /// ordinary paths or relative paths.
    #[test]
    fn pseudo_fs_predicate_table() {
        for p in [
            "/proc",
            "/proc/kcore",
            "/proc/self/maps",
            "/dev",
            "/dev/null",
            "/dev/sda",
            "/sys",
            "/sys/kernel/mm",
            "//proc/kcore",
        ] {
            assert!(is_pseudo_fs_source(Path::new(p)), "must reject {p}");
        }
        for p in [
            "/processor",
            "/provoke",
            "/sysfs",
            "/system",
            "/device",
            "/development",
            "proc/kcore",
            "dev/null",
            "sys/x",
            "relative.bin",
            "",
        ] {
            assert!(!is_pseudo_fs_source(Path::new(p)), "must allow {p}");
        }
    }

    /// Pseudo-filesystem entry rejection e2e: it precedes all IO (a macOS
    /// dev machine without /proc still hits the table; /dev/null and
    /// /dev/zero are device files intercepted by the table before stat —
    /// the same path on both platforms), zero artifacts written.
    #[tokio::test]
    async fn pseudo_fs_input_paths_rejected_end_to_end() {
        let root = temp_root_p126("pseudo");
        for p in ["/proc/kcore", "/sys/kernel/mm", "/dev/null", "/dev/zero"] {
            let err = create_torrent(params(
                vec![PathBuf::from(p)],
                CreateOutput::File(root.join("never.torrent")),
                TorrentForm::Hybrid,
            ))
            .await;
            assert!(
                matches!(err, Err(CreateTorrentError::PseudoFsPath { .. })),
                "{p} must be rejected as pseudo-fs source"
            );
        }
        assert!(
            !root.join("never.torrent").exists(),
            "no artifact written to disk"
        );
    }

    /// Device/non-regular rejection (the `is_file` gate, tests added
    /// here): a unix domain socket is portably constructible on both
    /// platforms (a stable face; the std mkfifo wrapper is not stable
    /// yet) and is equally a non-regular stat type; block/character
    /// devices normally live under /dev and are intercepted by the prefix
    /// table first (see the previous case).
    #[cfg(unix)]
    #[tokio::test]
    async fn non_regular_file_input_rejected() {
        use std::os::unix::net::UnixListener;
        let root = temp_root_p126("sock");
        let dir = root.join("in");
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let sock = dir.join("socket.bin");
        UnixListener::bind(&sock).unwrap_or_else(|e| panic!("bind: {e}"));
        assert!(matches!(
            create_torrent(params(
                vec![sock],
                CreateOutput::Dir(root),
                TorrentForm::Hybrid,
            ))
            .await,
            Err(CreateTorrentError::NotAFile { .. })
        ));
    }

    /// Linux-only: a real /proc mount point e2e — the pseudo file stats
    /// successfully with `is_file() == true`, and the entry table rejects
    /// before stat (the audit PoC's original path shape).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proc_pseudo_file_rejected_before_stat() {
        assert!(matches!(
            create_torrent(params(
                vec![PathBuf::from("/proc/self/stat")],
                CreateOutput::Dir(std::env::temp_dir()),
                TorrentForm::Hybrid,
            ))
            .await,
            Err(CreateTorrentError::PseudoFsPath { .. })
        ));
    }

    /// Linux-only: a symlink alias — a clean original prefix that stats
    /// successfully with `is_file() == true` (the target is a /proc
    /// pseudo file); canonicalize resolves the target and the table
    /// intercepts (`metadata()` following symlinks is exactly the audit
    /// PoC's follow face).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn proc_symlink_alias_rejected_by_canonicalize() {
        let root = temp_root_p126("alias");
        let dir = root.join("in");
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let link = dir.join("innocent.bin");
        std::os::unix::fs::symlink("/proc/self/stat", &link)
            .unwrap_or_else(|e| panic!("symlink: {e}"));
        assert!(matches!(
            create_torrent(params(
                vec![link],
                CreateOutput::Dir(root),
                TorrentForm::Hybrid,
            ))
            .await,
            Err(CreateTorrentError::PseudoFsPath { .. })
        ));
    }

    /// The budget boundary (table-driven): the boundary value is included
    /// (<=), +1 exceeds; a saturated u64 sum necessarily trips.
    #[test]
    fn budget_boundary_table() {
        assert!(
            !over_budget(MAX_INPUT_TOTAL_BYTES),
            "boundary value included (<=)"
        );
        assert!(over_budget(MAX_INPUT_TOTAL_BYTES + 1));
        assert!(
            over_budget(u64::MAX),
            "saturated sum necessarily exceeds the gate"
        );
    }

    /// Over budget = an explicit failure with zero disk reads: a sparse
    /// file pushes its stat length over the budget (no data blocks
    /// actually allocated) — if the implementation read first, this case
    /// would hash 64GiB+ instead of returning in milliseconds (the case's
    /// total runtime is the reverse assertion).
    #[tokio::test]
    async fn input_over_budget_rejected_without_hashing() {
        let root = temp_root_p126("budget");
        let dir = root.join("big");
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir: {e}"));
        let sparse = dir.join("sparse.bin");
        let file = fs::File::create(&sparse).unwrap_or_else(|e| panic!("create: {e}"));
        file.set_len(MAX_INPUT_TOTAL_BYTES + 1)
            .unwrap_or_else(|e| panic!("set_len: {e}"));
        drop(file);
        match create_torrent(params(
            vec![sparse],
            CreateOutput::Dir(root.clone()),
            TorrentForm::Hybrid,
        ))
        .await
        {
            Err(CreateTorrentError::InputTooLarge { total, limit }) => {
                assert_eq!(total, MAX_INPUT_TOTAL_BYTES + 1);
                assert_eq!(limit, MAX_INPUT_TOTAL_BYTES);
            }
            other => panic!("expected InputTooLarge, got {other:?}"),
        }
        assert!(
            !root.join("sparse.bin.torrent").exists(),
            "no artifact written to disk"
        );
    }

    /// The concurrency gate, table-driven: capacity parameterized (the
    /// process gate value 2 is covered in the table: "2 concurrent + the
    /// 3rd rejected"). Idle = immediate admission; at full capacity the
    /// N+1th caller queues the whole window then fails with an explicit
    /// Busy (the bounded-queueing-then-rejection trade-off).
    #[tokio::test]
    async fn concurrency_gate_table() {
        for cap in [1usize, 2, 4] {
            let sem = Arc::new(Semaphore::const_new(cap));
            // Idle: immediate admission (the queue window is not
            // consumed).
            let idle = acquire_create_permit(Duration::from_millis(50), &sem, cap).await;
            assert!(idle.is_ok(), "cap {cap}: idle admit must succeed");
            drop(idle);
            // Fully occupied: the N+1th queues the whole window -> an
            // explicit Busy.
            let held = sem
                .clone()
                .try_acquire_many_owned(cap as u32)
                .unwrap_or_else(|e| panic!("cap {cap}: acquire all: {e}"));
            let started = std::time::Instant::now();
            let err = acquire_create_permit(Duration::from_millis(200), &sem, cap).await;
            drop(held);
            match err {
                Err(CreateTorrentError::Busy { limit }) => assert_eq!(limit, cap),
                other => panic!("cap {cap}: expected Busy, got {other:?}"),
            }
            assert!(
                started.elapsed() >= Duration::from_millis(200),
                "cap {cap}: must queue the full window before rejecting"
            );
        }
    }

    /// Concurrency-gate queueing semantics: a caller arriving at full
    /// capacity does not fail immediately — a permit released within the
    /// window admits it (millisecond jitter does not hard-fail); permits
    /// return in full.
    #[tokio::test]
    async fn concurrency_gate_queues_then_admits_on_release() {
        let cap = MAX_CONCURRENT_CREATE;
        let sem = Arc::new(Semaphore::const_new(cap));
        let held = sem
            .clone()
            .try_acquire_many_owned(cap as u32)
            .unwrap_or_else(|e| panic!("acquire all: {e}"));
        let sem2 = sem.clone();
        let waiter =
            tokio::spawn(
                async move { acquire_create_permit(Duration::from_secs(5), &sem2, cap).await },
            );
        // The waiter enqueues first (waiting for a release, not an
        // instant admit/reject).
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(held);
        let permit = waiter
            .await
            .unwrap_or_else(|e| panic!("join: {e}"))
            .unwrap_or_else(|e| panic!("admit: {e}"));
        drop(permit);
        assert_eq!(sem.available_permits(), cap, "permits must return in full");
    }

    /// Permit parking for abandoned-but-running tasks: within the grace
    /// the gate does not admit (honest accounting of the timeout
    /// canceling only the response while hashing continues); when the
    /// grace expires the permit returns naturally (the refuse-until-
    /// drained semantics). The grace value is injected — production
    /// passes [`ABANDONED_PERMIT_GRACE`]; the mechanism is verified
    /// here.
    #[tokio::test]
    async fn abandoned_permit_park_holds_then_releases() {
        let sem = Arc::new(Semaphore::const_new(1));
        let permit = sem
            .clone()
            .try_acquire_owned()
            .unwrap_or_else(|e| panic!("acquire: {e}"));
        park_abandoned_permit(permit, Duration::from_millis(150));
        assert_eq!(
            sem.available_permits(),
            0,
            "gate must not admit while parked"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            sem.available_permits(),
            1,
            "permit returns after the grace expires"
        );
    }
}
