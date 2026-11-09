//! Migration ledger and schema DDL (authoritative definition; the ledger
//! advances `user_version` per migration).
//!
//! Discipline: every schema change adds a new [`Migration`] entry advancing
//! `user_version`; in-place table alterations are forbidden. The v1 DDL is
//! the baseline — changing the DDL requires updating the design docs
//! first (doc/code divergence = bug).
//! Pre-release baseline exception (settled): `global_tracker` is folded
//! directly into the v1 DDL — the project is unreleased with no existing
//! databases, so no migration is needed and old dev databases are simply
//! rebuilt; after release the append-only migration discipline resumes.

/// A single migration: the target `user_version` and its SQL sequence
/// (committed/rolled back as one transaction).
#[derive(Debug)]
pub struct Migration {
    /// The `user_version` value after the migration completes (strictly
    /// increasing, starting at 1).
    pub version: i64,
    /// This migration's SQL sequence (executed in a single transaction).
    pub sqls: &'static [&'static str],
}

/// Migration ledger (ordered). v1 = the baseline DDL set (including
/// `global_tracker` — the globally imported tracker set, the persistence
/// face of the second tier of the in-torrent announce-list ∪ global
/// imports ∪ per-torrent manual architecture; folded into the baseline
/// pre-release, see module docs). Later schema changes only append new
/// entries; the SQL of existing entries is never rewritten.
///
/// v2 (hash recovery): the `recovered_layer` derived table — piece layers
/// admitted during recovery at runtime are persisted (key = torrent gid +
/// file index, value = layer bytes + validation payload), read back across
/// restarts, re-validated with the admission semantics and re-stored, so a
/// recovered layer is never lost. Cross-validated against libtorrent's
/// merkle trees in resume data (torrent.cpp save / read-back) — a
/// different vehicle (sqlite derived table vs resume-data blob), the same
/// purpose (no re-fetch across restarts).
///
/// v3 (the media + HTTP data model): the full `http_task`
/// column set plus the `media_task`/`media_track`/`media_segment`/
/// `media_key` four tables. The design authority is the media data-model
/// DDL text. Under the pre-release
/// discipline (2026-10-13) the old "frozen once, never touched
/// again" posture is retired: until the first external release the
/// media DDL settles as written (dev databases rebuild), and the
/// first external release freezes the then-current DDL as the
/// migration baseline (ledger v4; squashes allowed before that).
/// During 0.2 the four media tables have zero write paths (no
/// PersistWriter messages); the 0.3 media work enables the
/// media_task/media_track/media_segment write faces.
/// Note: the design docs once called this migration
/// "user_version v2", but released binaries (hash recovery) already occupy
/// ledger v2, so this entry lands as ledger v3 — the DDL content follows
/// the spec text; the ledger number only records the occupation fact.
///
/// The first pre-release revision of v3: folds in the
/// `http_task_cookie` per-task cookie table — 0.2.0 is unreleased with no
/// existing databases, so one revision lands in place instead of a v4;
/// the rest of the DDL is untouched.
///
/// The second pre-release revision of v3: the media
/// tables settle with the milestone's actual write faces —
/// `media_segment` gains the `validator_digest` column and the
/// `media_task.state` comment widens to the full ten-state domain
/// (same in-place discipline; dev databases rebuild).
///
/// The third pre-release revision of v3: the
/// `media_key` write face lands (rotation rows, stable ids) and the
/// `media_segment` comments refresh — `key_id` now references
/// `media_key.id` and `seg_len` takes the **plaintext** length reading
/// (encrypted-track archives hold decrypted bytes; the recovery
/// reconcile's bitmap-bytes vs archive-length comparison stays
/// self-consistent on one semantics). Comment-only + write-face changes; the
/// column set is untouched.
///
/// The fourth pre-release revision of v3: the
/// `http_task_cookie` table is folded into the unified `task_cookie`
/// table (renamed + the `task_kind` http|media column + the FK to
/// http_task dropped). A unified table cannot carry one FK to either
/// parent family, so cleanup switches from the FK cascade to the
/// single-writer **paired-delete** discipline (task-row delete paths
/// delete the gid's cookie rows in the same transaction; the startup
/// GC backstops crash orphans); both families clear cookies on the
/// full terminal set (done **and** error, the v0.3 widening) and
/// `PRAGMA secure_delete=ON` lands on the open face. Same
/// pre-release basis as the prior three revisions (dev databases
/// rebuild; the first external release freezes the ledger as v4).
///
/// The fifth pre-release revision of v3:
/// the `media_archive` download-archive table lands (0.3 fingerprint
/// compartments = normalized URL digest + manifest digest; the
/// duplicate checkpoints read it, the Done close-out writes it,
/// `taiji.clearMediaArchive`/`--media-archive-clear` clear it). The
/// schema comment marks the sensitivity class — "equivalent to
/// browsing history" (a gloss kept verbatim in the DDL comment)
/// (the privacy face: the rows name what the user downloaded;
/// the destructive clear faces exist for exactly that). Same
/// pre-release basis (dev databases rebuild).
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sqls: &[
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            "CREATE TABLE torrent (
  gid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  state TEXT NOT NULL,
  queue_pos INTEGER NOT NULL,
  dir TEXT NOT NULL,
  config_json TEXT NOT NULL,
  kind TEXT NOT NULL,
  v1_infohash BLOB, v2_infohash BLOB,
  is_private INTEGER NOT NULL DEFAULT 0,
  metadata BLOB,
  error_code INTEGER, error_msg TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);",
            "CREATE TABLE torrent_file (
  gid TEXT NOT NULL REFERENCES torrent(gid) ON DELETE CASCADE,
  file_index INTEGER NOT NULL,
  path TEXT NOT NULL,
  length INTEGER NOT NULL,
  attr TEXT,
  pieces_root BLOB,
  piece_layer BLOB,
  v1_offset INTEGER,
  selected INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (gid, file_index)
);",
            "CREATE TABLE torrent_progress (
  gid TEXT PRIMARY KEY REFERENCES torrent(gid) ON DELETE CASCADE,
  piece_length INTEGER NOT NULL,
  v1_bitfield BLOB,
  v2_file_bits BLOB,
  upload_at_startup INTEGER NOT NULL DEFAULT 0,
  downloaded_total INTEGER NOT NULL DEFAULT 0,
  uploaded_total INTEGER NOT NULL DEFAULT 0,
  active_time_s INTEGER NOT NULL DEFAULT 0,
  seed_time_s INTEGER NOT NULL DEFAULT 0,
  digest BLOB NOT NULL, updated_at INTEGER NOT NULL
);",
            "CREATE TABLE tracker (
  gid TEXT NOT NULL REFERENCES torrent(gid) ON DELETE CASCADE,
  tier INTEGER NOT NULL, url TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_interval INTEGER, last_min_interval INTEGER,
  next_announce_at INTEGER, last_error TEXT, last_ok_at INTEGER,
  seeds INTEGER, leechers INTEGER,
  PRIMARY KEY (gid, tier, url)
);",
            // Globally imported tracker set: url primary key (the natural
            // dedup constraint for imports) + added_at (observability
            // column); import order = rowid order (the LoadGlobalTrackers
            // read convention). Folded into the v1 baseline pre-release
            // (no migration needed), see module docs.
            "CREATE TABLE global_tracker (
  url TEXT PRIMARY KEY, added_at INTEGER NOT NULL
);",
            "CREATE TABLE peer_ban (
  ip TEXT PRIMARY KEY, reason TEXT NOT NULL, until INTEGER NOT NULL);",
            "CREATE TABLE ipfilter (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL,
  rule TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);",
            "CREATE TABLE dht_state (
  family TEXT NOT NULL CHECK(family IN ('v4','v6')),
  node_id BLOB NOT NULL, routing_table BLOB NOT NULL,
  saved_at INTEGER NOT NULL, PRIMARY KEY(family));",
            "CREATE TABLE session_kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        ],
    },
    Migration {
        version: 2,
        sqls: &[
            // Recovery-layer derived table: derived from the
            // torrent_file(gid, file_index) coordinates and the admission
            // decision, hence a torrent subtable (FK cascade cleans up when
            // the task is deleted); append-only, v1 untouched (migration
            // ledger discipline). pieces_root / piece_length / file_length
            // are the validation payload for read-back re-verification
            // (inputs to validate_piece_layer's count and root-convergence
            // checks), not redundant mirrors.
            "CREATE TABLE recovered_layer (
  gid TEXT NOT NULL REFERENCES torrent(gid) ON DELETE CASCADE,
  file_index INTEGER NOT NULL,
  piece_length INTEGER NOT NULL,
  file_length INTEGER NOT NULL,
  pieces_root BLOB NOT NULL,
  layer BLOB NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (gid, file_index)
);",
        ],
    },
    // The media + HTTP data model, under the pre-release
    // discipline (2026-10-13): full http_task columns + the four media
    // tables. The old "v3 freezes the DDL forever" note is retired —
    // pre-release the media DDL settles as written (dev databases
    // rebuild); the first external release freezes the then-current DDL
    // as the migration baseline (ledger v4; squashes allowed before
    // that). Renovation: media_segment gains validator_digest
    // (segment-level normalized-identity digest, written from day one —
    // the 0.4 signature-refresh/structure-diff consumption face) and the
    // media_task.state comment widens to the full ten-state domain.
    // Further renovation (same discipline): media_task gains the
    // selector snapshot / the sanitized output name / the 0.5 bridge
    // slot columns, and the media_format table lands (the resolved
    // format-tree snapshot — the probe-token server cache's persisted
    // counterpart). Final renovation (same discipline): the
    // media_archive download-archive table + its manifest lookup
    // index land (see the fifth-revision note in the module
    // docs). media_task.state domain: the full ten-state
    // set — queued|resolving|downloading|recording|processing|
    // verifying|finalizing|paused|error|done (no CHECK; each phase
    // state is written by its own pipeline phase: the synthesis line's
    // processing/verifying, the LIVE line's recording/finalizing
    // — this comment widened the earlier 7-state listing and dropped
    // its stale pre-synthesis state-mapping sentence);
    // http_task.state domain: queued|probing|downloading|paused|error|done.
    // Scheduling runtime state (extent/AIMD/EWMA) is never persisted and is
    // rebuilt on recovery — block-completion accounting uses the bitmap as
    // the single source of truth.
    Migration {
        version: 3,
        sqls: &[
            "CREATE TABLE http_task (
  gid TEXT PRIMARY KEY,              -- shared namespace with BT (single GID pool)
  url TEXT NOT NULL, final_url TEXT NOT NULL,
  mirrors_json TEXT,                 -- multi-source expansion (per-source state/demotion, import restores from serialized)
  state TEXT NOT NULL,               -- queued|probing|downloading|paused|error|done
  queue_pos INTEGER NOT NULL, dir TEXT NOT NULL, out TEXT NOT NULL,
  config_json TEXT NOT NULL,
  probe_json TEXT,                   -- ProbeResult (per-source aggregate)
  validator_digest BLOB,
  block_size INTEGER NOT NULL,       -- block-grid granularity (power of two, import tasks may deviate)
  block_bitmap BLOB, block_count INTEGER,
            total_done INTEGER NOT NULL DEFAULT 0,
  error_code TEXT, error_msg TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);",
            "CREATE TABLE task_cookie (             -- unified task cookie store (http|media dual family, cleared at terminal states + startup GC, paired-delete discipline)
  gid TEXT NOT NULL,                        -- dual-family shared GID pool (globally unique, no cross-family FK — single-writer paired deletes)
  task_kind TEXT NOT NULL CHECK(task_kind IN ('http','media')),  -- GC/read routing label (plain column, not in PK)
  name TEXT NOT NULL, domain TEXT NOT NULL, path TEXT NOT NULL,
  value TEXT NOT NULL,
  expires_utc INTEGER,              -- NULL = session cookie (lives with the task)
  secure INTEGER NOT NULL, host_only INTEGER NOT NULL,
  creation_utc INTEGER NOT NULL,
  PRIMARY KEY (gid, name, domain, path)
);",
            "CREATE TABLE media_task (            -- written from 0.3 on
  gid TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('hls','dash')),
  manifest_url TEXT NOT NULL,
  state TEXT NOT NULL,               -- media state set (no CHECK, synthesis phases processing/verifying, LIVE phases recording/finalizing)
  phase_detail_json TEXT, variant_json TEXT,
  selector_json TEXT,                -- selector snapshot (three-layer selector expression + resolution layer, verbatim)
  output_name TEXT,                  -- sanitized product name from template expansion (basename-ized, leading-dash refused, length/charset clamped before insert)
  bridge_json TEXT,                  -- bridge metadata (reserved for a future yt-dlp bridge, always NULL in 0.3)
  staging_dir TEXT NOT NULL, output_path TEXT NOT NULL,
  manifest_norm_digest BLOB NOT NULL,
  total_done INTEGER NOT NULL DEFAULT 0,
  config_json TEXT NOT NULL,
  error_code TEXT, error_msg TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);",
            "CREATE TABLE media_format (        -- resolved format-tree snapshot (the persistent counterpart of the probe-token server cache)
  gid TEXT PRIMARY KEY REFERENCES media_task(gid) ON DELETE CASCADE,
  formats_json TEXT NOT NULL,        -- FormatTree serialization (unified format-tree nodes)
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);",
            "CREATE TABLE media_archive (        -- download archive (sensitivity = browsing-history-equivalent — a row means the user downloaded this, cleared via taiji.clearMediaArchive / --media-archive-clear)
  url_digest TEXT PRIMARY KEY,        -- checkpoint 1 intake/activation fingerprint: normalized URL digest (query/fragment stripped, path kept, SHA-256 hex, taiji-media archive_url_digest)
  manifest_digest TEXT NOT NULL,      -- checkpoint 2 Resolving-phase fingerprint: canonical digest of the fetched manifest (same content via a CDN/mirror hits, not one-row-per-URL — each URL keeps its own row)
  kind TEXT NOT NULL CHECK(kind IN ('hls','dash')),
  title TEXT,                         -- manifest-level title (DASH ProgramInformation/Title, HLS has no standard source = NULL)
  output_name TEXT NOT NULL,          -- sanitized product name (read-back face)
  gid TEXT NOT NULL,                  -- archiving task GID (provenance)
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);",
            "CREATE INDEX idx_media_archive_manifest ON media_archive(manifest_digest);",
            "CREATE TABLE media_track (
  gid TEXT NOT NULL REFERENCES media_task(gid) ON DELETE CASCADE,
  track_idx INTEGER NOT NULL, kind TEXT NOT NULL,   -- video|audio|subtitle
  playlist_uri TEXT NOT NULL, local_name TEXT NOT NULL,
  init_files_json TEXT, seg_bitmap BLOB, seg_count INTEGER,
  PRIMARY KEY (gid, track_idx)
);",
            "CREATE TABLE media_segment (
  gid TEXT NOT NULL REFERENCES media_task(gid) ON DELETE CASCADE,
  track_idx INTEGER NOT NULL, seg_idx INTEGER NOT NULL,
  media_sequence INTEGER,           -- HLS absolute sequence (IV key), NULL for DASH
  uri TEXT NOT NULL, byte_range TEXT, key_id INTEGER,
                                    -- key_id → media_key.id (decryption face, NULL = plaintext segment)
  seg_len INTEGER NOT NULL,         -- plaintext length semantics (encrypted tracks archive as decrypted plaintext appended in order — bitmap bytes and archive length share one semantics)
  duration_ms INTEGER,
  validator_digest BLOB,            -- segment-level canonical identity digest (consumed by signature refresh / structural diff)
  map_idx INTEGER,                  -- effective EXT-X-MAP index (multi-MAP boundary bookkeeping, consumed by the local rewrite)
  PRIMARY KEY (gid, track_idx, seg_idx)
);",
            "CREATE TABLE media_key (
  id INTEGER PRIMARY KEY,
  gid TEXT NOT NULL REFERENCES media_task(gid) ON DELETE CASCADE,
  key_id TEXT NOT NULL, uri TEXT NOT NULL,
  iv BLOB,                          -- NULL ⇒ derived from the segment's media_sequence (encrypted init segments carry MAP/KEY@IV, successors chain from the first segment seq)
  key BLOB NOT NULL,                -- exactly 16B (key material lives only in the DB, never in staging, plaintext-local threat model, at-rest encryption is future work)
  UNIQUE (gid, key_id)
);",
        ],
    },
];

/// Highest schema version the current code supports.
pub const LATEST_VERSION: i64 = match MIGRATIONS.last() {
    Some(m) => m.version,
    None => 0,
};

/// All table names required by the v1 baseline (tests check table completeness
/// against this). The v1 baseline includes `global_tracker` (folded in
/// pre-release, see module docs).
pub const SCHEMA_V1_TABLES: &[&str] = &[
    "meta",
    "torrent",
    "torrent_file",
    "torrent_progress",
    "tracker",
    "global_tracker",
    "peer_ban",
    "ipfilter",
    "dht_state",
    "session_kv",
];

/// Derived tables appended after the v1 baseline (table names per ledger
/// version; tests check the complete table set).
pub const SCHEMA_V2_TABLES: &[&str] = &["recovered_layer"];

/// The media data-model table set (ledger v3, under the
/// pre-release discipline — the fifth in-place revision
/// added the `media_archive` download-archive table after the fourth
/// folded `http_task_cookie` into the unified
/// `task_cookie`; tests check the complete table set and the DDL
/// surface).
pub const SCHEMA_V3_TABLES: &[&str] = &[
    "http_task",
    "task_cookie",
    "media_task",
    "media_track",
    "media_segment",
    "media_key",
    "media_format",
    "media_archive",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Comment/declaration consistency: the migration
    /// header comment's media_task.state value domain is the
    /// full ten-state set, and the declared active
    /// read face ([`crate::persist::writer::MEDIA_TASK_ACTIVE_STATES`])
    /// plus the two terminals reconstructs exactly that set (the
    /// header once listed only seven states with a stale
    /// pre-synthesis mapping sentence — this pin keeps the comment
    /// from drifting from the declarations again). The upsert
    /// guard's guarded set
    /// ([`crate::persist::writer::MEDIA_TASK_GUARDED_STATES`]) is
    /// pinned alongside: `paused` sits in BOTH lists by design
    /// (active: restart recovery resumes it; guarded: the teardown's
    /// row survives stale detached phase writes) — editing either
    /// list alone fails here. Zero DDL semantic
    /// change: the row comment inside the DDL string may evolve under
    /// the pre-release discipline, the column shape never.
    #[test]
    fn media_task_state_comment_matches_the_spec_full_set() {
        const SPEC_MEDIA_3_2_FULL_SET: &[&str] = &[
            "queued",
            "resolving",
            "downloading",
            "recording",
            "processing",
            "verifying",
            "finalizing",
            "paused",
            "error",
            "done",
        ];
        // CRLF-tolerant: a Windows checkout without eol=lf delivers \r\n
        // through include_str!, which would break the embedded-newline
        // literal below (the .gitattributes eol=lf rule is the systemic
        // fix; this normalization keeps the test immune even in
        // pre-existing clones).
        let source = include_str!("schema.rs").replace("\r\n", "\n");
        // Scan the declarations region only (this test's own wording
        // would otherwise self-match).
        let declarations = &source[..source.find("mod tests").unwrap_or(source.len())];
        // The header comment carries the full enumeration (matched on
        // the comment's own bar-joined form so a respelling or a
        // dropped state fails here).
        let enumerated = "media_task.state domain: the full ten-state\n    // set — queued|resolving|downloading|recording|processing|\n    // verifying|finalizing|paused|error|done";
        assert!(
            declarations.contains(enumerated),
            "the v3 migration header must enumerate the full ten-state set"
        );
        // The stale pre-synthesis mapping sentence is gone.
        assert!(
            !declarations.contains("Verifying -> processing"),
            "the stale pre-synthesis state mapping must not return"
        );
        // The active read face + terminals == the full set, element
        // for element (no extra, no missing).
        let active = crate::persist::writer::MEDIA_TASK_ACTIVE_STATES;
        let mut reconstructed: Vec<&str> = active.to_vec();
        reconstructed.extend_from_slice(&["error", "done"]);
        reconstructed.sort_unstable();
        let mut want: Vec<&str> = SPEC_MEDIA_3_2_FULL_SET.to_vec();
        want.sort_unstable();
        assert_eq!(
            reconstructed, want,
            "active read face + terminals must reconstruct the full ten-state set"
        );
        // And the active face never claims a terminal.
        assert!(!active.contains(&"error") && !active.contains(&"done"));
        // Guard-side pin: `paused` deliberately sits in BOTH lists
        // (active: restart recovery resumes it; guarded: the upsert
        // guard refuses stale live-phase overwrites of the paused
        // row), error/done are guarded only, the live-phase states
        // are active only — either list edited alone fails here.
        let guarded = crate::persist::writer::MEDIA_TASK_GUARDED_STATES;
        assert!(
            guarded.contains(&"paused") && active.contains(&"paused"),
            "paused must stay in both the active and the guarded set"
        );
        for state in ["error", "done"] {
            assert!(guarded.contains(&state), "{state} must stay guarded");
            assert!(
                !active.contains(&state),
                "{state} is terminal, never active"
            );
        }
        for state in [
            "queued",
            "resolving",
            "downloading",
            "recording",
            "processing",
            "verifying",
            "finalizing",
        ] {
            assert!(active.contains(&state), "{state} must stay active");
            assert!(
                !guarded.contains(&state),
                "{state} is a live phase, never guarded"
            );
        }
        // Neither list may grow a stray state either: deduped union
        // still reconstructs the full set.
        let mut union: Vec<&str> = active.to_vec();
        union.extend_from_slice(guarded);
        union.sort_unstable();
        union.dedup();
        assert_eq!(
            union, want,
            "active + guarded (deduped) must stay the full ten-state set"
        );
    }

    #[test]
    fn migrations_are_strictly_increasing_from_one() {
        let mut expected = 1i64;
        for m in MIGRATIONS {
            assert_eq!(
                m.version, expected,
                "the user_version ledger must increase strictly"
            );
            assert!(
                !m.sqls.is_empty(),
                "v{} migration must not be empty",
                m.version
            );
            expected += 1;
        }
        assert_eq!(LATEST_VERSION, expected - 1);
    }

    #[test]
    fn schema_v1_covers_all_spec_tables() {
        // Every v1 table appears in the v1 DDL.
        let v1_sql = MIGRATIONS[0].sqls.join("\n");
        for table in SCHEMA_V1_TABLES {
            assert!(
                v1_sql.contains(&format!("CREATE TABLE {table} ")),
                "v1 DDL is missing table {table}"
            );
        }
    }

    #[test]
    fn schema_v3_covers_all_phase_b_tables() {
        // Media data-model check: http_task + the four media tables appear
        // one by one in the v3 DDL.
        let v3_sql = MIGRATIONS[2].sqls.join("\n");
        assert_eq!(MIGRATIONS[2].version, 3, "v3 entry misplaced");
        for table in SCHEMA_V3_TABLES {
            assert!(
                v3_sql.contains(&format!("CREATE TABLE {table} ")),
                "v3 DDL is missing table {table}"
            );
        }
        // Freeze surface: no media-model table may appear outside ledger
        // v3 (the pre-release revisions all land IN v3; the
        // first external release freezes the ledger as v4).
        let earlier_sql = format!(
            "{}\n{}",
            MIGRATIONS[0].sqls.join("\n"),
            MIGRATIONS[1].sqls.join("\n")
        );
        for table in SCHEMA_V3_TABLES {
            assert!(
                !earlier_sql.contains(&format!("CREATE TABLE {table} ")),
                "table {table} must not appear in pre-v3 ledger entries"
            );
        }
    }

    /// The media_archive DDL carries the sensitivity
    /// annotation ("equivalent to browsing history" — the
    /// privacy class; the
    /// destructive clear faces exist because of it), the two
    /// fingerprint compartments, and the non-unique manifest index
    /// (same content under a second URL keeps its own row — the
    /// checkpoint 2 hit face stays a lookup, not a uniqueness
    /// constraint).
    #[test]
    fn media_archive_ddl_sensitivity_and_fingerprints() {
        let v3_sql = MIGRATIONS[2].sqls.join("\n");
        let start = v3_sql
            .find("CREATE TABLE media_archive ")
            .unwrap_or_else(|| panic!("missing media_archive"));
        let end = v3_sql[start..]
            .find(";")
            .map(|i| start + i)
            .unwrap_or(v3_sql.len());
        let ddl = &v3_sql[start..end];
        assert!(
            ddl.contains("browsing-history-equivalent"),
            "the sensitivity annotation must ride the DDL comment"
        );
        assert!(
            ddl.contains("url_digest TEXT PRIMARY KEY"),
            "checkpoint 1 compartment = the PK"
        );
        assert!(
            ddl.contains("manifest_digest TEXT NOT NULL"),
            "checkpoint 2 compartment present"
        );
        assert!(
            !ddl.to_uppercase().contains("UNIQUE"),
            "manifest_digest is a lookup index, not a uniqueness bar (same content under two URLs = two rows)"
        );
        assert!(
            v3_sql.contains(
                "CREATE INDEX idx_media_archive_manifest ON media_archive(manifest_digest)"
            ),
            "the checkpoint 2 lookup index lands with the table"
        );
    }

    /// FK discipline (the paired-delete surface): the media
    /// subtables must cascade from media_task; http_task has an
    /// independent primary key (shared-pool namespace with BT, no
    /// cross-engine FK); `task_cookie` (the unified table)
    /// carries **no FK at all** — a unified table cannot FK to either
    /// parent family, so cleanup is the single-writer paired-delete
    /// discipline (task-row delete paths clear the gid's cookie rows
    /// in the same transaction, pinned by the delete-face integration
    /// tests) plus the startup GC for crash orphans.
    #[test]
    fn schema_v3_foreign_key_discipline() {
        let v3_sql = MIGRATIONS[2].sqls.join("\n");
        for (table, parent) in [
            ("media_track", "media_task"),
            ("media_segment", "media_task"),
            ("media_key", "media_task"),
            ("media_format", "media_task"),
        ] {
            let start = v3_sql
                .find(&format!("CREATE TABLE {table} "))
                .unwrap_or_else(|| panic!("missing table {table}"));
            let end = v3_sql[start..]
                .find(";")
                .map(|i| start + i)
                .unwrap_or(v3_sql.len());
            let ddl = &v3_sql[start..end];
            assert!(
                ddl.contains(&format!("REFERENCES {parent}(gid) ON DELETE CASCADE")),
                "{table} must cascade from {parent}"
            );
        }
        let http_start = v3_sql
            .find("CREATE TABLE http_task ")
            .unwrap_or_else(|| panic!("missing http_task"));
        let http_end = v3_sql[http_start..]
            .find(";")
            .map(|i| http_start + i)
            .unwrap_or(v3_sql.len());
        assert!(
            !v3_sql[http_start..http_end].contains("REFERENCES"),
            "http_task must carry no cross-table FK (independent task rows)"
        );
        // The unified cookie table: PK stays (gid, name, domain, path)
        // with task_kind a plain routing column, and no FK (the
        // paired-delete discipline owns cleanup).
        let cookie_start = v3_sql
            .find("CREATE TABLE task_cookie ")
            .unwrap_or_else(|| panic!("missing task_cookie"));
        let cookie_end = v3_sql[cookie_start..]
            .find(";")
            .map(|i| cookie_start + i)
            .unwrap_or(v3_sql.len());
        let cookie_ddl = &v3_sql[cookie_start..cookie_end];
        assert!(
            !cookie_ddl.contains("REFERENCES"),
            "task_cookie must carry no cross-family FK (the paired-delete trade-off)"
        );
        assert!(
            cookie_ddl.contains("CHECK(task_kind IN ('http','media'))"),
            "the task_kind CHECK domain = http|media"
        );
        assert!(
            cookie_ddl.contains("PRIMARY KEY (gid, name, domain, path)"),
            "the PK stays (gid, name, domain, path) — task_kind is a plain column"
        );
    }
}
