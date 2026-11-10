//! Two guardrails pinning the rpc layer's place in the layering (root
//! Cargo.toml: cli -> rpc -> core{session} -> engine -> domain — rpc is the
//! only crate allowed to speak the aria2-compatible surface).
//!
//! 1. `aria2_status_literals_stay_within_baseline` — a leak counter for
//!    the aria2 task-status vocabulary. The 14 status words below are the
//!    v1 wire/persistence vocabulary (BT task states, HTTP task states,
//!    media phases); kernel crates speaking the raw strings is registered
//!    debt, pinned at [`BASELINE`] and only allowed to shrink: new
//!    capabilities go through the `taiji.*` v2 surface, or are registered
//!    in the ledger (`docs/compat/aria2-v1-deviations.yaml`). Raising
//!    BASELINE to absorb a new literal is not a sanctioned move.
//! 2. `kernel_manifests_do_not_declare_rpc_dependencies` — the manifest
//!    face of the same direction: no crate below rpc may declare
//!    taiji-rpc in a production `[dependencies]` section
//!    (dev-dependencies are allowed; the reverse edge would only surface
//!    as a dependency cycle after the fact, this pin turns it red at
//!    review time). The manifest walk enumerates `crates/` dynamically
//!    (like the leak counter's scan face), so crates joining the
//!    workspace are pinned automatically — only crates legitimately
//!    above rpc are exempted, by name, in [`RPC_CONSUMERS`].
//!
//! The whitelist rules of both guards are pinned on synthetic sources
//! (`whitelist_rules_are_pinned_on_synthetic_source`,
//! `test_module_declarations_are_pinned_on_synthetic_source`,
//! `manifest_predicates_are_pinned_on_synthetic_lines`): today's tree is
//! clean, so without those pins a lexer regression could silently idle
//! the guards green.
//!
//! # Leak-counter counting rules (exact, independently reproducible)
//!
//! - Scan face: every `crates/<crate>/src/**/*.rs` except
//!   `crates/taiji-rpc` itself; crates joining the workspace are scanned
//!   automatically. [`MIN_SCANNED_FILES`] floors the walk (an idling walk
//!   would make the assertion vacuously true).
//! - Counting unit: a string literal — plain, raw, byte or C form — whose
//!   *entire* content equals one of [`STATUS_WORDS`]. A status word inside
//!   a longer literal (`"download done"`) is prose, not a status literal,
//!   and never counts.
//! - Skipped, in order:
//!   1. comments — `//` (incl. `///`, `//!`) and nested `/* */`, stripped
//!      by lexical classification, not by line shape (a trailing comment
//!      after code is stripped too);
//!   2. test code — modules gated by `#[cfg(test)]` / `#[cfg(all(test,
//!      ..))]`: inline `mod x { .. }` blocks (brace-balanced over
//!      comment/string-blanked text) and out-of-line `mod x;`
//!      declarations resolved to `<moddir>/x.rs` or the `<moddir>/x/`
//!      subtree (`#[path = ".."]` honored), plus whole files gated by an
//!      inner `#![cfg(test)]`; unresolved declarations fail loudly rather
//!      than miscount;
//!   3. user-facing display text — literals inside the argument list of a
//!      logging/printing macro (`trace!`/`debug!`/`info!`/`warn!`/
//!      `error!`/`print!`/`println!`/`eprint!`/`eprintln!`) and
//!      `DebugStruct::field` labels (a string literal whose immediately
//!      preceding code is `.field(`).
//! - `#[cfg(test)]`-gated *non-module* items (helper fns, `use`s,
//!   statements) stay in the counted face: they are not tests
//!   modules/files, and counting them is the conservative direction.
//! - The guard never fails low: a measured count below [`BASELINE`] only
//!   prints a ratchet note on the passing path.
//!
//! # Known bypass surface (audit note, deliberate)
//!
//! The display exemption is the cheapest way to keep a status literal
//! out of the count: placing it in a log/print macro's argument (or in
//! first position after a `.field(` call, or inside a cfg(test)-gated
//! module) exempts it. All three have semantic grounds (user-visible
//! prose, debug labels and test code are not wire-surface vocabulary)
//! and the synthetic pins lock the rules themselves, but an auditor
//! should know that hiding a real state value inside log prose would
//! evade the counter — when in doubt, grep the display macros for the
//! bare words.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// The aria2 task-status vocabulary under governance: the BT persisted
/// task states, the HTTP task states and the media phases.
const STATUS_WORDS: &[&str] = &[
    "queued",
    "metadata",
    "checking",
    "allocating",
    "downloading",
    "seeding",
    "paused",
    "probing",
    "resolving",
    "recording",
    "processing",
    "verifying",
    "finalizing",
    "done",
];

/// Measured leak baseline (2026-11-10): taiji-core 81, taiji-store 24,
/// taiji-media 19, taiji-http 1. Ratchets down only — see the module doc.
const BASELINE: usize = 125;

/// Production-file floor for the scan face (300 at the baseline date).
const MIN_SCANNED_FILES: usize = 250;

/// The rpc crate: excluded from the leak scan (it is the one crate allowed
/// to speak the aria2 surface), and the forbidden dependency name for the
/// kernel manifests. Its own `tests/` target — this file included — is
/// outside every scan face, so the guard never self-matches.
const RPC_CRATE: &str = "taiji-rpc";

/// Logging/printing macros whose arguments are user-facing display text.
const DISPLAY_MACROS: &[&str] = &[
    "trace", "debug", "info", "warn", "error", "print", "println", "eprint", "eprintln",
];

/// Crates legitimately allowed to declare a taiji-rpc dependency: only
/// the CLI sits above rpc in the layering (cli -> rpc). This is the
/// guard's explicit registry — adding an above-rpc crate is a decision
/// recorded here with a rationale, never a silent pass.
const RPC_CONSUMERS: &[&str] = &["taiji"];

/// Manifest-walk floor (10 at the pin date: the 12 crates minus rpc and
/// the CLI). taiji-metalink is inside the walked face since 2026-11-10
/// (review finding): rpc consumes it via the `metalink` feature, so a
/// reverse edge there is exactly the violation this pin exists for — the
/// earlier static list missed it.
const MIN_SCANNED_MANIFESTS: usize = 10;

// ---------------------------------------------------------------------------
// Guard A: the leak counter
// ---------------------------------------------------------------------------

#[test]
fn aria2_status_literals_stay_within_baseline() {
    let root = workspace_root();
    let files = collect_scan_files(&root);

    let mut faces: Vec<(PathBuf, String, FileAnalysis)> = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let analysis = analyze_source(&text);
        faces.push((path.clone(), text, analysis));
    }
    let (test_files, test_dirs) = resolve_test_faces(&faces);

    let mut scanned = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    let mut per_crate: BTreeMap<String, usize> = BTreeMap::new();
    for (path, text, analysis) in &faces {
        if test_files.contains(path) || test_dirs.iter().any(|d| path.starts_with(d)) {
            continue;
        }
        scanned += 1;
        let rel_path = path.strip_prefix(&root).unwrap_or(path);
        let rel = rel_path.display().to_string();
        let hits = collect_status_hits(text, analysis);
        if hits.is_empty() {
            continue;
        }
        // The second path component is the crate name (crates/<crate>/..).
        let crate_name = rel_path
            .components()
            .nth(1)
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .unwrap_or_default();
        *per_crate.entry(crate_name).or_default() += hits.len();
        for (line, word) in hits {
            offenders.push(format!("{rel}:{line} \"{word}\""));
        }
    }

    assert!(
        scanned >= MIN_SCANNED_FILES,
        "scan surface distorted: only {scanned} production .rs files under \
         crates/*/src (floor {MIN_SCANNED_FILES}); did the workspace layout drift?"
    );

    let total = offenders.len();
    let mut breakdown = String::new();
    for (name, count) in &per_crate {
        breakdown.push_str(&format!("  {name}: {count}\n"));
    }
    assert!(
        total <= BASELINE,
        "aria2 task-status literal leak: {total} occurrences in non-rpc crate \
         src/ (baseline {BASELINE}).\n\
         新增 aria2 字面量请走 v2 或登记台账,不要提高基线\n\
         (new aria2 status literals must go through the taiji.* v2 surface or \
         be registered in the ledger, docs/compat/aria2-v1-deviations.yaml; \
         never raise BASELINE to absorb a new literal)\n\
         Sites (file:line \"word\"):\n{breakdown}{}",
        offenders.join("\n")
    );
    if total < BASELINE {
        eprintln!(
            "aria2 status literal count is {total} < baseline {BASELINE}: lower \
             the BASELINE constant to ratchet the guard down"
        );
    }
}

/// Pins every whitelist rule on a synthetic source, so the counting
/// caliber stays executable and reviewable (see the module doc).
#[test]
fn whitelist_rules_are_pinned_on_synthetic_source() {
    let src = concat!(
        // Skipped: comments (line, nested block), prose, display usages,
        // test-gated modules (both gate forms).
        "// \"paused\" in a line comment — skipped\n",
        "/* \"done\" in a /* \"queued\" nested */ block comment — skipped */\n",
        "let note = \"download done\"; // prose: not a bare status word\n",
        "let a = \"paused\";\n",
        "let raw = r##\"queued\"##;\n",
        "info!(target: \"t\", \"seeding\"); // log message: display text\n",
        "f.debug_struct(\"Row\").field(\n    \"metadata\",\n    &1,\n)\n",
        "#[cfg(test)]\nmod tests {\n    fn fixture() -> &'static str { \"checking\" }\n}\n",
        "#[cfg(all(test, unix))]\nmod more_tests {\n    fn g() -> &'static str { \"allocating\" }\n}\n",
        // Counted: every literal form of the bare word, and the faces
        // that are deliberately *not* whitelisted.
        "let b = b\"done\"; // byte-string form: same vocabulary\n",
        "let q = '\"'; let s = \"probing\"; // a quote char literal opens no string\n",
        "fn f<'a>(x: &'a str) -> &'a str { \"resolving\" } // lifetimes are not chars\n",
        "#[cfg(any(test, feature = \"x\"))]\nmod m { fn h() -> &'static str { \"recording\" } }\n",
        "#[cfg(test)]\nfn helper() -> &'static str { \"verifying\" } // gated fn, not a module\n",
        "assert_eq!(state, \"finalizing\"); // assertions are not display macros\n",
        "let c = 1; // \"processing\" in a trailing comment — skipped\n",
    );
    let analysis = analyze_source(src);
    assert_eq!(
        collect_status_hits(src, &analysis),
        [
            (4, "paused"),
            (5, "queued"),
            (19, "done"),
            (20, "probing"),
            (21, "resolving"),
            (23, "recording"),
            (25, "verifying"),
            (26, "finalizing"),
        ],
        "the synthetic source pins the counting rules as (line, word): comments \
         (line, trailing, nested block), prose literals, cfg(test)-gated modules \
         (both gate forms) and display usages (log-macro arguments, Debug field \
         labels) are skipped; plain, raw and byte-string forms of the bare words \
         are counted, as are cfg(any(test, ..)) modules, cfg(test)-gated \
         non-module items and assertion arguments"
    );
}

/// Pins the test-module declaration faces the real tree does not
/// exercise today (`#[path]` overrides, the inner `#![cfg(test)]` file
/// gate, visibility-qualified and late-gated declarations) next to the
/// non-gates.
#[test]
fn test_module_declarations_are_pinned_on_synthetic_source() {
    let gated = analyze_source(concat!(
        "#[cfg(test)]\n#[path = \"unit/probe.rs\"]\nmod probe;\n",
        "#[cfg(test)]\npub(crate) mod helpers;\n",
        "#[allow(dead_code)]\n#[cfg(test)]\nmod late_gate;\n",
        "mod production;\n",
        "#[cfg(any(test, feature = \"x\"))]\nmod support;\n",
    ));
    assert_eq!(
        gated.out_of_line_test_mods,
        [
            ("probe".to_string(), Some("unit/probe.rs".to_string()), 1),
            ("helpers".to_string(), None, 4),
            ("late_gate".to_string(), None, 6),
        ],
        "out-of-line test modules as (name, #[path] override, declaration \
         line): the gate may sit anywhere in the attribute run, visibility is \
         skipped, ungated and cfg(any(test, ..)) modules are not test faces"
    );
    assert!(
        !gated.inner_cfg_test,
        "outer attributes never gate the file"
    );
    assert!(
        analyze_source("#![cfg(test)]\nfn f() {}\n").inner_cfg_test,
        "an inner cfg(test) attribute gates the whole file"
    );
    assert!(
        !analyze_source("#![allow(dead_code)]\nfn f() {}\n").inner_cfg_test,
        "other inner attributes do not"
    );
}

// ---------------------------------------------------------------------------
// Guard B: the dependency-direction pin
// ---------------------------------------------------------------------------

#[test]
fn kernel_manifests_do_not_declare_rpc_dependencies() {
    let root = workspace_root();
    // Dynamic walk: every crate directory except rpc itself and the
    // registered above-rpc consumers. A static list went stale once
    // already (metalink sat outside it, review 2026-11-10); the walk
    // pins new crates automatically.
    let crates_dir = root.join("crates");
    let mut crate_names: Vec<String> = std::fs::read_dir(&crates_dir)
        .unwrap_or_else(|e| panic!("read crates dir {}: {e}", crates_dir.display()))
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != RPC_CRATE && !RPC_CONSUMERS.contains(&n.as_str()))
        .collect();
    crate_names.sort();
    assert!(
        crate_names.len() >= MIN_SCANNED_MANIFESTS,
        "scan surface distorted: only {} crate manifests under crates/ \
         (floor {MIN_SCANNED_MANIFESTS}); did the layout drift, or does a new \
         above-rpc crate need registering in RPC_CONSUMERS with a rationale?",
        crate_names.len()
    );

    let mut offenders: Vec<String> = Vec::new();
    for crate_name in &crate_names {
        let manifest = crates_dir.join(crate_name).join("Cargo.toml");
        let text = std::fs::read_to_string(&manifest)
            .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));
        // Section state machine: comment lines (`#`) are skipped; a table
        // header switches state. Production-dependency sections are
        // `[dependencies]`, `[dependencies.<name>]` and the target-specific
        // `[target.'..'.dependencies]`; `[dev-dependencies]` (explicitly
        // allowed) and every other table are outside the pinned face.
        let mut in_deps = false;
        for (i, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            if let Some(header) = table_header(trimmed) {
                in_deps = production_deps_section(header);
                if in_deps && mentions_crate(header, RPC_CRATE) {
                    offenders.push(format!("{crate_name}/Cargo.toml:{}: {trimmed}", i + 1));
                }
                continue;
            }
            if in_deps && mentions_crate(trimmed, RPC_CRATE) {
                offenders.push(format!("{crate_name}/Cargo.toml:{}: {trimmed}", i + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a crate below rpc declares {RPC_CRATE} in a production \
         [dependencies] section (dev-dependencies are allowed) — rpc sits above \
         every walked crate in the layering (cli -> rpc -> core -> engine -> \
         domain, see the root Cargo.toml layering comment); a reverse edge is a \
         layering violation:\n{}",
        offenders.join("\n")
    );
}

/// Pins the manifest-face predicates on synthetic lines (the kernel
/// manifests are clean today, so the real scan alone would never
/// exercise the red path).
#[test]
fn manifest_predicates_are_pinned_on_synthetic_lines() {
    for header in [
        "[dependencies]",
        "[dependencies.taiji-rpc]",
        "[target.'cfg(unix)'.dependencies]",
        "[target.'cfg(target_os = \"linux\")'.dependencies]",
        "[target.x86_64-unknown-linux-gnu.dependencies]",
    ] {
        assert!(
            table_header(header).is_some_and(production_deps_section),
            "{header}: a production-dependency section"
        );
    }
    for header in [
        "[dev-dependencies]",
        "[build-dependencies]",
        "[target.'cfg(unix)'.dev-dependencies]",
        "[target.x86_64-unknown-linux-gnu.dev-dependencies]",
        "[features]",
        "[[bench]]",
    ] {
        assert!(
            !table_header(header).is_some_and(production_deps_section),
            "{header}: not a production-dependency section"
        );
    }
    assert_eq!(
        table_header("[dependencies] # trailing comment"),
        Some("[dependencies]"),
        "a trailing comment does not hide a header"
    );
    assert_eq!(
        table_header("[\"rt\", \"macros\"] }"),
        None,
        "an array continuation line is not a header"
    );
    for line in [
        "taiji-rpc = { path = \"../taiji-rpc\" }",
        "taiji-rpc.workspace = true",
        "rpc = { package = \"taiji-rpc\", path = \"../taiji-rpc\" }",
        "[dependencies.taiji-rpc]",
    ] {
        assert!(
            mentions_crate(line, RPC_CRATE),
            "{line}: declares the rpc crate"
        );
    }
    for line in [
        "taiji-rpc-types = { path = \"../taiji-rpc-types\" }",
        "taiji-core = { path = \"../taiji-core\" }",
        "xtaiji-rpc = \"1\"",
    ] {
        assert!(
            !mentions_crate(line, RPC_CRATE),
            "{line}: a different package name"
        );
    }
}

/// The table header on a manifest line, if the line is one: `[..]` or
/// `[[..]]` from the first byte to the last `]`, followed by nothing or a
/// comment. An array continuation line (`["a", "b"] }`) is not a header.
fn table_header(trimmed: &str) -> Option<&str> {
    if !trimmed.starts_with('[') || trimmed.trim_start_matches('[').starts_with('"') {
        return None;
    }
    let close = trimmed.rfind(']')?;
    let tail = trimmed[close + 1..].trim_start();
    (tail.is_empty() || tail.starts_with('#')).then(|| &trimmed[..=close])
}

/// `[dependencies]`, `[dependencies.x]` or `[target.'..'.dependencies]`?
/// (dev-/build-dependencies and every other table answer false.)
fn production_deps_section(header: &str) -> bool {
    let Some(inner) = header.strip_prefix('[').and_then(|h| h.strip_suffix(']')) else {
        return false;
    };
    let section = match inner.strip_prefix("target.") {
        // Drop the platform selector. Quoted (`'cfg(unix)'`, may contain
        // dots): the section follows the closing quote. Bare triple (no
        // dots inside): the section follows the first dot.
        Some(rest) => {
            let tail = match rest.rsplit_once(['\'', '"']) {
                Some((_, tail)) => tail,
                None => match rest.split_once('.') {
                    Some((_, tail)) => tail,
                    None => return false,
                },
            };
            tail.trim_start_matches('.')
        }
        None => inner,
    };
    section == "dependencies" || section.starts_with("dependencies.")
}

/// Does `line` name the package `name` as a whole word? Package-name
/// characters (alphanumerics, `-`, `_`) on either side make it a
/// different package (`taiji-rpc-types` is not `taiji-rpc`).
fn mentions_crate(line: &str, name: &str) -> bool {
    let is_name_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    line.match_indices(name).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + name.len()..].chars().next();
        !before.is_some_and(is_name_char) && !after.is_some_and(is_name_char)
    })
}

// ---------------------------------------------------------------------------
// Scan pipeline (std only)
// ---------------------------------------------------------------------------

/// A string literal occurrence: token start (prefix included) and the
/// content span between the quotes.
struct StrLit {
    start: usize,
    content_start: usize,
    content_end: usize,
}

impl StrLit {
    fn content<'a>(&self, text: &'a str) -> &'a str {
        &text[self.content_start..self.content_end]
    }
}

/// One parsed attribute: whitespace-stripped inner text plus its span.
struct Attr {
    norm: String,
    start: usize,
    end: usize,
}

/// Per-file analysis: blanked code face, all string literals, and the
/// test-module structure extracted from it.
struct FileAnalysis {
    /// Source with comment/string/char-literal bytes blanked to spaces
    /// (newlines preserved): bracket balancing and identifier scans run
    /// on this face.
    code: Vec<u8>,
    literals: Vec<StrLit>,
    /// Byte ranges of inline `#[cfg(test)] mod x { .. }` blocks.
    inline_test_ranges: Vec<(usize, usize)>,
    /// Names of those inline modules (their child dirs are test-only).
    inline_test_mods: Vec<String>,
    /// `#[cfg(test)] mod x;` declarations: (name, `#[path]` override, line).
    out_of_line_test_mods: Vec<(String, Option<String>, usize)>,
    /// Whole file gated by an inner `#![cfg(test)]`.
    inner_cfg_test: bool,
}

/// Lexically classify a source file: comments, string literals and char
/// literals are blanked out of `code` (newlines kept) and every string
/// literal is recorded. Handles plain strings with escapes, raw strings
/// (`r".."`, `r#".."#`, `br#.."#`, `cr#.."#`), nested block comments, and
/// the char-literal vs lifetime distinction (`'a'` vs `'a`).
fn analyze_source(text: &str) -> FileAnalysis {
    let src = text.as_bytes();
    let mut code = src.to_vec();
    let mut literals: Vec<StrLit> = Vec::new();
    let mut i = 0usize;
    while i < src.len() {
        let c = src[i];
        if c == b'/' && src.get(i + 1) == Some(&b'/') {
            let mut j = i;
            while j < src.len() && src[j] != b'\n' {
                j += 1;
            }
            blank(&mut code, i, j);
            i = j;
        } else if c == b'/' && src.get(i + 1) == Some(&b'*') {
            let mut depth = 1usize;
            let mut j = i + 2;
            while j < src.len() && depth > 0 {
                if src[j] == b'/' && src.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if src[j] == b'*' && src.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut code, i, j);
            i = j;
        } else if c == b'"' {
            let mut j = i + 1;
            while j < src.len() {
                if src[j] == b'\\' {
                    j += 2;
                } else if src[j] == b'"' {
                    break;
                } else {
                    j += 1;
                }
            }
            let content_end = j.min(src.len());
            let token_end = (j + 1).min(src.len());
            literals.push(StrLit {
                start: i,
                content_start: i + 1,
                content_end,
            });
            blank(&mut code, i, token_end);
            i = token_end;
        } else if c == b'\'' {
            if src.get(i + 1) == Some(&b'\\') {
                // Escaped char literal: skip `\x`, scan to the closing
                // quote (further escapes inside, e.g. '\u{1F600}').
                let mut j = i + 3;
                while j < src.len() && src[j] != b'\'' {
                    if src[j] == b'\\' {
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                let end = (j + 1).min(src.len());
                blank(&mut code, i, end);
                i = end;
            } else {
                let len = utf8_len(src.get(i + 1).copied().unwrap_or(0));
                if src.get(i + 1 + len) == Some(&b'\'') {
                    let end = i + 1 + len + 1;
                    blank(&mut code, i, end);
                    i = end;
                } else {
                    i += 1; // lifetime or loop label: plain code
                }
            }
        } else if is_ident_start(c) {
            let mut j = i;
            while j < src.len() && is_ident_cont(src[j]) {
                j += 1;
            }
            let mut consumed = false;
            let word = &src[i..j];
            if word == b"r" || word == b"br" || word == b"cr" {
                let mut k = j;
                while k < src.len() && src[k] == b'#' {
                    k += 1;
                }
                let hashes = k - j;
                if src.get(k) == Some(&b'"') {
                    let mut j2 = k + 1;
                    let mut content_end = src.len();
                    let mut token_end = src.len();
                    while j2 < src.len() {
                        if src[j2] == b'"' {
                            let mut h = 0usize;
                            while h < hashes && src.get(j2 + 1 + h) == Some(&b'#') {
                                h += 1;
                            }
                            if h == hashes {
                                content_end = j2;
                                token_end = j2 + 1 + hashes;
                                break;
                            }
                        }
                        j2 += 1;
                    }
                    literals.push(StrLit {
                        start: i,
                        content_start: k + 1,
                        content_end,
                    });
                    blank(&mut code, i, token_end);
                    i = token_end;
                    consumed = true;
                }
            }
            if !consumed {
                i = j;
            }
        } else {
            i += 1;
        }
    }

    // Attribute/module pass on the blanked face: find test-gated modules.
    let mut inline_test_ranges: Vec<(usize, usize)> = Vec::new();
    let mut inline_test_mods: Vec<String> = Vec::new();
    let mut out_of_line_test_mods: Vec<(String, Option<String>, usize)> = Vec::new();
    let mut inner_cfg_test = false;
    let mut pos = 0usize;
    while let Some(offset) = code[pos..].iter().position(|&b| b == b'#') {
        let at = pos + offset;
        let (end, attrs) = parse_attr_run(&code, at);
        if attrs.is_empty() {
            pos = at + 1;
            continue;
        }
        let first_start = attrs[0].start;
        let is_inner = code.get(first_start + 1) == Some(&b'!');
        if is_inner && cfg_gate_is_test(&attrs[0].norm) {
            inner_cfg_test = true;
        }
        if !is_inner && attrs.iter().any(|a| cfg_gate_is_test(&a.norm)) {
            // `#[path = ".."]`: the value is blanked in `code`, so read it
            // from the literal table (the literal inside the attr span).
            let path_override: Option<String> = attrs
                .iter()
                .filter(|a| a.norm.starts_with("path="))
                .find_map(|a| {
                    literals
                        .iter()
                        .find(|l| a.start <= l.start && l.start < a.end)
                })
                .map(|lit| lit.content(text).to_string());
            let (mut ident, mut after_ident) = read_ident(&code, end);
            if ident == Some(b"pub".as_slice()) {
                let q = skip_ws(&code, after_ident);
                if code.get(q) == Some(&b'(') {
                    after_ident = match_delim(&code, q) + 1;
                }
                let (next, next_pos) = read_ident(&code, after_ident);
                ident = next;
                after_ident = next_pos;
            }
            if ident == Some(b"mod".as_slice()) {
                let (name, name_end) = read_ident(&code, after_ident);
                if let Some(name) = name {
                    let after = skip_ws(&code, name_end);
                    if code.get(after) == Some(&b'{') {
                        let close = match_delim(&code, after);
                        inline_test_ranges.push((first_start, close + 1));
                        inline_test_mods.push(String::from_utf8_lossy(name).into_owned());
                        pos = close + 1;
                        continue;
                    }
                    if code.get(after) == Some(&b';') {
                        let line = line_of(&code, first_start);
                        out_of_line_test_mods.push((
                            String::from_utf8_lossy(name).into_owned(),
                            path_override,
                            line,
                        ));
                        pos = after + 1;
                        continue;
                    }
                }
            }
        }
        pos = end.max(at + 1);
    }

    FileAnalysis {
        code,
        literals,
        inline_test_ranges,
        inline_test_mods,
        out_of_line_test_mods,
        inner_cfg_test,
    }
}

/// Apply the whitelist rules to one file's literals and return the
/// counted status hits as (line, word), in source order.
fn collect_status_hits<'a>(text: &'a str, analysis: &FileAnalysis) -> Vec<(usize, &'a str)> {
    let display = display_spans(&analysis.code);
    let mut hits: Vec<(usize, &'a str)> = Vec::new();
    for lit in &analysis.literals {
        let content = lit.content(text);
        if !STATUS_WORDS.contains(&content) {
            continue;
        }
        if analysis
            .inline_test_ranges
            .iter()
            .any(|(s, e)| *s <= lit.start && lit.start < *e)
        {
            continue;
        }
        if display
            .iter()
            .any(|(s, e)| *s <= lit.start && lit.start < *e)
        {
            continue;
        }
        if preceded_by_field_label(&analysis.code, lit.start) {
            continue;
        }
        hits.push((line_of(text.as_bytes(), lit.start), content));
    }
    hits
}

/// Resolve the test faces declared by the analyses: files that are wholly
/// test-only and directories below which everything is test-only.
/// Unresolvable declarations panic loudly — a guessed resolution would
/// silently distort the baseline.
fn resolve_test_faces(
    faces: &[(PathBuf, String, FileAnalysis)],
) -> (HashSet<PathBuf>, Vec<PathBuf>) {
    let mut test_files: HashSet<PathBuf> = HashSet::new();
    let mut test_dirs: Vec<PathBuf> = Vec::new();
    for (path, _, analysis) in faces {
        if analysis.inner_cfg_test {
            test_files.insert(path.clone());
        }
    }
    for (path, _, analysis) in faces {
        for (name, path_override, line) in &analysis.out_of_line_test_mods {
            let target = match path_override {
                Some(rel) => path.parent().unwrap_or(path).join(rel).canonicalize().ok(),
                None => {
                    let base = module_dir(path).join(name);
                    let as_file = base.with_extension("rs");
                    if as_file.is_file() {
                        Some(as_file)
                    } else if base.is_dir() {
                        Some(base)
                    } else {
                        None
                    }
                }
            };
            let Some(target) = target else {
                panic!(
                    "cfg(test) module `{name}` declared at {}:{line} did not resolve — \
                     extend the test-module resolution in this guard (a guessed \
                     resolution would silently miscount the leak baseline)",
                    path.display()
                );
            };
            if target.is_dir() {
                test_dirs.push(target);
            } else {
                // Child modules of `x.rs` live in `x/` and ride along.
                let child_dir = target.with_extension("");
                if child_dir.is_dir() {
                    test_dirs.push(child_dir);
                }
                test_files.insert(target);
            }
        }
        for name in &analysis.inline_test_mods {
            let dir = module_dir(path).join(name);
            if dir.is_dir() {
                test_dirs.push(dir);
            }
        }
    }
    (test_files, test_dirs)
}

/// Where out-of-line children of a module declared in `file` live:
/// `mod.rs`/`lib.rs`/`main.rs` host their siblings' directory, any other
/// `foo.rs` hosts `foo/`.
fn module_dir(file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or(file);
    match file.file_name().and_then(|n| n.to_str()) {
        Some("lib.rs" | "main.rs" | "mod.rs") => parent.to_path_buf(),
        _ => parent.join(file.file_stem().unwrap_or_default()),
    }
}

/// Argument spans of the display macros ([`DISPLAY_MACROS`]): a macro
/// invocation `name!(...)` (any delimiter) contributes the span from its
/// opening delimiter to the matching close, so every literal inside —
/// structured fields and message alike — is display text.
fn display_spans(code: &[u8]) -> Vec<(usize, usize)> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < code.len() {
        if is_ident_start(code[i]) && (i == 0 || !is_ident_cont(code[i - 1])) {
            let mut j = i;
            while j < code.len() && is_ident_cont(code[j]) {
                j += 1;
            }
            let name = &code[i..j];
            let is_display = DISPLAY_MACROS.iter().any(|m| m.as_bytes() == name);
            if is_display && code.get(j) == Some(&b'!') {
                let k = skip_ws(code, j + 1);
                if matches!(code.get(k), Some(b'(' | b'[' | b'{')) {
                    spans.push((k, match_delim(code, k)));
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    spans
}

/// Is the code immediately before `start` (skipping whitespace) `.field(`?
/// That first argument of `DebugStruct::field` is a debug label, never a
/// state value.
fn preceded_by_field_label(code: &[u8], start: usize) -> bool {
    let mut p = start;
    while p > 0 && code[p - 1].is_ascii_whitespace() {
        p -= 1;
    }
    code[..p].ends_with(b".field(")
}

/// Parse the run of consecutive attributes starting at `at` (which must
/// point at `#`); returns the offset past the run. An inner marker `!` is
/// accepted on the first attribute only. Normalized inner text drops all
/// whitespace, so `cfg(test)` and `cfg( test )` are one face; string
/// contents are blanked in `code`, hence `path=` values are read from the
/// literal table by the caller.
fn parse_attr_run(code: &[u8], at: usize) -> (usize, Vec<Attr>) {
    let mut attrs: Vec<Attr> = Vec::new();
    let mut p = at;
    let mut first = true;
    loop {
        let save = p;
        let q = skip_ws(code, p);
        if code.get(q) != Some(&b'#') {
            return (save, attrs);
        }
        let mut b = q + 1;
        if first && code.get(b) == Some(&b'!') {
            b += 1;
        }
        if code.get(b) != Some(&b'[') {
            return (save, attrs);
        }
        first = false;
        let mut depth = 0usize;
        let mut j = b;
        while j < code.len() {
            match code[j] {
                b'[' => depth += 1,
                b']' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        if j >= code.len() {
            return (save, attrs);
        }
        let norm: String = code[b + 1..j]
            .iter()
            .filter(|c| !c.is_ascii_whitespace())
            .map(|c| char::from(*c))
            .collect();
        attrs.push(Attr {
            norm,
            start: q,
            end: j + 1,
        });
        p = j + 1;
    }
}

/// Does a normalized cfg predicate gate on test? `cfg(test)` and
/// `cfg(all(test, ..))` do; `cfg(any(test, ..))` also builds outside the
/// test harness and stays in the counted face.
fn cfg_gate_is_test(norm: &str) -> bool {
    let Some(args) = norm.strip_prefix("cfg(").and_then(|a| a.strip_suffix(')')) else {
        return false;
    };
    if args == "test" {
        return true;
    }
    args.strip_prefix("all(")
        .and_then(|a| a.strip_suffix(')'))
        .is_some_and(|all| all.split(',').any(|part| part == "test"))
}

/// Collect every `crates/<crate>/src/**/*.rs` except the excluded crate,
/// sorted for deterministic diagnostics.
fn collect_scan_files(root: &Path) -> Vec<PathBuf> {
    let crates_dir = root.join("crates");
    let mut crate_names: Vec<String> = std::fs::read_dir(&crates_dir)
        .unwrap_or_else(|e| panic!("read crates dir {}: {e}", crates_dir.display()))
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n != RPC_CRATE)
        .collect();
    crate_names.sort();
    let mut files: Vec<PathBuf> = Vec::new();
    for name in &crate_names {
        let src = crates_dir.join(name).join("src");
        if src.is_dir() {
            collect_rs(&src, &mut files);
        }
    }
    files.sort();
    files
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn workspace_root() -> PathBuf {
    // Canonicalized so that walked paths and resolved test-module targets
    // compare equal as text (a `#[path = "../x.rs"]` override would
    // otherwise carry `..` components the walk never produces).
    std::fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(".."))
        .unwrap_or_else(|e| panic!("canonicalize workspace root: {e}"))
}

/// Blank `[from, to)` to spaces, keeping newlines (line numbers survive).
fn blank(code: &mut [u8], from: usize, to: usize) {
    let from = from.min(code.len());
    let to = to.min(code.len());
    for byte in &mut code[from..to] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// Matching close delimiter for the opener at `open` (same type only, on
/// the blanked face where strings/comments cannot unbalance it).
fn match_delim(code: &[u8], open: usize) -> usize {
    let (opener, closer) = match code.get(open) {
        Some(b'(') => (b'(', b')'),
        Some(b'[') => (b'[', b']'),
        Some(b'{') => (b'{', b'}'),
        _ => return open,
    };
    let mut depth = 0usize;
    let mut j = open;
    while j < code.len() {
        if code[j] == opener {
            depth += 1;
        } else if code[j] == closer {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return j;
            }
        }
        j += 1;
    }
    code.len().saturating_sub(1)
}

fn read_ident(code: &[u8], from: usize) -> (Option<&[u8]>, usize) {
    let p = skip_ws(code, from);
    match code.get(p) {
        Some(&b) if is_ident_start(b) => {
            let mut j = p;
            while j < code.len() && is_ident_cont(code[j]) {
                j += 1;
            }
            (Some(&code[p..j]), j)
        }
        _ => (None, p),
    }
}

fn skip_ws(code: &[u8], from: usize) -> usize {
    let mut p = from;
    while p < code.len() && code[p].is_ascii_whitespace() {
        p += 1;
    }
    p
}

fn line_of(text: &[u8], at: usize) -> usize {
    1 + text[..at.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_cont(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit()
}

/// Length in bytes of the UTF-8 sequence led by `b` (continuation bytes
/// defensively count as 1).
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0xBF => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}
