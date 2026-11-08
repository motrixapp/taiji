//! `taiji create-torrent`: an explicit file list -> the
//! [`taiji_core::create`] facade (the bt::creator kernel) -> a .torrent
//! written to disk.
//!
//! The argument surface shares its source with the RPC
//! `taiji.createTorrent` (same facade, same rules; the RPC's `outputDir`
//! directory form becomes the explicit `-o <file>` form here). Engine
//! freedoms — default values, announce rules, the omitted creation date
//! — are noted in the `taiji_core::create` module docs (aria2 has no
//! create-torrent to cross-check; libtorrent comparisons noted per
//! item).
//!
//! Reports go to stdout (this subcommand's user-facing artifact; errors
//! go to stderr — same rule as import.rs; the library-code stdout ban
//! does not cover cli-bin user-facing output).
//!
//! Upstream anchor mapping: docs/design/cli.md

use std::path::PathBuf;

use clap::{ArgAction, Args, builder::PossibleValuesParser};

use taiji_core::create::{CreateOutput, CreateTorrentParams, TorrentForm, create_torrent};

/// `taiji create-torrent` arguments (CLI form: `create-torrent <path…> -o
/// out.torrent [--piece-length] [--format] [--private] [--announce <url>]…`).
#[derive(Args, Debug)]
pub struct CreateTorrentArgs {
    /// Input files (explicit list, >= 1; no recursive directory scanning
    /// — callers enumerate themselves; one file = a single-file torrent
    /// (name = the file name), many files = a multi-file torrent (name =
    /// the common parent directory name; no common parent = an error)).
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Output .torrent path (overwrites a same-named file; the parent
    /// directory must already exist).
    #[arg(short, long)]
    output: PathBuf,
    /// Piece length (an aria2 size literal k/M/G or bare bytes; a power
    /// of two and >= 16KiB (BEP52); default 16k — the same value as
    /// libtorrent's automatic-mode floor).
    #[arg(long, default_value = "16k")]
    piece_length: String,
    /// Target form (default hybrid — under libtorrent's default flags a
    /// torrent with both hash sets is hybrid, create_torrent.hpp).
    #[arg(
        long,
        default_value = "hybrid",
        value_parser = PossibleValuesParser::new(["v1", "v2", "hybrid"])
    )]
    format: String,
    /// BEP27 private torrent (`private: 1` inside info).
    #[arg(long, default_value_t = false, action = ArgAction::SetTrue)]
    private: bool,
    /// Announce URLs (repeatable; 1 entry = the top-level announce; >=
    /// 2 entries = announce + announce-list with one tier per entry,
    /// the BEP12 form).
    #[arg(long)]
    announce: Vec<String>,
    /// Remark (the top-level `comment`).
    #[arg(long)]
    comment: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Subcommand entry point. Exit codes: 0 = success; 1 = argument or
/// creation failure (explicit error face; core::create::CreateTorrentError
/// Display printed directly).
pub async fn run(args: CreateTorrentArgs) -> i32 {
    let piece_length = match crate::parse_aria2_size(&args.piece_length) {
        // The creator's validation (merkle::validate_piece_len) is the
        // authority; the CLI-side pre-check with the same domain exists
        // only so the error message lands directly (out-of-range /
        // non-power-of-two values are refused explicitly here).
        Ok(n) if n >= 16384 && n.is_power_of_two() && n <= u32::MAX as u64 => n as u32,
        _ => {
            eprintln!(
                "error: invalid --piece-length value: {} (expected <n>[k|m|G], a power of two >= 16KiB)",
                args.piece_length
            );
            return 1;
        }
    };
    let form = match args.format.as_str() {
        "v1" => TorrentForm::V1Only,
        "v2" => TorrentForm::V2Only,
        _ => TorrentForm::Hybrid,
    };

    let params = CreateTorrentParams {
        files: args.paths.clone(),
        output: CreateOutput::File(args.output.clone()),
        piece_length,
        form,
        private: args.private,
        comment: args.comment.clone(),
        announce: args.announce.clone(),
        // creation date: the CLI likewise omits it by default (same as
        // the RPC face; the reproducible-output rule).
        creation_date: None,
    };
    match create_torrent(params).await {
        Ok(info) => {
            println!("created: {}", info.output.display());
            println!("name: {}", info.name);
            println!("format: {}", info.format_name());
            println!("piece length: {}", info.piece_length);
            println!("total length: {}", info.total_length);
            if let Some(h) = &info.info_hash_v1 {
                println!("infohash v1: {}", hex(h));
            }
            if let Some(h) = &info.info_hash_v2 {
                println!("infohash v2: {}", hex(h));
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Command;
    use super::*;
    use clap::{CommandFactory, FromArgMatches};
    use std::fs;
    use std::path::Path;

    /// Parse through the top-level Cli parser into the subcommand (the
    /// Args derive has no standalone CommandFactory; same technique as
    /// the existing main.rs tests).
    fn parse(args: &[&str]) -> Result<CreateTorrentArgs, clap::Error> {
        // try_get_matches_from's first argument is the bin name (skipped).
        let full: Vec<&str> = ["taiji", "create-torrent"]
            .into_iter()
            .chain(args.iter().copied())
            .collect();
        let matches = crate::Cli::command().try_get_matches_from(full)?;
        let cli = crate::Cli::from_arg_matches(&matches)?;
        match cli.command {
            Some(Command::CreateTorrent(a)) => Ok(a),
            _ => panic!("expected create-torrent subcommand"),
        }
    }

    fn write_file(path: &Path, len: usize, fill: impl Fn(usize) -> u8) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| panic!("mkdir {parent:?}: {e}"));
        }
        let data: Vec<u8> = (0..len).map(fill).collect();
        fs::write(path, &data).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
    }

    /// Argument surface: positional paths + -o + optional defaults
    /// (--piece-length 16k / --format hybrid) and explicit values
    /// (repeatable --announce).
    #[test]
    fn args_parse_defaults_and_explicit_values() {
        let a = parse(&["a.bin", "b.bin", "-o", "out.torrent"]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            a.paths,
            vec![PathBuf::from("a.bin"), PathBuf::from("b.bin")]
        );
        assert_eq!(a.output, PathBuf::from("out.torrent"));
        assert_eq!(a.piece_length, "16k");
        assert_eq!(a.format, "hybrid");
        assert!(!a.private);
        assert!(a.announce.is_empty());
        assert!(a.comment.is_none());

        let a = parse(&[
            "a.bin",
            "-o",
            "out.torrent",
            "--piece-length",
            "1M",
            "--format",
            "v2",
            "--private",
            "--announce",
            "http://a.invalid/ann",
            "--announce",
            "udp://b.invalid:6969/announce",
            "--comment",
            "hello",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(a.piece_length, "1M");
        assert_eq!(a.format, "v2");
        assert!(a.private);
        assert_eq!(a.announce.len(), 2);
        assert_eq!(a.comment.as_deref(), Some("hello"));
        // Domain: an invalid format is refused by clap (no silent
        // fallback).
        assert!(parse(&["a.bin", "-o", "o.torrent", "--format", "v3"]).is_err());
        // Required: no paths / no -o = refused.
        assert!(parse(&[]).is_err());
    }

    /// End to end: real files in a temp directory -> run()==0 -> the
    /// artifact survives a roundtrip through this repo's parser
    /// (taiji_core::metainfo::Metainfo).
    #[tokio::test]
    async fn end_to_end_creates_parseable_torrent() {
        let root = std::env::temp_dir().join(format!("bh-p108-cli-{}", std::process::id()));
        let dir = root.join("payload");
        write_file(&dir.join("one.bin"), 40000, |i| (i % 249) as u8);
        write_file(&dir.join("two.bin"), 16000, |i| ((i * 5) % 251) as u8);
        let out = root.join("payload.torrent");

        let code = run(CreateTorrentArgs {
            paths: vec![dir.join("one.bin"), dir.join("two.bin")],
            output: out.clone(),
            piece_length: "16k".to_string(),
            format: "hybrid".to_string(),
            private: true,
            announce: vec!["http://a.invalid/ann".to_string()],
            comment: Some("cli e2e".to_string()),
        })
        .await;
        assert_eq!(code, 0);

        let bytes = fs::read(&out).unwrap_or_else(|e| panic!("{e}"));
        let meta = taiji_core::metainfo::Metainfo::parse(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(meta.meta.kind, TorrentForm::Hybrid);
        assert_eq!(meta.name.as_deref(), Some("payload"));
        assert_eq!(meta.meta.piece_length, 16384);
        assert!(meta.private);
        assert_eq!(meta.announce, "http://a.invalid/ann");
        assert!(meta.multi_file);
        // The hybrid parse view = the v2 face (padding is not in the v2
        // file tree, BEP47); the v1 piece count =
        // ceil(padded total length / piece): 40000 + 9152 pad + 16000 =
        // 65152 -> 4 (padding planning is covered specifically in
        // core::create in v1-only form).
        let total: u64 = meta.meta.files.iter().map(|f| f.length).sum();
        assert_eq!(total, 56000);
        assert_eq!(meta.v1_pieces.len(), 4);
    }

    /// Error face: missing input / invalid piece-length -> exit code 1
    /// (explicit failure).
    #[tokio::test]
    async fn error_inputs_exit_nonzero() {
        let root = std::env::temp_dir().join(format!("bh-p108-cli-err-{}", std::process::id()));
        let code = run(CreateTorrentArgs {
            paths: vec![root.join("missing.bin")],
            output: root.join("out.torrent"),
            piece_length: "16k".to_string(),
            format: "hybrid".to_string(),
            private: false,
            announce: Vec::new(),
            comment: None,
        })
        .await;
        assert_eq!(code, 1, "missing input must fail explicitly");

        let dir = root.join("in");
        write_file(&dir.join("ok.bin"), 100, |i| i as u8);
        let code = run(CreateTorrentArgs {
            paths: vec![dir.join("ok.bin")],
            output: root.join("out.torrent"),
            piece_length: "24000".to_string(),
            format: "hybrid".to_string(),
            private: false,
            announce: Vec::new(),
            comment: None,
        })
        .await;
        assert_eq!(
            code, 1,
            "non-power-of-two piece length must fail explicitly"
        );
    }
}
