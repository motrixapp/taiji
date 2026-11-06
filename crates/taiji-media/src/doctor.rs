//! `taiji media doctor` — the initial health check.
//!
//! Aggregates, in order:
//!
//! 1. **discovery** — resolution tier + absolute pair;
//! 2. **version + license assertion** — both `-version` payloads
//! parsed through the real orchestrator (limits included), pairing
//! verified twice (same directory at discovery, version-token
//! agreement here), LGPL gate applied at the given strictness;
//! 3. **capability table** — `-demuxers`/`-muxers` parsed, required
//! set checked (deliverable 3);
//! 4. **self-check** — the ffmpeg `-version` spawn IS the self-check
//! (the card's "-version self-check" reading: no built-in stream probe in
//! M0).
//!
//! Output: [`DoctorReport`] (serde JSON for `--json`;
//! [`DoctorReport::render_human`] for the terminal). `red` counts the
//! hard failures — a GPL/nonfree gate failure under `gate` strictness
//! is a red line by design (a distro build is refused, not warned).

use std::path::PathBuf;

use serde::Serialize;

use crate::capability::{Capabilities, Direction};
use crate::discover::{self, DiscoveryRequest};
use crate::error::MediaError;
use crate::process::{MediaBin, MediaCommand};
use crate::version::{
    LicenseAudit, LicenseStrictness, VersionInfo, license_verdict, versions_agree,
};

/// Discovery section of the report.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryReport {
    /// Winning tier (`explicit`/`env`/`packaged`/`path`).
    pub source: String,
    /// Origin directory.
    pub dir: PathBuf,
    /// Absolute ffmpeg path.
    pub ffmpeg: PathBuf,
    /// Absolute ffprobe path.
    pub ffprobe: PathBuf,
    /// Same-origin pairing verdict (empty string = ok).
    pub pairing: String,
    /// Discovery error (`taiji.media.*` code + text), if any.
    pub error: Option<String>,
}

/// Version/license section of the report.
#[derive(Debug, Clone, Serialize)]
pub struct VersionReport {
    /// ffmpeg version token.
    pub ffmpeg_version: Option<String>,
    /// ffprobe version token.
    pub ffprobe_version: Option<String>,
    /// Raw ffmpeg configuration string.
    pub configuration: Option<String>,
    /// Token-exact license audit.
    pub license: LicenseAudit,
    /// Version-token agreement (pairing, second half). `None` = the
    /// section never ran (discovery failed) — no verdict implied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions_agree: Option<bool>,
    /// Gate verdict at the requested strictness (empty = pass).
    pub verdict: String,
    /// Section error, if any.
    pub error: Option<String>,
    /// Section never ran (discovery failed; the discovery section
    /// carries the root cause). A skipped section contributes no reds
    /// and states no findings — its default field values are absence,
    /// not verdicts. Absent from the JSON when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
}

/// Capability section of the report.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    /// Required demuxers missing from the build.
    pub missing_demuxers: Vec<String>,
    /// Required muxers missing from the build.
    pub missing_muxers: Vec<String>,
    /// Count of registered demuxers (context for the two vecs).
    pub demuxer_count: usize,
    /// Count of registered muxers.
    pub muxer_count: usize,
    /// Section error, if any.
    pub error: Option<String>,
    /// Section never ran (discovery failed) — the empty missing vecs
    /// are absence, not completeness. Absent from the JSON when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub skipped: bool,
}

/// Full doctor report (serde face of `taiji media doctor --json`).
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Discovery section.
    pub discovery: DiscoveryReport,
    /// Version/license section.
    pub version: VersionReport,
    /// Capability section.
    pub capabilities: CapabilityReport,
    /// Number of red findings (0 = all green).
    pub red: u32,
}

/// Doctor invocation options.
#[derive(Debug, Clone, Default)]
pub struct DoctorOptions {
    /// License-assertion tier (default = [`LicenseStrictness::Gate`]
    /// via the field being set explicitly by callers; `Default` yields
    /// Gate).
    pub strictness: LicenseStrictness,
    /// Precedence-1 explicit directory (None = environment tiers).
    pub explicit_dir: Option<std::path::PathBuf>,
    /// Exec-shim host override (None = `current_exe()`; tests point at
    /// the `taiji-media-shim` helper, see `process.rs`).
    pub shim_program: Option<std::path::PathBuf>,
}

/// Run the full doctor pass. Each section degrades independently: a
/// failed spawn lands in that section's `error` and counts one red,
/// never aborting the remaining sections.
pub async fn run_doctor(opts: DoctorOptions) -> DoctorReport {
    let mut red = 0u32;
    let shim = opts.shim_program.clone();

    // --- 1. discovery -------------------------------------------------
    let pair = discover::discover(&DiscoveryRequest {
        explicit_dir: opts.explicit_dir.clone(),
    });
    let discovery = match &pair {
        Ok(p) => DiscoveryReport {
            source: p.source.as_str().to_string(),
            dir: p.dir().to_path_buf(),
            ffmpeg: p.ffmpeg.clone(),
            ffprobe: p.ffprobe.clone(),
            pairing: String::new(),
            error: None,
        },
        Err(e) => {
            red += 1;
            DiscoveryReport {
                source: "none".to_string(),
                dir: std::path::PathBuf::new(),
                ffmpeg: std::path::PathBuf::new(),
                ffprobe: std::path::PathBuf::new(),
                pairing: String::new(),
                error: Some(format!("{}: {e}", e.code())),
            }
        }
    };

    // --- 2. version + license ------------------------------------------
    // A failed discovery skips both dependent sections: they report
    // `skipped` and state no findings (their defaults are absence, not
    // verdicts) — the discovery failure is the single red, never
    // inflated by phantom version/pairing/capability conclusions.
    let sections_skipped = pair.is_err();
    let mut version_report = VersionReport {
        ffmpeg_version: None,
        ffprobe_version: None,
        configuration: None,
        license: LicenseAudit {
            gpl: false,
            nonfree: false,
        },
        versions_agree: None,
        verdict: String::new(),
        error: None,
        skipped: sections_skipped,
    };
    if let Ok(pair) = &pair {
        match probe_versions(pair, opts.strictness, shim.as_deref()).await {
            Ok(v) => version_report = v,
            Err(e) => {
                red += 1;
                version_report.error = Some(format!("{}: {e}", e.code()));
            }
        }
    }
    // Findings only from a section that ran and did not error out.
    if !version_report.skipped && version_report.error.is_none() {
        if !version_report.verdict.is_empty() {
            red += 1;
        }
        if version_report.versions_agree == Some(false) {
            // Version-token disagreement is a mixed installation: red
            // regardless of strictness (it is a pairing failure, not a
            // policy tier).
            red += 1;
        }
    }

    // --- 3. capabilities ------------------------------------------------
    let mut capability_report = CapabilityReport {
        missing_demuxers: Vec::new(),
        missing_muxers: Vec::new(),
        demuxer_count: 0,
        muxer_count: 0,
        error: None,
        skipped: sections_skipped,
    };
    if let Ok(pair) = &pair {
        match probe_capabilities(pair, shim.as_deref()).await {
            Ok(caps) => {
                let (missing_demuxers, missing_muxers) = caps.missing_required();
                capability_report.demuxer_count = caps.demuxers.names().len();
                capability_report.muxer_count = caps.muxers.names().len();
                capability_report.missing_demuxers =
                    missing_demuxers.into_iter().map(String::from).collect();
                capability_report.missing_muxers =
                    missing_muxers.into_iter().map(String::from).collect();
                if !capability_report.missing_demuxers.is_empty()
                    || !capability_report.missing_muxers.is_empty()
                {
                    red += 1;
                }
            }
            Err(e) => {
                red += 1;
                capability_report.error = Some(format!("{}: {e}", e.code()));
            }
        }
    }

    DoctorReport {
        discovery,
        version: version_report,
        capabilities: capability_report,
        red,
    }
}

/// Probe both `-version` payloads through the orchestrator and apply
/// the license gate. A gate failure is a *section verdict* (red), not
/// a section error — "could not run -version" and "the build carries
/// --enable-gpl" are different findings.
async fn probe_versions(
    pair: &discover::FfmpegPair,
    strictness: LicenseStrictness,
    shim: Option<&std::path::Path>,
) -> Result<VersionReport, MediaError> {
    let ffmpeg_version = run_version_probe(MediaBin::Ffmpeg, &pair.ffmpeg, shim).await?;
    let ffprobe_version = run_version_probe(MediaBin::Ffprobe, &pair.ffprobe, shim).await?;
    let audit = LicenseAudit::audit(&ffmpeg_version.configuration);
    let (audit, verdict) = match license_verdict(audit, strictness, "ffmpeg -version") {
        Ok(a) => (a, String::new()),
        Err(e) => (audit, e.to_string()),
    };
    let agree = versions_agree(&ffmpeg_version, &ffprobe_version);
    Ok(VersionReport {
        ffmpeg_version: Some(ffmpeg_version.version),
        ffprobe_version: Some(ffprobe_version.version),
        configuration: Some(ffmpeg_version.configuration),
        license: audit,
        versions_agree: Some(agree),
        verdict,
        error: None,
        skipped: false,
    })
}

/// One `-version` spawn (the self-check spawn — the same orchestrator
/// path every media child takes, limits included).
async fn run_version_probe(
    bin: MediaBin,
    program: &std::path::Path,
    shim: Option<&std::path::Path>,
) -> Result<VersionInfo, MediaError> {
    let cmd = MediaCommand::new(bin, program)?
        .args(
            VersionInfo::version_args()
                .iter()
                .map(std::ffi::OsString::from),
        )
        .shim_program(shim.map(std::path::Path::to_path_buf))
        .spawn()?;
    let output = cmd.wait().await?.into_ok()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    VersionInfo::parse(&text)
}

/// Probe `-demuxers` + `-muxers` through the orchestrator.
async fn probe_capabilities(
    pair: &discover::FfmpegPair,
    shim: Option<&std::path::Path>,
) -> Result<Capabilities, MediaError> {
    let mut demuxer_stdout = Vec::new();
    let mut muxer_stdout = Vec::new();
    for direction in [Direction::Demuxers, Direction::Muxers] {
        let cmd = MediaCommand::new(MediaBin::Ffmpeg, &pair.ffmpeg)?
            .args(direction.args().iter().map(std::ffi::OsString::from))
            .shim_program(shim.map(std::path::Path::to_path_buf))
            .spawn()?;
        let output = cmd.wait().await?.into_ok()?;
        match direction {
            Direction::Demuxers => demuxer_stdout = output.stdout,
            Direction::Muxers => muxer_stdout = output.stdout,
        }
    }
    let demuxer_text = String::from_utf8_lossy(&demuxer_stdout).into_owned();
    let muxer_text = String::from_utf8_lossy(&muxer_stdout).into_owned();
    Capabilities::parse(&demuxer_text, &muxer_text)
}

impl DoctorReport {
    /// Human-readable rendering (the non-`--json` doctor face).
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        if let Some(err) = &self.discovery.error {
            out.push_str(&format!("discovery:  FAIL {err}\n"));
        } else {
            out.push_str(&format!(
                "discovery:  ok (source={}, dir={})\n",
                self.discovery.source,
                self.discovery.dir.display()
            ));
            out.push_str(&format!(
                "  ffmpeg:  {}\n  ffprobe: {}\n",
                self.discovery.ffmpeg.display(),
                self.discovery.ffprobe.display()
            ));
        }
        if self.version.skipped {
            out.push_str("version:    skipped (discovery failed — section not run)\n");
        } else if let Some(err) = &self.version.error {
            out.push_str(&format!("version:    FAIL {err}\n"));
        } else {
            out.push_str(&format!(
                "version:    ffmpeg={} ffprobe={}\n",
                self.version.ffmpeg_version.as_deref().unwrap_or("?"),
                self.version.ffprobe_version.as_deref().unwrap_or("?")
            ));
            out.push_str(&format!(
                "  license: gpl={} nonfree={} (LGPL gate)\n",
                self.version.license.gpl, self.version.license.nonfree
            ));
            if self.version.verdict.is_empty() {
                out.push_str("  verdict: pass\n");
            } else {
                out.push_str(&format!("  verdict: FAIL {}\n", self.version.verdict));
            }
            if self.version.versions_agree == Some(false) {
                out.push_str("  pairing: FAIL ffmpeg/ffprobe version tokens disagree\n");
            }
        }
        if self.capabilities.skipped {
            out.push_str("capability: skipped (discovery failed — section not run)\n");
        } else if let Some(err) = &self.capabilities.error {
            out.push_str(&format!("capability: FAIL {err}\n"));
        } else {
            out.push_str(&format!(
                "capability: {} demuxers / {} muxers registered\n",
                self.capabilities.demuxer_count, self.capabilities.muxer_count
            ));
            if self.capabilities.missing_demuxers.is_empty()
                && self.capabilities.missing_muxers.is_empty()
            {
                out.push_str("  required set: complete\n");
            } else {
                out.push_str(&format!(
                    "  required set: MISSING demuxers={:?} muxers={:?}\n",
                    self.capabilities.missing_demuxers, self.capabilities.missing_muxers
                ));
            }
        }
        if self.red == 0 {
            out.push_str("doctor: all green\n");
        } else {
            out.push_str(&format!("doctor: {} red finding(s)\n", self.red));
        }
        out
    }
}
