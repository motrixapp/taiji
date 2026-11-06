//! The lenient local ffmpeg runtime for the real-machine legs
//! (discovery + `-version`; the license gate is a production
//! posture — the dev machine's Homebrew build carries `--enable-gpl`,
//! the recorded e2e_real fixture fact). Test-support only.

#![allow(dead_code)]

use std::path::PathBuf;

use taiji_media::ffmpegmux::FfmpegRuntime;

pub async fn local_ffmpeg() -> Option<FfmpegRuntime> {
    let pair = taiji_media::discover(&taiji_media::DiscoveryRequest::default()).ok()?;
    let cmd = taiji_media::MediaCommand::new(taiji_media::MediaBin::Ffmpeg, &pair.ffmpeg)
        .ok()?
        .args(taiji_media::VersionInfo::version_args().iter().copied())
        .shim_program(Some(PathBuf::from(env!("CARGO_BIN_EXE_taiji-media-shim"))));
    let child = cmd.spawn().ok()?;
    let out = child.wait().await.ok()?;
    if !out.success {
        return None;
    }
    let version = taiji_media::VersionInfo::parse(&String::from_utf8_lossy(&out.stdout)).ok()?;
    Some(FfmpegRuntime {
        pair,
        version,
        shim_program: Some(PathBuf::from(env!("CARGO_BIN_EXE_taiji-media-shim"))),
    })
}
