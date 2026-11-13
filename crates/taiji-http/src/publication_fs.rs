//! Small file-publication primitives. Normal completion does not hash the
//! payload or require a volume UUID or filesystem file ID.
//! Reservation fallback assumes an application-managed download namespace;
//! it is not atomic exclusion against unrestricted external writers.
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub(crate) fn regular_len(path: &Path) -> io::Result<u64> {
    let metadata = fs::symlink_metadata(taiji_io::winpath::to_fs_path(path))?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "path is not a regular file",
        ));
    }
    Ok(metadata.len())
}

#[cfg(unix)]
fn exclusive_rename(from: &Path, to: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}
#[cfg(windows)]
fn exclusive_rename(from: &Path, to: &Path) -> io::Result<()> {
    atomicwrites::move_atomic(
        &taiji_io::winpath::to_fs_path(from),
        &taiji_io::winpath::to_fs_path(to),
    )
}
#[cfg(not(any(unix, windows)))]
fn exclusive_rename(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

fn unsupported_rename(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        matches!(error.raw_os_error(), Some(22 | 45 | 78 | 102))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        matches!(error.raw_os_error(), Some(22 | 38 | 95))
    }
    #[cfg(windows)]
    {
        matches!(error.raw_os_error(), Some(1 | 50 | 87 | 120))
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

pub(crate) fn reservation_bytes(token: &str) -> Vec<u8> {
    format!("taiji-publication-v1:{token}\n").into_bytes()
}

pub(crate) fn owns_reservation(path: &Path, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let expected = reservation_bytes(token);
    regular_len(path).is_ok_and(|len| len == expected.len() as u64)
        && fs::read(taiji_io::winpath::to_fs_path(path)).is_ok_and(|bytes| bytes == expected)
}

pub(crate) fn rename(from: &Path, to: &Path, token: &str) -> io::Result<()> {
    regular_len(from)?;
    if owns_reservation(to, token) {
        return replace_reservation(from, to, token);
    }
    match exclusive_rename(from, to) {
        Ok(()) => return Ok(()),
        Err(error) if unsupported_rename(&error) => {}
        Err(error) => return Err(error),
    }
    // NFS and several Unix drivers offer hard links but no exclusive rename.
    match fs::hard_link(
        taiji_io::winpath::to_fs_path(from),
        taiji_io::winpath::to_fs_path(to),
    ) {
        Ok(()) => {
            // The target now owns the complete file. A cleanup failure must
            // not turn a usable download into an error or remove its target.
            if let Err(error) = fs::remove_file(taiji_io::winpath::to_fs_path(from)) {
                tracing::warn!(%error, "publication succeeded; temporary hard link remains");
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Err(error),
        Err(error)
            if unsupported_rename(&error) || error.kind() == io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(error),
    }
    reserve_and_rename(from, to, token)
}

fn reserve_and_rename(from: &Path, to: &Path, token: &str) -> io::Result<()> {
    if from.parent() != to.parent() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reservation rename requires one directory",
        ));
    }
    let mut reservation = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(taiji_io::winpath::to_fs_path(to))?;
    reservation.write_all(&reservation_bytes(token))?;
    reservation.sync_all()?;
    drop(reservation);
    replace_reservation(from, to, token)
}

fn replace_reservation(from: &Path, to: &Path, token: &str) -> io::Result<()> {
    if !owns_reservation(to, token) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "publication reservation changed",
        ));
    }
    let result = fs::rename(
        taiji_io::winpath::to_fs_path(from),
        taiji_io::winpath::to_fs_path(to),
    );
    if result.is_err() && owns_reservation(to, token) {
        let _ = fs::remove_file(taiji_io::winpath::to_fs_path(to));
    }
    result
}

/// Late conflicts reserve space for the actual ordinal, including long names.
pub(crate) fn candidate(requested: &Path, ordinal: u32) -> std::path::PathBuf {
    let name = requested.file_name().unwrap_or_default().to_string_lossy();
    let marker = format!(".{ordinal}");
    let shortened = crate::naming::sanitize_user_name_with_budget(
        &name,
        crate::naming::MAX_NAME_BYTES.saturating_sub(marker.len()),
    );
    let (stem, extension) = crate::naming::split_name_ext(Path::new(&shortened));
    requested.with_file_name(format!("{}{marker}{extension}", stem.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scratch() -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("taiji-publish-{:032x}", rand::random::<u128>()));
        fs::create_dir(&path).unwrap_or_else(|error| panic!("{error}"));
        path
    }
    #[test]
    fn existing_targets_are_never_replaced() {
        let root = scratch();
        let source = root.join("file.motrix");
        let target = root.join("file");
        fs::write(&source, b"download").unwrap_or_else(|e| panic!("{e}"));
        fs::write(&target, b"stranger").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            rename(&source, &target, "token").err().map(|e| e.kind()),
            Some(io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(&target).unwrap_or_default(), b"stranger");
        fs::remove_dir_all(root).unwrap_or_else(|e| panic!("{e}"));
    }
    #[test]
    fn reservation_fallback_publishes_without_identity_or_full_hash_requirements() {
        let root = scratch();
        let source = root.join("file.motrix");
        let target = root.join("file");
        fs::write(&source, b"download").unwrap_or_else(|e| panic!("{e}"));
        reserve_and_rename(&source, &target, "persisted-nonce").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(fs::read(&target).unwrap_or_default(), b"download");
        assert!(!source.exists());
        fs::remove_dir_all(root).unwrap_or_else(|e| panic!("{e}"));
    }
    #[test]
    fn recorded_reservation_can_resume_after_creation_response_was_lost() {
        let root = scratch();
        let source = root.join("file.motrix");
        let target = root.join("file");
        fs::write(&source, b"download").unwrap_or_else(|e| panic!("{e}"));
        fs::write(&target, reservation_bytes("persisted-nonce")).unwrap_or_else(|e| panic!("{e}"));
        rename(&source, &target, "persisted-nonce").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(fs::read(&target).unwrap_or_default(), b"download");
        fs::remove_dir_all(root).unwrap_or_else(|e| panic!("{e}"));
    }
}
