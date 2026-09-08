//! Writing a file so that a power cut cannot leave half of it.
//!
//! This was private to `state.rs` until there was a second file to write, and
//! it moved rather than being copied because the rules are the whole content
//! and each of them was learned the expensive way: the fsync BEFORE the
//! rename, because a rename that lands ahead of the data is a file full of
//! zeroes on the other side of a power cut; the second fsync on the DIRECTORY,
//! because the rename is a directory operation and has its own durability; and
//! the mode set in the same call that creates the file, because a private key
//! that is briefly world readable was readable.
//!
//! `journal.rs` inherits all three instead of learning them again.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::{io, Result};

/// Replace a file atomically, owner readable only.
///
/// Write the replacement beside the real file, fsync it, rename over the top,
/// then fsync the directory so the rename itself survives a power cut. A
/// reader either sees the whole previous generation or the whole new one.
pub(crate) fn write_private(path: &Path, body: &[u8]) -> Result<()> {
    let directory = directory_of(path);
    ensure_directory(directory)?;

    let temporary = temporary_for(path)?;
    // A leftover from an interrupted save. It was never renamed, so nothing
    // ever read it and nothing depends on it.
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io(&temporary, error)),
    }

    let mut file = create_private(&temporary)?;
    file.write_all(body)
        .map_err(|error| io(&temporary, error))?;
    // Before the rename, not after. A rename that lands ahead of the data is a
    // file full of zeroes on the other side of a power cut.
    file.sync_all().map_err(|error| io(&temporary, error))?;
    drop(file);

    fs::rename(&temporary, path).map_err(|error| io(path, error))?;

    // The rename is a directory operation and needs its own flush, and BOTH
    // HALVES ARE CHECKED. Swallowing them, as this did, means returning
    // success while the durability this whole design rests on did not happen.
    // If the claim cannot be made, say so instead.
    let handle = fs::File::open(directory).map_err(|error| io(directory, error))?;
    handle.sync_all().map_err(|error| io(directory, error))?;
    Ok(())
}

/// The scratch file a replacement is written to, `state.json.new` beside
/// `state.json`.
///
/// The suffix goes on the whole name rather than replacing the extension, so
/// `journal.json` and `journal.conf` cannot collide on one scratch file.
fn temporary_for(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        crate::Error::Config(format!(
            "{} names a directory rather than a file to write.",
            path.display()
        ))
    })?;
    let mut scratch = name.to_os_string();
    scratch.push(".new");
    Ok(directory_of(path).join(scratch))
}

/// The directory a file lives in.
///
/// `Path::new("state.json").parent()` is `Some("")` rather than `None`, and an
/// empty path is not the current directory to anything that tries to open it.
/// Left unnormalised, a bare relative state path failed every save, which for a
/// device means losing the token it had just been handed.
pub(crate) fn directory_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Create the file readable and writable by its owner only, and by nobody at
/// any point in between.
///
/// `create_new` plus the mode in one call, so the file is never briefly world
/// readable while a private key is going into it. The v4 gateway's certificate
/// store sets no permissions at all, which means its first renewal quietly
/// rewrites the key at whatever the umask gives, usually 0644.
fn create_private(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| io(path, error))
}

/// The directory holds a private key, so it is 0700.
///
/// If it already exists and is more open than that, tighten it and say so.
/// Silently leaving a world readable directory around a key is worse than
/// surprising somebody who chose the permissions on purpose.
fn ensure_directory(directory: &Path) -> Result<()> {
    if !directory.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        return builder
            .create(directory)
            .map_err(|error| io(directory, error));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = fs::metadata(directory).map_err(|error| io(directory, error))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            tracing::warn!(
                directory = %directory.display(),
                mode = format!("{mode:04o}"),
                "device state directory was readable beyond its owner; tightening it to 0700"
            );
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| io(directory, error))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_relative_path_lives_in_the_current_directory() {
        // Not `""`, which is what `parent()` actually returns here and what
        // nothing can open.
        assert_eq!(directory_of(Path::new("state.json")), Path::new("."));
        assert_eq!(
            directory_of(Path::new("openqtt/state.json")),
            Path::new("openqtt")
        );
        assert_eq!(
            directory_of(Path::new("/etc/openqtt/state.json")),
            Path::new("/etc/openqtt")
        );
    }

    #[test]
    fn two_files_in_one_directory_do_not_share_a_scratch_file() {
        // `with_extension("json.new")` would answer the same name for both of
        // these, and two saves racing on one scratch file is how a journal
        // write could truncate a certificate.
        let state = temporary_for(Path::new("/etc/openqtt/state.json")).unwrap();
        let journal = temporary_for(Path::new("/etc/openqtt/journal.json")).unwrap();
        assert_eq!(state, Path::new("/etc/openqtt/state.json.new"));
        assert_ne!(state, journal);
    }
}
