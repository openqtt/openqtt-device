//! What a device keeps between runs, in ONE file, replaced by ONE rename.
//!
//! THE SINGLE FILE IS THE WHOLE POINT AND IT IS NOT TIDINESS.
//!
//! `next_token` rotates on every successful enrollment and the token it
//! replaces survives exactly one more rotation. So a device that writes a new
//! certificate without writing the token that came with it has spent its grace
//! window, and the next interruption leaves it holding a credential the
//! platform no longer accepts. The api says so in as many words:
//! "The device must write this before it writes anything else."
//!
//! Keeping the token, the certificate, the chain and the key in one file makes
//! "before" unnecessary: there is no order because there is one write. The v4
//! gateway put them in separate files and committed a rotation with two
//! `rename` calls and no fsync, so a power cut between them left a certificate
//! and a key from different generations with nothing to notice or repair it.
//!
//! The cost is real and it is accepted: an operator cannot run
//! `openssl x509 -in device.crt` against this. An `inspect` subcommand is the
//! answer to that, not four files.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{io, Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    /// The name in the certificate, which is also the name the api looks the
    /// device up by, and the username the broker derives from the certificate.
    pub common_name: String,
    /// PEM, the device's own certificate.
    pub certificate: String,
    /// PEM, the issuing intermediate then the root. Presented to the broker,
    /// never trusted: see `mqtt::client_config`.
    pub chain: String,
    /// PKCS#8 PEM. Generated here and never sent anywhere.
    pub private_key: String,
    /// The credential for the NEXT enrollment. Rotates every time.
    pub next_token: String,
    pub not_after: DateTime<Utc>,
    pub renew_after: DateTime<Utc>,
}

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Store { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The state, or `None` if this device has never enrolled.
    ///
    /// A file that exists and cannot be parsed is an error and never a default.
    /// Falling back to "no state" here would throw away the only copy of the
    /// token and re-enrol as nobody.
    pub fn load(&self) -> Result<Option<State>> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(&self.path, error)),
        };
        serde_json::from_str(&raw)
            .map(Some)
            .map_err(|error| Error::State {
                path: self.path.clone(),
                reason: error.to_string(),
            })
    }

    /// Replace the state atomically.
    ///
    /// Write the replacement beside the real file, fsync it, rename over the
    /// top, then fsync the directory so the rename itself survives a power cut.
    /// A reader either sees the whole previous generation or the whole new one.
    pub fn save(&self, state: &State) -> Result<()> {
        let directory = self.path.parent().unwrap_or(Path::new("."));
        ensure_directory(directory)?;

        let temporary = self.path.with_extension("json.new");
        // A leftover from an interrupted save. It was never renamed, so nothing
        // ever read it and nothing depends on it.
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io(&temporary, error)),
        }

        let body = serde_json::to_vec_pretty(state)
            .map_err(|error| Error::Crypto(format!("could not serialise device state: {error}")))?;

        let mut file = create_private(&temporary)?;
        file.write_all(&body)
            .map_err(|error| io(&temporary, error))?;
        // Before the rename, not after. A rename that lands ahead of the data
        // is a state file full of zeroes on the other side of a power cut.
        file.sync_all().map_err(|error| io(&temporary, error))?;
        drop(file);

        fs::rename(&temporary, &self.path).map_err(|error| io(&self.path, error))?;

        // The rename is a directory operation and needs its own flush.
        if let Ok(handle) = fs::File::open(directory) {
            let _ = handle.sync_all();
        }
        Ok(())
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

    fn sample(token: &str) -> State {
        State {
            common_name: "acme/production/pump-3".to_string(),
            certificate: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"
                .to_string(),
            chain: "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n".to_string(),
            private_key: "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"
                .to_string(),
            next_token: token.to_string(),
            not_after: Utc::now() + chrono::TimeDelta::days(7),
            renew_after: Utc::now() + chrono::TimeDelta::days(1),
        }
    }

    #[test]
    fn a_device_that_has_never_enrolled_has_no_state() {
        let home = tempfile::tempdir().unwrap();
        let store = Store::new(home.path().join("state.json"));
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn what_goes_in_comes_back() {
        let home = tempfile::tempdir().unwrap();
        let store = Store::new(home.path().join("state.json"));
        let written = sample("oqe_first");
        store.save(&written).unwrap();

        let read = store.load().unwrap().unwrap();
        assert_eq!(read.common_name, written.common_name);
        assert_eq!(read.next_token, "oqe_first");
        assert_eq!(read.private_key, written.private_key);
        assert_eq!(read.not_after, written.not_after);
    }

    #[test]
    fn the_token_and_the_certificate_land_together_or_not_at_all() {
        // The grace window is exactly one rotation, so a device must never
        // hold a certificate from one enrollment and a token from another.
        // One file makes that impossible rather than merely unlikely.
        let home = tempfile::tempdir().unwrap();
        let store = Store::new(home.path().join("state.json"));
        store.save(&sample("oqe_first")).unwrap();

        let mut second = sample("oqe_second");
        second.certificate =
            "-----BEGIN CERTIFICATE-----\nsecond\n-----END CERTIFICATE-----\n".to_string();
        store.save(&second).unwrap();

        let read = store.load().unwrap().unwrap();
        assert_eq!(read.next_token, "oqe_second");
        assert!(read.certificate.contains("second"));
    }

    #[test]
    fn a_state_file_that_cannot_be_read_is_an_error_and_never_a_default() {
        // Answering "no state" here would throw away the only copy of the
        // token and re-enrol as nobody.
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("state.json");
        fs::write(&path, "{ this is not json").unwrap();

        let error = Store::new(&path).load().unwrap_err();
        assert!(matches!(error, Error::State { .. }), "{error}");
    }

    #[test]
    fn an_interrupted_save_does_not_block_the_next_one() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("state.json");
        // What a power cut between the write and the rename leaves behind.
        fs::write(home.path().join("state.json.new"), "half a file").unwrap();

        let store = Store::new(&path);
        store.save(&sample("oqe_after")).unwrap();
        assert_eq!(store.load().unwrap().unwrap().next_token, "oqe_after");
    }

    #[cfg(unix)]
    #[test]
    fn the_key_is_readable_by_its_owner_and_nobody_else() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("openqtt").join("state.json");
        let store = Store::new(&path);
        store.save(&sample("oqe_first")).unwrap();

        let mode = |at: &Path| fs::metadata(at).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "the state file holds a private key");
        assert_eq!(mode(path.parent().unwrap()), 0o700);

        // And again after a rotation. The v4 gateway got this right on the
        // install script and wrong in the code, so its first renewal rewrote
        // the key at whatever the umask gave, usually 0644.
        store.save(&sample("oqe_second")).unwrap();
        assert_eq!(mode(&path), 0o600, "a renewal must not loosen the key");
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_was_left_open_is_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("openqtt");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();

        let store = Store::new(directory.join("state.json"));
        store.save(&sample("oqe_first")).unwrap();

        let mode = fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
