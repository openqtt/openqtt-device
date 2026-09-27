//! `journal.json`, the second state file, and why it is a second file.
//!
//! NOT IN `state.json`, AND THE REASON IS THE OTHER FILE'S DOCSTRING. That one
//! is a single write with no ordering because it holds the key, the
//! certificate and the token that rotates with them, and losing it costs the
//! device: a new token has to be read off a screen by a person standing next
//! to it. This one is written several times during a single update, and
//! putting it there would mean rewriting a private key to record that a test
//! passed.
//!
//! THE ASYMMETRY IS THE POINT AND IT IS NOT SYMMETRIC. Losing `state.json` is
//! unrecoverable without a site visit. Losing this file costs a repeated
//! diagnostic run, and one update that has to be rolled back by hand rather
//! than by itself. That is cheap enough to lose and expensive enough to write
//! carefully, which is why it goes through the same fsync-and-rename as the
//! key rather than the `write` its contents would otherwise deserve.
//!
//! What it holds is everything that must survive a restart the device is about
//! to perform on purpose: which firmware is on probation and how long it has
//! to prove itself, which firmware already failed and must not be installed
//! again, and the last diagnostic run this device answered.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::durable::{directory_of, write_private};
use crate::error::{io, Error, Result};

/// The name beside `state.json`. Not configurable on its own: it belongs to
/// the same directory as the identity it is keeping notes about, and a second
/// variable is a second thing to get wrong in a unit file.
const FILE: &str = "journal.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Journal {
    /// The update that is being proved right now, if there is one.
    #[serde(default)]
    pub probation: Option<Probation>,
    /// The sha256 of firmware that failed its probation here.
    ///
    /// WITHOUT THIS THE DEVICE INSTALLS IT FOREVER. The announcement is
    /// retained, so it is redelivered on every connect and says "the desired
    /// version is X". A device that rolled back from X reads X again a second
    /// later, installs it again, fails again, and does that until somebody
    /// notices. One remembered sha ends the loop, and a different sha in the
    /// announcement clears it, so the platform fixes it by shipping a fix.
    #[serde(default)]
    pub rejected: Option<String>,
    /// The last `run_id` this device answered, so a redelivered dispatch is a
    /// no-op rather than a second run.
    #[serde(default)]
    pub answered: Option<String>,
    /// Binaries beside the running one that this device is finished with and
    /// could not delete when it was.
    ///
    /// WINDOWS FILLS THIS AND NOTHING ELSE DOES. A running `.exe` can always
    /// be renamed and cannot be counted on to be deleted, so a rollback parks
    /// the candidate it replaces under a name of its own until a later start,
    /// when nothing is running it. And a file a virus scanner happens to be
    /// reading can refuse to go, so a kept update can fail to delete the
    /// binary it replaced, which would otherwise block every update after it.
    /// Each is retried at every start and before every update, and deleted
    /// only while it still holds what is recorded here.
    ///
    /// Not written at all while empty, so a journal that has never needed it
    /// is byte for byte what it was before the field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leftovers: Vec<Leftover>,
}

impl Journal {
    /// Remember a file to delete later.
    ///
    /// Replaces whatever was remembered about the same file: something was
    /// renamed onto it, so the old record no longer describes what it holds.
    pub fn leave(&mut self, file: Spare, sha256: &str) {
        self.leftovers.retain(|held| held.file != file);
        self.leftovers.push(Leftover {
            file,
            sha256: sha256.to_string(),
        });
    }
}

/// A file beside the binary, and what it held when it was given up on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Leftover {
    /// Which one.
    pub file: Spare,
    /// Its sha256 when it was recorded. It is deleted only while it still
    /// holds this, so a binary somebody put there since is never touched.
    pub sha256: String,
}

/// The files beside the binary that can be left over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Spare {
    /// `<binary>.old`, once the update that made it has been kept.
    Previous,
    /// `<binary>.rejected`, the candidate a rollback on Windows moved aside.
    Rejected,
}

/// An update that is installed but not yet believed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Probation {
    /// What the announcement called it, for the message a person reads.
    pub version: String,
    /// The candidate. Compared against the sha of the binary that actually
    /// booted, which is how a half-finished swap is told from a finished one.
    pub sha256: String,
    /// The sha of what `<binary>.old` holds, so a rollback can be checked
    /// rather than assumed.
    pub previous_sha256: String,
    /// What that binary called itself. Kept because a rollback has to say
    /// where it is going, and a person reads "1.3.0" where a digest tells them
    /// only that something happened.
    #[serde(default)]
    pub previous_version: String,
    /// The api's clock is not available here, so this is the local one. It is
    /// kept for the same reason `state::State::issued_at` is: a clock reading
    /// earlier than an instant that has demonstrably passed is a clock that
    /// cannot be used to judge a deadline. See [`Probation::over`].
    pub started_at: DateTime<Utc>,
    /// When an undecided probation gives up and goes back.
    pub deadline: DateTime<Utc>,
    /// How many times this device has booted into the candidate. Counted
    /// BEFORE the gating tests run, because the boot that never reaches them
    /// is the one this is for.
    pub attempts: u32,
}

impl Probation {
    /// Whether the candidate has run out of chances.
    ///
    /// TWO MEASURES, AND ONLY ONE OF THEM WORKS ON A DEVICE WITH NO CLOCK.
    /// The attempt count is monotonic and needs no time source, so it is what
    /// covers a device that crashes before it can answer. The deadline covers
    /// the opposite failure, a device that stays up and never answers at all,
    /// and it is only consulted when the clock is worth consulting: a local
    /// time earlier than the instant this probation started is proof the clock
    /// is wrong, exactly as `lib::usable` argues about the certificate.
    pub fn over(&self, attempts_allowed: u32, now: DateTime<Utc>) -> bool {
        if self.attempts >= attempts_allowed {
            return true;
        }
        now >= self.started_at && now > self.deadline
    }

    /// A fresh marker for `sha256`, with the window it has to prove itself in.
    pub fn new(
        version: impl Into<String>,
        sha256: impl Into<String>,
        previous: (impl Into<String>, impl Into<String>),
        window: TimeDelta,
    ) -> Probation {
        let started_at = Utc::now();
        Probation {
            version: version.into(),
            sha256: sha256.into(),
            previous_sha256: previous.0.into(),
            previous_version: previous.1.into(),
            started_at,
            deadline: started_at + window,
            attempts: 0,
        }
    }
}

pub(crate) struct Store {
    path: PathBuf,
}

impl Store {
    /// Beside the state file, whatever the state file was moved to.
    pub fn beside(state: &Path) -> Store {
        Store {
            path: directory_of(state).join(FILE),
        }
    }

    /// Only the tests reach past `load` and `save`; everything else names the
    /// file through the errors those two return.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// What was written last, or an empty journal on a device that has never
    /// updated.
    ///
    /// A FILE THAT EXISTS AND CANNOT BE PARSED IS AN ERROR, for the same
    /// reason `state.rs` refuses to default: the expensive field here is the
    /// probation marker, and treating an unreadable marker as "no marker" is
    /// exactly the guess `ota::recover` is written not to make.
    pub fn load(&self) -> Result<Journal> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Journal::default())
            }
            Err(error) => return Err(io(&self.path, error)),
        };
        serde_json::from_str(&raw).map_err(|error| Error::Journal {
            path: self.path.clone(),
            reason: error.to_string(),
        })
    }

    pub fn save(&self, journal: &Journal) -> Result<()> {
        let body = serde_json::to_vec_pretty(journal).map_err(|error| {
            Error::Crypto(format!("could not serialise the device journal: {error}"))
        })?;
        write_private(&self.path, &body)
    }

    /// Read, change, write. Every caller here does exactly that and the point
    /// of the shape is that the write is not forgotten.
    pub fn update(&self, change: impl FnOnce(&mut Journal)) -> Result<Journal> {
        let mut journal = self.load()?;
        change(&mut journal);
        self.save(&journal)?;
        Ok(journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probation() -> Probation {
        Probation::new("1.4.0", "aaaa", ("bbbb", "1.3.0"), TimeDelta::hours(1))
    }

    #[test]
    fn it_lives_beside_the_state_file_wherever_that_was_moved_to() {
        assert_eq!(
            Store::beside(Path::new("/etc/openqtt/state.json")).path(),
            Path::new("/etc/openqtt/journal.json")
        );
        // A bare relative state path is the case `directory_of` exists for.
        assert_eq!(
            Store::beside(Path::new("state.json")).path(),
            Path::new("./journal.json")
        );
    }

    #[test]
    fn a_device_that_has_never_updated_has_an_empty_journal() {
        let home = tempfile::tempdir().unwrap();
        let store = Store::beside(&home.path().join("state.json"));
        assert_eq!(store.load().unwrap(), Journal::default());
    }

    #[test]
    fn what_goes_in_comes_back() {
        let home = tempfile::tempdir().unwrap();
        let store = Store::beside(&home.path().join("state.json"));
        let mut written = Journal {
            probation: Some(probation()),
            rejected: Some("cccc".to_string()),
            answered: Some("0f9b2c1e".to_string()),
            leftovers: Vec::new(),
        };
        written.leave(Spare::Rejected, "dddd");
        store.save(&written).unwrap();
        assert_eq!(store.load().unwrap(), written);
    }

    #[test]
    fn a_journal_with_nothing_left_over_is_written_exactly_as_before() {
        // A Linux device never records a leftover, and its journal must not
        // change shape because a Windows one can.
        let written = Journal {
            rejected: Some("cccc".to_string()),
            answered: Some("0f9b2c1e".to_string()),
            ..Journal::default()
        };
        assert_eq!(
            String::from_utf8(serde_json::to_vec_pretty(&written).unwrap()).unwrap(),
            "{\n  \"probation\": null,\n  \"rejected\": \"cccc\",\n  \"answered\": \"0f9b2c1e\"\n}"
        );
    }

    #[test]
    fn a_file_left_over_twice_is_remembered_once_with_what_it_holds_now() {
        // A second rollback renames a second candidate onto `.rejected`, and
        // the first record no longer describes the file.
        let mut journal = Journal::default();
        journal.leave(Spare::Rejected, "aaaa");
        journal.leave(Spare::Previous, "bbbb");
        journal.leave(Spare::Rejected, "cccc");
        assert_eq!(
            journal.leftovers,
            [
                Leftover {
                    file: Spare::Previous,
                    sha256: "bbbb".to_string()
                },
                Leftover {
                    file: Spare::Rejected,
                    sha256: "cccc".to_string()
                },
            ]
        );
    }

    #[test]
    fn an_unreadable_journal_is_an_error_and_never_an_empty_one() {
        // Answering "no probation" here would silently give up the one thing
        // that can roll a bad update back on its own.
        let home = tempfile::tempdir().unwrap();
        let store = Store::beside(&home.path().join("state.json"));
        fs::write(store.path(), "{ not json").unwrap();
        let error = store.load().unwrap_err();
        assert!(matches!(error, Error::Journal { .. }), "{error}");
    }

    #[test]
    fn a_journal_written_before_this_field_existed_still_loads() {
        // Every field is `default`, so a device updated in the field reads its
        // own older journal rather than refusing to start.
        let home = tempfile::tempdir().unwrap();
        let store = Store::beside(&home.path().join("state.json"));
        fs::write(store.path(), r#"{"answered":"0f9b2c1e"}"#).unwrap();
        let held = store.load().unwrap();
        assert_eq!(held.answered.as_deref(), Some("0f9b2c1e"));
        assert!(held.probation.is_none());
    }

    #[test]
    fn the_attempt_count_ends_a_probation_with_no_clock_at_all() {
        let mut held = probation();
        held.attempts = 3;
        // 1970. Every deadline is in this device's future and it still gives up.
        assert!(held.over(3, DateTime::from_timestamp(0, 0).unwrap()));
    }

    #[test]
    fn a_clock_earlier_than_the_probation_itself_cannot_end_it() {
        // A device with no real time clock boots at the epoch, so `now` is
        // before `deadline` AND before `started_at`. The first comparison
        // alone would be right by accident here; the case that matters is a
        // clock that reads far in the FUTURE, below.
        let held = probation();
        assert!(!held.over(3, DateTime::from_timestamp(0, 0).unwrap()));
    }

    #[test]
    fn a_clock_that_jumped_forward_still_ends_a_probation() {
        // The deadline exists for a device that stays up and never answers,
        // and a clock reading later than the start is a clock that has at
        // least moved in the right direction.
        let held = probation();
        assert!(held.over(3, held.deadline + TimeDelta::seconds(1)));
        assert!(!held.over(3, held.deadline - TimeDelta::seconds(1)));
    }

    #[test]
    fn update_reads_changes_and_writes_in_one_call() {
        let home = tempfile::tempdir().unwrap();
        let store = Store::beside(&home.path().join("state.json"));
        store
            .update(|journal| journal.answered = Some("first".to_string()))
            .unwrap();
        store
            .update(|journal| journal.rejected = Some("cccc".to_string()))
            .unwrap();

        let held = store.load().unwrap();
        assert_eq!(held.answered.as_deref(), Some("first"));
        assert_eq!(held.rejected.as_deref(), Some("cccc"));
    }

    #[cfg(unix)]
    #[test]
    fn it_is_written_at_the_same_mode_as_the_key_beside_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let home = tempfile::tempdir().unwrap();
        let store = Store::beside(&home.path().join("openqtt").join("state.json"));
        store.save(&Journal::default()).unwrap();
        let mode = fs::metadata(store.path()).unwrap().permissions().mode() & 0o777;
        // Nothing secret is in here. It costs nothing to be consistent with
        // the file next to it, and being inconsistent invites a reader to
        // wonder which of the two is the mistake.
        assert_eq!(mode, 0o600);
    }
}
