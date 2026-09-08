//! Download an update, verify it, swap it in, and prove it afterwards.
//!
//! # The unit file this needs
//!
//! ```ini
//! [Service]
//! Restart=always
//! SuccessExitStatus=73
//! ```
//!
//! BOTH LINES, AND `Restart=on-failure` IS THE TRAP. An update ends by exiting
//! 73 so that the service manager starts the new binary; `SuccessExitStatus`
//! is what stops that exit being logged as a crash and counted against the
//! restart limiter. But `on-failure` reads the same declaration and concludes
//! that 73 is success, so it does not restart at all, and the service is dead
//! after every successful update until somebody starts it by hand.
//!
//! # Where things are written
//!
//! IN THE DIRECTORY THE RUNNING BINARY IS IN, and nowhere else. Two separate
//! incidents in the previous generation say why. `systemd` bind-mounts every
//! `ReadWritePaths` entry as its own filesystem, so staging into a data
//! directory and renaming into place fails `EXDEV`, and a rename is the only
//! way to replace a running binary atomically. And the binary's own directory
//! has to be writable, or the write fails `EROFS` before any of that matters.
//! Staging beside the target makes both conditions the same condition, which
//! is one thing to get right in a unit file instead of two.
//!
//! # The order, which is the whole design
//!
//! Verify the signature before a byte is written. Download and hash. Write the
//! probation marker BEFORE the two renames, because that marker is the only
//! thing that makes a power cut between them recoverable. Rename the running
//! binary aside, rename the new one into place, say goodbye, exit 73. Come back
//! up, run every gating test, and either keep it or put the old one back.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use chrono::{TimeDelta, Utc};
use serde::Deserialize;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::Notify;

use crate::error::{io, Error, Result};
use crate::journal::{self, Journal, Probation};
use crate::mqtt::Publisher;
use crate::signals::Signal;
use crate::tests::Registry;

/// `EX_TEMPFAIL` out of `sysexits.h`, which is as close as that list gets to
/// "nothing is wrong, start me again". Anything in the 1 to 63 range would be
/// indistinguishable from the program failing.
const RESTART: i32 = 73;

/// How long a new firmware has to answer its gating tests before it is put
/// back. Long enough for a slow boot and a full set of probes at the
/// catalogue's 300 second ceiling; short enough that a device nobody can talk
/// to repairs itself inside a working day.
const PROBATION_WINDOW: TimeDelta = TimeDelta::hours(1);

/// How many times a device may boot into a candidate without reaching a
/// verdict. This is the measure that works with no clock at all, and three is
/// enough to tell one bad boot from a crash loop.
const PROBATION_ATTEMPTS: u32 = 3;

/// A device binary is a few megabytes. This is a long way past that and its
/// job is only to stop a wrong URL from filling the partition the running
/// binary lives on, which would take the device down without any help from us.
const MAX_ARTIFACT: u64 = 256 * 1024 * 1024;

/// How much has to arrive before another progress message goes out. Progress
/// is what resets the platform's stall timer, so it has to be often enough to
/// do that and rare enough not to be the traffic.
const PROGRESS_STEP: u64 = 5 * 1024 * 1024;

/// Each step of the goodbye gets this much and no more. A device on its way out
/// must not be able to hang here.
const PRE_EXIT_BUDGET: Duration = Duration::from_secs(3);

pub(crate) const ANNOUNCEMENT_TOPIC: &str = "commands/firmware";
const PROGRESS_TOPIC: &str = "ota/progress";
const EVENT_TOPIC: &str = "ota/event";
const META_TOPIC: &str = "meta/firmware";

/// What the platform desires, on `commands/firmware`.
///
/// DESIRED STATE AND NOT AN ORDER. The device compares `sha256` against what it
/// is running and does nothing if they match, which is why this can be retained
/// and redelivered on every reconnect without a persisted job id.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Announcement {
    pub version: String,
    pub sha256: String,
    pub url: String,
    /// ECDSA P-256 over the raw 32 bytes of `sha256`, DER, base64.
    pub signature: String,
    /// Which key version signed it. Logged rather than checked: this device
    /// holds one public key and has no way to know which version that is, so
    /// naming it in the log is what makes a rotation debuggable.
    #[serde(default)]
    pub key_version: Option<String>,
}

/// What this device is running, and the only honest answer to that question.
#[derive(Debug, Clone)]
pub(crate) struct Firmware {
    pub version: String,
    pub sha256: String,
}

impl Firmware {
    /// The version the application declared, and the sha of the binary that
    /// actually booted.
    ///
    /// HASHED ONCE, AT STARTUP, BEFORE ANYTHING IS SWAPPED. `current_exe` on
    /// Linux resolves a path, and after this process renames a new binary over
    /// its own that path holds somebody else's bytes. Reading it later would
    /// answer with the firmware this device is about to become rather than the
    /// one it is.
    pub fn running(version: impl Into<String>, binary: &Path) -> Result<Firmware> {
        Ok(Firmware {
            version: version.into(),
            sha256: sha256_file(binary)?,
        })
    }

    /// `meta/firmware`, published on every connect.
    ///
    /// GROUND TRUTH, AND THE REASON IT IS SENT EVERY TIME RATHER THAN RETAINED
    /// ONCE. Installing an update means restarting, so the process that would
    /// have announced success was replaced mid-sentence. Judge a rollout by
    /// what a device reports running, never by whether it managed to announce
    /// that it finished.
    pub fn meta(&self) -> serde_json::Value {
        serde_json::json!({ "version": self.version, "sha256": self.sha256 })
    }
}

/// The three files an update touches, all in one directory.
#[derive(Debug, Clone)]
pub(crate) struct Paths {
    /// The binary this process was launched from.
    pub binary: PathBuf,
    /// Where the download lands. Beside the binary, because a rename across
    /// filesystems is `EXDEV`.
    pub staged: PathBuf,
    /// The last binary known to work. Never overwritten.
    pub previous: PathBuf,
}

impl Paths {
    pub fn beside(binary: PathBuf) -> Paths {
        Paths {
            staged: suffixed(&binary, ".new"),
            previous: suffixed(&binary, ".old"),
            binary,
        }
    }

    /// Where this process was launched from.
    ///
    /// A PATH ENDING IN " (deleted)" IS NOT A PATH. Linux answers
    /// `readlink /proc/self/exe` that way once the binary has been unlinked,
    /// which is exactly what a half-finished update leaves behind, and writing
    /// a file with that name would put an update somewhere nothing will ever
    /// execute it from.
    pub fn running() -> Result<Paths> {
        let binary = std::env::current_exe().map_err(|error| {
            Error::Ota(format!(
                "this device cannot tell which binary it is running, so it cannot \
                 replace it: {error}"
            ))
        })?;
        if binary.to_string_lossy().ends_with(" (deleted)") {
            return Err(Error::Ota(format!(
                "the running binary at {} has been unlinked, so there is nowhere \
                 to install an update. Something replaced it without going \
                 through this device.",
                binary.display()
            )));
        }
        Ok(Paths::beside(binary))
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Everything an update needs, held for the life of the process.
pub(crate) struct Updater {
    paths: Paths,
    running: Firmware,
    key: PathBuf,
    journal: journal::Store,
    http: reqwest::Client,
    flushed: Arc<Notify>,
    /// The last sha refused for being on the rejected list. The announcement
    /// is retained, so without this every reconnect republishes the same
    /// refusal for the rest of the device's life.
    refused: Option<String>,
}

impl Updater {
    pub fn new(
        paths: Paths,
        running: Firmware,
        key: PathBuf,
        journal: journal::Store,
        flushed: Arc<Notify>,
    ) -> Result<Updater> {
        let http = reqwest::Client::builder()
            // REDIRECTS ARE ALLOWED HERE AND REFUSED AT ENROLLMENT, and the
            // difference is what is being carried. An enrollment request holds
            // a rotating credential in its body, so a redirect can steal it.
            // This request carries nothing and asks for bytes whose signature
            // was checked before the request was made, so where they come from
            // is not a trust decision. Object stores redirect as a matter of
            // course.
            .redirect(reqwest::redirect::Policy::limited(5))
            .use_preconfigured_tls(crate::enroll::public_roots())
            // A STALL TIMER AND NOT A TOTAL BUDGET. A rollout times out on
            // being stuck rather than on taking a while, and a firmware image
            // over a metered uplink legitimately takes a while.
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(Duration::from_secs(60))
            .user_agent(concat!("openqtt-device/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| Error::Crypto(format!("could not build an https client: {error}")))?;
        Ok(Updater {
            paths,
            running,
            key,
            journal,
            http,
            flushed,
            refused: None,
        })
    }

    pub fn running(&self) -> &Firmware {
        &self.running
    }

    /// Answer an announcement.
    pub async fn accept(&mut self, publisher: &Publisher, announced: &Announcement) -> Next {
        match self.install(publisher, announced).await {
            Ok(next) => next,
            Err(error) => {
                tracing::error!(%error, version = %announced.version, "this update was not installed");
                event(
                    publisher,
                    &announced.version,
                    &announced.sha256,
                    "failed",
                    &error.to_string(),
                )
                .await;
                Next::Carry
            }
        }
    }

    /// THE EXIT IS NOT IN HERE, and that is deliberate. A function that ends
    /// the process cannot be run by a test, and the two renames it performs are
    /// the part most worth testing. What it returns is whether the binary on
    /// disk is still the one running.
    async fn install(&mut self, publisher: &Publisher, announced: &Announcement) -> Result<Next> {
        // DESIRED STATE, NOT AN ORDER, AND THIS COMPARISON IS THE WHOLE
        // DEDUPLICATION. It is why the announcement can be retained and
        // redelivered on every reconnect with no job-id file anywhere.
        if announced.sha256.eq_ignore_ascii_case(&self.running.sha256) {
            return Ok(Next::Carry);
        }

        let mut held = self.journal.load()?;
        // A DIFFERENT SHA CLEARS THE REFUSAL, and that is how a device that
        // rolled back comes home: the platform ships a fix, and the fix is not
        // the build that failed.
        if held
            .rejected
            .as_deref()
            .is_some_and(|sha| !sha.eq_ignore_ascii_case(&announced.sha256))
        {
            held = self.journal.update(|journal| journal.rejected = None)?;
            self.refused = None;
        }
        if held.rejected.is_some() {
            // Said once per process. The announcement is retained, so
            // repeating it would mean a refusal on every reconnect forever.
            if self.refused.as_deref() == Some(announced.sha256.as_str()) {
                return Ok(Next::Carry);
            }
            self.refused = Some(announced.sha256.clone());
            return Err(Error::Ota(format!(
                "{} was rolled back on this device by a gating test and will not \
                 be installed again. Announcing a different build clears this.",
                announced.version
            )));
        }
        if let Some(proving) = held.probation {
            return Err(Error::Ota(format!(
                "{} is still proving itself here, so nothing else is installed \
                 until it has. Attempt {} of {PROBATION_ATTEMPTS}.",
                proving.version, proving.attempts
            )));
        }

        // REFUSE TO CLOBBER `.old`. If the last update's health check hung,
        // that file is the last binary known to work, and overwriting it makes
        // the rollback target the previous bad one instead.
        if self.paths.previous.exists() {
            return Err(Error::Ota(format!(
                "{} is already there and is the last binary known to work. \
                 Overwriting it would make the next rollback land on a build \
                 that already failed, so nothing is installed until somebody \
                 looks at it.",
                self.paths.previous.display()
            )));
        }

        // BEFORE A SINGLE BYTE IS WRITTEN. The CDN is a distribution point and
        // never a trust anchor, so nothing it serves is touched until the
        // platform's signature over the digest has been checked against the key
        // on this disk.
        let digest = unhex(&announced.sha256)?;
        let signature = unbase64(&announced.signature)?;
        verify(&self.key, &digest, &signature).inspect_err(|_| {
            tracing::error!(
                key_version = announced.key_version.as_deref().unwrap_or("unnamed"),
                key = %self.key.display(),
                "the signature on this artifact does not check out against the key on disk"
            );
        })?;

        tracing::info!(version = %announced.version, sha256 = %announced.sha256, "installing an update");
        event(
            publisher,
            &announced.version,
            &announced.sha256,
            "started",
            "",
        )
        .await;

        self.download(publisher, announced, &digest).await?;

        progress(publisher, &announced.version, "applying", 100).await;
        let previous = self.running.sha256.clone();
        // THE MARKER GOES DOWN BEFORE THE RENAMES. It is the only thing that
        // makes the gap between them recoverable: with it, whatever comes up
        // next knows which binary was supposed to be running and which one to
        // put back. Without it there are two files with confusing names and
        // nothing that can safely be concluded from them.
        self.journal.update(|journal| {
            journal.probation = Some(Probation::new(
                &announced.version,
                &announced.sha256,
                &previous,
                PROBATION_WINDOW,
            ));
        })?;

        if let Err(error) = self.swap() {
            // The swap put itself back, so the marker is describing an update
            // that is not installed. Take it down rather than leave the next
            // boot something to puzzle over.
            let _ = self.journal.update(|journal| journal.probation = None);
            let _ = std::fs::remove_file(&self.paths.staged);
            return Err(error);
        }

        Ok(Next::Restart {
            into: announced.version.clone(),
        })
    }

    /// Say the one thing that has to survive, then hand the process back to
    /// the service manager. Never returns.
    pub async fn depart(&self, publisher: &Publisher, into: &str) -> ! {
        farewell(publisher, &self.flushed, into).await;
        restart()
    }

    /// Fetch the artifact into the staging file and check what arrived.
    async fn download(
        &self,
        publisher: &Publisher,
        announced: &Announcement,
        expected: &[u8],
    ) -> Result<()> {
        if !secure(&announced.url) {
            return Err(Error::Ota(format!(
                "the artifact url {} is not encrypted. The signature makes the \
                 bytes trustworthy either way, but the url alone says which \
                 firmware this device runs.",
                announced.url
            )));
        }
        // A leftover from an interrupted download. Nothing ever renamed it, so
        // nothing depends on it.
        remove_if_present(&self.paths.staged)?;

        let mut response = self
            .http
            .get(&announced.url)
            .send()
            .await
            .map_err(|source| Error::Transport {
                url: announced.url.clone(),
                source,
            })?;
        if !response.status().is_success() {
            return Err(Error::Ota(format!(
                "the artifact url answered {}",
                response.status().as_u16()
            )));
        }
        let total = response.content_length();
        if total.is_some_and(|length| length > MAX_ARTIFACT) {
            return Err(Error::Ota(format!(
                "the artifact is {} bytes, and this device will not write more \
                 than {MAX_ARTIFACT} beside its own binary.",
                total.unwrap_or_default()
            )));
        }

        // WRITTEN PRIVATE AND NOT EXECUTABLE. Whatever mode the running binary
        // has is copied onto this one at the very end, after the digest has
        // been checked, so a half-finished download is never a file the system
        // can be persuaded to run.
        let mut file = create_private(&self.paths.staged).await?;
        let mut hasher = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        let mut written = 0u64;
        let mut announced_at = 0u64;
        progress(publisher, &announced.version, "downloading", 0).await;

        loop {
            let chunk = response.chunk().await.map_err(|source| Error::Transport {
                url: announced.url.clone(),
                source,
            })?;
            let Some(chunk) = chunk else { break };
            written += chunk.len() as u64;
            if written > MAX_ARTIFACT {
                let _ = std::fs::remove_file(&self.paths.staged);
                return Err(Error::Ota(format!(
                    "the artifact passed {MAX_ARTIFACT} bytes without ending."
                )));
            }
            hasher.update(&chunk);
            file.write_all(&chunk)
                .await
                .map_err(|error| io(&self.paths.staged, error))?;

            if written - announced_at >= PROGRESS_STEP {
                announced_at = written;
                let percent = total.map_or(0, |length| {
                    (written.saturating_mul(100) / length.max(1)).min(100)
                });
                progress(publisher, &announced.version, "downloading", percent).await;
            }
        }

        file.sync_all()
            .await
            .map_err(|error| io(&self.paths.staged, error))?;
        drop(file);

        progress(publisher, &announced.version, "verifying", 100).await;
        let arrived = hasher.finish();
        if arrived.as_ref() != expected {
            let _ = std::fs::remove_file(&self.paths.staged);
            return Err(Error::Ota(format!(
                "the artifact hashes to {} and the announcement said {}. The \
                 signature was over the announced digest, so these bytes are \
                 not the ones that were signed.",
                hex(arrived.as_ref()),
                announced.sha256
            )));
        }

        // Only now, and copied from the binary it replaces rather than guessed:
        // 0755 is usually right and is not this crate's decision to make.
        copy_mode(&self.paths.binary, &self.paths.staged)?;
        Ok(())
    }

    /// Two renames, in the order that leaves something to recover from.
    ///
    /// A POWER CUT BETWEEN THEM LEAVES NO BINARY AT THE PATH, and there is no
    /// arrangement of renames that avoids that while still keeping a copy of
    /// the old one under a name of its own. What makes it survivable is the
    /// marker written before either of them: `.old` holds the last binary that
    /// worked and the journal says so, which is enough for anything that runs
    /// next to put it back. A failure of the SECOND rename is recovered here
    /// and now, because this process is still alive to do it.
    fn swap(&self) -> Result<()> {
        std::fs::rename(&self.paths.binary, &self.paths.previous)
            .map_err(|error| io(&self.paths.binary, error))?;
        if let Err(error) = std::fs::rename(&self.paths.staged, &self.paths.binary) {
            let put_back = std::fs::rename(&self.paths.previous, &self.paths.binary);
            if let Err(second) = put_back {
                return Err(Error::Ota(format!(
                    "the update could not be moved into place ({error}) and the \
                     binary it replaced could not be moved back either \
                     ({second}). {} holds the last binary that worked.",
                    self.paths.previous.display()
                )));
            }
            return Err(Error::Ota(format!(
                "the update could not be moved into place: {error}. The binary \
                 that was running has been put back."
            )));
        }
        Ok(())
    }
}

/// Whether the binary on disk is still the one this process is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Next {
    /// Carry on.
    Carry,
    /// The swap happened. Nothing else this process does matters now.
    Restart {
        /// What it is restarting into, for the message that goes out first.
        into: String,
    },
}

/// What the marker and the binary that actually booted say between them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// Nothing is being proved.
    Settled,
    /// This process is the candidate, and has to earn its place.
    Proving(Box<Probation>),
    /// The candidate never booted, and what did boot is the binary it was
    /// meant to replace. Nothing is broken; the update simply did not happen.
    Abandoned(Box<Probation>),
    /// The marker names a firmware nobody here is running, and the binary that
    /// booted is not the one it replaced either.
    Unrecoverable(String),
}

/// Read the situation from the marker and the sha of the binary that booted.
///
/// A PURE FUNCTION ON PURPOSE, because every branch of it is a state somebody
/// will only ever reach after a power cut, and the only way to be sure about
/// those is to write them down and test them.
///
/// REFUSING TO GUESS IS THE POINT OF THE LAST ARM. Three shas that do not
/// agree can mean a half-finished swap, or an operator who copied a binary
/// into place by hand, and putting `.old` back would be right in one of those
/// and destructive in the other. Saying so and changing nothing is the only
/// answer that is never wrong.
pub(crate) fn standing(journal: &Journal, running: &str) -> Standing {
    let Some(proving) = journal.probation.clone() else {
        return Standing::Settled;
    };
    if proving.sha256.eq_ignore_ascii_case(running) {
        return Standing::Proving(Box::new(proving));
    }
    if proving.previous_sha256.eq_ignore_ascii_case(running) {
        return Standing::Abandoned(Box::new(proving));
    }
    Standing::Unrecoverable(format!(
        "{} is on probation here and the binary that booted is neither it nor \
         the {} it replaced. This device is running {running} and nothing on \
         disk explains how. Nothing has been restored: check the binary, then \
         delete the journal beside the state file to clear this.",
        proving.sha256, proving.previous_sha256
    ))
}

/// Settle an update that has not been settled yet. Called once, at startup.
///
/// IT MUST NOT WAIT FOR THE BROKER AND IT DOES NOT. The firmware most in need
/// of being rolled back is the one that broke the network, so a rollback that
/// depended on a connection would be missing precisely when it is needed.
/// Everything published here is best effort; the decision is not.
pub(crate) async fn settle(
    updater: &mut Updater,
    publisher: &Publisher,
    probes: &Registry,
) -> Next {
    let held = match updater.journal.load() {
        Ok(held) => held,
        Err(error) => {
            // The journal is the only record of an update in flight, so an
            // unreadable one is exactly the ambiguity this refuses to resolve.
            tracing::error!(%error, "cannot tell whether an update is being proved here");
            return Next::Carry;
        }
    };

    match standing(&held, &updater.running.sha256) {
        Standing::Settled => {
            if updater.paths.previous.exists() {
                // No marker, so nothing here knows what that file is. It is
                // refused as a rollback target and it blocks the next update
                // until a person removes it, which is the loud version of a
                // question this code is not allowed to answer.
                tracing::warn!(
                    file = %updater.paths.previous.display(),
                    "there is a spare binary here and no record of an update. \
                     Nothing will be restored from it and no update will be \
                     installed until it is gone"
                );
            }
        }
        Standing::Unrecoverable(why) => {
            tracing::error!("{why}");
            event(
                publisher,
                &updater.running.version,
                &updater.running.sha256,
                "failed",
                &why,
            )
            .await;
        }
        Standing::Abandoned(proving) => {
            let why = format!(
                "{} was installed and never booted; this device came back up on the \
                 firmware it was meant to replace",
                proving.version
            );
            tracing::error!("{why}");
            // Recorded as rejected for the same reason a rollback is: the
            // announcement is retained, so a candidate that cannot boot would
            // otherwise be installed again on the next connect, forever.
            if let Err(error) = updater.journal.update(|journal| {
                journal.probation = None;
                journal.rejected = Some(proving.sha256.clone());
            }) {
                tracing::error!(%error, "could not record that this update never booted");
            }
            let _ = remove_if_present(&updater.paths.staged);
            // `.old` is a copy of what is running, under a name that would
            // block the next update.
            if updater.paths.previous.exists() {
                let same = sha256_file(&updater.paths.previous)
                    .is_ok_and(|sha| sha.eq_ignore_ascii_case(&updater.running.sha256));
                if same {
                    let _ = remove_if_present(&updater.paths.previous);
                } else {
                    tracing::warn!(
                        file = %updater.paths.previous.display(),
                        "this is not the binary that booted, so it is left alone"
                    );
                }
            }
            event(publisher, &proving.version, &proving.sha256, "failed", &why).await;
        }
        Standing::Proving(proving) => return prove(updater, publisher, probes, *proving).await,
    }
    Next::Carry
}

/// Run the gating tests and decide.
async fn prove(
    updater: &mut Updater,
    publisher: &Publisher,
    probes: &Registry,
    proving: Probation,
) -> Next {
    // COUNTED BEFORE THE PROBES RUN, because the boot that never reaches them
    // is the one this count is for. A device that crashes during its own
    // gating test would otherwise be on probation for the rest of its life.
    let attempts = proving.attempts.saturating_add(1);
    let mut proving = proving;
    proving.attempts = attempts;
    if let Err(error) = updater
        .journal
        .update(|journal| journal.probation = Some(proving.clone()))
    {
        tracing::error!(%error, "could not count this probation attempt; not proceeding");
        return Next::Carry;
    }

    if proving.over(PROBATION_ATTEMPTS, Utc::now()) {
        let why = format!(
            "{} never reached a verdict in {attempts} boots or before its deadline",
            proving.version
        );
        return revert(updater, publisher, &proving, &why).await;
    }

    tracing::info!(
        version = %proving.version,
        attempts,
        gating = probes.gating().count(),
        "this firmware is on probation"
    );
    let answers = crate::tests::gate(probes).await;

    if let Some(failed) = answers.iter().find(|answer| answer.outcome.reverts()) {
        let why = format!("{} failed: {}", failed.id, failed.message);
        return revert(updater, publisher, &proving, &why).await;
    }

    // A TIMEOUT IS NOT A FAILURE AND MUST NOT REVERT ANYTHING BY ITSELF. An
    // unanswered test means the state of this device is unknown, which is a
    // different thing from bad. The marker stays where it is, the attempt has
    // been counted, and the deadline is what eventually decides for a device
    // that cannot answer at all.
    if let Some(quiet) = answers
        .iter()
        .find(|answer| answer.outcome == crate::tests::Outcome::Timeout)
    {
        tracing::warn!(
            test_id = %quiet.id,
            version = %proving.version,
            attempts,
            "a gating test did not answer, so this update is neither kept nor \
             reverted yet"
        );
        return Next::Carry;
    }

    commit(updater, publisher, &proving).await;
    Next::Carry
}

/// Keep it.
async fn commit(updater: &mut Updater, publisher: &Publisher, proving: &Probation) {
    if let Err(error) = remove_if_present(&updater.paths.previous) {
        // Not fatal, but it blocks the next update, so it has to be loud.
        tracing::error!(%error, "could not remove the binary this update replaced");
    }
    if let Err(error) = updater.journal.update(|journal| journal.probation = None) {
        tracing::error!(%error, "could not clear the probation marker");
    }
    tracing::info!(version = %proving.version, "update kept");
    let _ = publisher.json(META_TOPIC, &updater.running.meta()).await;
    event(
        publisher,
        &updater.running.version,
        &updater.running.sha256,
        "succeeded",
        "",
    )
    .await;
}

/// Put the old one back and go, or say why that cannot be done.
async fn revert(
    updater: &mut Updater,
    publisher: &Publisher,
    proving: &Probation,
    why: &str,
) -> Next {
    tracing::error!(version = %proving.version, "{why}");

    // REFUSE TO GUESS. The only thing that may be restored is a file whose
    // contents are the ones the marker says were there. Anything else is a
    // binary somebody put here by hand, and putting it into place could be the
    // single most destructive thing this device ever does.
    let held = match sha256_file(&updater.paths.previous) {
        Ok(sha) if sha.eq_ignore_ascii_case(&proving.previous_sha256) => sha,
        found => {
            let sentence = match found {
                Ok(sha) => format!(
                    "{} holds {sha} and the marker says the binary to restore is \
                     {}, so it has not been restored",
                    updater.paths.previous.display(),
                    proving.previous_sha256
                ),
                Err(error) => format!(
                    "there is nothing to roll back to: {error}. This device is \
                     running firmware that failed its own gating test"
                ),
            };
            tracing::error!("{sentence}");
            // The marker comes down and the sha is refused. Leaving the marker
            // would mean re-running the gate on every boot for the rest of the
            // device's life, and it has already given its answer.
            if let Err(error) = updater.journal.update(|journal| {
                journal.probation = None;
                journal.rejected = Some(proving.sha256.clone());
            }) {
                tracing::error!(%error, "could not record the failed update");
            }
            event(
                publisher,
                &proving.version,
                &proving.sha256,
                "failed",
                &format!("{why}. {sentence}"),
            )
            .await;
            return Next::Carry;
        }
    };
    let _ = held;

    if let Err(error) = std::fs::rename(&updater.paths.previous, &updater.paths.binary) {
        tracing::error!(%error, "the previous binary could not be moved back into place");
        event(
            publisher,
            &proving.version,
            &proving.sha256,
            "failed",
            &format!("{why}. The rollback itself failed: {error}"),
        )
        .await;
        return Next::Carry;
    }

    // THE RENAME FIRST AND THE JOURNAL SECOND. A crash between them leaves a
    // marker for a candidate that is no longer installed running beside the
    // binary it named as previous, which `standing` reads as abandoned and
    // tidies up. The other order would leave the failed binary in place with
    // nothing recording that it failed.
    if let Err(error) = updater.journal.update(|journal| {
        journal.probation = None;
        journal.rejected = Some(proving.sha256.clone());
    }) {
        tracing::error!(%error, "rolled back but could not record it; this build may be installed again");
    }

    event(
        publisher,
        &proving.version,
        &proving.sha256,
        "rolled_back",
        why,
    )
    .await;
    Next::Restart {
        into: proving.previous_sha256.clone(),
    }
}

/// Say the one thing that has to survive, then go.
///
/// BOUNDED, AND IN THIS ORDER. The intent has to be published BEFORE the
/// DISCONNECT, because the broker tears the session down when it sees one and
/// anything after that is dropped on the floor. Waiting for the disconnect to
/// actually leave is what flushes everything queued ahead of it, because
/// rumqttc drains its request queue in order: seeing the DISCONNECT go out
/// means the intent went out too. Both waits are bounded, because a device on
/// its way to a restart must not be able to hang here.
async fn farewell(publisher: &Publisher, flushed: &Notify, version: &str) {
    let (topic, body) = Signal::Updating {
        to: version.to_string(),
    }
    .message(Utc::now());
    if tokio::time::timeout(PRE_EXIT_BUDGET, publisher.json(&topic, &body))
        .await
        .is_err()
    {
        tracing::warn!("could not say that this device is restarting; going anyway");
    }

    // Registered before the disconnect is asked for. A notification with no
    // waiter is dropped, so building the future afterwards is a race that
    // loses exactly when the connection is fastest.
    let flushed = flushed.notified();
    tokio::pin!(flushed);
    flushed.as_mut().enable();
    publisher.disconnect().await;
    if tokio::time::timeout(PRE_EXIT_BUDGET, flushed)
        .await
        .is_err()
    {
        tracing::warn!("restarting without confirmation that the last message was sent");
    }
}

/// Hand the process back to the service manager. See this module's header for
/// the two lines the unit file needs.
fn restart() -> ! {
    tracing::warn!(
        code = RESTART,
        "restarting so the new binary is the one running"
    );
    std::process::exit(RESTART)
}

async fn progress(publisher: &Publisher, version: &str, state: &str, percent: u64) {
    let body = serde_json::json!({ "version": version, "state": state, "percent": percent });
    if let Err(error) = publisher.json(PROGRESS_TOPIC, &body).await {
        tracing::debug!(%error, "could not report update progress");
    }
}

async fn event(publisher: &Publisher, version: &str, sha256: &str, state: &str, message: &str) {
    let body = serde_json::json!({
        "version": version,
        "sha256": sha256,
        "state": state,
        "message": message,
    });
    if let Err(error) = publisher.json(EVENT_TOPIC, &body).await {
        tracing::warn!(%error, state, "could not report an update event");
    }
}

/// One key, checked the way the root certificate is checked.
///
/// EXACTLY ONE, and a file with two in it is an error rather than a
/// convenience. This is the anchor that decides what runs on the device, and
/// quietly accepting a second one because somebody concatenated two files is
/// how it stops being an anchor.
fn public_key(path: &Path) -> Result<Vec<u8>> {
    let pem = std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::Ota(format!(
                "There is no firmware signing key at {}. Updates are checked \
                 against it and nothing else, so none will be installed until \
                 the file is there. Ask the platform operator for it, or point \
                 OPENQTT_ARTIFACT_KEY somewhere else.",
                path.display()
            ))
        } else {
            io(path, error)
        }
    })?;

    let mut found = Vec::new();
    for item in rustls_pemfile::read_all(&mut std::io::BufReader::new(pem.as_bytes())) {
        match item.map_err(|error| io(path, error))? {
            rustls_pemfile::Item::SubjectPublicKeyInfo(key) => found.push(key.as_ref().to_vec()),
            _ => {
                return Err(Error::Ota(format!(
                    "{} holds something that is not a public key.",
                    path.display()
                )))
            }
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(Error::Ota(format!(
            "{} holds no public key. It should hold one PEM block that begins \
             BEGIN PUBLIC KEY.",
            path.display()
        ))),
        many => Err(Error::Ota(format!(
            "{} holds {many} public keys and it must hold exactly one: this is \
             the single anchor that decides what runs on this device.",
            path.display()
        ))),
    }
}

/// ECDSA P-256 over the raw 32 bytes of the sha256, DER, as the protocol says.
fn verify(key: &Path, digest: &[u8], signature: &[u8]) -> Result<()> {
    let spki = public_key(key)?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, spki)
        .verify(digest, signature)
        .map_err(|_| {
            Error::Ota(
                "the signature over this artifact's digest is not valid for the \
                 firmware signing key on this device."
                    .to_string(),
            )
        })
}

fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).map_err(|error| io(path, error))?;
    let mut hasher = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| io(path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(hasher.finish().as_ref()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The 32 bytes a sha256 in the announcement stands for.
fn unhex(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if text.len() != 64 {
        return Err(Error::Ota(format!(
            "a sha256 is 64 hexadecimal characters and this one is {}.",
            text.len()
        )));
    }
    (0..32)
        .map(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                .map_err(|_| Error::Ota("the announced sha256 is not hexadecimal.".to_string()))
        })
        .collect()
}

/// Standard base64, which is what the signature arrives as.
///
/// Written out rather than depended on. Two versions of the `base64` crate are
/// already in this tree through other people's dependencies, and neither of
/// them is more "the" one than the other; thirty lines that only ever decode
/// one field are cheaper than choosing.
fn unbase64(text: &str) -> Result<Vec<u8>> {
    let mut bits = 0u32;
    let mut held = 0u32;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            // Padding carries no bits, and trailing whitespace is what a shell
            // adds to a file somebody echoed a signature into.
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return Err(Error::Ota("the signature is not base64.".to_string())),
        };
        held = (held << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((held >> bits) as u8);
            held &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err(Error::Ota("the signature is empty.".to_string()));
    }
    Ok(out)
}

/// Whether an artifact url keeps its own name to itself.
fn secure(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    url.strip_prefix("http://")
        .is_some_and(crate::config::is_loopback)
}

async fn create_private(path: &Path) -> Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).await.map_err(|error| io(path, error))
}

/// Whatever the operator chose for the running binary, not whatever this crate
/// would have guessed.
fn copy_mode(from: &Path, to: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(from)
            .map_err(|error| io(from, error))?
            .permissions();
        std::fs::set_permissions(to, mode).map_err(|error| io(to, error))?;
    }
    #[cfg(not(unix))]
    let _ = (from, to);
    Ok(())
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(path, error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mqtt::spy;
    use crate::tests::{Outcome, Probe};
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The platform's artifact key, and a signature over a digest with it.
    struct Signer {
        key: EcdsaKeyPair,
    }

    impl Signer {
        fn new() -> Signer {
            Signer {
                key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap(),
            }
        }

        /// PEM, `BEGIN PUBLIC KEY`, which is the shape a KMS export has.
        fn pem(&self) -> String {
            use aws_lc_rs::encoding::AsDer;
            let der: aws_lc_rs::encoding::PublicKeyX509Der<'_> =
                self.key.public_key().as_der().unwrap();
            let body = base64(der.as_ref());
            let wrapped: Vec<&str> = body
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).unwrap())
                .collect();
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                wrapped.join("\n")
            )
        }

        fn sign(&self, digest: &[u8]) -> String {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            base64(self.key.sign(&rng, digest).unwrap().as_ref())
        }
    }

    fn base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for group in bytes.chunks(3) {
            let mut block = [0u8; 3];
            block[..group.len()].copy_from_slice(group);
            let packed =
                (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
            for index in 0..4 {
                if index <= group.len() {
                    out.push(ALPHABET[((packed >> (18 - index * 6)) & 0x3f) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// A device with a binary, a key on disk and somewhere to write.
    struct Bench {
        _home: tempfile::TempDir,
        _server: MockServer,
        updater: Updater,
        journal: journal::Store,
        paths: Paths,
        signer: Signer,
        artifact: Vec<u8>,
        url: String,
    }

    impl Bench {
        async fn new() -> Bench {
            Bench::with_artifact(b"the new firmware".to_vec()).await
        }

        async fn with_artifact(artifact: Vec<u8>) -> Bench {
            let home = tempfile::tempdir().unwrap();
            let binary = home.path().join("bin").join("device");
            std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
            std::fs::write(&binary, b"the firmware that is running").unwrap();

            let signer = Signer::new();
            let key = home.path().join("artifact-key.pem");
            std::fs::write(&key, signer.pem()).unwrap();

            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/artifact"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(artifact.clone()))
                .mount(&server)
                .await;

            let paths = Paths::beside(binary.clone());
            let journal = journal::Store::beside(&home.path().join("state.json"));
            let running = Firmware::running("1.3.0", &binary).unwrap();
            let updater = Updater::new(
                paths.clone(),
                running,
                key,
                journal::Store::beside(&home.path().join("state.json")),
                Arc::new(Notify::new()),
            )
            .unwrap();

            let url = format!("{}/artifact", server.uri());
            Bench {
                _home: home,
                _server: server,
                updater,
                journal,
                paths,
                signer,
                artifact,
                url,
            }
        }

        /// A well formed announcement for the artifact this bench serves.
        fn announcement(&self) -> Announcement {
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &self.artifact);
            Announcement {
                version: "1.4.0".to_string(),
                sha256: hex(digest.as_ref()),
                url: self.url.clone(),
                signature: self.signer.sign(digest.as_ref()),
                key_version: Some("projects/openqtt-prod/.../cryptoKeyVersions/1".to_string()),
            }
        }
    }

    #[tokio::test]
    async fn an_update_stages_beside_the_binary_and_keeps_the_old_one() {
        let mut bench = Bench::new().await;
        let (publisher, sent) = spy::publisher();
        let announced = bench.announcement();

        let next = bench.updater.install(&publisher, &announced).await.unwrap();
        assert_eq!(
            next,
            Next::Restart {
                into: "1.4.0".to_string()
            }
        );

        assert_eq!(std::fs::read(&bench.paths.binary).unwrap(), bench.artifact);
        assert_eq!(
            std::fs::read(&bench.paths.previous).unwrap(),
            b"the firmware that is running"
        );
        assert!(!bench.paths.staged.exists(), "the staging file is consumed");

        // Everything is in the binary's own directory, because systemd mounts
        // each ReadWritePaths entry as its own filesystem and a rename across
        // two of those is EXDEV.
        let directory = bench.paths.binary.parent().unwrap();
        assert_eq!(bench.paths.previous.parent().unwrap(), directory);
        assert_eq!(bench.paths.staged.parent().unwrap(), directory);

        // And the marker went down BEFORE the renames, which is the only thing
        // that makes the gap between them recoverable.
        let held = bench.journal.load().unwrap().probation.unwrap();
        assert_eq!(held.sha256, announced.sha256);
        assert_eq!(held.version, "1.4.0");
        assert_eq!(held.attempts, 0);

        let events = spy::bodies(&sent, EVENT_TOPIC);
        assert_eq!(events[0]["state"], "started");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_half_written_artifact_is_never_executable() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut bench = Bench::new().await;
        std::fs::set_permissions(&bench.paths.binary, std::fs::Permissions::from_mode(0o750))
            .unwrap();
        let (publisher, _sent) = spy::publisher();
        let announced = bench.announcement();
        bench.updater.install(&publisher, &announced).await.unwrap();

        // The mode is copied from the binary it replaced and only after the
        // digest checked out, so nothing part way through the download was
        // ever a file the system could be persuaded to run.
        let mode = std::fs::metadata(&bench.paths.binary)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[tokio::test]
    async fn a_signature_that_does_not_check_out_stops_before_anything_is_fetched() {
        let mut bench = Bench::new().await;
        let (publisher, sent) = spy::publisher();
        let mut announced = bench.announcement();
        // Somebody else's key over the same digest.
        announced.signature = Signer::new().sign(&unhex(&announced.sha256).unwrap());

        let error = bench
            .updater
            .install(&publisher, &announced)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not valid"), "{error}");
        assert!(!bench.paths.staged.exists(), "nothing was written");
        assert!(bench.journal.load().unwrap().probation.is_none());
        // Not even asked for: the CDN is a distribution point and never a
        // trust anchor, so the check happens before the request.
        assert!(spy::bodies(&sent, PROGRESS_TOPIC).is_empty());
    }

    #[tokio::test]
    async fn bytes_that_are_not_the_bytes_that_were_signed_are_thrown_away() {
        let mut bench = Bench::with_artifact(b"one thing".to_vec()).await;
        let (publisher, _sent) = spy::publisher();
        // A valid signature over a digest the server does not serve.
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"another thing");
        let announced = Announcement {
            version: "1.4.0".to_string(),
            sha256: hex(digest.as_ref()),
            url: bench.url.clone(),
            signature: bench.signer.sign(digest.as_ref()),
            key_version: None,
        };

        let error = bench
            .updater
            .install(&publisher, &announced)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("not the ones that were signed"),
            "{error}"
        );
        assert!(!bench.paths.staged.exists());
        assert_eq!(
            std::fs::read(&bench.paths.binary).unwrap(),
            b"the firmware that is running"
        );
    }

    #[tokio::test]
    async fn the_last_binary_that_worked_is_never_overwritten() {
        // THE CASE: the previous update's health check hung, so `.old` still
        // holds the last binary known to work. Overwriting it would make the
        // next rollback land on the build that already failed.
        let mut bench = Bench::new().await;
        std::fs::write(&bench.paths.previous, b"the last one that actually worked").unwrap();
        let (publisher, _sent) = spy::publisher();
        let announced = bench.announcement();

        let error = bench
            .updater
            .install(&publisher, &announced)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("last binary known to work"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(&bench.paths.previous).unwrap(),
            b"the last one that actually worked"
        );
    }

    #[tokio::test]
    async fn the_running_sha_is_the_deduplication_and_nothing_else_is() {
        let mut bench = Bench::new().await;
        let (publisher, sent) = spy::publisher();
        let mut announced = bench.announcement();
        announced.sha256 = bench.updater.running.sha256.clone();

        assert_eq!(
            bench.updater.install(&publisher, &announced).await.unwrap(),
            Next::Carry
        );
        assert!(spy::published(&sent).is_empty(), "silence is the answer");
    }

    #[tokio::test]
    async fn a_rolled_back_build_is_refused_and_a_different_one_clears_it() {
        // WITHOUT THIS A DEVICE INSTALLS IT FOREVER. The announcement is
        // retained, so a device that rolled back from X reads X again on the
        // very next connect.
        let mut bench = Bench::new().await;
        let (publisher, sent) = spy::publisher();
        let announced = bench.announcement();
        bench
            .journal
            .update(|journal| journal.rejected = Some(announced.sha256.clone()))
            .unwrap();

        let error = bench
            .updater
            .install(&publisher, &announced)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("rolled back"), "{error}");
        assert_eq!(
            std::fs::read(&bench.paths.binary).unwrap(),
            b"the firmware that is running"
        );

        // Said once and not on every redelivery, or a device would republish
        // the same refusal for the rest of its life.
        assert_eq!(
            bench.updater.accept(&publisher, &announced).await,
            Next::Carry
        );
        assert!(spy::bodies(&sent, EVENT_TOPIC).is_empty());

        // A different sha is the platform shipping a fix, and that is what
        // clears it. This one goes no further than the clearing, because the
        // bench serves the old bytes, and that is all this asserts.
        let mut fixed = bench.announcement();
        fixed.version = "1.4.1".to_string();
        fixed.sha256 = hex(aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            b"a build with the fix in it",
        )
        .as_ref());
        fixed.signature = bench.signer.sign(&unhex(&fixed.sha256).unwrap());
        let _ = bench.updater.install(&publisher, &fixed).await;
        assert!(bench.journal.load().unwrap().rejected.is_none());
    }

    #[tokio::test]
    async fn nothing_new_is_installed_while_something_is_still_proving_itself() {
        let mut bench = Bench::new().await;
        let (publisher, _sent) = spy::publisher();
        bench
            .journal
            .update(|journal| {
                journal.probation = Some(Probation::new(
                    "1.4.0",
                    "aaaa",
                    &bench.updater.running.sha256,
                    PROBATION_WINDOW,
                ));
            })
            .unwrap();

        let mut announced = bench.announcement();
        announced.version = "1.5.0".to_string();
        let error = bench
            .updater
            .install(&publisher, &announced)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("still proving itself"),
            "{error}"
        );
    }

    #[test]
    fn a_failed_second_rename_puts_the_running_binary_back() {
        // THE POWER CUT BETWEEN THE TWO RENAMES, in the one shape a live
        // process can recover from: the first rename landed, the second could
        // not, and this process is still here to undo it.
        let home = tempfile::tempdir().unwrap();
        let binary = home.path().join("device");
        std::fs::write(&binary, b"running").unwrap();
        let paths = Paths::beside(binary.clone());
        let updater = Updater::new(
            paths.clone(),
            Firmware {
                version: "1.3.0".to_string(),
                sha256: "whatever".to_string(),
            },
            home.path().join("artifact-key.pem"),
            journal::Store::beside(&home.path().join("state.json")),
            Arc::new(Notify::new()),
        )
        .unwrap();

        // No staged file, so the second rename cannot succeed.
        let error = updater.swap().unwrap_err();
        assert!(error.to_string().contains("put back"), "{error}");
        assert_eq!(std::fs::read(&binary).unwrap(), b"running");
        assert!(!paths.previous.exists(), "and nothing is left lying around");
    }

    fn marker(candidate: &str, previous: &str) -> Journal {
        Journal {
            probation: Some(Probation::new(
                "1.4.0",
                candidate,
                previous,
                PROBATION_WINDOW,
            )),
            ..Journal::default()
        }
    }

    #[test]
    fn a_device_with_no_marker_is_settled_whatever_else_is_lying_around() {
        assert_eq!(standing(&Journal::default(), "aaaa"), Standing::Settled);
    }

    #[test]
    fn booting_into_the_candidate_is_what_starts_a_probation() {
        assert!(matches!(
            standing(&marker("aaaa", "bbbb"), "aaaa"),
            Standing::Proving(_)
        ));
    }

    #[test]
    fn booting_into_the_binary_the_candidate_replaced_means_it_never_took() {
        assert!(matches!(
            standing(&marker("aaaa", "bbbb"), "bbbb"),
            Standing::Abandoned(_)
        ));
    }

    #[test]
    fn a_third_binary_is_refused_rather_than_guessed_at() {
        // Somebody copied a binary into place by hand. Restoring `.old` would
        // be right if the swap had half happened and destructive here, and
        // there is no way to tell the two apart from this side.
        let Standing::Unrecoverable(why) = standing(&marker("aaaa", "bbbb"), "cccc") else {
            panic!("a binary nobody can account for must not be second-guessed");
        };
        assert!(why.contains("cccc"), "{why}");
        assert!(why.contains("Nothing has been restored"), "{why}");
    }

    /// A bench standing where an update has just been installed: the candidate
    /// is running, `.old` holds what it replaced, and the marker says so.
    async fn on_probation() -> Bench {
        let mut bench = Bench::new().await;
        let (publisher, _sent) = spy::publisher();
        let announced = bench.announcement();
        bench.updater.install(&publisher, &announced).await.unwrap();
        // The restart, as far as a test can have one: this process is now the
        // firmware that was just installed.
        bench.updater.running = Firmware::running("1.4.0", &bench.paths.binary).unwrap();
        bench
    }

    #[tokio::test]
    async fn a_firmware_that_passes_its_gate_is_kept() {
        let mut bench = on_probation().await;
        let (publisher, sent) = spy::publisher();
        let mut probes = Registry::default();
        probes.add(Probe::new("sd_card", |message| {
            message.push_str("mounted, 3.1 GB free");
            Outcome::Pass
        }));

        assert_eq!(
            settle(&mut bench.updater, &publisher, &probes).await,
            Next::Carry
        );
        assert!(bench.journal.load().unwrap().probation.is_none());
        assert!(
            !bench.paths.previous.exists(),
            "committed, so there is nothing to go back to"
        );
        assert_eq!(std::fs::read(&bench.paths.binary).unwrap(), bench.artifact);

        let events = spy::bodies(&sent, EVENT_TOPIC);
        assert_eq!(events.last().unwrap()["state"], "succeeded");
    }

    #[tokio::test]
    async fn a_failing_gate_puts_the_old_binary_back_and_says_which_probe() {
        let mut bench = on_probation().await;
        let (publisher, sent) = spy::publisher();
        let candidate = bench.updater.running.sha256.clone();
        let mut probes = Registry::default();
        probes.add(Probe::new("modbus_link", |message| {
            message.push_str("no reply from the meter");
            Outcome::Fail
        }));

        let next = settle(&mut bench.updater, &publisher, &probes).await;
        assert!(matches!(next, Next::Restart { .. }));
        assert_eq!(
            std::fs::read(&bench.paths.binary).unwrap(),
            b"the firmware that is running"
        );
        assert!(!bench.paths.previous.exists());

        let held = bench.journal.load().unwrap();
        assert!(held.probation.is_none());
        assert_eq!(held.rejected.as_deref(), Some(candidate.as_str()));

        let events = spy::bodies(&sent, EVENT_TOPIC);
        let last = events.last().unwrap();
        assert_eq!(last["state"], "rolled_back");
        assert!(
            last["message"]
                .as_str()
                .unwrap()
                .contains("no reply from the meter"),
            "the probe's own message is what a person reads: {last}"
        );
    }

    /// A gating probe that will not answer until the test lets it, so a test
    /// about timeouts costs one second rather than the probe's own patience.
    /// The flag matters: a blocking task cannot be cancelled, and dropping the
    /// runtime at the end of a test WAITS for it.
    fn never_answers() -> (Probe, Arc<std::sync::atomic::AtomicBool>) {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held = Arc::clone(&stop);
        let probe = Probe::new("modbus_link", move |_| {
            while !held.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Outcome::Pass
        })
        .timeout_secs(1);
        (probe, stop)
    }

    #[tokio::test]
    async fn an_unanswered_gate_reverts_nothing_by_itself() {
        // A TIMEOUT IS NOT A FAILURE. It means the state of the device is not
        // known, and reverting on unknown means one flaky probe reverts a
        // fleet. The deadline is what covers a device that cannot answer.
        let mut bench = on_probation().await;
        let (publisher, sent) = spy::publisher();
        let mut probes = Registry::default();
        let (probe, stop) = never_answers();
        probes.add(probe);

        assert_eq!(
            settle(&mut bench.updater, &publisher, &probes).await,
            Next::Carry
        );
        assert_eq!(std::fs::read(&bench.paths.binary).unwrap(), bench.artifact);
        let held = bench.journal.load().unwrap().probation.unwrap();
        assert_eq!(held.attempts, 1, "counted, and the marker stays");
        assert!(spy::bodies(&sent, EVENT_TOPIC).is_empty());
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[tokio::test]
    async fn a_candidate_that_never_answers_runs_out_of_attempts() {
        let mut bench = on_probation().await;
        let (publisher, _sent) = spy::publisher();
        let mut probes = Registry::default();
        let (probe, stop) = never_answers();
        probes.add(probe);

        // Two boots that reach a probe and cannot get an answer out of it.
        for expected in 1..PROBATION_ATTEMPTS {
            assert_eq!(
                settle(&mut bench.updater, &publisher, &probes).await,
                Next::Carry
            );
            assert_eq!(
                bench.journal.load().unwrap().probation.unwrap().attempts,
                expected
            );
        }
        // The third counts itself and gives up before running anything.
        let next = settle(&mut bench.updater, &publisher, &probes).await;
        assert!(matches!(next, Next::Restart { .. }));
        assert_eq!(
            std::fs::read(&bench.paths.binary).unwrap(),
            b"the firmware that is running"
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[tokio::test]
    async fn a_candidate_that_crashes_before_its_gate_still_runs_out() {
        // The count goes up before the probes run, so a firmware that panics
        // during its own gating test is not on probation for ever.
        let mut bench = on_probation().await;
        let (publisher, _sent) = spy::publisher();
        let probes = Registry::default();
        for _ in 0..PROBATION_ATTEMPTS {
            bench
                .journal
                .update(|journal| {
                    if let Some(held) = journal.probation.as_mut() {
                        held.attempts = held.attempts.saturating_add(1);
                    }
                })
                .unwrap();
        }
        let next = settle(&mut bench.updater, &publisher, &probes).await;
        assert!(matches!(next, Next::Restart { .. }), "{next:?}");
    }

    #[tokio::test]
    async fn a_firmware_with_no_gating_probes_at_all_is_kept() {
        // Vacuously true rather than an oversight: "every gating test passed"
        // with none registered. The build is where a missing gate is caught,
        // because it has the manifest and the binary in front of it.
        let mut bench = on_probation().await;
        let (publisher, _sent) = spy::publisher();
        assert_eq!(
            settle(&mut bench.updater, &publisher, &Registry::default()).await,
            Next::Carry
        );
        assert!(bench.journal.load().unwrap().probation.is_none());
    }

    #[tokio::test]
    async fn a_rollback_target_that_is_not_the_one_recorded_is_refused() {
        // REFUSE TO GUESS. Somebody replaced `.old` by hand between the two
        // boots, and moving it into place could be the most destructive thing
        // this device ever does.
        let mut bench = on_probation().await;
        std::fs::write(&bench.paths.previous, b"somebody else's binary").unwrap();
        let (publisher, sent) = spy::publisher();
        let mut probes = Registry::default();
        probes.add(Probe::new("sd_card", |message| {
            message.push_str("no card");
            Outcome::Fail
        }));

        assert_eq!(
            settle(&mut bench.updater, &publisher, &probes).await,
            Next::Carry,
            "nothing is restored, so nothing restarts"
        );
        assert_eq!(
            std::fs::read(&bench.paths.previous).unwrap(),
            b"somebody else's binary"
        );
        assert_eq!(std::fs::read(&bench.paths.binary).unwrap(), bench.artifact);
        let events = spy::bodies(&sent, EVENT_TOPIC);
        assert_eq!(events.last().unwrap()["state"], "failed");
    }

    #[tokio::test]
    async fn an_update_that_never_booted_is_tidied_up_and_not_installed_again() {
        let mut bench = Bench::new().await;
        let (publisher, sent) = spy::publisher();
        let announced = bench.announcement();
        bench.updater.install(&publisher, &announced).await.unwrap();
        // The power came back on the OLD binary: the swap never completed, or
        // something put it back.
        std::fs::write(&bench.paths.binary, b"the firmware that is running").unwrap();
        std::fs::write(&bench.paths.previous, b"the firmware that is running").unwrap();

        assert_eq!(
            settle(&mut bench.updater, &publisher, &Registry::default()).await,
            Next::Carry
        );
        let held = bench.journal.load().unwrap();
        assert!(held.probation.is_none());
        assert_eq!(
            held.rejected.as_deref(),
            Some(announced.sha256.as_str()),
            "a build that cannot boot must not be installed again on the next connect"
        );
        assert!(
            !bench.paths.previous.exists(),
            "and the next update is not blocked"
        );
        assert_eq!(
            spy::bodies(&sent, EVENT_TOPIC).last().unwrap()["state"],
            "failed"
        );
    }

    #[test]
    fn a_signing_key_file_holds_exactly_one_key() {
        let home = tempfile::tempdir().unwrap();
        let signer = Signer::new();
        let path = home.path().join("artifact-key.pem");

        std::fs::write(&path, format!("{}{}", signer.pem(), Signer::new().pem())).unwrap();
        let error = public_key(&path).unwrap_err().to_string();
        assert!(error.contains("exactly one"), "{error}");

        std::fs::write(&path, signer.pem()).unwrap();
        public_key(&path).unwrap();
    }

    #[test]
    fn a_missing_signing_key_refuses_the_update_rather_than_skipping_the_check() {
        let home = tempfile::tempdir().unwrap();
        let error = verify(&home.path().join("nowhere.pem"), &[0u8; 32], &[0u8; 8])
            .unwrap_err()
            .to_string();
        assert!(error.contains("OPENQTT_ARTIFACT_KEY"), "{error}");
    }

    #[test]
    fn base64_round_trips_through_the_decoder_that_ships() {
        for length in 0..64usize {
            let bytes: Vec<u8> = (0..length).map(|index| (index * 7 + 3) as u8).collect();
            if length == 0 {
                assert!(unbase64(&base64(&bytes)).is_err());
                continue;
            }
            assert_eq!(unbase64(&base64(&bytes)).unwrap(), bytes, "{length} bytes");
        }
        assert!(unbase64("not base64!").is_err());
    }

    #[test]
    fn a_sha256_that_is_not_one_is_refused_by_length() {
        assert!(unhex("aa").is_err());
        assert!(unhex(&"z".repeat(64)).is_err());
        assert_eq!(unhex(&"0f".repeat(32)).unwrap(), vec![0x0f; 32]);
    }

    #[test]
    fn an_unencrypted_artifact_url_is_refused_away_from_loopback() {
        assert!(secure("https://cdn.openqtt.com/artifacts/9f86"));
        assert!(secure("http://127.0.0.1:8099/artifact"));
        assert!(!secure("http://cdn.openqtt.com/artifacts/9f86"));
    }

    #[test]
    fn the_staging_and_previous_files_sit_beside_the_binary() {
        let paths = Paths::beside(PathBuf::from("/opt/acme/pump"));
        assert_eq!(paths.staged, PathBuf::from("/opt/acme/pump.new"));
        assert_eq!(paths.previous, PathBuf::from("/opt/acme/pump.old"));
    }
}
