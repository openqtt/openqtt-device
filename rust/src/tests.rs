//! Diagnostics: what the platform can ask a device to prove about itself.
//!
//! REGISTRATION HAPPENS BEFORE CONNECT, WHICH IS WHY THERE IS A BUILDER. The
//! dispatch is a retained message, so it can arrive on the first CONNACK,
//! before a line after `connect().await` has run. A registry filled in
//! afterwards answers `not_registered` to the first dispatch of every boot and
//! then works perfectly for the rest of the run, which is the worst kind of
//! bug: it reproduces only on the machine that was switched off.
//!
//! A PROBE IS CUSTOMER CODE AND IT RUNS NOWHERE NEAR THE EVENT LOOP. Every one
//! goes to `spawn_blocking` with a bound from the manifest, because the two
//! things a probe does most are block on a file descriptor and take longer
//! than its author believed. Either of those on the task that drives the MQTT
//! connection stops the keepalive, and a device that stops answering PINGREQ is
//! dropped by the broker at keepalive times 1.5 and reads as offline while it
//! is busy proving it is healthy.
//!
//! NO FIXED CAPACITY ANYWHERE IN HERE. The reference implementation used a
//! static array of eight while the one real firmware built against it
//! registered eleven, and its dispatch queue was two deep, which dropped most
//! of any "run all" and surfaced in the console as phantom timeouts on
//! whichever probes happened to be late in the list.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::journal;
use crate::mqtt::Publisher;

/// What the catalogue allows, enforced here rather than asked of the author.
/// A probe that blocks forever must not be able to hold a connection, and a
/// probe given five minutes has had five minutes.
const TIMEOUT_RANGE: std::ops::RangeInclusive<u64> = 1..=300;

/// What a probe gets if its registration did not say. The manifest is the
/// source of truth and a build checks the two against each other, so this is
/// only ever reached by a probe registered without one.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A probe message is read by a person in a console, one line at a time. This
/// is generous for that and small enough that a probe which accidentally
/// returns a log file cannot push the packet past what the broker accepts.
const MAX_MESSAGE: usize = 256;

/// Where the platform asks, and where the answers go.
pub(crate) const DISPATCH_TOPIC: &str = "commands/test";
const RESULT_TOPIC: &str = "test/result";

/// How a probe answered.
///
/// FIVE, NOT TWO, AND EACH OF THE EXTRA THREE EARNS ITS PLACE. `Timeout` means
/// the device's state is not known, which is a different thing from failing and
/// must not revert firmware on its own. `NotRegistered` means the manifest
/// declared a test this binary does not implement, which is a build mistake and
/// should read as one rather than as a hardware fault. `Warn` is for a probe
/// that passes on purpose while reporting bad news: without it, an author whose
/// test gates a rollout has to choose between reverting firmware over a
/// configuration problem and saying nothing at all.
///
/// A probe returns any of the five. The last two are normally the library's to
/// say, but a probe that genuinely knows it could not reach the hardware it
/// tests is telling the truth by saying `Timeout`, and unknown is exactly what
/// a rollback must not act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Healthy.
    Pass,
    /// Healthy, with something a person should read.
    Warn,
    /// Not healthy. This is the one that reverts an update.
    Fail,
    /// No answer. Not a failure: the state is unknown.
    Timeout,
    /// Asked for by name and not built into this firmware.
    NotRegistered,
}

impl Outcome {
    /// The wire value, which is the closed set in the protocol.
    pub(crate) fn status(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Warn => "warn",
            Outcome::Fail => "fail",
            Outcome::Timeout => "timeout",
            Outcome::NotRegistered => "not_registered",
        }
    }

    /// Whether this outcome, from a gating probe, sends an update back.
    ///
    /// ONLY `Fail` DOES, and the omission of `Timeout` is the important half.
    /// An unanswered test means the device's state is unknown, and reverting on
    /// unknown means one flaky probe reverts a fleet. What covers a device that
    /// cannot answer at all is the probation deadline, which is a slower and
    /// much less trigger-happy instrument.
    pub(crate) fn reverts(self) -> bool {
        matches!(self, Outcome::Fail)
    }
}

type Run = dyn Fn(&mut String) -> Outcome + Send + Sync + 'static;

/// One diagnostic this firmware can run.
///
/// The fields mirror an entry in `.openqtt/tests.yml` one for one, because the
/// build has the manifest and the binary in front of it and checks the two
/// lists against each other there. Discovering the disagreement in the field
/// means a typo can revert a fleet.
///
/// ```
/// use openqtt_device::{Outcome, Probe};
///
/// let probe = Probe::new("sd_card", |message| {
///     message.push_str("mounted, 3.1 GB free");
///     Outcome::Pass
/// })
/// .timeout_secs(20);
/// ```
pub struct Probe {
    id: String,
    timeout: Duration,
    gating: bool,
    run: Arc<Run>,
}

impl Probe {
    /// Register `id` to run `probe`.
    ///
    /// The probe writes a short human-readable message into the string it is
    /// handed, and that message is shown verbatim beside the result. It runs on
    /// a blocking thread, so it may do ordinary blocking work: open a device
    /// node, read a file, talk to a bus.
    ///
    /// Gating by default. See [`Probe::gating`].
    pub fn new(
        id: impl Into<String>,
        probe: impl Fn(&mut String) -> Outcome + Send + Sync + 'static,
    ) -> Probe {
        Probe {
            id: id.into(),
            timeout: DEFAULT_TIMEOUT,
            gating: true,
            run: Arc::new(probe),
        }
    }

    /// How long this probe gets, clamped to the 1 to 300 seconds the catalogue
    /// allows. Mirror `timeout_secs` from the manifest entry.
    pub fn timeout_secs(mut self, seconds: u64) -> Probe {
        let allowed = seconds.clamp(*TIMEOUT_RANGE.start(), *TIMEOUT_RANGE.end());
        if allowed != seconds {
            tracing::warn!(
                id = %self.id,
                asked = seconds,
                allowed,
                "a probe timeout outside 1 to 300 seconds was clamped"
            );
        }
        self.timeout = Duration::from_secs(allowed);
        self
    }

    /// Whether failing this probe sends an update back.
    ///
    /// TRUE BY DEFAULT, MIRRORING THE MANIFEST, WHERE `gating` ABSENT MEANS
    /// GATING. A test that can revert an update is the safe default, and the
    /// flag exists to opt out for hardware that legitimately varies per unit: a
    /// bench unit with no GNSS module, a probe that needs sky. Without the opt
    /// out the only choices are a gate that blocks every update on hardware
    /// variance or no gate at all, and the second is what you end up with.
    pub fn gating(mut self, gating: bool) -> Probe {
        self.gating = gating;
        self
    }

    /// The id this probe answers to.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl std::fmt::Debug for Probe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Probe")
            .field("id", &self.id)
            .field("timeout", &self.timeout)
            .field("gating", &self.gating)
            .finish_non_exhaustive()
    }
}

/// Everything this firmware can be asked to run. Filled in before connect and
/// never changed afterwards.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    probes: Vec<Probe>,
}

impl Registry {
    /// Later wins, loudly. Registering an id twice is a mistake either way, and
    /// a device that refuses to start over it is a worse answer than a line in
    /// the log naming the id.
    pub fn add(&mut self, probe: Probe) {
        if let Some(existing) = self.probes.iter().position(|held| held.id == probe.id) {
            tracing::warn!(id = %probe.id, "a second probe was registered under this id; the later one wins");
            self.probes[existing] = probe;
            return;
        }
        self.probes.push(probe);
    }

    fn find(&self, id: &str) -> Option<&Probe> {
        self.probes.iter().find(|probe| probe.id == id)
    }

    /// In registration order, which is the order a `run_all` runs them in.
    fn all(&self) -> &[Probe] {
        &self.probes
    }

    /// The probes that can send an update back.
    pub fn gating(&self) -> impl Iterator<Item = &Probe> {
        self.probes.iter().filter(|probe| probe.gating)
    }
}

/// What the platform sends to `commands/test`.
///
/// THE ONE IMPERATIVE MESSAGE IN THE PROTOCOL, which is why it carries a run
/// id. Running a diagnostic is an act rather than a state, and this message is
/// retained, so without the id a device that renews its certificate daily would
/// re-run its diagnostics forever.
#[derive(Debug, Deserialize)]
pub(crate) struct Dispatch {
    pub run_id: String,
    #[serde(default)]
    pub tests: Vec<String>,
    #[serde(default)]
    pub run_all: bool,
}

/// One probe's answer.
#[derive(Debug, Clone)]
pub(crate) struct Answer {
    pub id: String,
    pub outcome: Outcome,
    pub message: String,
    pub duration: Duration,
}

impl Answer {
    fn body(&self, run_id: &str) -> serde_json::Value {
        serde_json::json!({
            "run_id": run_id,
            "test_id": self.id,
            "status": self.outcome.status(),
            "message": self.message,
            "duration_ms": self.duration.as_millis() as u64,
        })
    }
}

/// Run one probe, off the event loop and inside its bound.
///
/// A TIMEOUT DOES NOT STOP THE PROBE, and there is no way to make it. A
/// blocking task cannot be cancelled: dropping its handle stops the waiting,
/// not the work. So a probe that blocks forever holds one thread of the
/// blocking pool for the life of the process. That is survivable, which
/// "holding the connection" is not, and it is why the bound exists in the
/// library rather than being asked of the author.
pub(crate) async fn run(probe: &Probe) -> Answer {
    let started = Instant::now();
    let seconds = probe.timeout.as_secs();
    let body = Arc::clone(&probe.run);
    let work = tokio::task::spawn_blocking(move || {
        let mut message = String::new();
        let outcome = body(&mut message);
        (outcome, message)
    });

    let (outcome, message) = match tokio::time::timeout(probe.timeout, work).await {
        Ok(Ok((outcome, message))) => (outcome, trimmed(message)),
        // A PANIC IN CUSTOMER CODE IS A FAILED TEST AND NOT A FAILED DEVICE.
        // `spawn_blocking` catches it, so the alternative to naming it here is
        // a probe that silently reports nothing at all.
        Ok(Err(panicked)) => (
            Outcome::Fail,
            format!("the probe panicked: {panicked}").trim().to_string(),
        ),
        Err(_) => (
            Outcome::Timeout,
            format!("no answer after {seconds}s; this probe is still running"),
        ),
    };

    Answer {
        id: probe.id.clone(),
        outcome,
        message,
        duration: started.elapsed(),
    }
}

/// Answer a dispatch: one `test/result` per probe, then remember the run.
///
/// THE RUN ID IS RECORDED BEFORE THE RETAINED MESSAGE IS CLEARED, and the order
/// is the whole reason both exist. The clear is what stops the dispatch coming
/// back on the next connect; the recorded id is what makes it harmless if it
/// does, whether because the clear was denied by the ACL, or lost with the
/// connection, or simply overtaken by a reconnect. Recording after clearing
/// would leave exactly the window this is meant to close.
pub(crate) async fn answer(
    publisher: &Publisher,
    registry: &Registry,
    journal: &journal::Store,
    dispatch: &Dispatch,
) {
    let asked: Vec<String> = if dispatch.run_all {
        registry
            .all()
            .iter()
            .map(|probe| probe.id.clone())
            .collect()
    } else {
        dispatch.tests.clone()
    };

    tracing::info!(run_id = %dispatch.run_id, tests = asked.len(), "running diagnostics");
    for id in &asked {
        let answered = match registry.find(id) {
            Some(probe) => run(probe).await,
            // NAMED RATHER THAN IGNORED. A manifest that declares a test this
            // binary does not have is a build mistake, and silence turns it
            // into a probe that looks like it never finished.
            None => Answer {
                id: id.clone(),
                outcome: Outcome::NotRegistered,
                message: "this firmware has no probe registered under that id".to_string(),
                duration: Duration::ZERO,
            },
        };
        tracing::info!(
            test_id = %answered.id,
            status = answered.outcome.status(),
            message = %answered.message,
            "diagnostic finished"
        );
        if let Err(error) = publisher
            .json(RESULT_TOPIC, &answered.body(&dispatch.run_id))
            .await
        {
            tracing::warn!(%error, test_id = %answered.id, "could not report a diagnostic result");
        }
    }

    if let Err(error) = journal.update(|held| held.answered = Some(dispatch.run_id.clone())) {
        tracing::error!(
            %error,
            run_id = %dispatch.run_id,
            "could not record which diagnostic run was answered; a redelivery will run it again"
        );
    }
    if let Err(error) = publisher.clear(DISPATCH_TOPIC).await {
        tracing::debug!(%error, "could not clear the retained dispatch");
    }
}

/// Run every gating probe, for a firmware that has to prove itself.
///
/// No `test/result` goes out for these: a result carries a run id and there is
/// no dispatch here to have one. What a person sees is the `ota/event`, which
/// carries the message of whichever probe decided the outcome.
pub(crate) async fn gate(registry: &Registry) -> Vec<Answer> {
    let mut answers = Vec::new();
    for probe in registry.gating() {
        answers.push(run(probe).await);
    }
    answers
}

/// Cut a message to something a console can show, on a character boundary.
fn trimmed(mut message: String) -> String {
    if message.len() <= MAX_MESSAGE {
        return message;
    }
    let mut cut = MAX_MESSAGE;
    while cut > 0 && !message.is_char_boundary(cut) {
        cut -= 1;
    }
    message.truncate(cut);
    message
}

// Named for what it tests rather than `tests`, because this module is already
// called that and the nesting reads as a mistake.
#[cfg(test)]
mod probes {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn passing(id: &str) -> Probe {
        Probe::new(id, |message| {
            message.push_str("fine");
            Outcome::Pass
        })
    }

    #[tokio::test]
    async fn a_probe_answers_with_its_message_and_how_long_it_took() {
        let answer = run(&passing("sd_card")).await;
        assert_eq!(answer.outcome, Outcome::Pass);
        assert_eq!(answer.message, "fine");
        assert_eq!(answer.id, "sd_card");
    }

    #[tokio::test]
    async fn a_probe_that_hangs_is_timed_out_rather_than_waited_for() {
        // THE FAILURE THIS EXISTS FOR: a probe blocking on a device node that
        // never answers. On the event loop that stops the keepalive and the
        // broker drops the device while it is busy proving it is healthy.
        //
        // A REAL SECOND, NOT A PAUSED ONE. `start_paused` advances the clock
        // when the runtime goes idle, and a `spawn_blocking` task outstanding
        // is not idle, so a paused version of this test hangs forever. The
        // shortest the catalogue allows is one second and that is what this
        // costs.
        let stop = Arc::new(AtomicBool::new(false));
        let held = Arc::clone(&stop);
        let probe = Probe::new("modbus_link", move |message| {
            while !held.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
            message.push_str("answered eventually, which is too late");
            Outcome::Pass
        })
        .timeout_secs(1);

        let answer = run(&probe).await;
        assert_eq!(answer.outcome, Outcome::Timeout);
        assert!(answer.message.contains("1s"), "{}", answer.message);
        // And it is STILL RUNNING, which the message says out loud because
        // there is no way to stop it and pretending otherwise would be worse.
        assert!(!stop.load(Ordering::Relaxed));
        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn a_probe_that_panics_is_a_failed_test_and_not_a_dead_device() {
        let answer = run(&Probe::new("sd_card", |_| panic!("no card"))).await;
        assert_eq!(answer.outcome, Outcome::Fail);
        assert!(answer.message.contains("panicked"), "{}", answer.message);
    }

    #[tokio::test]
    async fn a_probe_that_returns_a_log_file_is_cut_to_something_a_console_shows() {
        let answer = run(&Probe::new("noisy", |message| {
            message.push_str(&"x".repeat(10_000));
            Outcome::Warn
        }))
        .await;
        assert_eq!(answer.message.len(), MAX_MESSAGE);
    }

    #[test]
    fn a_timeout_outside_the_catalogue_range_is_clamped_rather_than_honoured() {
        assert_eq!(passing("a").timeout_secs(0).timeout, Duration::from_secs(1));
        assert_eq!(
            passing("a").timeout_secs(9_000).timeout,
            Duration::from_secs(300)
        );
    }

    #[test]
    fn only_a_failure_sends_an_update_back() {
        assert!(Outcome::Fail.reverts());
        for undecided in [
            Outcome::Pass,
            Outcome::Warn,
            Outcome::Timeout,
            Outcome::NotRegistered,
        ] {
            assert!(!undecided.reverts(), "{undecided:?}");
        }
    }

    #[test]
    fn the_registry_has_no_ceiling() {
        // The reference implementation had a static array of eight and its one
        // real firmware registered eleven.
        let mut registry = Registry::default();
        for index in 0..64 {
            registry.add(passing(&format!("probe_{index}")));
        }
        assert_eq!(registry.all().len(), 64);
        assert!(registry.find("probe_63").is_some());
    }

    #[test]
    fn registering_an_id_twice_keeps_the_later_one() {
        let mut registry = Registry::default();
        registry.add(passing("sd_card").timeout_secs(9));
        registry.add(passing("sd_card").timeout_secs(11));
        assert_eq!(registry.all().len(), 1);
        assert_eq!(registry.find("sd_card").unwrap().timeout.as_secs(), 11);
    }

    #[test]
    fn gating_is_the_default_and_the_opt_out_is_explicit() {
        let mut registry = Registry::default();
        registry.add(passing("sd_card"));
        registry.add(passing("gps").gating(false));
        let gated: Vec<&str> = registry.gating().map(|probe| probe.id()).collect();
        assert_eq!(gated, ["sd_card"]);
    }

    #[tokio::test]
    async fn a_run_all_runs_everything_registered() {
        let (publisher, sent) = crate::mqtt::spy::publisher();
        let home = tempfile::tempdir().unwrap();
        let journal = journal::Store::beside(&home.path().join("state.json"));

        let ran = Arc::new(AtomicUsize::new(0));
        let mut registry = Registry::default();
        for index in 0..11 {
            let counted = Arc::clone(&ran);
            registry.add(Probe::new(format!("probe_{index}"), move |message| {
                counted.fetch_add(1, Ordering::SeqCst);
                message.push_str("fine");
                Outcome::Pass
            }));
        }

        answer(
            &publisher,
            &registry,
            &journal,
            &Dispatch {
                run_id: "0f9b2c1e".to_string(),
                tests: Vec::new(),
                run_all: true,
            },
        )
        .await;

        assert_eq!(ran.load(Ordering::SeqCst), 11);
        let results = crate::mqtt::spy::published(&sent);
        assert_eq!(
            results
                .iter()
                .filter(|(topic, _, _)| topic == RESULT_TOPIC)
                .count(),
            11,
            "one result per probe"
        );
    }

    #[tokio::test]
    async fn a_test_the_manifest_declared_and_the_binary_lacks_is_named() {
        let (publisher, sent) = crate::mqtt::spy::publisher();
        let home = tempfile::tempdir().unwrap();
        let journal = journal::Store::beside(&home.path().join("state.json"));

        let mut registry = Registry::default();
        registry.add(passing("sd_card"));

        answer(
            &publisher,
            &registry,
            &journal,
            &Dispatch {
                run_id: "0f9b2c1e".to_string(),
                tests: vec!["sd_card".to_string(), "modbus_link".to_string()],
                run_all: false,
            },
        )
        .await;

        let bodies = crate::mqtt::spy::bodies(&sent, RESULT_TOPIC);
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0]["status"], "pass");
        assert_eq!(bodies[1]["test_id"], "modbus_link");
        assert_eq!(bodies[1]["status"], "not_registered");
        assert_eq!(bodies[1]["run_id"], "0f9b2c1e");
    }

    #[tokio::test]
    async fn the_run_is_recorded_before_the_retained_dispatch_is_cleared() {
        // The clear can be denied by the ACL and arrives as silence when it
        // is. What actually stops a redelivery from running everything twice
        // is the recorded id, so it has to be on disk first.
        let (publisher, sent) = crate::mqtt::spy::publisher();
        let home = tempfile::tempdir().unwrap();
        let journal = journal::Store::beside(&home.path().join("state.json"));
        let mut registry = Registry::default();
        registry.add(passing("sd_card"));

        answer(
            &publisher,
            &registry,
            &journal,
            &Dispatch {
                run_id: "0f9b2c1e".to_string(),
                tests: vec!["sd_card".to_string()],
                run_all: false,
            },
        )
        .await;

        assert_eq!(
            journal.load().unwrap().answered.as_deref(),
            Some("0f9b2c1e")
        );
        let last = crate::mqtt::spy::published(&sent).pop().unwrap();
        assert_eq!(last.0, DISPATCH_TOPIC, "the clear goes out last");
        assert!(last.1.is_empty(), "a clear is zero bytes");
        assert!(last.2, "and it is the one thing this crate retains");
    }

    #[tokio::test]
    async fn only_gating_probes_decide_an_update() {
        let mut registry = Registry::default();
        registry.add(passing("sd_card"));
        registry.add(
            Probe::new("gps", |message| {
                message.push_str("no sky");
                Outcome::Fail
            })
            .gating(false),
        );

        let answers = gate(&registry).await;
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].id, "sd_card");
    }
}
