//! Enrol a device with OpenQTT, keep its certificate fresh, and publish.
//!
//! ```no_run
//! # async fn run() -> Result<(), openqtt_device::Error> {
//! let device = openqtt_device::Device::connect().await?;
//! device.publish("temperature", 21.5).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # What this is for
//!
//! Not wrapping MQTT. Publishing is three lines in any client and a library
//! that only removed those would have removed almost nothing. What is actually
//! hard is identity: generating a key that never leaves the machine, turning a
//! one-time token into a certificate, keeping that certificate alive across
//! years of power cuts and bad uplinks, and doing it against a broker whose
//! rules are not the defaults.
//!
//! # What a device needs before it starts
//!
//! One certificate on disk and two variables.
//!
//! - `OPENQTT_ROOT_CA`, default `/etc/openqtt/root.pem`: the OpenQTT Root CA.
//!   THIS IS NOT OPTIONAL AND THERE IS NO PUBLIC FALLBACK. The broker's
//!   certificate is issued by a private authority, so the Mozilla bundle
//!   rejects it. Get the file from the platform operator, out of band.
//! - `OPENQTT_DEVICE`: the device's name, `<organization>/<namespace>/<device>`.
//! - `OPENQTT_TOKEN`: the enrollment token shown once when the device was
//!   created. Needed for the FIRST run only. After that the rotated token in
//!   the state file is the credential, and this variable is ignored.
//!
//! Also `OPENQTT_API` and `OPENQTT_BROKER` if this is not the hosted platform,
//! and `OPENQTT_STATE` to move `/etc/openqtt/state.json` somewhere else.
//!
//! Also `OPENQTT_ARTIFACT_KEY` if this device accepts firmware updates: the
//! public half of the key the platform signs them with, `/etc/openqtt/artifact-key.pem`
//! by default. With no key on disk an update is refused rather than installed.
//!
//! # Two things that surprise everybody
//!
//! **Publish `temperature`, not `ingest/acme/production/pump-3/temperature`.**
//! The broker prepends the prefix itself. Sending it too publishes to a place
//! nobody is listening. [`Device::publish`] refuses that rather than let it
//! happen quietly.
//!
//! **A device subscribes to exactly one thing, and it is about itself.** This
//! used to say a device cannot subscribe at all, and for a while that was
//! true. It subscribes to `commands/#` now, which the broker mounts under this
//! device's own prefix, so the platform can tell a device to update itself,
//! run a diagnostic or renew early. Everything else is unchanged: reading
//! other devices' data back out is still a job for a consumer with its own
//! credential, not for the machines in the field.
//!
//! # What the platform can ask for
//!
//! Three things, all of them retained, so a device that has been switched off
//! for a week gets them on the next connect.
//!
//! - **A firmware version.** Desired state rather than an order: the device
//!   compares the announced sha256 against the binary it is running. It
//!   verifies the platform's signature over that digest before writing
//!   anything, installs beside the running binary, restarts into it, and puts
//!   the old one back if a gating diagnostic fails. See [`Builder::firmware`].
//! - **A diagnostic run.** Every probe registered with [`Builder::probe`],
//!   each on its own blocking thread inside its own timeout, one `test/result`
//!   each. See [`Probe`].
//! - **An early certificate renewal**, for a compromised intermediate. Only
//!   the instruction travels; the device fetches through the enrollment route
//!   it already uses, so the private key still never leaves it.
//!
//! # The unit file, if this device updates itself
//!
//! ```ini
//! [Service]
//! Restart=always
//! SuccessExitStatus=73
//! ```
//!
//! An update ends by exiting 73 so the service manager starts the new binary.
//! `SuccessExitStatus` stops that being logged as a crash and counted against
//! the restart limiter. `Restart=on-failure` is the trap: it reads the same
//! declaration, concludes 73 is success, does not restart, and leaves the
//! service dead after every update.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod commands;
mod config;
mod durable;
mod enroll;
mod error;
mod identity;
mod journal;
mod mqtt;
mod ota;
mod renew;
mod signals;
mod state;
mod tests;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{TimeDelta, Utc};
use rumqttc::tokio_rustls::rustls::pki_types::CertificateDer;
use rumqttc::{AsyncClient, QoS};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;

pub use crate::config::{BrokerTransport, Config};
pub use crate::error::{Error, Result};
pub use crate::signals::Signal;
pub use crate::tests::{Outcome, Probe};

/// How long a handover waits for the replacement connection before giving up
/// and letting the ordinary retry take over. Long enough for a handshake, short
/// enough that a renewal never blocks publishing for a noticeable time.
const HANDOFF_TIMEOUT: Duration = Duration::from_secs(3);

/// Renew at startup rather than connect, if the certificate has this little
/// left. A handshake with an expired certificate fails in a way that says
/// nothing useful.
const STARTUP_MARGIN: TimeDelta = TimeDelta::hours(2);

/// rumqttc's request channel. Deep enough that a burst during a certificate
/// handover queues instead of failing.
const REQUEST_QUEUE: usize = 256;

/// How long the outgoing connection is left polling after it is told to
/// disconnect, so the packet reaches the wire before the task is stopped.
const DISCONNECT_GRACE: Duration = Duration::from_secs(2);

/// How many times a first enrollment retries writing its identity down before
/// giving up. Small, because somebody is watching a first run and a device that
/// cannot write to its own disk is not going to start working.
const SAVE_ATTEMPTS: u32 = 5;

/// The pinned root, and where it came from, so a mismatch can name the file.
#[derive(Clone)]
pub(crate) struct Pin {
    pub certificate: CertificateDer<'static>,
    pub path: PathBuf,
}

/// A connected device.
///
/// Holds the live broker connection and the background work that keeps it
/// alive. Dropping it stops both.
pub struct Device {
    /// THE CLIENT LIVES BEHIND A CELL AND EVERY PUBLISH RESOLVES THROUGH IT.
    ///
    /// This is not an optimisation and it cannot be added later. rumqttc's own
    /// reconnect reuses the TLS configuration captured when the client was
    /// built, so a renewed certificate on disk changes nothing until the client
    /// itself is replaced. The v5 gateway has no way to do that and needs a
    /// process restart to pick up a new certificate; v4 added it afterwards and
    /// paid for it with a certificate-error sniffer and a watchdog that exits
    /// the process, both of which exist only because the closures that publish
    /// had already captured a client.
    ///
    /// [`mqtt::Publisher`] is that cell, and everything this crate spawns in
    /// the background holds one too rather than a client of its own.
    publisher: mqtt::Publisher,
    common_name: String,
    /// Notified when a connection has put its DISCONNECT on the wire. Shared
    /// with every polling task, so `shutdown` waits on the same signal a
    /// handover does instead of sleeping and hoping.
    flushed: Arc<Notify>,
    /// Aborted on drop. The supervisor owns the polling task, so aborting the
    /// supervisor drops that too.
    _tasks: Vec<Abort>,
}

impl Device {
    /// Read the environment, enrol if needed, connect, and start renewing.
    ///
    /// On a device's FIRST run this waits for the broker to acknowledge the
    /// connection and fails if it does not, because somebody is watching and an
    /// error is more use to them than a process that sits there. On every run
    /// after that an unreachable broker is a warning: the device is returned
    /// connecting, and both the connection and the renewal keep retrying in the
    /// background. A device whose certificate has run out can only be repaired
    /// by the renewal task, so refusing to return one would remove the only
    /// thing able to fix it.
    pub async fn connect() -> Result<Device> {
        Device::builder().connect().await
    }

    /// The same, with configuration from somewhere other than the environment.
    pub async fn with_config(config: Config) -> Result<Device> {
        Device::builder().config(config).connect().await
    }

    /// A device with diagnostics, or a firmware version, or both.
    ///
    /// EVERYTHING THE PLATFORM CAN ASK FOR HAS TO BE IN PLACE BEFORE THE
    /// CONNECTION, because every command is retained and can therefore arrive
    /// on the first CONNACK, ahead of the next line of the program. That is why
    /// this is a builder and not a pair of methods on a connected device.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), openqtt_device::Error> {
    /// use openqtt_device::{Device, Outcome, Probe};
    ///
    /// let device = Device::builder()
    ///     .firmware(env!("CARGO_PKG_VERSION"))
    ///     .probe(Probe::new("sd_card", |message| {
    ///         message.push_str("mounted, 3.1 GB free");
    ///         Outcome::Pass
    ///     }).timeout_secs(20))
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// The name in this device's certificate, which is also the prefix every
    /// message it publishes arrives under.
    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    /// Publish `payload` as JSON, at least once.
    ///
    /// The topic is relative: see the note on the module about the mountpoint.
    pub async fn publish<T: Serialize>(&self, topic: &str, payload: T) -> Result<()> {
        let body = serde_json::to_vec(&payload)
            .map_err(|error| Error::Crypto(format!("could not encode the payload: {error}")))?;
        self.publish_bytes(topic, body, QoS::AtLeastOnce).await
    }

    /// Say what this device is doing, when that is not a reading.
    ///
    /// One of exactly three things: see [`Signal`]. A closed set because a
    /// console that renders an unknown status is showing a string nobody
    /// chose.
    ///
    /// ```no_run
    /// # async fn run(device: &openqtt_device::Device) -> Result<(), openqtt_device::Error> {
    /// use std::time::Duration;
    /// use openqtt_device::Signal;
    ///
    /// device.signal(Signal::Sleeping { wakes_in: Duration::from_secs(3600) }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn signal(&self, signal: Signal) -> Result<()> {
        let (topic, body) = signal.message(Utc::now());
        self.publish(&topic, body).await
    }

    /// Publish bytes, choosing the quality of service.
    pub async fn publish_bytes(
        &self,
        topic: &str,
        payload: impl Into<Vec<u8>>,
        qos: QoS,
    ) -> Result<()> {
        self.publisher.bytes(topic, payload.into(), qos).await
    }

    /// Disconnect cleanly and stop renewing.
    ///
    /// A clean DISCONNECT suppresses the last will, which is what tells the
    /// platform this was a planned stop and not a machine that fell over.
    pub async fn shutdown(self) {
        // Registered before the disconnect is asked for, or a fast connection
        // notifies before anything is listening. Waiting for the signal rather
        // than sleeping is what stops a publish that was still queued from
        // being aborted along with the task at the end of this function.
        let flushed = self.flushed.notified();
        tokio::pin!(flushed);
        flushed.as_mut().enable();

        self.publisher.disconnect().await;
        if tokio::time::timeout(DISCONNECT_GRACE, flushed)
            .await
            .is_err()
        {
            tracing::warn!(
                seconds = DISCONNECT_GRACE.as_secs(),
                "shutting down without confirmation that queued messages were sent"
            );
        }
    }
}

/// A device under construction. See [`Device::builder`].
#[derive(Default)]
pub struct Builder {
    config: Option<Config>,
    probes: tests::Registry,
    firmware: Option<String>,
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Builder")
            .field("firmware", &self.firmware)
            .finish_non_exhaustive()
    }
}

impl Builder {
    /// Configuration from somewhere other than the environment.
    pub fn config(mut self, config: Config) -> Builder {
        self.config = Some(config);
        self
    }

    /// Register a diagnostic this firmware can run. See [`Probe`].
    ///
    /// Registering the same id twice keeps the later one and says so.
    pub fn probe(mut self, probe: Probe) -> Builder {
        self.probes.add(probe);
        self
    }

    /// What version this firmware is, which is what turns updates on.
    ///
    /// THE ONLY THING THIS CRATE CANNOT WORK OUT FOR ITSELF. It hashes the
    /// running binary to know WHICH firmware it is, and that is what a rollout
    /// is judged by, but the version is a name the application chose and
    /// `env!("CARGO_PKG_VERSION")` is usually it. Without one, `meta/firmware`
    /// is not published and an announced update is refused with a line in the
    /// log rather than installed against a version nobody can name.
    pub fn firmware(mut self, version: impl Into<String>) -> Builder {
        self.firmware = Some(version.into());
        self
    }

    /// Read the environment if it has to, enrol if it has to, connect, and
    /// start everything that runs in the background.
    pub async fn connect(self) -> Result<Device> {
        let config = match self.config {
            Some(config) => config,
            None => Config::from_env()?,
        };
        let store = state::Store::new(&config.state);
        let journal = journal::Store::beside(&config.state);
        let pin = read_pin(&config.root_ca)?;
        let api = enroll::Client::new(config.enroll_url())?;

        let Established {
            current,
            wait,
            first,
        } = establish(&api, &store, &config).await?;

        let flushed = Arc::new(Notify::new());
        // Absent on a build that did not say what version it is, and absent
        // rather than fatal when this device cannot find its own binary: a
        // device that cannot be updated should still publish its readings.
        let updater = match &self.firmware {
            None => None,
            Some(version) => match updater(version, &config, &flushed) {
                Ok(updater) => Some(updater),
                Err(error) => {
                    tracing::error!(%error, "updates are off on this device");
                    None
                }
            },
        };

        let (client, eventloop) = build_client(&current, &pin, &config)?;
        let cell = Arc::new(ArcSwap::from_pointee(client.clone()));
        let publisher = mqtt::Publisher::new(Arc::clone(&cell));

        let (deliveries, incoming) = mpsc::channel(commands::QUEUE);
        let wiring = Arc::new(mqtt::Wiring {
            firmware: updater.as_ref().and_then(|updater| {
                serde_json::to_vec(&updater.running().meta())
                    .inspect_err(|error| tracing::warn!(%error, "could not encode meta/firmware"))
                    .ok()
            }),
            commands: deliveries,
        });

        let (ready, connected) = oneshot::channel();
        let pump = Connection::spawn(
            client,
            eventloop,
            ready,
            Arc::clone(&flushed),
            Arc::clone(&wiring),
        );

        let common_name = current.common_name.clone();

        // RENEWAL STARTS BEFORE THE CONNECTION IS WAITED FOR, and the order is
        // a fix rather than a tidy-up. It used to start afterwards, so a device
        // that could not reach the broker never renewed: the certificate ran
        // out, which guaranteed it could not reach the broker, and every
        // restart repeated the same minute. The two are independent and the one
        // that heals the other has to run first.
        let (renewed, handovers) = mpsc::channel(1);
        let (asked, asking) = mpsc::channel(1);
        let renewing = Abort(tokio::spawn(renew::task(
            enroll::Client::new(config.enroll_url())?,
            state::Store::new(&config.state),
            current,
            wait,
            renewed,
            asking,
        )));

        // AND SO DOES THE WORKER, for the same shape of reason. The first thing
        // it does is settle an update that has not been settled yet, and the
        // firmware most in need of being rolled back is the one that broke the
        // network.
        let working = Abort(tokio::spawn(commands::work(
            commands::Worker {
                publisher: publisher.clone(),
                journal,
                probes: Arc::new(self.probes),
                firmware: updater,
                certificate: asked,
            },
            incoming,
        )));

        let acknowledged = tokio::time::timeout(config.connect_timeout, connected).await;
        if acknowledged.is_err() || acknowledged.is_ok_and(|inner| inner.is_err()) {
            let timeout = Error::Timeout {
                doing: "waiting for the broker to acknowledge the connection",
                seconds: config.connect_timeout.as_secs(),
            };
            // WHO IS WATCHING DECIDES WHETHER THIS IS FATAL. On a first
            // enrollment somebody is at a terminal and an error is the useful
            // answer. For a device that already had state this is a bad minute
            // on a link, and returning an error would stop the renewal task
            // that is the only thing able to fix a spent certificate.
            if first {
                return Err(timeout);
            }
            tracing::warn!(%timeout, "connecting anyway; the connection and the renewal both retry");
        }

        let supervising = Abort(tokio::spawn(supervise(
            cell, store, pin, config, pump, handovers, wiring,
        )));

        Ok(Device {
            publisher,
            common_name,
            flushed,
            _tasks: vec![renewing, working, supervising],
        })
    }
}

/// The three things an update needs to know about this device.
fn updater(version: &str, config: &Config, flushed: &Arc<Notify>) -> Result<ota::Updater> {
    let paths = ota::Paths::running()?;
    let running = ota::Firmware::running(version, &paths.binary)?;
    tracing::info!(version, sha256 = %running.sha256, binary = %paths.binary.display(), "running");
    ota::Updater::new(
        paths,
        running,
        config.artifact_key.clone(),
        journal::Store::beside(&config.state),
        Arc::clone(flushed),
    )
}

impl std::fmt::Debug for Device {
    /// The name and nothing else. What is behind the cell is a live connection
    /// and a private key, and neither belongs in a log line somebody wrote
    /// `{:?}` into.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Device")
            .field("common_name", &self.common_name)
            .finish_non_exhaustive()
    }
}

/// Aborts the task it holds when it goes out of scope, INCLUDING when the task
/// holding it is itself aborted. That is what stops the polling loop when the
/// `Device` is dropped: the supervisor owns the connection, and dropping the
/// supervisor's future drops what its stack was holding.
struct Abort(JoinHandle<()>);

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One polling task, the switch that tells it it is on its way out, and the
/// signal that says it has finished going.
struct Connection {
    task: JoinHandle<()>,
    retiring: Arc<AtomicBool>,
    flushed: Arc<Notify>,
}

impl Connection {
    fn spawn(
        client: AsyncClient,
        eventloop: rumqttc::EventLoop,
        ready: oneshot::Sender<()>,
        flushed: Arc<Notify>,
        wiring: Arc<mqtt::Wiring>,
    ) -> Connection {
        let retiring = Arc::new(AtomicBool::new(false));
        Connection {
            task: tokio::spawn(mqtt::pump(
                client,
                eventloop,
                Some(ready),
                Arc::clone(&flushed),
                Arc::clone(&retiring),
                wiring,
            )),
            retiring,
            flushed,
        }
    }

    /// This connection is being replaced. Nothing changes except how loudly it
    /// reports the close it is about to be asked for.
    fn retire(&self) {
        self.retiring.store(true, Ordering::Relaxed);
    }

    /// Wait until the DISCONNECT has actually gone out, or the budget runs out.
    ///
    /// A REAL SIGNAL RATHER THAN A GUESS AT HOW LONG WRITING TAKES. This used to
    /// be a flat 200ms sleep, which is a number somebody picked: anything still
    /// queued when it elapsed was thrown away with the task. rumqttc drains its
    /// request queue in order, so seeing the DISCONNECT leave means everything
    /// queued ahead of it left too.
    ///
    /// WHAT IT DOES NOT PROMISE IS DELIVERY, and the reason is worth writing
    /// down because it is a trade and not an oversight. Both connections carry
    /// the same client id, so the broker takes this one over the moment the
    /// replacement is accepted, and after that there is nothing to flush to: a
    /// publish still queued at that instant is lost. Flushing FIRST and
    /// connecting the replacement afterwards would save it, at the price of
    /// tearing down a working connection before knowing the new certificate is
    /// accepted. Losing at most an in-flight message once a day is the smaller
    /// harm than going dark until the next renewal, so this is the order.
    ///
    /// QoS 1 does not rescue it either: `clean_session` is true and the
    /// replacement shares no packet-id state, and changing that brings back the
    /// unsolicited-puback reconnect loop `mqtt::options` exists to avoid.
    async fn drain(&self, client: &AsyncClient, budget: Duration) {
        // Registered BEFORE the disconnect is asked for. A notification with no
        // waiter is dropped on the floor, so building the future afterwards is
        // a race that loses exactly when the connection is fastest.
        let flushed = self.flushed.notified();
        tokio::pin!(flushed);
        flushed.as_mut().enable();

        let _ = client.disconnect().await;
        if tokio::time::timeout(budget, flushed).await.is_err() {
            // Expected during a handover and not worth a warning: both
            // connections carry the same client id, so accepting the
            // replacement is what closed this one, and a connection the broker
            // has already taken over has nothing left to flush to. It is a
            // warning on shutdown, where there is no such excuse.
            tracing::debug!(
                seconds = budget.as_secs(),
                "no disconnect was reported; the connection was most likely already closed"
            );
        }
    }
}

/// Aborted on drop, including when the task holding it is aborted.
impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Get to a usable certificate, whatever this device was holding when it
/// started.
///
/// THREE CASES AND THEY ALL END IN THE SAME PLACE, which is the api's design
/// rather than this crate's: a device that has never enrolled and a device
/// whose certificate expired eleven months ago send the same request to the
/// same route with the same kind of credential.
struct Established {
    current: state::State,
    wait: Duration,
    /// Whether this device had never enrolled before. The only thing it decides
    /// is whether a broker that does not answer is fatal: see `with_config`.
    first: bool,
}

async fn establish(
    api: &enroll::Client,
    store: &state::Store,
    config: &Config,
) -> Result<Established> {
    let stored = store.load()?;

    if let (Some(held), Some(configured)) = (&stored, &config.device) {
        if held.common_name != *configured {
            return Err(Error::Config(format!(
                "OPENQTT_DEVICE is '{configured}' but {} holds the identity of \
                 '{}'. One device, one state file: move it aside to enrol as \
                 something else.",
                store.path().display(),
                held.common_name
            )));
        }
    }

    match stored {
        Some(held) if usable(&held) => {
            // The schedule here is the one place a local clock is consulted at
            // all, because a stored instant is all there is until the next
            // response arrives. It errs safe: a clock reading late renews early,
            // which costs one request.
            let wait = renew::next_wake(
                Utc::now(),
                held.renew_after,
                held.not_after,
                renew::jitter(),
            );
            tracing::info!(
                common_name = %held.common_name,
                not_after = %held.not_after,
                "using the stored certificate"
            );
            Ok(Established {
                current: held,
                wait,
                first: false,
            })
        }
        // Spent, or held by a device whose clock cannot be trusted to say. The
        // token is what proves this device, and the token does not expire.
        //
        // RENEWED BY THE BACKGROUND TASK RATHER THAN HERE, with a wait of zero.
        // Doing it inline made exactly one unpaced request whose failure
        // returned from `with_config` before the renewal task existed: a device
        // refused by the platform then had no backoff at all, and a service
        // manager restarting it hammered a rate-limit bucket the whole fleet
        // shares. The task has the pacing and the retry-the-write rule, so the
        // spent certificate goes to it and the connection simply fails until it
        // lands.
        Some(held) => {
            tracing::info!(
                common_name = %held.common_name,
                not_after = %held.not_after,
                "the stored certificate cannot be relied on; renewing at once"
            );
            Ok(Established {
                current: held,
                wait: Duration::ZERO,
                first: false,
            })
        }
        None => first_enrollment(api, store, config).await,
    }
}

/// Whether a stored certificate can be connected with.
///
/// TWO QUESTIONS, AND THE SECOND IS ABOUT THE CLOCK RATHER THAN THE
/// CERTIFICATE. Comparing `not_after` against `Utc::now()` is only meaningful
/// if `Utc::now()` means anything, and on a device with no real time clock it
/// often does not. A clock reading BEFORE the moment the api issued this very
/// certificate is proof of that, needing no trusted source to establish: the
/// certificate exists, so its issuing instant has passed. Without this check a
/// device that booted thinking it was 1970 would see a far-future `not_after`,
/// declare a long-expired certificate healthy, fail the handshake with
/// something unhelpful, and do it again on every restart forever.
///
/// WHAT THIS CANNOT DO IS BOOTSTRAP THE TIME. A clock wrong by more than the
/// enrollment endpoint's own certificate lifetime fails the HTTPS handshake to
/// the api as well, so the device cannot fetch a `server_time` to correct
/// itself with. It will keep trying, and the warning above says what is wrong,
/// but something outside this crate has to supply the time: NTP, a GPS fix, an
/// RTC with a live battery, or a person. Detecting the condition and recovering
/// from it are different problems, and only the first is solved here.
fn usable(held: &state::State) -> bool {
    let now = Utc::now();
    if now < held.issued_at {
        tracing::warn!(
            issued_at = %held.issued_at,
            local_time = %now,
            "this device's clock reads earlier than its own certificate was issued, \
             so it cannot judge what is expired; renewing to find out the time"
        );
        return false;
    }
    held.not_after > now + STARTUP_MARGIN
}

async fn first_enrollment(
    api: &enroll::Client,
    store: &state::Store,
    config: &Config,
) -> Result<Established> {
    let device = config.device.as_deref().ok_or_else(|| {
        Error::Config(format!(
            "This device has no state at {} and OPENQTT_DEVICE is not set. Set \
             it to the device's name, as acme/production/pump-3.",
            store.path().display()
        ))
    })?;
    let token = config.bootstrap_token.as_deref().ok_or_else(|| {
        Error::Config(format!(
            "This device has no state at {} and OPENQTT_TOKEN is not set. Use \
             the enrollment token shown when the device was created.",
            store.path().display()
        ))
    })?;

    let identity = identity::generate(device)?;
    let mut attempt = 0u32;
    let fresh = loop {
        match api.enroll(device, token, &identity.csr_pem).await {
            Ok(fresh) => break fresh,
            // A wrong token on a first enrollment is somebody's typing, and a
            // process that hangs forever on that is worse than one that exits
            // and lets the service manager bring it back.
            Err(error) if error.fatal_at_bootstrap() => return Err(error),
            Err(error) => {
                let pause = enroll::backoff(attempt, error.retry());
                tracing::warn!(
                    %error,
                    seconds = pause.as_secs(),
                    attempt,
                    "first enrollment failed, will try again"
                );
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(pause).await;
            }
        }
    };

    // NOTHING FALLIBLE BETWEEN THE 200 AND THE WRITE. The token has already
    // rotated on the api's side, so anything that fails here and returns costs
    // the one grace enrollment this device has in reserve. See `renew::renew`,
    // where the same rule cost a device its entire ability to enrol.
    let held = state::State {
        common_name: fresh.common_name.clone(),
        certificate: fresh.certificate.clone(),
        chain: fresh.chain.clone(),
        private_key: identity.private_key_pem,
        next_token: fresh.next_token.clone(),
        not_after: fresh.not_after,
        renew_after: fresh.renew_after,
        issued_at: fresh.server_time,
    };
    // RETRY THE WRITE, NEVER THE REQUEST. The token has already rotated on the
    // api's side, so asking again would spend the grace enrollment. If it still
    // will not write after this, the error is returned and the token is lost
    // with it: there is nothing better available on a first run, and a device
    // whose disk is unwritable has a larger problem than enrollment.
    let mut attempt = 0u32;
    while let Err(error) = store.save(&held) {
        if attempt >= SAVE_ATTEMPTS {
            tracing::error!(
                %error,
                "a certificate was issued and could not be written down. The \
                 enrollment token is spent; this device needs a new one."
            );
            return Err(error);
        }
        let waiting = enroll::backoff(attempt, error.retry());
        tracing::warn!(%error, seconds = waiting.as_secs(), "could not write the new identity down");
        attempt = attempt.saturating_add(1);
        tokio::time::sleep(waiting).await;
    }
    tracing::info!(common_name = %held.common_name, "enrolled");

    let wait = renew::next_wake(
        fresh.server_time,
        fresh.renew_after,
        fresh.not_after,
        renew::jitter(),
    );
    Ok(Established {
        current: held,
        wait,
        first: true,
    })
}

/// Replace the live connection every time a renewal commits.
///
/// The order is v4's, and it is the order because the other one shipped: it
/// signalled the handover before committing the new certificate to disk, the
/// handover read the old one back, and a fleet kept presenting the previous
/// day's certificate until the broker started rejecting it.
async fn supervise(
    cell: Arc<ArcSwap<AsyncClient>>,
    store: state::Store,
    pin: Pin,
    config: Config,
    mut polling: Connection,
    mut handovers: mpsc::Receiver<()>,
    wiring: Arc<mqtt::Wiring>,
) {
    while handovers.recv().await.is_some() {
        // Everything that can fail happens BEFORE the cell is touched, so a
        // failure here leaves the working connection exactly as it was. Its
        // certificate is still valid for days: a lost handover is a delay and
        // not an outage.
        let (client, eventloop) = match prepare(&store, &pin, &config) {
            Ok(pair) => pair,
            Err(error) => {
                tracing::error!(
                    %error,
                    "could not hand the connection over to the renewed certificate; \
                     keeping the existing one"
                );
                continue;
            }
        };

        // THE REPLACEMENT HAS TO PROVE ITSELF BEFORE THE WORKING ONE IS GIVEN
        // UP. The old order disconnected and aborted the live connection first
        // and only then started the new one, so a certificate the broker
        // refused took the device dark immediately, even though the one it was
        // already using had days left.
        //
        // Both connections use the same client id, so the broker takes the
        // older one over the moment this one is accepted. That is survivable
        // and brief; going dark on a certificate the broker will not accept is
        // neither.
        // THE REPLACEMENT SUBSCRIBES BECAUSE IT CANNOT BE BUILT WITHOUT THE
        // WIRING THAT MAKES IT. A new client has no subscriptions at all, and a
        // handover that forgot to resubscribe would leave a device that worked
        // perfectly until its first renewal and was deaf from then on.
        let (ready, connected) = oneshot::channel();
        let replacement = Connection::spawn(
            client.clone(),
            eventloop,
            ready,
            Arc::clone(&polling.flushed),
            Arc::clone(&wiring),
        );

        if tokio::time::timeout(HANDOFF_TIMEOUT, connected)
            .await
            .is_err()
        {
            tracing::error!(
                seconds = HANDOFF_TIMEOUT.as_secs(),
                "the renewed certificate was not accepted by the broker; keeping \
                 the connection that works and trying again at the next renewal"
            );
            // The old connection was never retired, so it is untouched and
            // reconnects on its own if the broker took its session over.
            drop(replacement);
            continue;
        }

        // Accepted. RETIRE THE OLD ONE NOW AND NOT A MOMENT EARLIER. The broker
        // has just taken its session over, because both carry the same client
        // id, and a loop still allowed to reconnect would take it straight
        // back. Retiring is what stops it: a retired loop flushes and exits.
        // Measured against the real broker, retiring only after the replacement
        // is proven turned about a second of the two of them trading the
        // session into a clean swap.
        polling.retire();
        let previous = cell.swap(Arc::new(client));
        // Now let it say goodbye and flush whatever it still had queued.
        polling.drain(&previous, DISCONNECT_GRACE).await;
        polling = replacement;
        tracing::info!("broker connection now using the renewed certificate");
    }
    // The channel closed. `renew::task` never returns for any other reason, so
    // this means the `Device` itself is gone: take the connection down with it
    // rather than leave a task publishing into nothing. That guarantee is the
    // renewal loop's to keep, and when it did not keep it a non-transient
    // renewal error killed a connection with days of certificate left.
    drop(polling);
}

/// Build a replacement client from what the renewal just committed.
fn prepare(
    store: &state::Store,
    pin: &Pin,
    config: &Config,
) -> Result<(AsyncClient, rumqttc::EventLoop)> {
    let held = store.load()?.ok_or_else(|| Error::State {
        path: store.path().to_path_buf(),
        reason: "it disappeared between the renewal and the handover".to_string(),
    })?;
    build_client(&held, pin, config)
}

fn build_client(
    held: &state::State,
    pin: &Pin,
    config: &Config,
) -> Result<(AsyncClient, rumqttc::EventLoop)> {
    let tls = mqtt::client_config(pin, &held.certificate, &held.chain, &held.private_key)?;
    let options = mqtt::options(
        &held.common_name,
        &config.broker_host,
        config.broker_port,
        &config.broker_transport,
        tls,
    );
    Ok(AsyncClient::new(options, REQUEST_QUEUE))
}

fn read_pin(path: &std::path::Path) -> Result<Pin> {
    let pem = std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::Config(format!(
                "There is no root certificate at {}. This device checks the \
                 broker against the OpenQTT root and nothing else, so the file \
                 has to be there before it can connect. Ask the platform \
                 operator for it, or point OPENQTT_ROOT_CA somewhere else.",
                path.display()
            ))
        } else {
            error::io(path, error)
        }
    })?;
    Ok(Pin {
        certificate: mqtt::root_certificate(&pem)?,
        path: path.to_path_buf(),
    })
}
