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
//! # Two things that surprise everybody
//!
//! **Publish `temperature`, not `ingest/acme/production/pump-3/temperature`.**
//! The broker prepends the prefix itself. Sending it too publishes to a place
//! nobody is listening. [`Device::publish`] refuses that rather than let it
//! happen quietly.
//!
//! **A device cannot subscribe.** The broker denies it. This is a one
//! directional client on purpose: reading the data back out is a job for a
//! consumer with its own credential, not for the machines in the field.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod enroll;
mod error;
mod identity;
mod mqtt;
mod renew;
mod state;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{TimeDelta, Utc};
use rumqttc::tokio_rustls::rustls::pki_types::CertificateDer;
use rumqttc::{AsyncClient, QoS};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub use crate::config::Config;
pub use crate::error::{Error, Result};

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
const DISCONNECT_GRACE: Duration = Duration::from_millis(200);

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
    client: Arc<ArcSwap<AsyncClient>>,
    common_name: String,
    /// Aborted on drop, in order. The supervisor owns the polling task, so
    /// aborting the supervisor drops its guard and stops that too.
    _tasks: Vec<Abort>,
}

impl Device {
    /// Read the environment, enrol if needed, connect, and start renewing.
    ///
    /// Returns once the broker has acknowledged the connection, so a device
    /// that is misconfigured fails while somebody is still watching rather than
    /// running for a week publishing into nothing.
    pub async fn connect() -> Result<Device> {
        Device::with_config(Config::from_env()?).await
    }

    /// The same, with configuration from somewhere other than the environment.
    pub async fn with_config(config: Config) -> Result<Device> {
        let store = state::Store::new(&config.state);
        let pin = read_pin(&config.root_ca)?;
        let api = enroll::Client::new(config.enroll_url())?;

        let (current, wait) = establish(&api, &store, &pin, &config).await?;

        let (client, eventloop) = build_client(&current, &pin, &config)?;
        let (ready, connected) = oneshot::channel();
        let pump = Abort(tokio::spawn(mqtt::pump(eventloop, Some(ready))));
        let acknowledged = tokio::time::timeout(config.connect_timeout, connected).await;
        if acknowledged.is_err() || acknowledged.is_ok_and(|inner| inner.is_err()) {
            return Err(Error::Timeout {
                doing: "waiting for the broker to acknowledge the connection",
                seconds: config.connect_timeout.as_secs(),
            });
        }

        let common_name = current.common_name.clone();
        let cell = Arc::new(ArcSwap::from_pointee(client));

        let (renewed, handovers) = mpsc::channel(1);
        let renewing = Abort(tokio::spawn(renew::task(
            enroll::Client::new(config.enroll_url())?,
            state::Store::new(&config.state),
            pin.clone(),
            current,
            wait,
            renewed,
        )));
        let supervising = Abort(tokio::spawn(supervise(
            Arc::clone(&cell),
            store,
            pin,
            config,
            pump,
            handovers,
        )));

        Ok(Device {
            client: cell,
            common_name,
            _tasks: vec![renewing, supervising],
        })
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

    /// Publish bytes, choosing the quality of service.
    pub async fn publish_bytes(
        &self,
        topic: &str,
        payload: impl Into<Vec<u8>>,
        qos: QoS,
    ) -> Result<()> {
        mqtt::check_topic(topic)?;
        let payload = payload.into();
        if payload.len() > mqtt::MAX_PACKET {
            return Err(Error::Topic(format!(
                "the payload is {} bytes and the broker accepts {}.",
                payload.len(),
                mqtt::MAX_PACKET
            )));
        }
        // `load` and not a captured clone: this is the cell that makes a
        // certificate handover invisible to the caller.
        self.client
            .load()
            .publish(topic, qos, false, payload)
            .await?;
        Ok(())
    }

    /// Disconnect cleanly and stop renewing.
    ///
    /// A clean DISCONNECT suppresses the last will, which is what tells the
    /// platform this was a planned stop and not a machine that fell over.
    pub async fn shutdown(self) {
        let _ = self.client.load().disconnect().await;
        // Let the polling task put the packet on the wire before the tasks are
        // aborted by the drop at the end of this function.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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

/// Aborts the task it holds when it goes out of scope, including when the task
/// holding IT is aborted.
struct Abort(JoinHandle<()>);

impl Abort {
    /// Stop the task now, keeping the handle. Idempotent, and `Drop` does the
    /// same thing, so calling it early is only ever a matter of timing.
    fn stop(&self) {
        self.0.abort();
    }
}

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Get to a usable certificate, whatever this device was holding when it
/// started.
///
/// THREE CASES AND THEY ALL END IN THE SAME PLACE, which is the api's design
/// rather than this crate's: a device that has never enrolled and a device
/// whose certificate expired eleven months ago send the same request to the
/// same route with the same kind of credential.
async fn establish(
    api: &enroll::Client,
    store: &state::Store,
    pin: &Pin,
    config: &Config,
) -> Result<(state::State, Duration)> {
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
        // Usable. Note that the schedule here is the one place a local clock
        // enters at all, because a stored instant is all there is until the
        // next response arrives. It errs safe: a clock that reads late renews
        // early, which costs one request.
        Some(held) if held.not_after > Utc::now() + STARTUP_MARGIN => {
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
            Ok((held, wait))
        }
        // Expired, or close enough that connecting first would just fail. The
        // token is what proves this device, and the token does not expire.
        Some(held) => {
            tracing::info!(
                common_name = %held.common_name,
                not_after = %held.not_after,
                "the stored certificate is spent; enrolling before connecting"
            );
            renew::renew(api, store, pin, &held).await
        }
        None => first_enrollment(api, store, pin, config).await,
    }
}

async fn first_enrollment(
    api: &enroll::Client,
    store: &state::Store,
    pin: &Pin,
    config: &Config,
) -> Result<(state::State, Duration)> {
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
                let pause = enroll::backoff(attempt);
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

    renew::check_root(&fresh, pin, api)?;
    let held = state::State {
        common_name: fresh.common_name.clone(),
        certificate: fresh.certificate.clone(),
        chain: fresh.chain.clone(),
        private_key: identity.private_key_pem,
        next_token: fresh.next_token.clone(),
        not_after: fresh.not_after,
        renew_after: fresh.renew_after,
    };
    store.save(&held)?;
    tracing::info!(common_name = %held.common_name, "enrolled");

    let wait = renew::next_wake(
        fresh.server_time,
        fresh.renew_after,
        fresh.not_after,
        renew::jitter(),
    );
    Ok((held, wait))
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
    mut polling: Abort,
    mut handovers: mpsc::Receiver<()>,
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

        // SWAPPED BEFORE THE NEW LOOP IS RUNNING, on purpose. A publish in
        // this window resolves through the cell, lands in the new client's
        // queue, and goes out as soon as the loop starts. Swapping afterwards
        // would send it through a connection that is about to be torn down.
        let previous = cell.swap(Arc::new(client));
        let _ = previous.disconnect().await;
        // The old loop is still polling, which is what puts the DISCONNECT on
        // the wire. A clean DISCONNECT suppresses the last will, so the
        // platform sees a planned handover rather than a machine falling over.
        tokio::time::sleep(DISCONNECT_GRACE).await;

        // AND NOW STOP IT, BEFORE THE REPLACEMENT STARTS. rumqttc reconnects
        // on its own as long as something keeps polling, and this loop still
        // holds the certificate that was just replaced. Two connections under
        // one client id means the broker takes one of them over, and which one
        // survives is a race nobody should have to think about.
        polling.stop();

        let (ready, connected) = oneshot::channel();
        polling = Abort(tokio::spawn(mqtt::pump(eventloop, Some(ready))));
        if tokio::time::timeout(HANDOFF_TIMEOUT, connected)
            .await
            .is_err()
        {
            // Not an error. rumqttc keeps retrying inside the task that was
            // just spawned, so the connection comes back on its own.
            tracing::warn!(
                seconds = HANDOFF_TIMEOUT.as_secs(),
                "the renewed connection has not been acknowledged yet; leaving it to retry"
            );
        } else {
            tracing::info!("broker connection now using the renewed certificate");
        }
    }
    // The channel closed, which means the `Device` is gone. Take the connection
    // down with it rather than leaving a task publishing nothing forever.
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
    let tls = mqtt::client_config(
        pin.certificate.clone(),
        &held.certificate,
        &held.chain,
        &held.private_key,
    )?;
    let options = mqtt::options(
        &held.common_name,
        &config.broker_host,
        config.broker_port,
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
