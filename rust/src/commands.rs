//! What the platform asks for, and what answers it.
//!
//! A DEVICE SUBSCRIBES NOW, AND IT DID NOT USED TO. The broker denied every
//! subscribe on the grounds that this is a one directional client, and that
//! sentence is in this crate's history and in the README. It stops being true
//! at exactly one filter: `commands/#`, mounted by the broker under this
//! device's own prefix, so a device can be told things about itself and about
//! nothing else. Reading other devices' data back out is still a job for a
//! consumer with its own credential.
//!
//! EVERY COMMAND IS RETAINED, and that is what makes this a queue rather than a
//! notification. Durable sessions are off, so a queued message lives in one
//! node's memory and a pod roll drops it silently. A retained message is
//! replicated, redelivered on every fresh subscribe, and has no expiry horizon,
//! so the device that has been switched off for a week gets its instructions on
//! the next connect. That is the case that matters, because the device somebody
//! needs to reach is the one that is not there.
//!
//! The cost of retained is redelivery, and every command carries its own answer
//! to it. Firmware and certificate are DESIRED STATE, so a device compares and
//! does nothing when it already agrees. A diagnostic run is an act rather than
//! a state, so it carries a run id and the journal remembers the last one
//! answered.
//!
//! NOTHING HERE RUNS ON THE TASK THAT DRIVES THE CONNECTION. The pump hands
//! deliveries to this worker over a channel and goes straight back to polling,
//! because a download or a probe on that task stops the keepalive and the
//! broker drops a device that is busy doing what it was told.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::journal;
use crate::mqtt::Publisher;
use crate::ota;
use crate::tests::{answer, Dispatch, Registry};

/// The filter, mounted by the broker under `ingest/<common name>/`.
pub(crate) const FILTER: &str = "commands/#";

/// How many commands may be waiting for the worker.
///
/// DEEP ENOUGH THAT A FULL SET OF RETAINED MESSAGES LANDS AT ONCE. Every
/// command is redelivered on every fresh subscribe, so a reconnect delivers all
/// of them in a burst while the worker may still be inside a probe. The
/// reference implementation used a queue two deep, which dropped most of a "run
/// all" and surfaced in the console as phantom timeouts.
pub(crate) const QUEUE: usize = 64;

/// One message off the wire, with the polling task already back at work.
#[derive(Debug)]
pub(crate) struct Delivery {
    pub topic: String,
    pub payload: Vec<u8>,
}

/// `commands/certificate`: renew now if what is on disk is older than this.
#[derive(Debug, Deserialize)]
struct Certificate {
    not_before: DateTime<Utc>,
}

/// The last level of a command topic, or `None` if this is not one.
///
/// THE TOPIC ARRIVES RELATIVE, because the broker's mountpoint is stripped on
/// the way out as well as prepended on the way in: a device subscribes to
/// `commands/#`, the platform publishes to `ingest/<name>/commands/firmware`,
/// and what arrives here says `commands/firmware`.
///
/// The mounted form is accepted as well, and that is not defensive clutter. A
/// listener configured without the mountpoint delivers the absolute topic, and
/// a device that then matched nothing would sit there receiving every command
/// and acting on none of them, with no error anywhere. That is the hardest
/// shape of failure to find, and one extra branch closes it.
pub(crate) fn route(topic: &str) -> Option<&str> {
    if let Some(suffix) = topic.strip_prefix("commands/") {
        return Some(suffix);
    }
    let mut levels = topic.splitn(6, '/');
    if levels.next()? != "ingest" {
        return None;
    }
    // `<organization>/<namespace>/<device>`, which is what the common name is
    // made of and therefore what the mountpoint spends.
    levels.next()?;
    levels.next()?;
    levels.next()?;
    if levels.next()? != "commands" {
        return None;
    }
    levels.next()
}

/// Everything the worker needs to answer with.
pub(crate) struct Worker {
    pub publisher: Publisher,
    pub journal: journal::Store,
    pub probes: Arc<Registry>,
    /// `None` when this build did not say what firmware version it is, which
    /// is the only way to opt out of updates.
    pub firmware: Option<ota::Updater>,
    /// Into the renewal loop, to make it stop waiting.
    pub certificate: mpsc::Sender<DateTime<Utc>>,
}

/// One task, one command at a time, for the life of the device.
///
/// SERIAL ON PURPOSE. A download and a diagnostic run at the same time on a
/// device with one core and a metered uplink is worse at both than doing them
/// in order, and it makes the order things happen in something that can be
/// reasoned about rather than raced.
pub(crate) async fn work(mut worker: Worker, mut incoming: mpsc::Receiver<Delivery>) {
    // BEFORE ANY COMMAND AND WITHOUT WAITING FOR THE BROKER. The firmware most
    // in need of being rolled back is the one that broke the network, so the
    // decision cannot depend on a connection. Whatever it publishes is best
    // effort and queues until there is somewhere to send it.
    if let Some(updater) = worker.firmware.as_mut() {
        if let ota::Next::Restart { into } =
            ota::settle(updater, &worker.publisher, &worker.probes).await
        {
            updater.depart(&worker.publisher, &into).await;
        }
    }

    while let Some(delivery) = incoming.recv().await {
        dispatch(&mut worker, delivery).await;
    }
    tracing::debug!("the device has gone away; nothing left to answer");
}

async fn dispatch(worker: &mut Worker, delivery: Delivery) {
    let Some(suffix) = route(&delivery.topic) else {
        tracing::debug!(topic = %delivery.topic, "not a command; ignored");
        return;
    };
    // A ZERO BYTE RETAINED PAYLOAD CLEARS THE TOPIC and means "nothing
    // desired". It arrives here as an ordinary delivery, so it has to be read
    // as the absence of an instruction rather than as an unparseable one.
    if delivery.payload.is_empty() {
        tracing::debug!(topic = %delivery.topic, "nothing desired here");
        return;
    }

    match suffix {
        "firmware" => firmware(worker, &delivery.payload).await,
        "test" => diagnostics(worker, &delivery.payload).await,
        "certificate" => certificate(worker, &delivery.payload).await,
        // A DEVICE THAT MEETS SOMETHING IT DOES NOT UNDERSTAND SKIPS IT. The
        // protocol has no version field anywhere on purpose: a new instruction
        // is a new topic, and an old device ignoring one is the design working.
        other => tracing::info!(command = other, "this firmware does not know that command"),
    }
}

async fn firmware(worker: &mut Worker, payload: &[u8]) {
    let announced: ota::Announcement = match serde_json::from_slice(payload) {
        Ok(announced) => announced,
        Err(error) => {
            tracing::warn!(%error, "could not read the firmware announcement");
            return;
        }
    };
    let Some(updater) = worker.firmware.as_mut() else {
        tracing::warn!(
            version = %announced.version,
            "an update was announced and this build cannot install one: it did \
             not say what firmware version it is. See Device::builder"
        );
        return;
    };
    if let ota::Next::Restart { into } = updater.accept(&worker.publisher, &announced).await {
        updater.depart(&worker.publisher, &into).await;
    }
}

async fn diagnostics(worker: &Worker, payload: &[u8]) {
    let dispatch: Dispatch = match serde_json::from_slice(payload) {
        Ok(dispatch) => dispatch,
        Err(error) => {
            tracing::warn!(%error, "could not read the diagnostic dispatch");
            return;
        }
    };
    // THE RECORDED RUN ID IS WHAT MAKES A REDELIVERY HARMLESS. The retained
    // message is cleared when a run finishes, but the clear can be lost, denied
    // or overtaken by a reconnect, and running every probe again because a
    // certificate was renewed is exactly what this protects against.
    match worker.journal.load() {
        Ok(held) if held.answered.as_deref() == Some(dispatch.run_id.as_str()) => {
            tracing::debug!(run_id = %dispatch.run_id, "already answered this run");
            return;
        }
        Ok(_) => {}
        Err(error) => {
            // Unreadable, so there is no way to tell a repeat from a new run.
            // Running twice is a wasted minute; never running is a device
            // nobody can diagnose, so this errs towards answering.
            tracing::error!(%error, "cannot tell whether this diagnostic run was already answered");
        }
    }
    answer(
        &worker.publisher,
        &worker.probes,
        &worker.journal,
        &dispatch,
    )
    .await;
}

async fn certificate(worker: &Worker, payload: &[u8]) {
    let asked: Certificate = match serde_json::from_slice(payload) {
        Ok(asked) => asked,
        Err(error) => {
            tracing::warn!(%error, "could not read the certificate instruction");
            return;
        }
    };
    // ONLY THE INSTRUCTION TRAVELS. The device fetches through the enrollment
    // route it already uses, so the private key still never leaves it, and the
    // renewal loop is the only thing that ever writes a certificate down.
    tracing::info!(not_before = %asked.not_before, "asked to renew");
    if worker.certificate.send(asked.not_before).await.is_err() {
        tracing::warn!("nothing is renewing certificates any more");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_command_topic_is_what_actually_arrives() {
        assert_eq!(route("commands/firmware"), Some("firmware"));
        assert_eq!(route("commands/test"), Some("test"));
        assert_eq!(route("commands/certificate"), Some("certificate"));
    }

    #[test]
    fn a_mounted_command_topic_is_understood_too() {
        // A listener with no mountpoint delivers this shape, and a device that
        // matched nothing would receive every command and act on none.
        assert_eq!(
            route("ingest/acme/production/pump-3/commands/firmware"),
            Some("firmware")
        );
    }

    #[test]
    fn nothing_that_is_not_a_command_is_read_as_one() {
        assert_eq!(route("temperature"), None);
        assert_eq!(route("meta/firmware"), None);
        assert_eq!(route("commands"), None);
        // Not a command topic: `commands` is not where the mountpoint puts it.
        assert_eq!(route("elsewhere/commands/firmware"), None);
        assert_eq!(
            route("ingest/acme/production/pump-3/readings/commands"),
            None
        );
    }

    #[test]
    fn an_unknown_command_is_skipped_rather_than_refused() {
        // The protocol has no version field: a new instruction is a new topic,
        // and this is what an old device does with one.
        assert_eq!(
            route("commands/quantum-realignment"),
            Some("quantum-realignment")
        );
    }
}
