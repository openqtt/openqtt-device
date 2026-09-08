//! Log batches, on their way off the device.
//!
//! WHY THIS IS NOT MQTT, GIVEN THERE IS ALREADY A CONNECTION. A log batch is
//! kilobytes and a reading is bytes. Pushing batches through the broker puts
//! them in its memory, through its router and past every consumer subscribed to
//! the tenant, to reach a bucket none of that is on the way to. The connection
//! being there is not a reason to use it.
//!
//! WHY IT IS NOT `api.openqtt.com` EITHER. That name is behind Cloudflare, and
//! a proxy that terminates TLS consumes the client certificate: the server
//! would see the request and not who sent it. `logs.openqtt.com` is DNS only
//! and regional, the same shape and the same reason as the broker's own
//! endpoint. The device presents the certificate it already holds and the
//! server reads the organization and namespace out of the common name, so
//! nothing in the body says who this is and nothing in the body can lie.
//!
//! CONTENT-LENGTH, NEVER CHUNKED. v5's SDK header records that some proxies,
//! Cloudflare among them, answer `Transfer-Encoding: chunked` request bodies
//! with a 400. Nothing on this path is behind one today and that is exactly the
//! kind of thing that changes without the device finding out, so the body is
//! built whole and its length is known before the request starts.
//!
//! THE DROP POLICY IS THE FEATURE. A device that cannot reach the platform for
//! a week must not fill its own disk, and it must not silently forget that it
//! did. v4's queue was a bounded set with an age cap and a hard ceiling, which
//! is the right shape: keep the newest, drop the oldest, and say how many.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
// THROUGH rumqttc, NEVER AS A DIRECT DEPENDENCY. Two rustls in one binary is
// two crypto provider registries, and the second one to be asked answers with
// a handshake failure that reads like a certificate problem. `cargo tree -i
// rustls` returning one line is the check.
use rumqttc::tokio_rustls::rustls::ClientConfig;
use serde::Serialize;

use crate::error::{Error, Result};

/// The hosted endpoint. Regional and DNS only, like the broker.
pub const DEFAULT_LOGS: &str = "https://logs.openqtt.com/v1/logs";

/// How much of one batch may go in a single request.
///
/// Chosen against the broker's 1 MB packet cap so the two limits are the same
/// order and neither becomes the surprising one. A batch is built whole in
/// memory to be measured, so this is also the largest allocation this module
/// makes.
pub const MAX_BATCH_BYTES: usize = 512 * 1024;

/// How long a batch waits for company before it goes on its own.
pub const MAX_BATCH_AGE: Duration = Duration::from_secs(60);

/// The ceiling on everything held back by an uplink that is not working.
pub const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;

/// How old a line may be and still be worth sending.
///
/// A week, matching the certificate headroom: a device offline longer than this
/// has a bigger problem than its logs, and the lines from the start of the
/// outage are the ones least likely to still matter.
pub const MAX_QUEUED_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// One line, with the platform's own clock nowhere in sight.
///
/// `at` is the device's clock and may be wrong; the server stamps its own
/// arrival time and keeps both. A device with no working clock still produces
/// usable logs, ordered among themselves, which is most of what a log is for.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Line {
    pub at: DateTime<Utc>,
    pub level: &'static str,
    pub message: String,
}

impl Line {
    /// What this line costs against the ceilings.
    ///
    /// The message plus a fixed allowance for the timestamp, the level and the
    /// JSON around them. Deliberately an estimate: serialising every line to
    /// measure it would double the work on the hot path, and the ceilings exist
    /// to bound memory rather than to be exact.
    fn weight(&self) -> usize {
        self.message.len() + 64
    }
}

/// The levels a line may carry. A closed set, so a console filtering on level
/// is filtering on something somebody chose.
pub const LEVELS: [&str; 4] = ["debug", "info", "warn", "error"];

/// What is waiting to go, and what had to be given up on.
///
/// Pure: no clock of its own, no I/O. Every method that needs the time is
/// handed it, for the reason the rest of this crate gives, which is that a
/// device's clock is not to be trusted and a test should not have to wait.
#[derive(Debug, Default)]
pub struct Queue {
    lines: VecDeque<Line>,
    bytes: usize,
    /// Lines given up on since the last batch went out, reported with the next
    /// one. **A silent drop is the failure this counter exists to prevent**:
    /// without it the first sign of a device losing logs is a gap nobody can
    /// date.
    dropped: u64,
    oldest_at: Option<DateTime<Utc>>,
}

impl Queue {
    pub fn new() -> Self {
        Queue::default()
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Add a line, dropping the oldest if that puts the queue over the ceiling.
    ///
    /// NEWEST WINS, and that is a choice rather than an accident of the data
    /// structure. A device that has been offline for days is most useful when
    /// it comes back describing what it is doing now; the lines from the start
    /// of an outage are the ones somebody is least likely to still want.
    pub fn push(&mut self, line: Line) {
        if self.oldest_at.is_none() {
            self.oldest_at = Some(line.at);
        }
        self.bytes += line.weight();
        self.lines.push_back(line);
        while self.bytes > MAX_QUEUED_BYTES {
            match self.lines.pop_front() {
                Some(gone) => {
                    self.bytes -= gone.weight();
                    self.dropped += 1;
                    self.oldest_at = self.lines.front().map(|next| next.at);
                }
                // Unreachable while `bytes` is derived from `lines`, and the
                // break rather than an unwrap is what keeps that true if it
                // ever stops being: a wrong byte count must not become a spin.
                None => break,
            }
        }
    }

    /// Throw away anything too old to be worth sending.
    ///
    /// Called before a batch is built rather than on a timer, so a device that
    /// wakes after a long sleep discards in one pass instead of sending a week
    /// of history nobody asked for.
    pub fn expire(&mut self, now: DateTime<Utc>) {
        let horizon = match chrono::TimeDelta::from_std(MAX_QUEUED_AGE) {
            Ok(span) => now - span,
            // A constant that cannot be represented is a bug in this file, not
            // a reason to drop somebody's logs.
            Err(_) => return,
        };
        while self.lines.front().is_some_and(|line| line.at < horizon) {
            if let Some(gone) = self.lines.pop_front() {
                self.bytes -= gone.weight();
                self.dropped += 1;
            }
        }
        self.oldest_at = self.lines.front().map(|line| line.at);
    }

    /// Whether there is enough, or it has waited long enough.
    ///
    /// Size OR age, never size alone. A device that logs one line an hour would
    /// otherwise hold its first line until it had half a megabyte of company,
    /// which on a quiet device is never.
    pub fn ready(&self, now: DateTime<Utc>) -> bool {
        if self.lines.is_empty() {
            return false;
        }
        if self.bytes >= MAX_BATCH_BYTES {
            return true;
        }
        match (self.oldest_at, chrono::TimeDelta::from_std(MAX_BATCH_AGE)) {
            (Some(oldest), Ok(span)) => now - oldest >= span,
            _ => false,
        }
    }

    /// Take what fits in one request, leaving the rest.
    ///
    /// THE LINES ARE NOT REMOVED UNTIL THE UPLOAD SUCCEEDS. This hands back a
    /// borrowed count and `settle` is what commits it, because v5's log flush
    /// cleared its batch before knowing whether the publish had worked, which
    /// loses exactly the logs somebody is about to go looking for.
    pub fn batch(&mut self, now: DateTime<Utc>) -> Batch {
        self.expire(now);
        let mut bytes = 0;
        let mut taken = 0;
        for line in &self.lines {
            let next = bytes + line.weight();
            if taken > 0 && next > MAX_BATCH_BYTES {
                break;
            }
            bytes = next;
            taken += 1;
        }
        Batch {
            lines: self.lines.iter().take(taken).cloned().collect(),
            dropped: self.dropped,
        }
    }

    /// The batch went. Forget those lines and reset the drop counter.
    pub fn settle(&mut self, batch: &Batch) {
        for _ in 0..batch.lines.len() {
            if let Some(gone) = self.lines.pop_front() {
                self.bytes -= gone.weight();
            }
        }
        self.dropped = self.dropped.saturating_sub(batch.dropped);
        self.oldest_at = self.lines.front().map(|line| line.at);
    }
}

/// One request body.
#[derive(Debug, Clone, Serialize)]
pub struct Batch {
    pub lines: Vec<Line>,
    /// How many lines were given up on before these. Reported so a gap in a log
    /// is a number rather than a mystery.
    pub dropped: u64,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The body, whole, so its length is known before the request starts.
    pub fn body(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|error| Error::Crypto(format!("could not serialise a log batch: {error}")))
    }
}

/// Refuse an endpoint that would put device logs on the wire in clear.
///
/// The same rule and the same exemption as `config::clean_api`: loopback is
/// allowed because a test on one machine has no wire to intercept. Logs are not
/// a credential, but they are the customer's data and they travel from a device
/// that has a certificate proving who it is, so sending them unauthenticated
/// and unencrypted would throw away both halves at once.
pub fn clean_endpoint(raw: &str) -> Result<String> {
    let endpoint = raw.trim().trim_end_matches('/').to_string();
    if endpoint.is_empty() {
        return Err(Error::Config("OPENQTT_LOGS is empty.".to_string()));
    }
    if endpoint.starts_with("https://") {
        return Ok(endpoint);
    }
    let loopback = endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://localhost")
        || endpoint.starts_with("http://[::1]");
    if loopback {
        return Ok(endpoint);
    }
    if endpoint.starts_with("http://") {
        return Err(Error::Config(format!(
            "OPENQTT_LOGS is '{endpoint}', which is not encrypted. A log batch \
             carries the customer's data and is authenticated by a client \
             certificate, and plain HTTP throws away both. Use https, or a \
             loopback address for a test."
        )));
    }
    Err(Error::Config(format!(
        "OPENQTT_LOGS is '{endpoint}', which has no scheme. It looks like \
         {DEFAULT_LOGS}."
    )))
}

/// Send one batch, over a client built for this one request.
///
/// **THE CLIENT IS BUILT PER BATCH AND THAT IS THE POINT, not laziness.** A TLS
/// client captures its certificate when it is created, which is the whole
/// reason the broker connection lives behind a swappable cell: a renewed
/// certificate changes nothing until the client itself is replaced, and v5
/// needed a process restart for exactly this. A long-lived connection has no
/// choice. A batch upload does: a flush happens about once a minute, building a
/// client costs microseconds beside a network round trip, and doing it here
/// makes a whole class of "worked for a day, then quietly stopped" impossible
/// on this path rather than something to remember.
pub async fn send(endpoint: &str, tls: ClientConfig, batch: &Batch) -> Result<()> {
    let body = batch.body()?;
    let http = reqwest::Client::builder()
        // NO REDIRECTS, for the reason `enroll::Client` gives: a redirect
        // replays the body, and a 307 to an http endpoint would put the
        // customer's logs on the wire in clear after `clean_endpoint` refused
        // exactly that.
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(tls)
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("openqtt-device/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| Error::Crypto(format!("could not build a log client: {error}")))?;

    let response = http
        .post(endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        // EXPLICIT, so nothing decides to stream this. The body is already
        // whole; saying its length is what keeps the request out of
        // `Transfer-Encoding: chunked`, which some proxies answer with a 400.
        .header(reqwest::header::CONTENT_LENGTH, body.len())
        .body(body)
        .send()
        .await
        .map_err(|source| Error::Transport {
            url: endpoint.to_string(),
            source,
        })?;

    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    // NOTHING IS DROPPED ON A REFUSAL. The caller settles the queue only on
    // Ok, so a 4xx keeps the batch and retries it. That is deliberate even for
    // a 400: a body this crate built and the server refused is a bug worth
    // still having the evidence for, and the age cap is what stops it being
    // kept for ever.
    Err(Error::Api {
        status: status.as_u16(),
        message: format!("the log endpoint answered {status}"),
    })
}

/// How often the flusher looks. Well under `MAX_BATCH_AGE`, so a batch goes
/// close to when it is due rather than up to a whole window late.
const TICK: Duration = Duration::from_secs(10);

/// Hold lines and send them, for as long as the device runs.
///
/// **READS THE CERTIFICATE OFF DISK EVERY TIME IT SENDS**, which is what keeps
/// this working across a renewal. The alternative is holding a client built at
/// startup, and that client would present a certificate that expires in a week
/// while the device carries on queueing into it. Reading costs one small file
/// per minute and removes the failure entirely.
///
/// A failed send keeps the batch. The queue is settled only on success, because
/// v5's flush cleared its batch whether or not the publish worked, which loses
/// exactly the logs somebody is about to go looking for. The age cap is what
/// stops a permanently refused batch being kept for ever.
pub async fn task(
    endpoint: String,
    store: crate::state::Store,
    pin: crate::Pin,
    queue: Arc<Mutex<Queue>>,
) {
    loop {
        tokio::time::sleep(TICK).await;

        let batch = {
            // The guard is dropped before anything is awaited: a lock held
            // across a network round trip would block every `log` call on this
            // device for as long as the uplink is slow.
            let Ok(mut held) = queue.lock() else {
                tracing::error!("the log queue is poisoned; logs are no longer being uploaded");
                return;
            };
            let now = Utc::now();
            if !held.ready(now) {
                continue;
            }
            held.batch(now)
        };
        if batch.is_empty() {
            continue;
        }

        let tls = match store.load() {
            Ok(Some(current)) => crate::mqtt::client_config(
                &pin,
                &current.certificate,
                &current.chain,
                &current.private_key,
            ),
            // No state at all means this device has not enrolled, which the
            // rest of the crate is already busy fixing. Keep the lines.
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(%error, "could not read the certificate to upload logs");
                continue;
            }
        };
        let tls = match tls {
            Ok(tls) => tls,
            Err(error) => {
                tracing::warn!(%error, "could not build a client to upload logs");
                continue;
            }
        };

        match send(&endpoint, tls, &batch).await {
            Ok(()) => {
                if let Ok(mut held) = queue.lock() {
                    held.settle(&batch);
                }
            }
            // Kept, not dropped. The next tick tries the same lines again.
            Err(error) => tracing::warn!(
                %error,
                lines = batch.lines.len(),
                "a log batch did not go; it is still queued"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + seconds, 0).expect("a valid instant")
    }

    fn line(seconds: i64, message: &str) -> Line {
        Line {
            at: at(seconds),
            level: "info",
            message: message.to_string(),
        }
    }

    #[test]
    fn a_quiet_device_still_sends_its_one_line() {
        // Size alone would hold it until it had half a megabyte of company,
        // which on a device logging once an hour is never.
        let mut queue = Queue::new();
        queue.push(line(0, "the only thing that happened today"));
        assert!(!queue.ready(at(30)), "not yet");
        assert!(queue.ready(at(61)), "the age is what releases it");
    }

    #[test]
    fn nothing_is_ready_when_there_is_nothing() {
        let queue = Queue::new();
        assert!(!queue.ready(at(10_000)));
        assert!(queue.is_empty());
    }

    #[test]
    fn the_newest_lines_are_the_ones_kept() {
        let mut queue = Queue::new();
        let big = "x".repeat(64 * 1024);
        for n in 0..200 {
            queue.push(line(n, &format!("{n} {big}")));
        }
        assert!(queue.dropped() > 0, "the ceiling was reached");
        // The oldest went and the newest stayed, which is the choice being made.
        let held = queue.batch(at(1_000));
        assert!(
            !held.lines.iter().any(|l| l.message.starts_with("0 ")),
            "the first line should have been dropped"
        );
    }

    #[test]
    fn a_batch_is_not_forgotten_until_it_has_actually_gone() {
        // v5 cleared its batch before knowing whether the publish worked, which
        // loses exactly the logs somebody is about to go looking for.
        let mut queue = Queue::new();
        queue.push(line(0, "first"));
        queue.push(line(1, "second"));

        let batch = queue.batch(at(61));
        assert_eq!(batch.lines.len(), 2);
        assert_eq!(queue.len(), 2, "still held, the upload has not happened");

        queue.settle(&batch);
        assert_eq!(queue.len(), 0, "now it has");
    }

    #[test]
    fn lines_older_than_the_horizon_are_given_up_on() {
        let mut queue = Queue::new();
        queue.push(line(0, "from last week"));
        queue.push(line(8 * 24 * 60 * 60, "from today"));

        let batch = queue.batch(at(8 * 24 * 60 * 60 + 1));
        assert_eq!(batch.lines.len(), 1);
        assert_eq!(batch.lines[0].message, "from today");
        assert_eq!(batch.dropped, 1, "and it says so rather than hiding it");
    }

    #[test]
    fn one_batch_never_exceeds_what_one_request_may_carry() {
        let mut queue = Queue::new();
        let big = "y".repeat(100 * 1024);
        for n in 0..20 {
            queue.push(line(n, &big));
        }
        let batch = queue.batch(at(1_000));
        let weight: usize = batch.lines.iter().map(Line::weight).sum();
        assert!(weight <= MAX_BATCH_BYTES, "{weight} over the cap");
        assert!(!batch.is_empty(), "and it is not empty either");
        // The rest is still there for the next one.
        queue.settle(&batch);
        assert!(!queue.is_empty());
    }

    #[test]
    fn a_single_line_over_the_cap_still_goes_rather_than_wedging_the_queue() {
        // Without the `taken > 0` guard this batch is empty for ever and every
        // line behind it is stuck behind a line that can never be sent.
        let mut queue = Queue::new();
        queue.push(line(0, &"z".repeat(MAX_BATCH_BYTES + 1)));
        let batch = queue.batch(at(61));
        assert_eq!(batch.lines.len(), 1);
    }

    #[test]
    fn the_drop_count_resets_only_for_what_was_reported() {
        let mut queue = Queue::new();
        queue.push(line(0, "old"));
        queue.push(line(8 * 24 * 60 * 60, "new"));
        let batch = queue.batch(at(8 * 24 * 60 * 60 + 1));
        assert_eq!(batch.dropped, 1);
        queue.settle(&batch);
        assert_eq!(queue.dropped(), 0, "reported, so no longer outstanding");
    }

    #[test]
    fn the_body_is_built_whole_so_its_length_is_known() {
        let mut queue = Queue::new();
        queue.push(line(0, "hello"));
        let body = queue.batch(at(61)).body().expect("serialise");
        assert!(!body.is_empty());
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(parsed["lines"][0]["message"], "hello");
        assert_eq!(parsed["dropped"], 0);
    }

    #[test]
    fn an_endpoint_that_would_send_logs_in_clear_is_refused() {
        assert!(clean_endpoint("https://logs.openqtt.com/v1/logs").is_ok());
        assert!(clean_endpoint("http://127.0.0.1:8080/v1/logs").is_ok());
        assert!(clean_endpoint("http://localhost:8080/v1/logs").is_ok());

        let plain = clean_endpoint("http://logs.example.com/v1/logs").unwrap_err();
        assert!(format!("{plain}").contains("not encrypted"), "{plain}");

        let bare = clean_endpoint("logs.openqtt.com").unwrap_err();
        assert!(format!("{bare}").contains("no scheme"), "{bare}");

        assert!(clean_endpoint("   ").is_err());
    }

    #[test]
    fn a_trailing_slash_is_not_a_different_endpoint() {
        assert_eq!(
            clean_endpoint("https://logs.openqtt.com/v1/logs/").unwrap(),
            "https://logs.openqtt.com/v1/logs"
        );
    }

    #[test]
    fn the_levels_are_a_closed_set() {
        assert!(LEVELS.contains(&"warn"));
        assert!(!LEVELS.contains(&"critical"));
    }
}
