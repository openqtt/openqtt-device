//! Keeping the certificate fresh, on a clock the device may not have.
//!
//! The api issues 7 days and asks to be seen again after 1, so six consecutive
//! failures are survivable. That headroom is the offline tolerance and not a
//! freshness target: what protects a stolen certificate is a refused renewal,
//! not a short life.

use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use rand::Rng as _;
use tokio::sync::mpsc;

use crate::enroll::{self, Enrolled};
use crate::error::{Error, Result};
use crate::identity;
use crate::mqtt;
use crate::state::{State, Store};
use crate::Pin;

/// How far past `renew_after` a device may drift, as a fraction of the slack
/// between `renew_after` and `not_after`.
///
/// A quarter of six days is about 36 hours of spread, which leaves four and a
/// half days of retry budget on the far side. THE SPREAD IS NOT COSMETIC: the
/// api's rate limiter counts the ingress address rather than the device's, so
/// the whole fleet shares one bucket of 60 a minute. Devices installed together
/// enrol together, and without this they would come back together every day for
/// the life of the fleet.
const SPREAD: f64 = 0.25;

/// A local clock this far from the api's is worth a line in the log.
///
/// It is also, on a device with no real time clock, the explanation for a TLS
/// handshake that fails for no visible reason: rustls checks the broker's
/// certificate against the system clock, and a device that thinks it is 1990
/// rejects a perfectly good certificate as not yet valid.
const NOTABLE_SKEW: TimeDelta = TimeDelta::minutes(5);

/// How long to wait before coming back, measured entirely on the API'S clock.
///
/// EVERY VALUE HERE COMES FROM THE RESPONSE AND NONE FROM `Utc::now()`, and the
/// result is slept on the monotonic timer. That is what makes a wrong local
/// clock survivable: the device does not need to know what time it is, only how
/// long to wait, and the api told it both ends of that interval.
///
/// `jitter` is a fraction in `[0, 1)`, passed in rather than drawn here so the
/// schedule is a function of its inputs and can be tested as one.
pub fn next_wake(
    server_time: DateTime<Utc>,
    renew_after: DateTime<Utc>,
    not_after: DateTime<Utc>,
    jitter: f64,
) -> Duration {
    let due = (renew_after - server_time).max(TimeDelta::zero());
    // THE SLACK IS MEASURED FROM WHEN THE WAIT ENDS, NOT FROM `renew_after`.
    // Using the nominal window instead would spread a certificate that is
    // ALREADY EXPIRED across another day and a half, which is the opposite of
    // what a device in that state needs. A device that is late gets a smaller
    // spread, and one that is out of time gets none.
    let slack = (not_after - renew_after.max(server_time)).max(TimeDelta::zero());
    let spread = slack.num_milliseconds() as f64 * SPREAD * jitter.clamp(0.0, 1.0);
    Duration::from_millis(due.num_milliseconds().max(0) as u64 + spread as u64)
}

pub(crate) fn jitter() -> f64 {
    rand::rng().random_range(0.0..1.0)
}

/// One renewal: a new key, a new certificate, committed to disk.
///
/// A NEW KEYPAIR EVERY TIME, not a new certificate over the old key. It costs
/// a few milliseconds on a P-256 curve and it means a key that leaked is worth
/// at most seven days rather than the life of the device.
pub(crate) async fn renew(
    api: &enroll::Client,
    store: &Store,
    pin: &Pin,
    state: &State,
) -> Result<(State, Duration)> {
    let identity = identity::generate(&state.common_name)?;
    let fresh = api
        .enroll(&state.common_name, &state.next_token, &identity.csr_pem)
        .await?;

    report_clock(&fresh);
    check_root(&fresh, pin, api)?;

    let next = State {
        common_name: fresh.common_name.clone(),
        certificate: fresh.certificate.clone(),
        chain: fresh.chain.clone(),
        private_key: identity.private_key_pem,
        next_token: fresh.next_token.clone(),
        not_after: fresh.not_after,
        renew_after: fresh.renew_after,
    };
    // COMMITTED BEFORE ANYTHING IS TOLD ABOUT IT. The caller reads this file
    // back to rebuild the connection, so signalling first hands it the
    // certificate that was just replaced. The v4 gateway signalled first and a
    // fleet presented the previous day's certificate until the broker started
    // rejecting it.
    store.save(&next)?;

    let wait = next_wake(
        fresh.server_time,
        fresh.renew_after,
        fresh.not_after,
        jitter(),
    );
    Ok((next, wait))
}

/// The renewal loop. Ends only when the device it belongs to is dropped, or
/// when the failure is one that waiting cannot fix.
pub(crate) async fn task(
    api: enroll::Client,
    store: Store,
    pin: Pin,
    mut state: State,
    mut wait: Duration,
    renewed: mpsc::Sender<()>,
) {
    loop {
        tracing::debug!(seconds = wait.as_secs(), "next certificate renewal");
        tokio::time::sleep(wait).await;

        let mut attempt = 0u32;
        loop {
            match renew(&api, &store, &pin, &state).await {
                Ok((fresh, next)) => {
                    tracing::info!(
                        not_after = %fresh.not_after,
                        "certificate renewed"
                    );
                    state = fresh;
                    wait = next;
                    // The device has gone away. Nothing left to hand over to.
                    if renewed.send(()).await.is_err() {
                        return;
                    }
                    break;
                }
                Err(error) if error.transient() => {
                    let pause = enroll::backoff(attempt);
                    // A 403 and a flat network reach here the same way, so the
                    // log has to carry which one it was.
                    tracing::warn!(
                        %error,
                        seconds = pause.as_secs(),
                        attempt,
                        "certificate renewal failed, will try again"
                    );
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(pause).await;
                }
                Err(error) => {
                    tracing::error!(
                        %error,
                        "certificate renewal cannot succeed and will not be retried"
                    );
                    return;
                }
            }
        }
    }
}

fn report_clock(fresh: &Enrolled) {
    let skew = fresh.server_time - Utc::now();
    if skew.abs() > NOTABLE_SKEW {
        tracing::warn!(
            server_time = %fresh.server_time,
            local_time = %Utc::now(),
            skew_seconds = skew.num_seconds(),
            "this device's clock disagrees with the platform. TLS checks certificate \
             validity against the local clock, so this is the first thing to look at \
             if the broker connection fails"
        );
    }
}

/// The chain must end where the pin says it does.
///
/// AN EQUALITY CHECK, NOT A TRUST DECISION. Nothing in the response becomes an
/// anchor; this only catches the case where the pinned root and the platform
/// have moved apart, and turns it into a sentence at enrollment instead of a
/// handshake failure a week later that says `UnknownIssuer` and nothing else.
pub(crate) fn check_root(fresh: &Enrolled, pin: &Pin, api: &enroll::Client) -> Result<()> {
    let served = mqtt::chain_root(&fresh.chain)?;
    if served == pin.certificate {
        return Ok(());
    }
    Err(Error::RootMismatch {
        api: api.url().to_string(),
        root: pin.path.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    const DAY: i64 = 24 * 60 * 60;

    #[test]
    fn the_wait_is_the_gap_the_api_described() {
        // Issued now, renew in a day, expires in seven. No jitter.
        let wait = next_wake(at(0), at(DAY), at(7 * DAY), 0.0);
        assert_eq!(wait, Duration::from_secs(DAY as u64));
    }

    #[test]
    fn a_device_whose_clock_is_a_year_wrong_waits_exactly_as_long() {
        // The local clock never enters the calculation, so there is nothing to
        // be wrong. The three instants below are the api's, and a device that
        // thinks it is 1990 gets the same answer as one that is correct.
        let epoch = 20 * 365 * DAY;
        let wait = next_wake(at(epoch), at(epoch + DAY), at(epoch + 7 * DAY), 0.0);
        assert_eq!(wait, Duration::from_secs(DAY as u64));
    }

    #[test]
    fn jitter_spreads_a_fleet_across_a_quarter_of_the_slack() {
        let full = next_wake(at(0), at(DAY), at(7 * DAY), 1.0);
        // Six days of slack, a quarter of it, on top of the one day due.
        let expected = DAY as u64 + (6 * DAY as u64) / 4;
        assert_eq!(full.as_secs(), expected);
    }

    #[test]
    fn a_certificate_already_due_is_renewed_at_once() {
        // renew_after in the api's past: no negative durations, no panic.
        let wait = next_wake(at(3 * DAY), at(DAY), at(7 * DAY), 0.0);
        assert_eq!(wait, Duration::ZERO);
    }

    #[test]
    fn an_expired_certificate_is_renewed_now_however_the_dice_fall() {
        // The device is two days past expiry. There is no slack left to
        // spread across, so no draw of the jitter may delay it at all.
        for step in 0..=100 {
            let wait = next_wake(at(9 * DAY), at(DAY), at(7 * DAY), step as f64 / 100.0);
            assert_eq!(wait, Duration::ZERO, "jitter {step}");
        }
    }

    #[test]
    fn a_late_device_gets_a_smaller_spread_than_a_punctual_one() {
        // Three days in on a seven day certificate: four days of life left,
        // so at most one day of spread rather than the full day and a half.
        let late = next_wake(at(3 * DAY), at(DAY), at(7 * DAY), 1.0);
        let punctual = next_wake(at(0), at(DAY), at(7 * DAY), 1.0);
        assert_eq!(late.as_secs(), DAY as u64);
        assert!(late < punctual);
    }

    #[test]
    fn the_wait_never_reaches_expiry_from_anywhere() {
        // The property that matters: whatever the clock says and however the
        // jitter falls, a device always wakes up while its certificate is
        // still valid. Six survivable failures is the design, and it only
        // holds if the first attempt happens with time left.
        for now in 0..=7 {
            for step in 0..=20 {
                let server_time = at(now * DAY);
                let wait = next_wake(server_time, at(DAY), at(7 * DAY), step as f64 / 20.0);
                let remaining = (7 - now) * DAY;
                assert!(
                    wait < Duration::from_secs(remaining.max(1) as u64),
                    "at day {now} with jitter {step}: waits {wait:?} of {remaining}s left"
                );
            }
        }
    }
}
