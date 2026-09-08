//! What a device is doing, when that is worth saying out loud.
//!
//! A CLOSED SET OF THREE, AND CLOSED IS THE FEATURE. A console that renders an
//! unknown status is a console showing a string nobody chose: it cannot colour
//! it, cannot sort by it, cannot alarm on it, and cannot tell a typo from a new
//! capability. The api argues the same thing about its own device types, and
//! the argument is the same one both times. Adding a fourth kind here is a
//! breaking change on purpose, because a fourth kind is a change to what the
//! console has to draw and pretending otherwise only moves the discovery to a
//! screenshot from a customer.
//!
//! `sleeping` is the one that pays for the idea. A dashboard that says
//! "sleeping, wakes in 40 minutes" raises an alarm when the wake deadline is
//! missed, rather than raising one every time a battery powered device does
//! exactly what it was told.

use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};

/// Something a device says about itself that is not a reading.
///
/// Published to `status/<kind>` and never retained: a device is denied the
/// retain flag by the broker, so the last thing a device said is the
/// platform's to remember and not the broker's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// Going quiet on purpose, and when to expect it back.
    ///
    /// The deadline is the product: missing it is an alarm, and being absent
    /// until it is not.
    Sleeping {
        /// How long until this device is expected to be heard from again.
        wakes_in: Duration,
    },
    /// About to restart into `to`, so the gap that follows is planned.
    Updating {
        /// The version being installed.
        to: String,
    },
    /// Moving to another broker, and which one.
    Migrating {
        /// The hostname this device is moving to.
        to: String,
    },
}

impl Signal {
    /// The last level of the topic. One of exactly three strings.
    pub fn kind(&self) -> &'static str {
        match self {
            Signal::Sleeping { .. } => "sleeping",
            Signal::Updating { .. } => "updating",
            Signal::Migrating { .. } => "migrating",
        }
    }

    /// The topic and the body, ready to publish.
    ///
    /// `at` is passed in rather than read here so this is a function of its
    /// inputs. It is the DEVICE'S opinion of the time and it can be wrong: a
    /// device with no real time clock reports 1970 until something tells it
    /// otherwise, which is why the platform stamps its own arrival time and
    /// treats this field as a claim rather than a fact.
    pub(crate) fn message(&self, at: DateTime<Utc>) -> (String, serde_json::Value) {
        let at = at.to_rfc3339_opts(SecondsFormat::Secs, true);
        let body = match self {
            Signal::Sleeping { wakes_in } => {
                serde_json::json!({ "at": at, "wakes_in_secs": wakes_in.as_secs() })
            }
            Signal::Updating { to } | Signal::Migrating { to } => {
                serde_json::json!({ "at": at, "to": to })
            }
        };
        (format!("status/{}", self.kind()), body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> DateTime<Utc> {
        DateTime::from_timestamp(1_788_782_400, 0).unwrap()
    }

    #[test]
    fn each_kind_lands_on_its_own_topic() {
        let kinds: Vec<String> = [
            Signal::Sleeping {
                wakes_in: Duration::from_secs(3600),
            },
            Signal::Updating {
                to: "1.4.0".to_string(),
            },
            Signal::Migrating {
                to: "mqtt.broker-fra.openqtt.com".to_string(),
            },
        ]
        .iter()
        .map(|signal| signal.message(at()).0)
        .collect();
        assert_eq!(
            kinds,
            ["status/sleeping", "status/updating", "status/migrating"]
        );
    }

    #[test]
    fn a_sleep_reports_a_duration_in_seconds_and_not_a_wake_time() {
        // The instant a device expects to wake up is arithmetic on a clock it
        // may not have. A duration is the same number without the clock.
        let (_, body) = Signal::Sleeping {
            wakes_in: Duration::from_secs(3600),
        }
        .message(at());
        assert_eq!(body["wakes_in_secs"], 3600);
        assert_eq!(body["at"], "2026-09-07T12:00:00Z");
    }

    #[test]
    fn an_update_and_a_migration_both_name_where_they_are_going() {
        let (topic, body) = Signal::Updating {
            to: "1.4.0".to_string(),
        }
        .message(at());
        assert_eq!(topic, "status/updating");
        assert_eq!(body["to"], "1.4.0");

        let (topic, body) = Signal::Migrating {
            to: "mqtt.broker-fra.openqtt.com".to_string(),
        }
        .message(at());
        assert_eq!(topic, "status/migrating");
        assert_eq!(body["to"], "mqtt.broker-fra.openqtt.com");
    }

    #[test]
    fn every_signal_topic_is_one_a_device_is_allowed_to_publish() {
        // `status/sleeping` is relative, which is the trap `check_topic`
        // exists for. Building it with the mountpoint would put it where
        // nobody is listening.
        for signal in [
            Signal::Sleeping {
                wakes_in: Duration::ZERO,
            },
            Signal::Updating { to: String::new() },
            Signal::Migrating { to: String::new() },
        ] {
            crate::mqtt::check_topic(&signal.message(at()).0).unwrap();
        }
    }
}
