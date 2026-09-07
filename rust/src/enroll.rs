//! `POST /api/v1/enroll`, the only call this crate makes to the platform.
//!
//! ONE ROUTE FOR THE FIRST CERTIFICATE AND THE FOUR-HUNDREDTH. There is no
//! renew variant and that is deliberate on the api's side: a device that has
//! been switched off for a year cannot present a valid certificate to prove
//! itself, so a renewal path authenticated by the current certificate would
//! need a recovery path beside it, and a path taken once per device per
//! lifetime is a path that is broken without anybody knowing.
//!
//! TRUST HERE IS NOT TRUST IN `mqtt.rs`, AND MIXING THEM UP IS THE EASIEST WAY
//! TO BUILD SOMETHING THAT CANNOT CONNECT. `api.openqtt.com` sits behind
//! Cloudflare with a publicly signed certificate, so the Mozilla roots are
//! correct here. The broker's certificate is issued by the OpenQTT Root CA and
//! the public roots reject it outright.

use std::time::Duration;

use chrono::{DateTime, Utc};
use rand::Rng as _;
use rumqttc::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result, Retry};

/// Ceiling for something that is probably about to fix itself. Chosen against
/// the certificate lifetime, not out of taste: 7 days of validity with a
/// renewal due after 1 leaves 6 days of slack, so a device retrying every 15
/// minutes gets roughly 570 attempts before anything stops working.
pub const FAST_CAP: Duration = Duration::from_secs(15 * 60);

/// Ceiling for a credential the platform has rejected.
///
/// SIZED BY THE FLEET AND NOT BY THIS DEVICE. Everything behind the ingress
/// shares one bucket of 60 requests a minute. Full jitter means a device
/// averages one attempt per half-cap, so at 15 minutes a dead device costs 8
/// requests an hour and about 450 of them consume the whole bucket, which is a
/// handful of decommissioned machines stopping every healthy device from
/// renewing. At 6 hours it is 4 a day, and it takes something on the order of
/// ten thousand before the arithmetic matters. A device re-enabled in the
/// console still recovers on its own, which is the property being protected.
pub const SLOW_CAP: Duration = Duration::from_secs(6 * 60 * 60);

const BACKOFF_BASE: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize)]
struct Request<'a> {
    device: &'a str,
    token: &'a str,
    csr: &'a str,
}

/// The response, field for field. `extra="forbid"` on the api's side means this
/// shape is a contract rather than a sample of one.
#[derive(Debug, Clone, Deserialize)]
pub struct Enrolled {
    /// PEM, the leaf.
    pub certificate: String,
    /// PEM, the issuing intermediate then the root.
    pub chain: String,
    pub common_name: String,
    pub not_after: DateTime<Utc>,
    /// THE TOKEN THAT REPLACES THE ONE JUST USED. See `state::State`.
    pub next_token: String,
    pub renew_after: DateTime<Utc>,
    /// The api's own clock, so a device with no working one can tell that is
    /// what is wrong rather than reporting an impossible certificate.
    pub server_time: DateTime<Utc>,
}

pub struct Client {
    http: reqwest::Client,
    url: String,
}

impl Client {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(public_roots())
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("openqtt-device/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| Error::Crypto(format!("could not build an https client: {error}")))?;
        Ok(Client {
            http,
            url: url.into(),
        })
    }

    /// One attempt. The retrying lives in the callers, because a first
    /// enrollment and a renewal want different answers to a 401.
    pub async fn enroll(&self, device: &str, token: &str, csr: &str) -> Result<Enrolled> {
        let response = self
            .http
            .post(&self.url)
            .json(&Request { device, token, csr })
            .send()
            .await
            .map_err(|source| Error::Transport {
                url: self.url.clone(),
                source,
            })?;

        let status = response.status().as_u16();
        if status == 200 {
            return response
                .json::<Enrolled>()
                .await
                .map_err(|source| Error::Transport {
                    url: self.url.clone(),
                    source,
                });
        }

        let body = response.text().await.unwrap_or_default();
        Err(match status {
            400 => Error::Rejected(message_from(&body, "the request was refused")),
            401 => Error::Refused,
            403 => Error::Disabled,
            // 422 is a body this crate should never send. It is not transient
            // and the detail is the only thing that makes it debuggable.
            422 => Error::Rejected(message_from(&body, "the request body was rejected")),
            429 => Error::RateLimited,
            _ => Error::Api {
                status,
                message: message_from(&body, "no message"),
            },
        })
    }
}

/// The Mozilla root bundle, compiled in.
///
/// Baked into the binary rather than read from the host, because minimal Alpine
/// and Yocto images routinely ship no `/etc/ssl/certs` and a device SDK that
/// only works on a full distribution is not one. This costs about 250 KB and it
/// bought the v4 gateway its entire fielded fleet back after a broker
/// certificate moved to a public issuer.
fn public_roots() -> ClientConfig {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// The message out of an error body.
///
/// Two shapes, in order. `kit` owns the envelope for the whole fleet and puts
/// the sentence at `error.message`; FastAPI's own `detail` is the fallback for
/// a service that has not redeployed onto the envelope yet.
fn message_from(body: &str, fallback: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return fallback.to_string();
    };
    value
        .pointer("/error/message")
        .or_else(|| value.pointer("/detail"))
        .and_then(|found| found.as_str())
        .unwrap_or(fallback)
        .to_string()
}

/// How long to wait before attempt number `attempt`, counting from zero.
///
/// FULL JITTER, AND ON THIS PLATFORM IT IS LOAD BEARING RATHER THAN POLITE.
/// The api's limiter is 60 requests a minute with a burst of 20 and
/// `trusted_proxies = 0`, so it sees the ingress address and not the device's:
/// every device in the fleet shares one bucket. A fleet retrying on a fixed
/// interval synchronises itself into a permanent 429 and the outage is entirely
/// self-inflicted.
/// `pace` picks the ceiling: see [`Retry`] for why a rejected credential backs
/// off on a different scale from a flat network.
pub fn backoff(attempt: u32, pace: Retry) -> Duration {
    let cap = match pace {
        Retry::Soon => FAST_CAP,
        Retry::Rarely => SLOW_CAP,
    };
    let ceiling = BACKOFF_BASE
        .saturating_mul(1u32 << attempt.min(20))
        .min(cap);
    let millis = rand::rng().random_range(0..=ceiling.as_millis() as u64);
    Duration::from_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn answering(status: u16, body: serde_json::Value) -> (MockServer, Client) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/enroll"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&server)
            .await;
        let client = Client::new(format!("{}/api/v1/enroll", server.uri())).unwrap();
        (server, client)
    }

    fn issued() -> serde_json::Value {
        serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
            "chain": "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
            "common_name": "acme/production/pump-3",
            "not_after": "2026-09-14T12:00:00Z",
            "next_token": "oqe_second",
            "renew_after": "2026-09-08T12:00:00Z",
            "server_time": "2026-09-07T12:00:00Z"
        })
    }

    #[tokio::test]
    async fn a_certificate_comes_back_whole() {
        let (_server, client) = answering(200, issued()).await;
        let fresh = client
            .enroll(
                "acme/production/pump-3",
                "oqe_first",
                "-----BEGIN CERTIFICATE REQUEST-----",
            )
            .await
            .unwrap();

        assert_eq!(fresh.common_name, "acme/production/pump-3");
        assert_eq!(fresh.next_token, "oqe_second");
        assert!(fresh.certificate.contains("leaf"));
        assert!(fresh.chain.contains("chain"));
        // A day of validity before renewal, seven before expiry.
        assert_eq!((fresh.renew_after - fresh.server_time).num_days(), 1);
        assert_eq!((fresh.not_after - fresh.server_time).num_days(), 7);
    }

    #[tokio::test]
    async fn the_body_is_the_three_fields_the_api_accepts() {
        // `extra="forbid"` on the api's side, so an extra field is a 422 and
        // a renamed one is a silent nothing. Pin the shape.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/enroll"))
            .and(body_json(serde_json::json!({
                "device": "acme/production/pump-3",
                "token": "oqe_first",
                "csr": "a csr"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(issued()))
            .mount(&server)
            .await;

        let client = Client::new(format!("{}/api/v1/enroll", server.uri())).unwrap();
        client
            .enroll("acme/production/pump-3", "oqe_first", "a csr")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_dead_credential_says_so_without_saying_which_half() {
        let (_server, client) = answering(
            401,
            serde_json::json!({"detail": "That device name and token do not match a device."}),
        )
        .await;
        let error = client
            .enroll("a/b/c", "oqe_wrong", "csr")
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Refused));
        // A working device that lost its credential keeps trying, because a
        // person can put it back. A first enrollment stops, because a person
        // is watching. And it keeps trying SLOWLY, because a fleet of dead
        // devices asking quickly is what empties the shared rate-limit bucket.
        assert_eq!(error.retry(), Retry::Rarely);
        assert!(error.fatal_at_bootstrap());
    }

    #[tokio::test]
    async fn a_disabled_device_stops_being_renewed_but_keeps_asking() {
        let (_server, client) = answering(403, serde_json::json!({"detail": "disabled"})).await;
        let error = client
            .enroll("a/b/c", "oqe_first", "csr")
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Disabled));
        assert_eq!(
            error.retry(),
            Retry::Rarely,
            "re-enabling must not need a site visit, but it must not cost the fleet either"
        );
    }

    #[tokio::test]
    async fn a_bad_request_carries_the_sentence_the_api_wrote() {
        let (_server, client) = answering(
            400,
            serde_json::json!({"error": {"message": "The certificate request must use P-256."}}),
        )
        .await;
        let error = client
            .enroll("a/b/c", "oqe_first", "csr")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("P-256"), "{error}");
        assert_eq!(
            error.retry(),
            Retry::Rarely,
            "retrying quickly will not change the curve"
        );
    }

    #[tokio::test]
    async fn rate_limiting_is_an_ordinary_condition_on_a_fleet() {
        // trusted_proxies = 0, so the limiter counts the ingress address and
        // every device shares one bucket of 60 a minute.
        let (_server, client) = answering(429, serde_json::json!({"detail": "slow down"})).await;
        let error = client
            .enroll("a/b/c", "oqe_first", "csr")
            .await
            .unwrap_err();
        assert!(matches!(error, Error::RateLimited));
        assert_eq!(error.retry(), Retry::Soon);
    }

    #[tokio::test]
    async fn a_platform_fault_is_worth_waiting_out() {
        let (_server, client) = answering(500, serde_json::json!({"detail": "oh dear"})).await;
        let error = client
            .enroll("a/b/c", "oqe_first", "csr")
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Api { status: 500, .. }), "{error}");
        assert_eq!(error.retry(), Retry::Soon);
    }

    #[tokio::test]
    async fn an_unreachable_api_is_transient() {
        // Nothing listening: a device booting before its uplink is up.
        let client = Client::new("http://127.0.0.1:1/api/v1/enroll").unwrap();
        let error = client
            .enroll("a/b/c", "oqe_first", "csr")
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Transport { .. }), "{error}");
        assert_eq!(error.retry(), Retry::Soon);
        assert!(!error.fatal_at_bootstrap());
    }

    #[test]
    fn neither_pace_ever_exceeds_its_cap() {
        for attempt in 0..64 {
            assert!(backoff(attempt, Retry::Soon) <= FAST_CAP);
            assert!(backoff(attempt, Retry::Rarely) <= SLOW_CAP);
        }
    }

    #[test]
    fn a_rejected_credential_backs_off_on_a_different_scale() {
        // The whole point of the second cap: a fleet of dead devices must not
        // be able to consume the bucket every healthy device renews through.
        // Sampled rather than asserted once, because full jitter means any
        // single draw can be small.
        let far: Duration = (0..200).map(|_| backoff(30, Retry::Rarely)).max().unwrap();
        let near: Duration = (0..200).map(|_| backoff(30, Retry::Soon)).max().unwrap();
        assert!(far > FAST_CAP, "the slow pace must reach past the fast cap");
        assert!(near <= FAST_CAP);
    }

    #[test]
    fn backoff_is_jittered_rather_than_a_schedule() {
        // The point of full jitter is that a fleet does not agree on when to
        // come back. Two draws at the same attempt should differ.
        let draws: Vec<_> = (0..16).map(|_| backoff(12, Retry::Soon)).collect();
        assert!(draws.iter().any(|value| *value != draws[0]));
    }

    #[test]
    fn the_error_envelope_wins_and_detail_is_the_fallback() {
        assert_eq!(
            message_from(r#"{"error":{"message":"nope"}}"#, "fallback"),
            "nope"
        );
        assert_eq!(message_from(r#"{"detail":"nope"}"#, "fallback"), "nope");
        assert_eq!(message_from("not json", "fallback"), "fallback");
    }
}
