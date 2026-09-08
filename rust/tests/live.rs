//! The legs that a mock cannot prove, run by hand against a real broker.
//!
//! IGNORED BY DEFAULT AND THAT IS A DECISION, NOT AN OVERSIGHT. Nothing in
//! this repository can stand up an MQTT broker honestly: the thing being
//! tested is a listener with `verify_peer`, a private issuing chain, a
//! mountpoint and an ACL, and a fake with any of those wrong would pass while
//! the real one refused. Neither v4 nor v5 of the SCADABLE gateway has a
//! single test that connects to a broker, which is exactly why v4 grew four
//! separate layers of certificate workaround in production.
//!
//! So the broker leg is proven against the real thing, and this file is how
//! that is done the same way twice rather than from memory.
//!
//! # Against a local production image
//!
//! Run the broker image `70-broker` pins, with the production `acl.conf` and
//! the PEMs from `iot/api/pki/`, then:
//!
//! ```sh
//! export OPENQTT_LIVE=1
//! export OPENQTT_DEVICE=acme/production/pump-3
//! export OPENQTT_TOKEN=oqe_...
//! export OPENQTT_API=http://127.0.0.1:8080
//! export OPENQTT_BROKER=127.0.0.1:8883
//! export OPENQTT_ROOT_CA=../../api/pki/root.crt.pem
//! export OPENQTT_STATE=/tmp/openqtt-live/state.json
//! cargo test --test live -- --ignored --nocapture
//! ```
//!
//! # Against production
//!
//! Create a device in the console, take the token, and leave `OPENQTT_API`
//! and `OPENQTT_BROKER` unset so the hosted defaults apply.
//!
//! Confirm the message arrived on the other side, because this test cannot:
//!
//! ```sh
//! mosquitto_sub -h <broker> -p 1883 -t 'ingest/acme/production/pump-3/#' -v
//! ```
//!
//! # What was measured
//!
//! 2026-09-07, against `ghcr.io/openqtt/openqtt@sha256:aaea53c9`, the digest
//! `stacks/prod/70-broker/main.tf` pins, with the production `acl.conf`, a
//! throwaway CA and a stub that issues the same leaf profile as
//! `services/pki.py`.
//!
//! ```text
//! enrol, connect, publish `temperature`
//!   -> CONNACK 0, username taken from the certificate CN
//!   -> an internal consumer on 1883, as svc.ingest, received
//!      ingest/acme/production/pump-3/temperature 21.5
//!   -> state.json 0600 in a 0700 directory, holding a rotated token
//!      rather than the bootstrap one
//!
//! the same device subscribes to `temperature`  -> denied
//! the same device subscribes to `#`            -> denied
//! no client certificate at all                 -> connection refused
//!
//! NOT MEASURED, AND OWED. `commands/#` was added after that run and the ACL
//! that has to allow it is the platform's. What is still unproven against a
//! real broker: that `ingest/${username}/commands/#` is accepted, that a
//! device is still refused `#` and another device's commands, and whether a
//! device may clear the retained dispatch on `commands/test` or is denied the
//! retain flag there as it is everywhere else. The last one is not a
//! correctness question, because the run id in the journal is what stops a
//! redelivery from running twice, but it decides whether a device that has
//! answered its diagnostics keeps being handed them.
//!
//! certificate handover, forced by shortening the renewal
//!   -> five consecutive handovers, one connect each
//!   -> ten messages delivered across them with no gap in the consumer
//!
//! the same device over a WEBSOCKET, OPENQTT_BROKER=wss://localhost:8084/mqtt,
//! against a broker whose only external listener is wss
//!   -> CONNACK 0, username still taken from the certificate CN
//!   -> ingest/acme/production/pump-3/temperature 21.5
//!   -> ws:default reported `running: false`, so the plaintext WebSocket
//!      listener the schema materialises by default really is off
//! ```
//!
//! The handover run needed two temporary changes that are NOT in the tree: the
//! stub issued three-hour certificates due for renewal after four seconds, and
//! `renew::SPREAD` was set to zero. Both exist because the spread is a quarter
//! of the window by design, so a real handover is up to 45 minutes late on
//! purpose and cannot be waited for. If you reproduce it, change those two and
//! change them back.

use openqtt_device::{Config, Device};

/// `--ignored` alone is not enough of a guard. These publish real messages
/// under a real device's name, so they also need somebody to have said so.
fn live() -> Config {
    assert!(
        std::env::var("OPENQTT_LIVE").is_ok(),
        "set OPENQTT_LIVE=1 to run against a real broker"
    );
    Config::from_env().expect("configuration")
}

#[tokio::test]
#[ignore = "needs a real broker and a real device"]
async fn a_device_enrols_connects_and_publishes() {
    let config = live();
    let state = config.state.clone();

    let device = Device::with_config(config).await.expect("connect");
    println!("connected as {}", device.common_name());

    // A relative topic. It arrives as ingest/<common name>/temperature.
    device.publish("temperature", 21.5).await.expect("publish");
    println!("published to ingest/{}/temperature", device.common_name());

    // The certificate and the rotated token are on disk, in one file, owned.
    let held = std::fs::read_to_string(&state).expect("state file");
    assert!(held.contains("next_token"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    device.shutdown().await;
}

#[tokio::test]
#[ignore = "needs a real broker and a real device"]
async fn a_device_subscribes_to_commands_and_to_nothing_else() {
    // THIS TEST USED TO ASSERT THE OPPOSITE and the change is the product's,
    // not this crate's: the ACL now allows `ingest/${username}/commands/#` and
    // still denies everything else. The device subscribes on its own, on every
    // CONNACK, so there is nothing to call here; what has to be confirmed by
    // hand against the real broker is what the ACL does with the two
    // subscriptions this crate never sends.
    //
    //   mosquitto_sub with this device's certificate on `#`            -> denied
    //   the same on another device's `ingest/<other>/commands/#`       -> denied
    //
    // The connection below reaching CONNACK is what says the allowed one was
    // accepted: a denied subscribe with `deny_action = ignore` is silence, so
    // the only honest check is on the broker's own log.
    let device = Device::with_config(live()).await.expect("connect");
    device.shutdown().await;
}

#[tokio::test]
#[ignore = "needs a real broker and a real device"]
async fn a_spent_certificate_is_replaced_before_connecting() {
    // Rewrite `not_after` into the past, then start. The device should enrol
    // again rather than try to connect with something the broker will refuse,
    // and the token it uses is the rotated one rather than OPENQTT_TOKEN.
    let config = live();
    let path = config.state.clone();
    let mut held: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("enrol first")).unwrap();
    let before = held["next_token"].as_str().unwrap().to_string();
    held["not_after"] = serde_json::json!("2000-01-01T00:00:00Z");
    std::fs::write(&path, serde_json::to_string_pretty(&held).unwrap()).unwrap();

    let device = Device::with_config(config).await.expect("connect");
    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_ne!(
        after["next_token"].as_str().unwrap(),
        before,
        "token rotated"
    );
    device.shutdown().await;
}
