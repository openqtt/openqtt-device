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
async fn a_device_cannot_subscribe() {
    // The ACL denies every subscribe and the crate offers no way to try, so
    // this asserts the shape of the product rather than the behaviour of the
    // broker: there is no `subscribe` on `Device`, and adding one would need
    // the broker rules to change first.
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
