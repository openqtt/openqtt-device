//! The path a device actually takes on first boot, through the public API.
//!
//! Everything up to the broker is exercised here: read the pin, generate a
//! key, ask for a certificate, check the chain against the pin, build the TLS
//! configuration out of what came back, and commit the result.
//!
//! THE MOCK SIGNS THE DEVICE'S REAL CERTIFICATE REQUEST. A canned response
//! would be cheaper and would prove less: rustls checks that the certificate
//! and the private key agree, so a fixed certificate over somebody else's
//! public key fails at the last step and the test would never reach it. Signing
//! the CSR the device actually sent is what makes the certificate this crate
//! generated, the certificate it stored, and the certificate it presents the
//! same certificate.
//!
//! The broker itself is not here, because nothing in this repository can stand
//! one up honestly. That leg is proven against the real thing: see
//! `tests/live.rs`.

use std::sync::Arc;
use std::time::Duration;

use openqtt_device::{Config, Device, Error};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A self-signed P-256 certificate authority, standing in for the OpenQTT Root.
struct Authority {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    pem: String,
}

impl Authority {
    fn new() -> Arc<Self> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let pem = params.self_signed(&key).unwrap().pem();
        Arc::new(Authority {
            issuer: rcgen::Issuer::new(params, key),
            pem,
        })
    }
}

/// Stands in for `POST /api/v1/enroll`: reads the certificate request out of
/// the body and answers with a certificate over the public key in it.
struct Enrollment {
    signing: Arc<Authority>,
    /// What goes in `chain`. Its last certificate is what the device compares
    /// against its pin, so a different authority here is a mismatch.
    chain: Arc<Authority>,
    token: &'static str,
}

impl Respond for Enrollment {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let csr = body["csr"].as_str().unwrap();
        let parsed = rcgen::CertificateSigningRequestParams::from_pem(csr).unwrap();
        let certificate = parsed.signed_by(&self.signing.issuer).unwrap().pem();

        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "certificate": certificate,
            "chain": self.chain.pem,
            "common_name": body["device"],
            "not_after": "2099-09-14T12:00:00Z",
            "next_token": self.token,
            "renew_after": "2099-09-08T12:00:00Z",
            "server_time": "2099-09-07T12:00:00Z"
        }))
    }
}

struct Fixture {
    _home: tempfile::TempDir,
    _server: MockServer,
    config: Config,
}

/// A device, its pinned root, and an api. `chain` is the authority whose
/// certificate the api puts in the response, so passing a different one is how
/// a stale pin is simulated.
async fn fixture(pinned: Arc<Authority>, chain: Arc<Authority>) -> Fixture {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("root.pem");
    std::fs::write(&root, &pinned.pem).unwrap();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/enroll"))
        .respond_with(Enrollment {
            signing: Arc::clone(&pinned),
            chain,
            token: "oqe_second",
        })
        .mount(&server)
        .await;

    let config = Config {
        device: Some("acme/production/pump-3".to_string()),
        bootstrap_token: Some("oqe_first".to_string()),
        api: server.uri(),
        // Nothing listens on port 1, which is the point: this test is about
        // everything that happens before the broker.
        broker_host: "127.0.0.1".to_string(),
        broker_port: 1,
        root_ca: root,
        state: home.path().join("openqtt").join("state.json"),
        connect_timeout: Duration::from_secs(1),
    };
    Fixture {
        _home: home,
        _server: server,
        config,
    }
}

#[tokio::test]
async fn a_bare_device_enrols_and_keeps_what_it_was_given() {
    let authority = Authority::new();
    let fixture = fixture(Arc::clone(&authority), authority).await;
    let state = fixture.config.state.clone();

    // The broker is not there, so this ends in a timeout. Reaching the timeout
    // is the result: it means the certificate, the chain and the key were good
    // enough to build a TLS client out of.
    let error = Device::with_config(fixture.config).await.unwrap_err();
    assert!(matches!(error, Error::Timeout { .. }), "{error}");

    let held: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(held["common_name"], "acme/production/pump-3");
    // THE TOKEN THAT CAME BACK, not the one that was used. The one it used
    // survives exactly one more rotation, so a device that kept the bootstrap
    // token would be one interruption away from being locked out.
    assert_eq!(held["next_token"], "oqe_second");
    assert!(held["certificate"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE-----"));
    // The key was generated here. Nothing the api sent contains it.
    assert!(held["private_key"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN PRIVATE KEY-----"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the state file holds a private key");
    }
}

#[tokio::test]
async fn the_second_run_uses_what_the_first_one_stored() {
    let authority = Authority::new();
    let fixture = fixture(Arc::clone(&authority), authority).await;
    let state = fixture.config.state.clone();

    let _ = Device::with_config(fixture.config.clone()).await;
    let first = std::fs::read_to_string(&state).unwrap();

    // No bootstrap token this time, which is how a device runs for the rest of
    // its life: the credential is the one in the state file.
    let mut second = fixture.config.clone();
    second.bootstrap_token = None;
    second.device = None;
    let error = Device::with_config(second).await.unwrap_err();
    assert!(matches!(error, Error::Timeout { .. }), "{error}");

    // Nothing was re-enrolled: the stored certificate is good until 2099.
    assert_eq!(std::fs::read_to_string(&state).unwrap(), first);
}

#[tokio::test]
async fn a_chain_that_does_not_end_at_the_pin_is_refused_before_anything_is_kept() {
    // The pin and the platform have moved apart. Saying so here, with both
    // names in the message, beats an UnknownIssuer handshake failure a week
    // later that names neither.
    let fixture = fixture(Authority::new(), Authority::new()).await;
    let state = fixture.config.state.clone();

    let error = Device::with_config(fixture.config).await.unwrap_err();
    assert!(matches!(error, Error::RootMismatch { .. }), "{error}");
    assert!(
        !state.exists(),
        "nothing is committed when the pin disagrees"
    );
}

#[tokio::test]
async fn a_wrong_token_on_a_first_run_stops_rather_than_retrying_forever() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("root.pem");
    std::fs::write(&root, &Authority::new().pem).unwrap();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/enroll"))
        .respond_with(ResponseTemplate::new(401).set_body_json(
            serde_json::json!({"detail": "That device name and token do not match a device."}),
        ))
        .mount(&server)
        .await;

    let config = Config {
        device: Some("acme/production/pump-3".to_string()),
        bootstrap_token: Some("oqe_wrong".to_string()),
        api: server.uri(),
        broker_host: "127.0.0.1".to_string(),
        broker_port: 1,
        root_ca: root,
        state: home.path().join("state.json"),
        connect_timeout: Duration::from_secs(1),
    };

    let error = Device::with_config(config).await.unwrap_err();
    assert!(matches!(error, Error::Refused), "{error}");
}

#[tokio::test]
async fn a_device_will_not_quietly_become_a_different_device() {
    let authority = Authority::new();
    let mut fixture = fixture(Arc::clone(&authority), authority).await;
    let _ = Device::with_config(fixture.config.clone()).await;

    // Somebody repurposed the machine and changed OPENQTT_DEVICE without
    // clearing the state. The stored identity, and the token that goes with
    // it, belong to the old name.
    fixture.config.device = Some("acme/production/pump-4".to_string());
    let message = Device::with_config(fixture.config)
        .await
        .unwrap_err()
        .to_string();
    assert!(message.contains("pump-4"), "{message}");
    assert!(message.contains("pump-3"), "{message}");
}

#[tokio::test]
async fn a_missing_root_says_which_file_and_why() {
    let home = tempfile::tempdir().unwrap();
    let config = Config {
        device: Some("acme/production/pump-3".to_string()),
        bootstrap_token: Some("oqe_first".to_string()),
        api: "http://127.0.0.1:1".to_string(),
        broker_host: "127.0.0.1".to_string(),
        broker_port: 1,
        root_ca: home.path().join("nowhere").join("root.pem"),
        state: home.path().join("state.json"),
        connect_timeout: Duration::from_secs(1),
    };

    let message = Device::with_config(config).await.unwrap_err().to_string();
    assert!(message.contains("root.pem"), "{message}");
    assert!(message.contains("OPENQTT_ROOT_CA"), "{message}");
}
