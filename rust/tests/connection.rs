//! What this client does across its own connections, proven against a socket.
//!
//! THIS IS NOT A BROKER AND IT IS NOT EVIDENCE ABOUT ONE. `tests/live.rs`
//! explains, at length, why the broker leg is proven against the real thing:
//! the subject there is a listener with `verify_peer`, a private issuing chain,
//! a mountpoint and an ACL, and a fake with any of those wrong passes where the
//! real one refuses. Nothing here enforces any of them and nothing here should
//! ever be read as saying they work.
//!
//! What is under test here is the CLIENT, in the one situation a real broker
//! cannot be talked into producing on demand: a certificate handover. A
//! renewal replaces the live client, the replacement is a new connection with
//! no subscriptions at all, and a device that failed to subscribe again would
//! work perfectly for a day and then go deaf, silently, with no error anywhere
//! and nothing in the log. That is the worst shape a bug can take and it is
//! worth a socket to close.
//!
//! So the peer below answers CONNECT with CONNACK, answers SUBSCRIBE with
//! SUBACK, writes down what it was told, and can push a retained-style command
//! at a device that has just subscribed. That is the whole of it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use openqtt_device::{BrokerTransport, Config, Device, Outcome, Probe};
use rumqttc::tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rumqttc::tokio_rustls::rustls::ServerConfig;
use rumqttc::tokio_rustls::TlsAcceptor;
use rumqttc::{ConnAck, ConnectReturnCode, Packet, Publish, QoS, SubAck, SubscribeReasonCode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A self-signed P-256 authority, standing in for the OpenQTT Root. The same
/// fixture as `tests/enrollment.rs`, which keeps its own copy because that file
/// reads as the narrative of a first boot and is better for having it inline.
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

    /// A server certificate for 127.0.0.1. The IP has to be in a SAN: rustls
    /// checks the name the connection was opened with and an address is a name.
    fn server(&self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(std::net::IpAddr::from([
            127, 0, 0, 1,
        ]))];
        let certificate = params.signed_by(&key, &self.issuer).unwrap();
        (
            vec![certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }
}

/// Stands in for `POST /api/v1/enroll`, signing whatever certificate request
/// the device actually sent.
///
/// THE FIRST CERTIFICATE IS DUE FOR RENEWAL THE MOMENT IT IS ISSUED, which is
/// how a handover is forced without waiting for one. Every certificate after it
/// is long lived, so exactly one handover happens.
struct Enrollment {
    signing: Arc<Authority>,
    issued: AtomicUsize,
}

impl Respond for Enrollment {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let csr = body["csr"].as_str().unwrap();
        let parsed = rcgen::CertificateSigningRequestParams::from_pem(csr).unwrap();
        let certificate = parsed.signed_by(&self.signing.issuer).unwrap().pem();

        let count = self.issued.fetch_add(1, Ordering::SeqCst);
        let now = chrono::Utc::now();
        // The first one is already due, so `next_wake` is zero and the renewal
        // task goes back to the api at once. The slack it spreads across is
        // four seconds, so the whole handover happens inside this test.
        let (renew_after, not_after) = if count == 0 {
            (now, now + chrono::TimeDelta::seconds(4))
        } else {
            (
                now + chrono::TimeDelta::days(1),
                now + chrono::TimeDelta::days(7),
            )
        };

        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "certificate": certificate,
            "chain": self.signing.pem,
            "common_name": body["device"],
            "not_after": not_after,
            "next_token": format!("oqe_{}", count + 1),
            "renew_after": renew_after,
            "server_time": now,
        }))
    }
}

/// One connection the peer accepted, and what arrived on it.
#[derive(Debug, Default, Clone)]
struct Session {
    client_id: String,
    filters: Vec<String>,
    published: Vec<(String, Vec<u8>)>,
}

#[derive(Default)]
struct Log {
    sessions: Vec<Session>,
}

/// A socket that speaks just enough MQTT to make this client observable.
struct Peer {
    port: u16,
    log: Arc<Mutex<Log>>,
}

impl Peer {
    /// `push` is published to every device that subscribes, which is what a
    /// broker does with a retained message on a fresh subscription.
    async fn start(authority: &Authority, push: Option<(String, Vec<u8>)>) -> Peer {
        let (chain, key) = authority.server();
        let acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Log::default()));

        let held = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let log = Arc::clone(&held);
                let push = push.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(socket).await else {
                        return;
                    };
                    serve(stream, log, push).await;
                });
            }
        });

        Peer { port, log }
    }

    /// Every connection so far, in the order they were opened. Not drained: a
    /// handover leaves the second one still open, and a test that took the
    /// list away would only ever see connections that had already ended.
    fn sessions(&self) -> Vec<Session> {
        self.log.lock().unwrap().sessions.clone()
    }
}

/// One connection: answer what has to be answered, write down the rest.
async fn serve<S>(mut stream: S, log: Arc<Mutex<Log>>, push: Option<(String, Vec<u8>)>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = BytesMut::with_capacity(8 * 1024);
    let mut out = BytesMut::with_capacity(8 * 1024);
    let mut session = Session::default();
    let mut index = None;

    loop {
        let packet = match Packet::read(&mut buffer, 1024 * 1024) {
            Ok(packet) => packet,
            Err(rumqttc::mqttbytes::Error::InsufficientBytes(_)) => {
                match stream.read_buf(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            Err(_) => break,
        };

        out.clear();
        match packet {
            Packet::Connect(connect) => {
                session.client_id = connect.client_id;
                ConnAck::new(ConnectReturnCode::Success, false)
                    .write(&mut out)
                    .unwrap();
            }
            Packet::Subscribe(subscribe) => {
                for filter in &subscribe.filters {
                    session.filters.push(filter.path.clone());
                }
                SubAck::new(
                    subscribe.pkid,
                    vec![SubscribeReasonCode::Success(QoS::AtLeastOnce)],
                )
                .write(&mut out)
                .unwrap();
                if let Some((topic, payload)) = &push {
                    // What a broker does with a retained message the instant a
                    // subscription matches it. The packet id is the peer's to
                    // choose and zero is not a legal one.
                    let mut delivery = Publish::new(topic, QoS::AtLeastOnce, payload.clone());
                    delivery.pkid = 1;
                    delivery.retain = true;
                    delivery.write(&mut out).unwrap();
                }
            }
            Packet::Publish(publish) => {
                session
                    .published
                    .push((publish.topic.clone(), publish.payload.to_vec()));
                if publish.qos != QoS::AtMostOnce {
                    rumqttc::PubAck::new(publish.pkid).write(&mut out).unwrap();
                }
            }
            Packet::PingReq => {
                rumqttc::PingResp.write(&mut out).unwrap();
            }
            Packet::Disconnect => break,
            _ => {}
        }

        // WRITTEN DOWN WHILE THE CONNECTION IS STILL OPEN. A handover leaves
        // the replacement connected for the rest of the test, so recording
        // only on close would show every connection except the one under test.
        {
            let mut held = log.lock().unwrap();
            match index {
                Some(at) => held.sessions[at] = session.clone(),
                None => {
                    held.sessions.push(session.clone());
                    index = Some(held.sessions.len() - 1);
                }
            }
        }

        if !out.is_empty() && stream.write_all(&out).await.is_err() {
            break;
        }
    }
}

struct Fixture {
    _home: tempfile::TempDir,
    _api: MockServer,
    peer: Peer,
    config: Config,
}

async fn fixture(push: Option<(String, Vec<u8>)>) -> Fixture {
    let home = tempfile::tempdir().unwrap();
    let authority = Authority::new();
    let root = home.path().join("root.pem");
    std::fs::write(&root, &authority.pem).unwrap();

    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/enroll"))
        .respond_with(Enrollment {
            signing: Arc::clone(&authority),
            issued: AtomicUsize::new(0),
        })
        .mount(&api)
        .await;

    let peer = Peer::start(&authority, push).await;
    let config = Config {
        device: Some("acme/production/pump-3".to_string()),
        bootstrap_token: Some("oqe_first".to_string()),
        api: api.uri(),
        broker_host: "127.0.0.1".to_string(),
        broker_port: peer.port,
        broker_transport: BrokerTransport::Tls,
        root_ca: root,
        state: home.path().join("openqtt").join("state.json"),
        artifact_key: home.path().join("artifact-key.pem"),
        // Loopback, so nothing here can reach a real endpoint even if a
        // flush fires while a test is running.
        logs: "http://127.0.0.1:1/v1/logs".to_string(),
        connect_timeout: Duration::from_secs(10),
    };
    Fixture {
        _home: home,
        _api: api,
        peer,
        config,
    }
}

/// Wait until `count` connections have subscribed, or give up and say what
/// did arrive.
async fn subscribed(peer: &Peer, count: usize) -> Vec<Session> {
    for _ in 0..200 {
        let seen = peer.sessions();
        if seen.len() >= count && seen.iter().take(count).all(|one| !one.filters.is_empty()) {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "{count} subscribed connections never arrived: {:?}",
        peer.sessions()
    );
}

/// Wait for one message on `topic`, from any of the peer's connections.
async fn published(peer: &Peer, topic: &str) -> serde_json::Value {
    for _ in 0..200 {
        for session in peer.sessions() {
            for (sent_to, payload) in session.published {
                if sent_to == topic {
                    return serde_json::from_slice(&payload).unwrap();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "nothing was ever published to {topic}: {:?}",
        peer.sessions()
    );
}

#[tokio::test]
async fn a_device_subscribes_as_soon_as_it_is_connected() {
    let fixture = fixture(None).await;
    let device = Device::builder()
        .config(fixture.config.clone())
        .connect()
        .await
        .unwrap();

    let seen = subscribed(&fixture.peer, 1).await;
    assert_eq!(seen[0].client_id, "acme/production/pump-3");
    assert_eq!(seen[0].filters, ["commands/#"]);
    device.shutdown().await;
}

#[tokio::test]
async fn the_connection_a_renewal_hands_over_to_subscribes_again() {
    // THE FAILURE THIS EXISTS FOR. A renewal replaces the live client, and the
    // replacement is a connection that has never subscribed to anything: the
    // session is clean, so nothing is restored, and rumqttc does not resend a
    // subscription it never sent. A device that got this wrong would receive
    // commands for a day and then stop, with nothing in any log to say so.
    let fixture = fixture(None).await;
    let device = Device::builder()
        .config(fixture.config.clone())
        .connect()
        .await
        .unwrap();

    let seen = subscribed(&fixture.peer, 2).await;
    for (index, session) in seen.iter().take(2).enumerate() {
        assert_eq!(
            session.filters,
            ["commands/#"],
            "connection {index} did not subscribe: {session:?}"
        );
    }
    device.shutdown().await;
}

#[tokio::test]
async fn a_dispatch_that_arrives_on_connect_is_answered() {
    // Retained, so it is delivered the instant the subscription lands, which
    // is before the line after `connect()` has run. That is the whole reason
    // probes are registered on the builder.
    let dispatch = serde_json::json!({ "run_id": "0f9b2c1e", "run_all": true });
    let fixture = fixture(Some((
        "commands/test".to_string(),
        serde_json::to_vec(&dispatch).unwrap(),
    )))
    .await;

    let device = Device::builder()
        .config(fixture.config.clone())
        .probe(Probe::new("sd_card", |message| {
            message.push_str("mounted, 3.1 GB free");
            Outcome::Pass
        }))
        .connect()
        .await
        .unwrap();

    let result = published(&fixture.peer, "test/result").await;
    assert_eq!(result["run_id"], "0f9b2c1e");
    assert_eq!(result["test_id"], "sd_card");
    assert_eq!(result["status"], "pass");
    assert_eq!(result["message"], "mounted, 3.1 GB free");
    device.shutdown().await;
}

#[tokio::test]
async fn a_signal_lands_on_its_own_topic() {
    let fixture = fixture(None).await;
    let device = Device::builder()
        .config(fixture.config.clone())
        .connect()
        .await
        .unwrap();
    device
        .signal(openqtt_device::Signal::Sleeping {
            wakes_in: Duration::from_secs(3600),
        })
        .await
        .unwrap();

    let sent = published(&fixture.peer, "status/sleeping").await;
    assert_eq!(sent["wakes_in_secs"], 3600);
    device.shutdown().await;
}

#[tokio::test]
async fn what_this_device_is_running_is_announced_on_every_connect() {
    // GROUND TRUTH, AND THE REASON IT IS NOT RETAINED ONCE. Installing an
    // update means restarting, so the process that would have announced
    // success was replaced mid-sentence. A rollout is judged by what a device
    // reports running, which means every connection has to say it, including
    // the one a renewal hands over to.
    let fixture = fixture(None).await;
    let device = Device::builder()
        .config(fixture.config.clone())
        // The sha is the running binary's, which here is this test.
        .firmware("1.4.0")
        .connect()
        .await
        .unwrap();

    let seen = subscribed(&fixture.peer, 2).await;
    for (index, session) in seen.iter().take(2).enumerate() {
        let meta = session
            .published
            .iter()
            .find(|(topic, _)| topic == "meta/firmware")
            .unwrap_or_else(|| panic!("connection {index} announced nothing: {session:?}"));
        let body: serde_json::Value = serde_json::from_slice(&meta.1).unwrap();
        assert_eq!(body["version"], "1.4.0");
        assert_eq!(body["sha256"].as_str().unwrap().len(), 64);
    }
    device.shutdown().await;
}
