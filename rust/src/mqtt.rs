//! The broker connection: one pinned root, one client certificate, and the
//! handful of options that each exist because something broke in the field.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rumqttc::tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rumqttc::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use rumqttc::{Event, EventLoop, MqttOptions, Outgoing, Packet, TlsConfiguration, Transport};
use tokio::sync::oneshot;

use crate::error::{Error, Result};

/// The broker's own ceiling (`emqx_schema.erl`, `max_packet_size`). rumqttc
/// defaults to 10 KB and refuses anything larger CLIENT SIDE, silently, which
/// is how a 30 KB payload became a message that was never sent and never
/// logged. Matching the broker means the only thing that can refuse a publish
/// is the broker.
pub const MAX_PACKET: usize = 1024 * 1024;

/// What the broker prepends. Counted here because the packet the LISTENER
/// measures is the mounted one, not the one this device wrote.
const MOUNT_PREFIX: &str = "ingest/";

/// How large the PUBLISH will be by the time the broker measures it.
///
/// Three things the payload length on its own leaves out: the two bytes of
/// topic length and two of packet identifier in the variable header, the one to
/// four bytes of the fixed header, and the mountpoint, which makes the topic
/// the broker sees longer than the one that was passed in.
pub fn packet_size(topic: &str, common_name: usize, payload: usize) -> usize {
    let mounted = MOUNT_PREFIX.len() + common_name + 1 + topic.len();
    // 2 for the topic length, 2 for the packet identifier at QoS 1 and 2.
    let remaining = 2 + mounted + 2 + payload;
    1 + remaining_length_bytes(remaining) + remaining
}

/// MQTT encodes the remaining length in one to four bytes, seven bits at a
/// time. Worth the four lines: at the 1 MB boundary it is 4, and rounding it to
/// 1 would put the check on the wrong side of the line.
fn remaining_length_bytes(remaining: usize) -> usize {
    match remaining {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}

/// 30 seconds, and 5 is the number this is not.
///
/// The broker drops a client at keepalive times 1.5, so this is a 45 second
/// grace. At 5 seconds a single missed PINGRESP reconnects, and residential and
/// mobile uplinks jitter past 5 seconds routinely: the v4 fleet sat in a 10
/// second reconnect cycle for hours and read as offline-then-online all day.
/// The broker also warns below 30.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// The one certificate this device trusts on the broker connection.
///
/// EXACTLY ONE, and a file with two in it is an error rather than a hint. The
/// pin is the security property here; quietly accepting a second anchor because
/// somebody concatenated two files is how it stops being one.
pub fn root_certificate(pem: &str) -> Result<CertificateDer<'static>> {
    let mut found = read_certificates(pem, "the root certificate")?;
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(Error::Crypto(
            "the root certificate file holds no certificate.".to_string(),
        )),
        many => Err(Error::Crypto(format!(
            "the root certificate file holds {many} certificates. It must hold \
             exactly one: this is the single anchor the broker connection is \
             checked against."
        ))),
    }
}

/// The last certificate in an enrollment chain, which is the root.
///
/// The api documents `chain` as the issuing intermediate then the root, and
/// `Device::connect` compares this against the pinned copy. It is an equality
/// check and never a trust decision: nothing in the response is an anchor.
pub fn chain_root(chain_pem: &str) -> Result<CertificateDer<'static>> {
    let found = read_certificates(chain_pem, "the enrollment chain")?;
    found
        .into_iter()
        .next_back()
        .ok_or_else(|| Error::Crypto("the enrollment chain holds no certificate.".to_string()))
}

/// Trust one root, present the leaf and everything under it.
///
/// NO `webpki_roots` ON THIS PATH, and it is not an oversight. The broker's
/// certificate comes from the OpenQTT Server Issuing CA under the OpenQTT Root
/// CA, so the public bundle rejects it:
///
/// ```text
///  0 s:O=OpenQTT, CN=mqtt.broker-yyz.openqtt.com
///  1 s:O=OpenQTT, OU=SCADABLE IoT, CN=OpenQTT Server Issuing CA
///  Verify return code: 20 (unable to get local issuer certificate)
/// ```
///
/// The broker sends the intermediate itself, so the root alone is enough.
///
/// THE PIN IS CHECKED HERE AND NOT AT ENROLLMENT, and moving it was a bug fix
/// rather than tidying. The check used to run on the enrollment response,
/// before the response was persisted. But the api rotates the token on every
/// success, so by the time the check ran the response was already a spent
/// credential: a device with a stale pin enrolled, refused its own new token,
/// retried on the one-rotation grace, refused that too, and was locked out of
/// the platform for good. Checking the STORED chain, at connect time, costs
/// nothing, repeats until somebody fixes it, and can never consume a token.
pub fn client_config(
    pin: &crate::Pin,
    certificate_pem: &str,
    chain_pem: &str,
    private_key_pem: &str,
) -> Result<ClientConfig> {
    if chain_root(chain_pem)? != pin.certificate {
        return Err(Error::RootMismatch {
            root: pin.path.clone(),
        });
    }

    let mut roots = RootCertStore::empty();
    roots
        .add(pin.certificate.clone())
        .map_err(|error| Error::Crypto(format!("the root certificate is unusable: {error}")))?;

    // LEAF FIRST, THEN THE CHAIN. TLS wants the path in order from the end
    // entity upwards. The broker holds both anchors so a bare leaf would also
    // verify, but sending the intermediate is what makes this work against a
    // broker that only has the root.
    let mut presented = read_certificates(certificate_pem, "the device certificate")?;
    presented.extend(read_certificates(chain_pem, "the enrollment chain")?);

    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(presented, private_key(private_key_pem)?)
        .map_err(|error| {
            Error::Crypto(format!(
                "the device certificate and key do not agree: {error}"
            ))
        })
}

pub fn options(common_name: &str, host: &str, port: u16, tls: ClientConfig) -> MqttOptions {
    // The common name as the client id. It is unique per device by
    // construction, it is what the broker will call this connection anyway
    // (`peer_cert_as_username = cn`), and it gives correct take-over semantics:
    // a reconnecting device displaces its own stale session rather than living
    // beside it.
    let mut options = MqttOptions::new(common_name, host, port);
    options.set_keep_alive(KEEPALIVE);

    // A resumed session delivers pubacks for packet ids the new session never
    // sent. rumqttc calls that an "Unsolicited puback packet", errors, and
    // reconnects, which is a loop rather than an incident. Nothing is lost by
    // starting clean: the ACL denies every subscribe, so there is no
    // subscription to restore.
    options.set_clean_session(true);
    options.set_max_packet_size(MAX_PACKET, MAX_PACKET);

    // NO USERNAME AND NO PASSWORD. The listener has `enable_authn = false` and
    // `peer_cert_as_username = cn`, so anything sent here is overwritten by the
    // certificate's common name before authorization ever sees it.
    options.set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
        Arc::new(tls),
    )));
    options
}

/// What a device may publish to.
///
/// THE TOPIC YOU PUBLISH IS NOT THE TOPIC THAT ARRIVES, and this is the trap
/// every first user hits. The listener carries `mountpoint = ingest/${username}/`
/// and the broker prepends it after authorization, so a device publishes
/// `temperature` and subscribers see
/// `ingest/acme/production/pump-3/temperature`. Sending the full path publishes
/// to `ingest/<name>/ingest/<name>/temperature`, which is allowed and which
/// nobody is listening to. Refusing it here turns a silent wrong answer into a
/// sentence.
pub fn check_topic(topic: &str) -> Result<()> {
    if topic.is_empty() {
        return Err(Error::Topic("A topic cannot be empty.".to_string()));
    }
    if topic.starts_with("ingest/") {
        return Err(Error::Topic(format!(
            "Publish '{}', not '{topic}'. The broker prepends ingest/<device>/ \
             itself; sending it as well publishes it twice.",
            topic.trim_start_matches("ingest/")
        )));
    }
    if topic.starts_with('/') {
        return Err(Error::Topic(format!(
            "'{topic}' starts with a slash, which makes the first topic level \
             empty. Drop the leading slash."
        )));
    }
    if topic.contains('+') || topic.contains('#') {
        return Err(Error::Topic(format!(
            "'{topic}' contains a wildcard. Wildcards belong in a subscription, \
             and a published topic names one place."
        )));
    }
    if topic.contains('\0') {
        return Err(Error::Topic(
            "A topic cannot contain a null byte.".to_string(),
        ));
    }
    // `max_topic_levels` is 128 on the listener, and the mountpoint spends
    // FOUR of them before this topic starts: `ingest` plus the three the common
    // name is made of, `<organization>/<namespace>/<device>`.
    let levels = topic.split('/').count();
    if levels > 124 {
        return Err(Error::Topic(format!(
            "'{topic}' has {levels} levels. The broker allows 128 and the \
             mountpoint uses four of them."
        )));
    }
    Ok(())
}

/// Poll the connection forever, telling `ready` about the first CONNACK.
///
/// rumqttc reconnects on its own as long as something keeps polling, so the
/// only job here is to keep polling and to not do it in a tight loop. 500ms and
/// not 5s: a broker pod rollout ends with the dying pod resetting the
/// connection, and 5s turns a sub-second event into a five second gap in the
/// data. Going below 500ms buys nothing, because rumqttc rate limits its own
/// reconnects, and costs CPU when the failure is permanent.
///
/// `retiring` is set when this connection is being replaced by a renewed one.
/// It changes nothing except the log level, and that is the point: a handover
/// asks the broker to close, so this loop sees the close it asked for. Without
/// the flag every device logs a connection error at WARN once a day, for the
/// most routine thing it does, and a log that cries wolf daily is one nobody
/// reads on the day it matters.
/// `flushed` fires when this loop has actually put a DISCONNECT on the wire.
/// That is the signal a handover waits on, and it is a real one rather than a
/// guess at how long writing takes: rumqttc drains its request queue in order,
/// so the DISCONNECT leaving means everything queued before it left too.
pub async fn pump(
    mut eventloop: EventLoop,
    mut ready: Option<oneshot::Sender<()>>,
    mut flushed: Option<oneshot::Sender<()>>,
    retiring: Arc<AtomicBool>,
) {
    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Packet::ConnAck(_))) => {
                tracing::info!("connected to the broker");
                if let Some(sender) = ready.take() {
                    let _ = sender.send(());
                }
            }
            Ok(Event::Outgoing(Outgoing::Disconnect)) => {
                tracing::debug!("disconnect sent; everything queued before it has gone out");
                if let Some(sender) = flushed.take() {
                    let _ = sender.send(());
                }
            }
            Ok(_) => {}
            Err(error) if retiring.load(Ordering::Relaxed) => {
                tracing::debug!(%error, "the replaced connection closed, as asked");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => {
                // A certificate problem reads as a plain connection error here
                // rather than as anything typed, so say enough that the log
                // names the likely cause without pretending to know.
                tracing::warn!(%error, "broker connection error, retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

fn read_certificates(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    // Every failure is an error. The v5 gateway does `filter_map(|c| c.ok())`
    // here, so a truncated certificate in the middle of a chain is dropped and
    // the handshake fails somewhere else entirely.
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::Crypto(format!("could not read {what}: {error}")))
}

/// PKCS#8 first, SEC1 second.
///
/// rcgen writes PKCS#8, so the first branch is the one this crate's own keys
/// take. The fallback is for a key somebody generated with openssl, which emits
/// SEC1 `BEGIN EC PRIVATE KEY` by default. No RSA branch: the api issues over
/// P-256 and refuses anything else.
fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let pkcs8: Vec<PrivatePkcs8KeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::Crypto(format!("could not read the private key: {error}")))?;
    if let Some(key) = pkcs8.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let sec1: Vec<PrivateSec1KeyDer<'static>> = rustls_pemfile::ec_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::Crypto(format!("could not read the private key: {error}")))?;
    sec1.into_iter()
        .next()
        .map(PrivateKeyDer::Sec1)
        .ok_or_else(|| {
            Error::Crypto(
                "the stored private key is neither PKCS#8 nor SEC1. A device key is P-256."
                    .to_string(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mountpoint_trap_is_refused_by_name() {
        let message = check_topic("ingest/acme/production/pump-3/temperature")
            .unwrap_err()
            .to_string();
        assert!(message.contains("prepends"), "{message}");
        assert!(message.contains("Publish 'acme/"), "{message}");
    }

    #[test]
    fn wildcards_and_empty_levels_are_refused() {
        assert!(check_topic("sensors/+/temperature").is_err());
        assert!(check_topic("sensors/#").is_err());
        assert!(check_topic("/temperature").is_err());
        assert!(check_topic("").is_err());
    }

    #[test]
    fn an_ordinary_topic_is_allowed() {
        check_topic("temperature").unwrap();
        check_topic("sensors/bay-4/temperature").unwrap();
    }

    #[test]
    fn a_key_that_is_neither_shape_is_named_rather_than_guessed() {
        let error =
            private_key("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
                .unwrap_err()
                .to_string();
        assert!(error.contains("P-256"), "{error}");
    }

    #[test]
    fn a_root_file_with_two_certificates_is_refused() {
        let identity = crate::identity::generate("a/b/c").unwrap();
        // Not a certificate, but enough to prove the count is what is checked
        // and not the contents.
        let _ = identity;
        let two = format!("{PEM}{PEM}", PEM = STUB);
        let error = root_certificate(&two).unwrap_err().to_string();
        assert!(error.contains("exactly one"), "{error}");
    }

    const STUB: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
}
