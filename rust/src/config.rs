//! Configuration, from the environment and from nowhere else.
//!
//! NO CONFIG FILE, AND THAT IS THE FEATURE. The SCADABLE v5 gateway loads one
//! with `.ok().and_then(|c| toml::from_str(&c).ok()).unwrap_or_default()`, so a
//! malformed file and a missing file are indistinguishable and the device runs
//! on defaults having told nobody. Reading the environment, where every parse
//! failure is an error with a sentence, removes that class of bug instead of
//! reimplementing it.
//!
//! An empty variable is an unset variable. `Environment=OPENQTT_TOKEN=` in a
//! systemd unit is somebody clearing a value, not setting it to nothing.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result};

pub const DEFAULT_API: &str = "https://api.openqtt.com";
pub const DEFAULT_BROKER: &str = "mqtt.broker-yyz.openqtt.com:8883";
pub const DEFAULT_ROOT_CA: &str = "/etc/openqtt/root.pem";
pub const DEFAULT_STATE: &str = "/etc/openqtt/state.json";

/// The public halves of the keys the platform signs firmware with. Beside the
/// root certificate because it is the same kind of thing: a trust anchor that
/// arrives out of band and has no fallback.
pub const DEFAULT_ARTIFACT_KEY: &str = "/etc/openqtt/artifact-key.pem";
const DEFAULT_TLS_PORT: u16 = 8883;
const DEFAULT_WEBSOCKET_PORT: u16 = 8084;

/// The broker's own default `websocket.mqtt_path`. It has to match or the
/// upgrade request lands on a path the listener does not answer.
const DEFAULT_WEBSOCKET_PATH: &str = "/mqtt";

/// The listener gives a connection 15 seconds from TCP open to CONNECT, and a
/// TLS handshake happens inside that. 30 covers a slow uplink and still fails
/// while somebody is watching a first boot.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How this device reaches the broker.
///
/// ONE OR THE OTHER, CHOSEN BY THE NAMESPACE the device belongs to. Both carry
/// the same mutual TLS and both end up with the same identity: the broker takes
/// the username from the client certificate's common name either way, because
/// `emqx_channel:init/2` reads one `peercert` field and does not know or care
/// which listener filled it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerTransport {
    /// MQTT straight over TLS, on 8883. The default, and the right answer
    /// wherever the port is open.
    Tls,
    /// MQTT inside a WebSocket, on 8084. Slower to set up and one more thing to
    /// go wrong, and the only way out of a site whose firewall passes nothing
    /// but 443-shaped traffic. That is most industrial sites.
    WebSocket {
        /// The listener's `mqtt_path`. Sent in the upgrade request, so it has
        /// to be the path the broker actually answers on.
        path: String,
    },
}

/// Where this device enrols, where it publishes, and what it keeps on disk.
#[derive(Debug, Clone)]
pub struct Config {
    /// The certificate name, `<organization>/<namespace>/<device>`. Required
    /// on a first run, ignored once state exists.
    pub device: Option<String>,
    /// The one-time credential. Bootstrap only: see `state::State::next_token`.
    pub bootstrap_token: Option<String>,
    /// The platform's base URL, with no trailing slash.
    pub api: String,
    /// The broker's hostname. A NAME and not an address: the broker's
    /// certificate carries a DNS name and no IP, so an address cannot verify.
    pub broker_host: String,
    /// The broker's TLS port.
    pub broker_port: u16,
    /// Whether to speak MQTT directly or wrap it in a WebSocket.
    pub broker_transport: BrokerTransport,
    /// The single certificate the broker connection is checked against.
    pub root_ca: PathBuf,
    /// Where the certificate, the key and the rotating token live. The
    /// journal that records an update in progress lives beside it.
    pub state: PathBuf,
    /// The keys firmware signatures are checked against, one PEM block each.
    ///
    /// A SET AND NOT ONE KEY, so the signing key can be rotated: ship an
    /// artifact signed by the old key that adds the new one to this file, let
    /// the fleet converge, then sign with the new one. With a single key the
    /// only way to install a replacement is an update signed by the key being
    /// replaced, so losing it strands the fleet.
    ///
    /// Fail closed like the root certificate: with an empty or missing file an
    /// update is refused rather than installed unverified. The CDN is a
    /// distribution point and never a trust anchor.
    pub artifact_key: PathBuf,
    /// How long [`crate::Device::connect`] waits for the broker to acknowledge
    /// the connection before giving up. Worth raising on a link where a
    /// handshake takes longer than a person would wait, such as satellite.
    pub connect_timeout: Duration,
}

impl Config {
    /// Read the six `OPENQTT_*` variables, filling in the hosted defaults.
    pub fn from_env() -> Result<Self> {
        let broker = var("OPENQTT_BROKER").unwrap_or_else(|| DEFAULT_BROKER.to_string());
        let broker = parse_broker(&broker)?;
        Ok(Config {
            device: var("OPENQTT_DEVICE"),
            bootstrap_token: var("OPENQTT_TOKEN"),
            api: clean_api(&var("OPENQTT_API").unwrap_or_else(|| DEFAULT_API.to_string()))?,
            broker_host: broker.host,
            broker_port: broker.port,
            broker_transport: broker.transport,
            root_ca: var("OPENQTT_ROOT_CA")
                .unwrap_or_else(|| DEFAULT_ROOT_CA.to_string())
                .into(),
            state: var("OPENQTT_STATE")
                .unwrap_or_else(|| DEFAULT_STATE.to_string())
                .into(),
            artifact_key: var("OPENQTT_ARTIFACT_KEY")
                .unwrap_or_else(|| DEFAULT_ARTIFACT_KEY.to_string())
                .into(),
            connect_timeout: match var("OPENQTT_CONNECT_TIMEOUT") {
                None => DEFAULT_CONNECT_TIMEOUT,
                Some(seconds) => Duration::from_secs(seconds.parse().map_err(|_| {
                    Error::Config(format!(
                        "OPENQTT_CONNECT_TIMEOUT is '{seconds}', which is not a number of seconds."
                    ))
                })?),
            },
        })
    }

    pub(crate) fn enroll_url(&self) -> String {
        format!("{}/api/v1/enroll", self.api)
    }
}

fn var(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// The enrollment endpoint, refusing a scheme that would put the credential on
/// the wire in clear.
///
/// THE TOKEN IS IN THE BODY AND IT ROTATES, which makes plain HTTP worse here
/// than it looks. Anybody on the path reads both the credential this device is
/// using and the one it is about to use, and the second of those is enough to
/// enrol as this device and keep doing so after the real one has moved on.
/// There is no warning that makes that acceptable, so it is refused rather
/// than logged.
///
/// Loopback is exempt. A harness on the same machine has no wire to intercept,
/// and refusing it would mean this crate could not be exercised end to end
/// without standing up a certificate authority. Its own live test uses
/// `http://127.0.0.1`.
fn clean_api(raw: &str) -> Result<String> {
    let api = raw.trim().trim_end_matches('/');
    if api.is_empty() {
        return Err(Error::Config("OPENQTT_API is empty.".to_string()));
    }
    if api.starts_with("https://") {
        return Ok(api.to_string());
    }
    match api.strip_prefix("http://") {
        Some(authority) if is_loopback(authority) => Ok(api.to_string()),
        Some(_) => Err(Error::Config(format!(
            "OPENQTT_API is '{api}', which is not encrypted. The enrollment token \
             travels in the body and rotates on every use, so anybody on the path \
             reads both the credential this device is using and the one it is about \
             to use. Use https, or a loopback address for a test."
        ))),
        None => Err(Error::Config(format!(
            "OPENQTT_API is '{api}', which has no scheme. It looks like \
             https://api.openqtt.com."
        ))),
    }
}

/// Whether an authority names this machine. Handles `host`, `host:port` and
/// `[::1]:port`, and stops at the first `/` so a path cannot smuggle a name in.
pub(crate) fn is_loopback(authority: &str) -> bool {
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    // USERINFO IS THE TRAP AND IT IS NOT THEORETICAL. In
    // `http://127.0.0.1:80@example.com` the host is example.com; everything
    // before the `@` is a username and password. A check that scans for the
    // first thing shaped like an address finds the loopback in the userinfo and
    // waves the whole URL through, and the device then posts its rotating token
    // in clear to somebody else's server. Nothing legitimate here has userinfo,
    // so the presence of an `@` is enough to refuse.
    if authority.contains('@') {
        return false;
    }
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host),
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// What `OPENQTT_BROKER` names, in each of the shapes it is allowed to take.
#[derive(Debug, PartialEq, Eq)]
struct Broker {
    host: String,
    port: u16,
    transport: BrokerTransport,
}

/// `host`, `host:port`, `[::1]:port`, `mqtts://...`, or `wss://host:port/path`.
///
/// Hand-rolled because the v5 gateway's `rfind(':')` turns `[::1]:8883` into
/// host `[` and a parse error, and because refusing the plaintext schemes here
/// is the cheapest place to make them impossible: v5's builder skips the whole
/// TLS block when the CA is empty and connects unencrypted with no warning.
fn parse_broker(raw: &str) -> Result<Broker> {
    let raw = raw.trim();
    for plaintext in ["mqtt://", "ws://"] {
        if let Some(rest) = raw.strip_prefix(plaintext) {
            return Err(Error::Config(format!(
                "OPENQTT_BROKER is {plaintext}{rest}, which is not encrypted. This \
                 device authenticates with a client certificate, so the connection \
                 is always TLS. Use mqtts:// or wss://, or a bare host:port."
            )));
        }
    }

    if let Some(rest) = raw.strip_prefix("wss://") {
        // The path is part of the URL here and not an afterthought: rumqttc
        // sends it as the upgrade request's target, and the broker only answers
        // on its configured `mqtt_path`.
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].to_string()),
            None => (rest, DEFAULT_WEBSOCKET_PATH.to_string()),
        };
        let (host, port) = split_authority(authority, DEFAULT_WEBSOCKET_PORT)?;
        return Ok(Broker {
            host,
            port,
            transport: BrokerTransport::WebSocket { path },
        });
    }

    let authority = raw
        .strip_prefix("mqtts://")
        .unwrap_or(raw)
        .trim_end_matches('/');
    let (host, port) = split_authority(authority, DEFAULT_TLS_PORT)?;
    Ok(Broker {
        host,
        port,
        transport: BrokerTransport::Tls,
    })
}

fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
    if authority.is_empty() {
        return Err(Error::Config("OPENQTT_BROKER is empty.".to_string()));
    }

    let bad_port = |port: &str| {
        Error::Config(format!(
            "OPENQTT_BROKER has '{port}' where a port number belongs."
        ))
    };

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(|| {
            Error::Config("OPENQTT_BROKER opens a bracket it never closes.".to_string())
        })?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().map_err(|_| bad_port(port))?,
            None if tail.is_empty() => default_port,
            None => return Err(bad_port(tail)),
        };
        return Ok((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !host.is_empty() => {
            Ok((host.to_string(), port.parse().map_err(|_| bad_port(port))?))
        }
        // More than one colon and no brackets is a bare IPv6 literal. Refuse
        // rather than guess: the alternative is silently connecting to a host
        // named `::1` on port 8883, or to `::` on port 1.
        Some(_) => Err(Error::Config(format!(
            "OPENQTT_BROKER is '{authority}'. Put an IPv6 address in brackets, \
             as [{authority}]:{default_port}."
        ))),
        None => Ok((authority.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(host: &str, port: u16) -> Broker {
        Broker {
            host: host.to_string(),
            port,
            transport: BrokerTransport::Tls,
        }
    }

    #[test]
    fn broker_forms() {
        assert_eq!(
            parse_broker("mqtt.broker-yyz.openqtt.com").unwrap(),
            tls("mqtt.broker-yyz.openqtt.com", 8883)
        );
        assert_eq!(
            parse_broker("mqtts://example.test:1884").unwrap(),
            tls("example.test", 1884)
        );
        assert_eq!(parse_broker("[::1]:1884").unwrap(), tls("::1", 1884));
        assert_eq!(parse_broker("[::1]").unwrap(), tls("::1", 8883));
    }

    #[test]
    fn a_websocket_broker_carries_its_own_port_and_path() {
        assert_eq!(
            parse_broker("wss://example.test").unwrap(),
            Broker {
                host: "example.test".to_string(),
                // Not 8883: a WebSocket listener is a different listener.
                port: 8084,
                transport: BrokerTransport::WebSocket {
                    // The broker's own default `mqtt_path`. Getting this wrong
                    // means the upgrade lands on a path it does not answer.
                    path: "/mqtt".to_string()
                },
            }
        );
        assert_eq!(
            parse_broker("wss://example.test:443/somewhere").unwrap(),
            Broker {
                host: "example.test".to_string(),
                port: 443,
                transport: BrokerTransport::WebSocket {
                    path: "/somewhere".to_string()
                },
            }
        );
    }

    #[test]
    fn both_plaintext_schemes_are_refused_by_name() {
        // `ws://` is the trap that `mqtt://` is not: it looks like the secure
        // one with two characters missing.
        for plaintext in ["mqtt://example.test:1883", "ws://example.test:8083/mqtt"] {
            let message = parse_broker(plaintext).unwrap_err().to_string();
            assert!(message.contains("not encrypted"), "{plaintext}: {message}");
        }
    }

    #[test]
    fn bare_ipv6_is_refused_rather_than_guessed() {
        // v5's rfind(':') would answer host "::" port 1 here, and connect.
        assert!(parse_broker("::1").is_err());
        assert!(parse_broker("wss://::1/mqtt").is_err());
    }

    #[test]
    fn a_port_that_is_not_a_number_is_an_error() {
        assert!(parse_broker("example.test:mqtt").is_err());
    }

    #[test]
    fn https_is_kept_and_the_trailing_slash_is_not() {
        assert_eq!(
            clean_api("https://api.openqtt.com/").unwrap(),
            "https://api.openqtt.com"
        );
    }

    #[test]
    fn plain_http_to_a_real_host_is_refused_and_says_why() {
        let message = clean_api("http://api.openqtt.com").unwrap_err().to_string();
        assert!(message.contains("not encrypted"), "{message}");
        // The reason has to name what is actually lost, which is the NEXT
        // token rather than only the current one.
        assert!(message.contains("about to use"), "{message}");
    }

    #[test]
    fn loopback_over_http_is_allowed_because_a_test_needs_it() {
        for allowed in [
            "http://127.0.0.1:8099",
            "http://localhost:8099",
            "http://LocalHost",
            "http://[::1]:8099",
        ] {
            assert!(clean_api(allowed).is_ok(), "{allowed}");
        }
    }

    #[test]
    fn a_host_that_only_looks_like_loopback_is_still_refused() {
        // The check stops at the first slash and at the port, so none of these
        // reach the exemption.
        for refused in [
            "http://localhost.example.com",
            "http://127.0.0.1.example.com",
            "http://example.com/localhost",
            "http://example.com/127.0.0.1",
            // Userinfo: the host here is example.com, not the loopback that
            // appears first.
            "http://127.0.0.1:80@example.com",
            "http://localhost@example.com",
            "http://user:pass@127.0.0.1.example.com",
        ] {
            assert!(clean_api(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn an_api_with_no_scheme_is_refused_rather_than_guessed() {
        let message = clean_api("api.openqtt.com").unwrap_err().to_string();
        assert!(message.contains("no scheme"), "{message}");
    }
}
