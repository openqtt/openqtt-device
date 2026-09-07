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
const DEFAULT_PORT: u16 = 8883;

/// The listener gives a connection 15 seconds from TCP open to CONNECT, and a
/// TLS handshake happens inside that. 30 covers a slow uplink and still fails
/// while somebody is watching a first boot.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// The single certificate the broker connection is checked against.
    pub root_ca: PathBuf,
    /// Where the certificate, the key and the rotating token live.
    pub state: PathBuf,
    /// How long [`crate::Device::connect`] waits for the broker to acknowledge
    /// the connection before giving up. Worth raising on a link where a
    /// handshake takes longer than a person would wait, such as satellite.
    pub connect_timeout: Duration,
}

impl Config {
    /// Read the six `OPENQTT_*` variables, filling in the hosted defaults.
    pub fn from_env() -> Result<Self> {
        let broker = var("OPENQTT_BROKER").unwrap_or_else(|| DEFAULT_BROKER.to_string());
        let (broker_host, broker_port) = parse_broker(&broker)?;
        Ok(Config {
            device: var("OPENQTT_DEVICE"),
            bootstrap_token: var("OPENQTT_TOKEN"),
            api: clean_api(&var("OPENQTT_API").unwrap_or_else(|| DEFAULT_API.to_string()))?,
            broker_host,
            broker_port,
            root_ca: var("OPENQTT_ROOT_CA")
                .unwrap_or_else(|| DEFAULT_ROOT_CA.to_string())
                .into(),
            state: var("OPENQTT_STATE")
                .unwrap_or_else(|| DEFAULT_STATE.to_string())
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
fn is_loopback(authority: &str) -> bool {
    let authority = authority.split('/').next().unwrap_or_default();
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

/// `host`, `host:port`, `[::1]:port`, optionally prefixed `mqtts://`.
///
/// Hand-rolled because the v5 gateway's `rfind(':')` turns `[::1]:8883` into
/// host `[` and a parse error, and because refusing `mqtt://` here is the
/// cheapest place to make plaintext impossible: v5's builder skips the whole
/// TLS block when the CA is empty and connects unencrypted with no warning.
fn parse_broker(raw: &str) -> Result<(String, u16)> {
    if let Some(rest) = raw.strip_prefix("mqtt://") {
        return Err(Error::Config(format!(
            "OPENQTT_BROKER is mqtt://{rest}, which is plaintext. This device \
             authenticates with a client certificate, so the connection is \
             always TLS. Use mqtts:// or a bare host:port."
        )));
    }
    let raw = raw
        .strip_prefix("mqtts://")
        .unwrap_or(raw)
        .trim_end_matches('/');
    if raw.is_empty() {
        return Err(Error::Config("OPENQTT_BROKER is empty.".to_string()));
    }

    let bad_port = |port: &str| {
        Error::Config(format!(
            "OPENQTT_BROKER has '{port}' where a port number belongs."
        ))
    };

    if let Some(rest) = raw.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(|| {
            Error::Config("OPENQTT_BROKER opens a bracket it never closes.".to_string())
        })?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().map_err(|_| bad_port(port))?,
            None if tail.is_empty() => DEFAULT_PORT,
            None => return Err(bad_port(tail)),
        };
        return Ok((host.to_string(), port));
    }

    match raw.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !host.is_empty() => {
            Ok((host.to_string(), port.parse().map_err(|_| bad_port(port))?))
        }
        // More than one colon and no brackets is a bare IPv6 literal. Refuse
        // rather than guess: the alternative is silently connecting to a host
        // named `::1` on port 8883, or to `::` on port 1.
        Some(_) => Err(Error::Config(format!(
            "OPENQTT_BROKER is '{raw}'. Put an IPv6 address in brackets, as [{raw}]:{DEFAULT_PORT}."
        ))),
        None => Ok((raw.to_string(), DEFAULT_PORT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_forms() {
        assert_eq!(
            parse_broker("mqtt.broker-yyz.openqtt.com").unwrap(),
            ("mqtt.broker-yyz.openqtt.com".to_string(), 8883)
        );
        assert_eq!(
            parse_broker("mqtts://example.test:1884").unwrap(),
            ("example.test".to_string(), 1884)
        );
        assert_eq!(
            parse_broker("[::1]:1884").unwrap(),
            ("::1".to_string(), 1884)
        );
        assert_eq!(parse_broker("[::1]").unwrap(), ("::1".to_string(), 8883));
    }

    #[test]
    fn plaintext_is_refused_by_name() {
        let message = parse_broker("mqtt://example.test:1883")
            .unwrap_err()
            .to_string();
        assert!(message.contains("plaintext"), "{message}");
    }

    #[test]
    fn bare_ipv6_is_refused_rather_than_guessed() {
        // v5's rfind(':') would answer host "::" port 1 here, and connect.
        assert!(parse_broker("::1").is_err());
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
