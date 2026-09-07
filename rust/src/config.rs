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
            api: var("OPENQTT_API")
                .unwrap_or_else(|| DEFAULT_API.to_string())
                .trim_end_matches('/')
                .to_string(),
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
}
