//! One error type, and the distinction that matters most in it.
//!
//! TERMINAL AND TRANSIENT ARE DIFFERENT THINGS AND THE CALLER CANNOT GUESS.
//! A device that retries a wrong token forever looks identical, from the
//! outside, to a device that cannot reach the network, and the operator needs
//! to be able to tell those apart from a log line. `Error::transient` is what
//! the retry loops branch on, so the decision is written down once here rather
//! than re-derived at three call sites.

use std::path::PathBuf;

/// This crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong between a bare device and a published message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Configuration is missing or unusable. Never transient: nothing about
    /// waiting makes an unset variable set itself.
    #[error("{0}")]
    Config(String),

    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },

    /// The journal exists and cannot be understood. Not a default either, and
    /// for a smaller but similar reason: the expensive field in it is the
    /// probation marker, and reading an unreadable marker as "no marker" is
    /// the guess `ota::recover` exists not to make.
    #[error("{path} is not a readable device journal: {reason}. Move it aside; a device forgets one diagnostic run and one rollback by doing so")]
    Journal {
        /// The journal file.
        path: PathBuf,
        /// Why it could not be understood.
        reason: String,
    },

    /// An update could not be applied, or could not be trusted enough to try.
    #[error("{0}")]
    Ota(String),

    /// The state file exists and cannot be understood. NOT a default: a device
    /// that silently starts over would discard the token it needs and enrol as
    /// nobody. Better to stop and say the file is unreadable.
    #[error("{path} is not readable device state: {reason}. Move it aside to enrol again from OPENQTT_TOKEN")]
    State {
        /// The state file.
        path: PathBuf,
        /// Why it could not be understood.
        reason: String,
    },

    /// A 401: one message for an unknown name, a name that resolves to
    /// nothing, and a wrong token, because telling them apart turns a guessed
    /// device name into a confirmed one.
    #[error("that device name and token do not match a device. Check OPENQTT_DEVICE and OPENQTT_TOKEN against the console")]
    Refused,

    /// A 403. The credential was right, which is why the api will say so.
    #[error("this device is disabled. Its certificate will not be renewed")]
    Disabled,

    /// A 400: the common name or the certificate request is wrong, and no
    /// amount of retrying changes either.
    #[error("the api refused the request: {0}")]
    Rejected(String),

    /// A 429. Every device behind the ingress shares one bucket, so this is
    /// an ordinary condition on a fleet and not an error in the usual sense.
    #[error("the api is rate limiting enrollment")]
    RateLimited,

    /// Any other answer from the api, including every 5xx.
    #[error("the api answered {status}: {message}")]
    Api {
        /// The HTTP status.
        status: u16,
        /// The sentence out of the error envelope, if there was one.
        message: String,
    },

    /// The api could not be reached, or answered something unreadable.
    #[error("could not reach {url}: {source}")]
    Transport {
        /// What was being called.
        url: String,
        /// What the http client said.
        #[source]
        source: reqwest::Error,
    },

    /// The last certificate in the enrollment chain is not the root this device
    /// was given. See `Device::connect`: an equality check, not a trust
    /// decision.
    #[error(
        "the stored certificate chain does not end at the root in {root}. \
         One of the two is stale, and this device cannot check the broker \
         until they agree"
    )]
    RootMismatch {
        /// The pinned root this device was given.
        root: PathBuf,
    },

    /// A key, a certificate or a certificate request could not be built or read.
    #[error("{0}")]
    Crypto(String),

    /// The mountpoint trap, refused early rather than silently denied by the
    /// broker later.
    #[error("{0}")]
    Topic(String),

    /// The mqtt client refused a request, usually because it has shut down.
    #[error("mqtt: {0}")]
    Mqtt(#[from] rumqttc::ClientError),

    /// Something took longer than it is ever expected to.
    #[error("timed out after {seconds}s {doing}")]
    Timeout {
        /// What was being waited for.
        doing: &'static str,
        /// How long it was given.
        seconds: u64,
    },
}

/// How soon a failed renewal should be tried again.
///
/// EVERYTHING IS RETRIED AND ONLY THE PACE DIFFERS, which is what lets the
/// renewal loop run forever. A loop that can exit has to tell the rest of the
/// program that it did, and getting that wrong took a working connection down
/// with it once already: see `lib::supervise`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Something outside this device is having a moment: a flat network, a
    /// rate limit, a bad minute on the platform. Come back quickly.
    Soon,
    /// The platform has looked at this device's credential and said no, or
    /// something here is broken in a way that waiting does not fix. A person
    /// has to act.
    ///
    /// SLOWLY, AND THE REASON IS THE FLEET RATHER THAN THIS DEVICE. The api's
    /// rate limiter counts the address it sees, which is the ingress and not
    /// the device, so every device shares one bucket of 60 requests a minute.
    /// At the fast cap a dead device asks 8 times an hour and about 450 of them
    /// saturate it, which would mean a handful of decommissioned machines
    /// quietly stopping every healthy device from renewing.
    Rarely,
}

impl Error {
    /// How soon to try again. There is no "never": see [`Retry`].
    ///
    /// `Refused` and `Disabled` are deliberately retried. Both describe a
    /// record on the platform that a person can change, and a device that gave
    /// up on the first 403 would need a site visit after somebody re-enabled it
    /// in the console.
    pub fn retry(&self) -> Retry {
        match self {
            Error::RateLimited | Error::Transport { .. } | Error::Timeout { .. } => Retry::Soon,
            Error::Api { status, .. } if *status >= 500 => Retry::Soon,
            _ => Retry::Rarely,
        }
    }

    /// Whether a FIRST enrollment should stop rather than keep trying.
    ///
    /// Different from [`Error::retry`] on purpose, and the difference is who is
    /// watching. A 401 during renewal means a working device lost its
    /// credential and should keep asking, because somebody may put it back. A
    /// 401 on the very first enrollment means somebody has just typed the token
    /// wrong and is looking at the screen, and a process that hangs forever is
    /// worse than one that exits and lets `Restart=always` bring it back.
    pub fn fatal_at_bootstrap(&self) -> bool {
        !matches!(self.retry(), Retry::Soon)
    }
}

pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
    Error::Io {
        path: path.into(),
        source,
    }
}
