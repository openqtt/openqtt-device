# openqtt-device

The device SDK for [OpenQTT](https://github.com/openqtt/OpenQTT). Enrol a
machine, keep its certificate fresh, publish.

```rust
let device = openqtt_device::Device::connect().await?;
device.publish("temperature", 21.5).await?;
```

That is the whole of it. Behind those two lines: a P-256 key generated on the
device, a certificate signed against a one-time token, both written to disk so
one power cut cannot separate them, a mutual-TLS connection to the broker, and
a background task that renews every day and hands the live connection over
without a restart.

| | what | for | state |
| --- | --- | --- | --- |
| `openqtt-device` | Rust crate | a program under Linux | **here** |
| `libopenqtt-device` | ESP-IDF component | firmware on bare metal | planned, `c/` |
| `openqtt-consumer` | Python package | reading the data back out | blocked |

`openqtt-consumer` is blocked on the platform rather than on effort: no route
serves what a device published, nothing subscribes to `ingest/#`, and nothing
stores it. A consumer library today would have no call to make.

## What this is actually for

Not wrapping MQTT. Publishing is three lines in any client and a library that
only removed those would have removed almost nothing.

What is hard is identity. A device has to hold a private key that never leaves
it, turn a token somebody read off a screen once into a certificate, keep that
certificate alive across years of power cuts and bad uplinks, and do all of it
against a broker whose rules are not the defaults. Getting any one of those
subtly wrong produces a device that works for six days and then goes dark.

## Before a device starts

One file and two variables.

```sh
# The OpenQTT Root CA. Get it from whoever runs the platform.
sudo install -D -m 644 root.pem /etc/openqtt/root.pem

export OPENQTT_DEVICE=acme/production/pump-3   # the device's name
export OPENQTT_TOKEN=oqe_...                   # first run only
```

`OPENQTT_TOKEN` is a bootstrap credential, not a permanent one. It rotates on
the first enrollment and every one after that, and the current value lives in
the state file. Once a device has enrolled, the variable is ignored and
deleting it is the right thing to do.

### The root certificate is not optional

**There is no public certificate authority fallback and adding one would be a
downgrade.** The broker's certificate is issued by the OpenQTT Root CA, so the
Mozilla bundle rejects it outright:

```text
 0 s:O=OpenQTT, CN=mqtt.broker-yyz.openqtt.com
 1 s:O=OpenQTT, OU=SCADABLE IoT, CN=OpenQTT Server Issuing CA
 Verify return code: 20 (unable to get local issuer certificate)
```

The crate trusts that one certificate on the broker connection and nothing
else. It also checks, at every enrollment, that the chain the platform serves
still ends at the copy on disk, so a stale pin is a sentence at startup rather
than an `UnknownIssuer` a week later.

The enrollment call itself is a different question with a different answer:
`api.openqtt.com` is publicly signed, and that call verifies against the
Mozilla roots compiled into the binary. Two connections, two trust stores, on
purpose.

## Configuration

| variable | default | |
| --- | --- | --- |
| `OPENQTT_DEVICE` | | the certificate name, `<organization>/<namespace>/<device>` |
| `OPENQTT_TOKEN` | | the enrollment token. First run only |
| `OPENQTT_ROOT_CA` | `/etc/openqtt/root.pem` | the one trusted certificate |
| `OPENQTT_STATE` | `/etc/openqtt/state.json` | key, certificate and rotating token |
| `OPENQTT_API` | `https://api.openqtt.com` | must be `https`, or a loopback address |
| `OPENQTT_BROKER` | `mqtt.broker-yyz.openqtt.com:8883` | must not be `mqtt://` |
| `OPENQTT_CONNECT_TIMEOUT` | `30` | seconds to wait for the first connection |

Nothing is read from a config file, deliberately. A file that fails to parse
and a file that is not there are hard to tell apart, and a device that quietly
runs on defaults because of a stray comma is worse than one that refuses to
start.

Both endpoints refuse to be unencrypted, and neither refusal is pedantry. The
enrollment token travels in the request body and rotates on every use, so plain
HTTP hands anybody on the path both the credential the device is using and the
one it is about to use, which is enough to enrol as that device and keep doing
so. Loopback is the one exemption, because a test on the same machine has no
wire to intercept.

## Two things that surprise everybody

**Publish `temperature`, not `ingest/acme/production/pump-3/temperature`.** The
broker prepends the prefix itself, from the name in your certificate. Sending
it as well publishes to `ingest/<name>/ingest/<name>/temperature`, which is
allowed and which nobody is listening to. `publish` refuses that rather than
let it happen quietly.

**A device cannot subscribe.** The broker denies it, always. This is a one
directional client on purpose: reading data back out is a job for a consumer
with its own credential, not for the machines in the field.

## How renewal works

Certificates live seven days and the platform asks to be seen again after one,
so six consecutive failures are survivable. That headroom is offline tolerance,
not a freshness target: what protects a stolen certificate is a refused
renewal, not a short life.

Three things about the schedule are worth knowing.

**A wrong clock does not break it.** Every instant in the calculation comes out
of the enrollment response, and the result is slept on the monotonic timer. A
device that thinks it is 1990 still renews on time. If its clock is far enough
out to matter, the log says so, because that is also the explanation for a TLS
handshake that otherwise fails for no visible reason.

Startup is the one place a stored instant has to be compared against something,
and the comparison is chosen so a broken clock cannot poison it: alongside the
certificate the device keeps `issued_at`, the platform's own clock at the moment
that certificate was signed. A device reading earlier than that is holding proof
its clock is wrong, because the certificate exists and so its issuing moment has
passed. It renews rather than believe itself. Without that check a device
booting at the epoch reads a far-future expiry, calls a long-dead certificate
healthy, and repeats the same failed handshake on every restart forever.

**What that still does not fix, stated plainly.** A device whose clock is wrong
by more than the enrollment endpoint's certificate lifetime cannot enrol either,
because the HTTPS handshake to `api.openqtt.com` validates dates against the
same broken clock. The device will keep trying and its log will say why, but it
cannot recover on its own: something has to give it the time first, whether NTP,
a GPS fix, an RTC with a working battery, or a hand-set date. This crate cannot
bootstrap trusted time out of nothing, and pretending otherwise would be worse
than saying so.

**Renewals are spread.** The api's rate limiter counts the address it sees,
which is the ingress and not the device, so a whole fleet shares one bucket of
60 requests a minute. Devices installed on the same day would otherwise come
back on the same minute for the rest of their lives. Each device picks a random
offset across about the first 36 hours of the window, and every retry uses full
jitter.

**The connection is replaced, not restarted.** A renewed certificate is useless
until something rebuilds the TLS client, because the old one captured its
configuration when it was created. The live client sits behind a lock-free cell
and every publish resolves through it, so a handover is invisible to the
caller and nothing has to be restarted.

## Running the example

```sh
cd rust
export OPENQTT_DEVICE=acme/production/pump-3
export OPENQTT_TOKEN=oqe_...
export OPENQTT_ROOT_CA=./root.pem
export OPENQTT_STATE=./state.json
cargo run --example publish
```

And from the other side, with a service credential:

```sh
mosquitto_sub -h <broker> -p 1883 -t 'ingest/acme/production/pump-3/#' -v
```

## Layout

```
rust/     the crate
c/        libopenqtt-device, planned
```

Two directories because the enrollment protocol has to stay the same in both,
and the cheapest way to keep that true is to have the second one land next to
the first rather than in another repository.

## Tests

```sh
cd rust
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

No test in that run touches a network or a broker. Enrollment is exercised
against a mock that signs the device's real certificate request, which is what
makes the certificate the crate generated, stored and presents the same
certificate.

The broker leg is proven by hand against a real one, and `rust/tests/live.rs`
is how, so it is done the same way twice rather than from memory:

```sh
cd rust
OPENQTT_LIVE=1 cargo test --test live -- --ignored --nocapture
```

That file is ignored by default on purpose. The thing under test is a listener
with `verify_peer`, a private issuing chain, a mountpoint and an ACL, and a
fake with any one of those wrong would pass where the real broker refuses.

## Licence

Apache 2.0. See `LICENSE` and `NOTICE`.
