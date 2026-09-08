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
| `OPENQTT_ARTIFACT_KEY` | `/etc/openqtt/artifact-key.pem` | the keys firmware signatures are checked against |
| `OPENQTT_API` | `https://api.openqtt.com` | must be `https`, or a loopback address |
| `OPENQTT_BROKER` | `mqtt.broker-yyz.openqtt.com:8883` | `host:port`, `mqtts://...` or `wss://host:port/mqtt` |
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

## TCP or WebSocket, and the namespace picks

A namespace chooses one way its devices connect, and every device in it follows.

```sh
export OPENQTT_BROKER=mqtt.broker-yyz.openqtt.com:8883        # MQTT over TLS
export OPENQTT_BROKER=wss://mqtt.broker-yyz.openqtt.com:8084/mqtt   # over a WebSocket
```

WebSocket exists for one reason: port 8883 is blocked on a great many industrial
and corporate networks and 443-shaped traffic is not. It is slower to set up and
one more thing to go wrong, so it is the answer when the first one cannot get
out of the building, not before.

**Nothing about identity changes.** Both carry the same mutual TLS and the
broker takes the username from the client certificate either way. Verified
against the production broker image: a device connected over `wss://` and its
message arrived on `ingest/acme/production/pump-3/temperature`, the same place
the TCP one lands.

The path matters. `/mqtt` is the broker's own default and the upgrade request
has to name a path the listener answers on. The port in a `wss://` URL is the
one that is used; a WebSocket transport reads host and port out of the URL and
ignores everything else.

## Two things that surprise everybody

**Publish `temperature`, not `ingest/acme/production/pump-3/temperature`.** The
broker prepends the prefix itself, from the name in your certificate. Sending
it as well publishes to `ingest/<name>/ingest/<name>/temperature`, which is
allowed and which nobody is listening to. `publish` refuses that rather than
let it happen quietly.

**A device subscribes to exactly one thing, and it is about itself.** This
section said for a while that a device cannot subscribe at all, and while that
was true it was the whole design: the broker denied every subscribe and this
was a one directional client. It stops being true at one filter. A device
subscribes to `commands/#`, which the broker mounts under its own prefix, so
the platform can tell it to update itself, run a diagnostic, or renew its
certificate early.

Nothing else about that changed and the reason it was true still holds:
reading other devices' data back out is a job for a consumer with its own
credential, not for the machines in the field. A device can be told things
about itself and can be told nothing else.

## What the platform can ask for

Three things, all retained, so a device that has been switched off for a week
gets them on the next connect rather than not at all. Durable sessions are off:
a queued message would live in one broker node's memory and a pod roll would
drop it silently.

```rust
let device = Device::builder()
    .firmware(env!("CARGO_PKG_VERSION"))
    .probe(Probe::new("sd_card", |message| {
        message.push_str("mounted, 3.1 GB free");
        Outcome::Pass
    }).timeout_secs(20))
    .connect()
    .await?;
```

`Device::connect()` still does what it always did. The builder exists because
everything the platform can ask for has to be in place **before** the
connection: a retained command arrives on the first CONNACK, ahead of the next
line of your program, and a probe registered afterwards answers
`not_registered` to the first dispatch of every boot and then works perfectly
for the rest of the run. That bug reproduces only on the machine that was
switched off.

### Diagnostics

Every probe runs on its own blocking thread inside the timeout its manifest
entry declares, and one `test/result` goes out per probe. Off the connection's
task, always: a probe that blocks on a device node would otherwise stop the
keepalive, and the broker drops a client at keepalive times 1.5, so a device
would read as offline while it was busy proving it is healthy.

A timeout does not stop a probe, because a blocking thread cannot be cancelled.
The bound exists so that a probe which never returns costs a thread rather than
the connection.

A dispatch is the one imperative message in the protocol, so it carries a run
id and the device writes down the last one it answered. That is the whole of
the deduplication: the platform clears the retained dispatch when it sees the
results, and the device never touches it. Clearing a retained topic means
writing to it with the retain flag, and a device is denied that flag precisely
so the retained store cannot become control-plane state a device writes to. So
the run id has to be on disk whether the clear is fast, slow, or never comes.

There are five outcomes and not two. `timeout` means the state of the device is
not known, which is different from failing, and must not revert firmware on its
own. `not_registered` means the manifest declared a test this binary does not
have, which is a build mistake and should read as one. `warn` is for a probe
that passes on purpose while reporting bad news, so an author whose test gates a
rollout does not have to choose between reverting firmware over a configuration
problem and saying nothing.

### Updates

The announcement is desired state, not an order: the device compares the
announced sha256 against the binary it is actually running and does nothing if
they agree. That comparison is the whole deduplication, which is what lets the
message be retained.

What happens then, in order, because the order is the design.

**The signature is checked before a byte is written.** ECDSA P-256 over the raw
digest, against the keys in `OPENQTT_ARTIFACT_KEY`. The CDN is a distribution
point and never a trust anchor, and with an empty or missing key file an update
is refused rather than installed.

That file holds a set rather than one key, and the plural is the point. A
signing key that cannot be replaced is one that never is: with a single key,
the only way to install a second is an update signed by the key being replaced,
so a lost or compromised key strands the fleet on the most attractive target in
the product. With a set, rotation is an ordinary sequence where every step is
signed by something every device already trusts. Ship an artifact signed by the
old key whose payload adds the new key to the file, wait for the fleet to
converge, start signing with the new one, then later ship one that drops the
old. The device logs how many keys it loaded at startup, because a key somebody
was sure they installed should be visible as wrong long before an update needs
it.

**Everything is staged in the running binary's own directory.** Two separate
incidents in the previous generation: systemd bind-mounts each `ReadWritePaths`
entry as its own filesystem, so staging into a data directory and renaming into
place fails `EXDEV`, and the binary's own directory has to be writable or the
write fails `EROFS` before that matters. Staging beside the target makes both
of those the same condition.

**The probation marker is written before the two renames**, because it is the
only thing that makes a power cut between them recoverable. `<binary>.old` is
never overwritten: after a health check that hung, it is the last binary known
to work, and clobbering it makes the next rollback land on a build that already
failed.

**Then the device exits 73** and the service manager starts the new binary.

```ini
[Service]
Restart=always
SuccessExitStatus=73
```

Both lines. `Restart=on-failure` is the trap: it reads the same declaration,
concludes that 73 is success, does not restart, and leaves the service dead
after every successful update.

**On the way back up it has to prove itself.** Every gating probe runs. All
pass and the update is kept. One fails and the old binary goes back, the device
exits 73 again, and the probe's own message rides out on `ota/event`. A probe
that does not answer reverts nothing at all: unknown is not failure, and
reverting on unknown means one flaky probe reverts a fleet. What covers a
device that cannot answer is the deadline and the attempt count in the marker.

**A build that was rolled back is not installed again.** The announcement is
retained, so a device that rolled back from a version reads that same version
on the very next connect, which without this is a loop for the life of the
device. The rejected sha is remembered, and announcing a different one clears
it, so the platform fixes it by shipping a fix.

**Recovery refuses to guess.** The old binary is restored only against an
unambiguous marker whose recorded digest matches the file on disk. An operator
who moved something by hand gets a sentence in the log and an untouched
filesystem.

### An early renewal

`commands/certificate` carries an instant, and a device whose certificate was
issued before it renews at once instead of waiting out the jitter. For a
compromised intermediate. Only the instruction travels: the device fetches
through the enrollment route it already uses, so the private key still never
leaves it.

## Saying what a device is doing

```rust
device.signal(Signal::Sleeping { wakes_in: Duration::from_secs(3600) }).await?;
```

Three kinds and no more: `sleeping`, `updating`, `migrating`. Closed because a
console that renders an unknown status is showing a string nobody chose.
`sleeping` is the one that earns the idea: a dashboard that says "sleeping,
wakes in 40 minutes" raises an alarm when the wake deadline is missed rather
than every time a battery powered device does exactly what it was told.

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

No test in that run reaches the internet or a real broker. Enrollment is
exercised against a mock that signs the device's real certificate request,
which is what makes the certificate the crate generated, stored and presents
the same certificate. Updates are exercised against a mock CDN and a key pair
the test generates, so the signature, the digest, both renames and every
recovery decision run for real against a temporary directory.

`rust/tests/connection.rs` opens a loopback socket that speaks enough MQTT to
answer a CONNECT. **It is not a broker and it is not evidence about one.** It
enforces no ACL, no mountpoint and no client certificate policy. It exists for
the one situation a real broker cannot be talked into producing on demand: a
certificate handover, where the live client is replaced and the replacement is
a connection with no subscriptions at all. A device that failed to subscribe
again would work for a day and then go deaf, silently.

The broker's own rules are proven by hand against a real one, and
`rust/tests/live.rs` is how, so it is done the same way twice rather than from
memory:

```sh
cd rust
OPENQTT_LIVE=1 cargo test --test live -- --ignored --nocapture
```

That file is ignored by default on purpose. The thing under test is a listener
with `verify_peer`, a private issuing chain, a mountpoint and an ACL, and a
fake with any one of those wrong would pass where the real broker refuses.

## Licence

Apache 2.0. See `LICENSE` and `NOTICE`.
