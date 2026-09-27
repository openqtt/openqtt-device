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
| `openqtt-device` | Rust crate | a program under Linux, Windows or macOS | **here** |
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

On Windows the files live under `%ProgramData%\OpenQTT` instead, and the
folder has to be made private before the first run: see [Windows](#windows).
On macOS they live under `/Library/Application Support/OpenQTT`: see
[macOS](#macos).

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
| `OPENQTT_LOGS` | `https://logs.broker-yyz.openqtt.com/v1/logs` | where batched log lines go. `https`, or a loopback address |
| `OPENQTT_CONNECT_TIMEOUT` | `30` | seconds to wait for the first connection |

On Windows the three paths default to `%ProgramData%\OpenQTT\` rather than
`/etc/openqtt/`, which is `C:\ProgramData\OpenQTT\` unless somebody moved it.
On macOS they default to `/Library/Application Support/OpenQTT/`.

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

**A build for another machine is refused before anything is fetched.** A
namespace can hold devices of several architectures, and a binary built for one
fails on another with `Exec format error` the first time the service manager
starts it: after the swap, where the rollback that lives inside the binary never
gets to run. So each announcement names the target triple its build is for, and
the device compares that with the triple it was compiled for. On a mismatch it
reports `built for x86_64-unknown-linux-gnu, this device is
aarch64-unknown-linux-gnu` as a failed `ota/event` and stops there. The sha is
not remembered as rejected, because nothing is wrong with the build except where
it was sent. An announcement with no target, from a platform older than the
field, is taken as before. The device sends its own triple at every enrollment,
which is how the platform knows which build to send it, and reports it on
`meta/firmware` beside the sha it is running.

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

On Windows the service control manager plays this part, and it needs two
settings of its own and a binary that talks to it: see [Windows](#windows).
On macOS it is launchd, which needs one key and an ordinary program: see
[macOS](#macos).

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

## Logs

```rust
device.log("warn", "the pump drew 14A on start, expected 9A");
```

Queued, batched, and POSTed to `logs.openqtt.com` under the same client
certificate the broker connection uses. The call returns immediately and cannot
fail: a device that cannot log still has a job to do, and a logging call that
returns an error is one every caller has to decide what to do about.

**Not over MQTT, even though the connection is already there.** A batch is
kilobytes and a reading is bytes. Pushing batches through the broker puts them
in its memory, through its router and past every consumer subscribed to that
tenant, to reach a bucket none of that is on the way to.

**Not `api.openqtt.com` either.** That name is behind Cloudflare, and a proxy
that terminates TLS eats the client certificate: the server would see the
request and not who sent it. `logs.openqtt.com` is DNS only and regional, the
same shape and the same reason as the broker endpoint. The server reads the
organization and namespace out of the common name, so nothing in the body says
who this is and nothing in the body can lie.

**A batch goes on size or age, whichever comes first.** Size alone means a
device logging one line an hour holds its first line until it has half a
megabyte of company, which on a quiet device is never.

**A device that cannot reach the platform for a week must not fill its own
disk.** There is a byte ceiling and an age cap, and when either bites the oldest
lines go first: a device coming back after an outage is most useful describing
what it is doing now. **What it dropped travels with the next batch**, so a gap
in a log is a number rather than a mystery.

```rust
let (queued, dropped) = device.logs_pending();
```

Worth reporting from a probe. The best diagnostic in the previous generation is
the one that passes while saying something is wrong: its SD card test reports
how many captures are still waiting to upload, because a backlog that only grows
is the early warning that things land but never drain.

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

## Windows

x86-64, Windows 10 or Server 2016 and later, built for `x86_64-pc-windows-gnu`.
The device does the same things and says the same things on the wire. What
changes is where its files live, what keeps them private, and what starts it
again after an update.

### Where things live

```text
C:\Program Files\OpenQTT\device.exe       the binary; updates are staged beside it
C:\ProgramData\OpenQTT\root.pem           OPENQTT_ROOT_CA
C:\ProgramData\OpenQTT\artifact-key.pem   OPENQTT_ARTIFACT_KEY
C:\ProgramData\OpenQTT\state.json         OPENQTT_STATE, written by the device
C:\ProgramData\OpenQTT\journal.json       beside it, written by the device
```

The defaults read `%ProgramData%`, so a machine that moved it is followed. The
build the platform makes for this target is `<bin>.exe`, because that is what
cargo writes for it. Updates are written beside the binary, so the service's
account has to be able to write to that folder, which LocalSystem, the account
`sc.exe create` uses unless told otherwise, can.

**The crate sets no permissions on Windows, and ProgramData is not private by
default.** On Linux it creates the state file 0600 in a 0700 directory, and
tightens a directory that is more open than that. Windows has no mode to set: a
file takes the ACL of the folder it is created in, and every local user can
read what is under `%ProgramData%` unless the folder says otherwise. So the
folder is made private once, at installation, and everything the device writes
into it inherits that. From an elevated Command Prompt:

```bat
mkdir "%ProgramData%\OpenQTT"
icacls "%ProgramData%\OpenQTT" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F
```

That leaves SYSTEM, which the service runs as, and Administrators, and nobody
else. The two SIDs rather than their names, because the names are translated on
a Windows that is not in English. Then copy `root.pem` and `artifact-key.pem`
into it.

### Enrol by hand, then install the service

The binary a service runs can also be run from a prompt, and the first run is
the one worth watching. From the same elevated prompt:

```bat
set OPENQTT_DEVICE=acme/production/pump-3
set OPENQTT_TOKEN=oqe_...
"C:\Program Files\OpenQTT\device.exe"
```

Stop it with Ctrl+C once it says it is connected. The rotated token is in
`state.json` now, which is why the bootstrap token never has to go into the
service's own configuration, where it would sit long after its use.

```bat
sc.exe create openqtt-device binPath= "\"C:\Program Files\OpenQTT\device.exe\"" start= auto
sc.exe failure openqtt-device reset= 0 actions= restart/2000
sc.exe failureflag openqtt-device 1
sc.exe start openqtt-device
```

Three things in there are easy to get wrong.

**The quotes inside `binPath`.** Without them the path is read at its first
space, and Windows tries `C:\Program.exe` before the binary if one is there.
The space after each `=` is sc.exe's syntax, not a typo.

**`failure` is `Restart=always`, and without it a device is dead after its
first update.** An update ends by exiting 73. The service control manager
counts a process that ends without saying it stopped as a failure, whatever the
code, and a failure restarts the service only when a recovery action says so.
There is none by default. With one action and `reset= 0`, every failure gets
the same answer: start it again two seconds later.

**`failureflag` covers the other way a device stops.** An error returned from
the service's `main` is reported to the SCM as a stop with an error, and that
counts as a failure only with the flag set. Without it such a device stays
stopped, which is the `Restart=on-failure` trap again in Windows' words.

A variable the service needs, such as `OPENQTT_BROKER` for a namespace on
WebSocket, goes in its `Environment` value, one `NAME=value` per entry:

```bat
reg add HKLM\SYSTEM\CurrentControlSet\Services\openqtt-device /v Environment /t REG_MULTI_SZ /d "OPENQTT_BROKER=wss://mqtt.broker-yyz.openqtt.com:8084/mqtt" /f
```

Anybody who can read the service's configuration can read that, so it is no
place for the token.

### The binary has to talk to the service manager

A program the service control manager starts has to call
`StartServiceCtrlDispatcher` within about thirty seconds or it is killed, and
the start fails with error 1053. An ordinary `main` never does. The crate has
that conversation behind a feature:

```toml
openqtt-device = { version = "0.2", features = ["windows-service"] }
```

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    openqtt_device::service::run("openqtt-device", |stop| {
        tokio::runtime::Runtime::new()?.block_on(async move {
            let device = openqtt_device::Device::connect().await?;
            stop.requested().await;
            device.shutdown().await;
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    })
}
```

The name is the one given to `sc.exe create`. `stop` resolves when the service
is asked to stop or the machine is shutting down, and never when the binary is
run by hand, which is what lets the enrollment above use the same binary.
`rust/examples/windows_service.rs` is the `publish` device written this way. A
service has no console, so what it prints goes nowhere; `Device::log` reaches
the platform either way.

### What an update does differently

Nothing on the wire and nothing in the order: refuse another target, verify,
download beside the binary, write the marker, rename the running binary to
`.old`, rename the download into its place, exit 73. Windows has always let a
running `.exe` be renamed, and that is all an install needs.

Putting the old one back is where it differs. Linux renames `.old` over the
running candidate in one step. Windows cannot be counted on to replace a
running `.exe`, so a rollback renames the candidate to `device.exe.rejected`
first, then `.old` into its place. The candidate is still running then and is
deleted by the next start.

Anything Windows will not let go of at the time, such as a `.old` a virus
scanner is reading when an update is kept, is written down in the journal and
tried again at every start and before the next update, and deleted only if it
still holds what was recorded. Without that, a `.old` nobody could delete would
refuse every update after it.

## macOS

Apple silicon and Intel, built for `aarch64-apple-darwin` and
`x86_64-apple-darwin`, from macOS 11 and 10.12 respectively, the oldest Rust
builds those two for. CI runs everything on Apple silicon and compiles for
Intel without running it. The device does the same things and says the same
things on the wire. What changes is where its files live and what starts it
again after an update, and launchd starts an ordinary program, so a binary
needs nothing from this crate to be a daemon.

The builder image makes the Linux and Windows builds only. A macOS build is
made on a Mac.

### Where things live

```text
/usr/local/libexec/openqtt/device                       the binary; updates are staged beside it
/Library/Application Support/OpenQTT/root.pem           OPENQTT_ROOT_CA
/Library/Application Support/OpenQTT/artifact-key.pem   OPENQTT_ARTIFACT_KEY
/Library/Application Support/OpenQTT/state.json         OPENQTT_STATE, written by the device
/Library/Application Support/OpenQTT/journal.json       beside it, written by the device
/Library/LaunchDaemons/com.openqtt.device.plist         what starts it, and starts it again
/Library/Logs/OpenQTT/device.log                        what it prints
```

The folder the three defaults are in is the only change from Linux. The crate
creates the state file 0600 in a 0700 folder, and tightens a folder that is
more open than that, as it does there. The binary has a folder of its own
because an update writes `device.new` and `device.old` beside it, and the
daemon runs as root, the one account that should be able to write there.

```sh
sudo install -d -m 700 "/Library/Application Support/OpenQTT"
sudo install -m 644 root.pem artifact-key.pem "/Library/Application Support/OpenQTT/"
sudo install -d -m 755 /usr/local/libexec/openqtt /Library/Logs/OpenQTT
sudo install -m 755 device /usr/local/libexec/openqtt/device
```

**A binary a browser downloaded will not run.** The browser marks it with
`com.apple.quarantine`, `install` copies the mark, and macOS kills an ad hoc
signed binary that carries it as it starts: `Killed: 9`. Clear the mark
before installing, with `xattr -d com.apple.quarantine device`, or fetch the
build with `curl`, which does not set it.

### Enrol by hand, then load the daemon

The first run is the one worth watching, so it is made from a Terminal:

```sh
sudo env OPENQTT_DEVICE=acme/production/pump-3 OPENQTT_TOKEN=oqe_... /usr/local/libexec/openqtt/device
```

`sudo env` because sudo does not pass the caller's variables through. Stop it
with Ctrl+C once it says it is connected. The rotated token is in `state.json`
now, which is why the bootstrap token never has to go into the plist, where
every user on the machine could read it.

The plist, as `com.openqtt.device.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.openqtt.device</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/libexec/openqtt/device</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>OPENQTT_DEVICE</key>
        <string>acme/production/pump-3</string>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>StandardOutPath</key>
    <string>/Library/Logs/OpenQTT/device.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/OpenQTT/device.log</string>
</dict>
</plist>
```

```sh
sudo install -m 644 -o root -g wheel com.openqtt.device.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.openqtt.device.plist
```

It starts at once, because `KeepAlive` implies `RunAtLoad`, and at every boot,
because the plist is in `/Library/LaunchDaemons`. Four things in there are
easy to get wrong.

**`KeepAlive` is `true`, not `SuccessfulExit` false.** Nothing tells launchd
that 73 is a success, so both restart the device after an update. They part
on an exit 0: `true` restarts after any exit, and `SuccessfulExit` false leaves
the device stopped after one that returned 0, which is `Restart=on-failure` in
launchd's words. Measured both ways on macOS 26.

**`ThrottleInterval` is launchd's own default, written down so it is a
decision.** launchd starts a job at most once every ten seconds, counted from
its last start. A device that has been up longer than that when an update ends
it is started again at once, and one that exits sooner waits out the rest of
the ten seconds. That wait is what keeps a device that cannot start at all
from asking the enrollment endpoint more than six times a minute, out of a
limit the whole fleet shares. Lower makes that loop louder; higher delays an
update or a rollback that comes in the first seconds after a start.

**Nothing secret goes in `EnvironmentVariables`.** The plist is readable by
every user, and so is what `launchctl print` says about the daemon.
`OPENQTT_DEVICE` is there because it is not a secret and it pins the state
file to this device: a state file holding another device's identity is
refused at startup rather than used. A variable a namespace needs, such as
`OPENQTT_BROKER` for one on WebSocket, goes beside it. The token never does.

**The plist belongs to root and nobody else can write it**, which is what
`-o root -g wheel -m 644` is for. launchd refuses to load one that others can
write.

Both log keys name one file, and what the device prints to either stream lands
in it in order. launchd creates the file; the folder is made above, so that
its mode is one somebody chose.

```sh
launchctl print system/com.openqtt.device                # its state, pid and last exit code
sudo launchctl kickstart -k system/com.openqtt.device    # stop it and start it again now
sudo launchctl bootout system/com.openqtt.device         # stop it and unload it
```

After an update `print` says `last exit code = 73: EX_CANTCREAT`. That is
launchd naming 73 out of `sysexits.h`, and for this device it means an update
restarted it, not that a file could not be created. `bootout` lasts until the
next boot; delete the plist afterwards to remove the daemon for good.

### What an update does differently

Nothing on the wire, nothing in the order, and nothing on disk that Linux does
not do: the running binary is renamed to `device.old`, the download renamed
into its place, the device exits 73. A rollback renames `device.old` back over
the running candidate in one step, as on Linux, so there is never a
`device.rejected`. The update is written beside the file the binary really is,
even when the plist names a link to it, which is what Linux does without being
asked.

What Apple silicon adds is the signature. The kernel starts no arm64 binary
without a valid one: with it removed, the same build is `Killed: 9` before it
prints a word. The linker signs every arm64 build ad hoc by itself, which
`codesign -dv` reports as `flags=0x20002(adhoc,linker-signed)`, and the
signature is inside the binary, so an update brings its own. The device writes
the download itself, so there is no quarantine mark on it, and it starts as
the build it came from would. Both are checked on every test run on a Mac: a
signed binary sent through the device's own download and renames is started
from where it landed.

**Never copy a new build over one that has run.** A signed file overwritten in
place after it has run once is killed at every start after that: measured on
macOS 26, `cp` over such a binary gives `Killed: 9` from then on. `install` and
`mv` make a new file and are fine, and so is every update, because an update
only ever renames.

**Developer ID signing and notarization are future work.** An ad hoc signature
says the bytes are whole and nothing about who built them, and that is all
macOS asks of a binary without the quarantine mark. What makes an update
trustworthy is the platform's own signature over its digest, checked before a
byte is written. A Developer ID signature would give macOS an identity to
check as well, and notarization is what would let a build a browser downloaded
run without the mark being cleared first.

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

The Windows decisions around an update, parking a running candidate and
retrying what could not be deleted, run on every machine against a simulated
lock. What Windows itself does is proven on Windows, by two programs CI runs on
`windows-latest`. `rust/tests/running_binary.rs` renames and deletes real
running copies of itself in the crate's order. `rust/tests/service_manager.rs`
registers a real service with the settings above and checks that exit 73 and a
stop with an error both start it again; it needs an elevated prompt, so it only
does that when asked:

```bat
cd rust
set OPENQTT_SCM_TEST=1
cargo test --locked --all-features --test service_manager
```

macOS is proven the same way, on `macos-latest`, which is Apple silicon. On a
Mac, `rust/tests/running_binary.rs` puts real running copies of itself through
the Unix install and rollback and starts what is at the path after each
rename, and a unit test sends a signed binary through the device's own
download and starts it. `rust/tests/launchd.rs` takes the plist out of this
README and checks it on every run. When asked, it loads that plist as a real
LaunchDaemon for a copy of itself, and checks that an exit 73, an exit 0 and
an exit after a long run all start it again, the quick ones no sooner than
`ThrottleInterval` allows. It asks `sudo -n` for root, so run `sudo -v` first
where sudo wants a password, or load the plist as an agent of your own user,
which needs no root and goes through the same keys:

```sh
cd rust
OPENQTT_LAUNCHD_TEST=1 cargo test --locked --test launchd
OPENQTT_LAUNCHD_TEST=user cargo test --locked --test launchd
```

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
