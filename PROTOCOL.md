# The device protocol

What a device and the platform say to each other over MQTT, so that two
implementations of the same client agree. `rust/` is the first; `c/` will be the
second, and this file exists because the cheapest moment to keep them the same
is before the second one is written.

## Everything is relative, and the broker prepends the rest

A device publishes to `temperature` and the message arrives on
`ingest/acme/production/pump-3/temperature`. It subscribes to `commands` and
receives what the platform published to `ingest/acme/production/pump-3/commands`.
The prefix comes from the common name in the client certificate, applied by the
broker's mountpoint, and a device that sends the prefix itself publishes to
`ingest/<name>/ingest/<name>/...` where nobody is listening.

**So every topic in this file is relative for the device and absolute for the
platform.** The platform publishes to `ingest/<common name>/<topic>`. Nothing in
a payload identifies the device, because the topic already does and a device
that names itself in a payload can name somebody else.

## What the platform sends

All retained, all under `commands/`. Retained rather than QoS 1 because durable
sessions are off, the queue is one node's memory, and a pod roll would drop
every queued command silently. Retained messages are replicated, redelivered on
every fresh subscribe, and have no expiry horizon.

A zero-byte retained payload clears the topic and means "nothing desired".

### `commands/firmware`

```json
{
  "version": "1.4.0",
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "url": "https://cdn.openqtt.com/artifacts/9f86d081...",
  "signature": "MEUCIQD...",
  "key_version": "projects/openqtt-prod/locations/.../cryptoKeyVersions/1"
}
```

**Desired state, not an order.** The device compares `sha256` against what it is
running and does nothing if they match. That comparison is the deduplication,
which is why this message can be redelivered on every reconnect without a
persisted job-id file.

`signature` is ECDSA P-256 over the raw 32 bytes of `sha256`, DER, base64. The
device verifies it against the artifact key before writing anything. The CDN is
a distribution point and never a trust anchor.

### `commands/test`

```json
{ "run_id": "0f9b2c1e", "tests": ["sd_card", "modbus_link"] }
{ "run_id": "0f9b2c1e", "run_all": true }
```

**The one imperative message here**, which is why it carries `run_id`. Running a
diagnostic is an act, not a state, and a retained message is redelivered on every
reconnect, so a device that renews its certificate daily would re-run
diagnostics forever. The device records the last `run_id` it answered and
ignores a repeat.

**The PLATFORM clears this topic, on seeing the results arrive, and the device
never does.** An earlier draft of this file asked the device to clear it, which
contradicts the rule two sections down: a device is denied the retain flag so
that the retained store cannot become control-plane state a device writes to,
and clearing a retained topic means writing to it with that flag. The invariant
is the one worth keeping. The platform published this dispatch, is already
subscribed to the results, and is the side allowed to retain.

That makes the recorded `run_id` the whole of the deduplication rather than a
cover for the gap before a clear lands. It has to be on disk before the results
are believed, because a clear that is slow, lost, or never sent must not cost a
second run.

Retained is what makes this a queue: a device that is switched off for a week
gets its diagnostics on the next connect, which is the case that matters,
because the device somebody needs to diagnose is the one that is not there.

### `commands/certificate`

```json
{ "not_before": "2026-09-08T00:00:00Z" }
```

Renew now if the certificate on disk was issued before this instant. Desired
state again, so it deduplicates by comparison. For a compromised intermediate,
where waiting out the renewal jitter is not acceptable. Only the instruction
travels; the device fetches through the enrollment route it already uses, so the
private key still never leaves it.

## What the device sends

Never retained. Devices are denied the retain flag by the broker's ACL, before
the retained store becomes control-plane state that a device can write to.

### `meta/firmware`, on every connect

```json
{ "version": "1.4.0", "sha256": "9f86d081..." }
```

**Ground truth, and the reason it is sent on every connect rather than retained
once.** Installing an update means restarting, so the process that would have
announced success was replaced mid-sentence. Judge a rollout by what a device
reports running, never by whether it managed to announce that it finished.

### `status/<kind>`

`kind` is one of `sleeping`, `updating`, `migrating`. A closed set, because a
console that renders an unknown status is a console showing a string nobody
chose.

```json
status/sleeping   { "at": "...", "wakes_in_secs": 3600 }
status/updating   { "at": "...", "to": "1.4.0" }
status/migrating  { "at": "...", "to": "mqtt.broker-fra.openqtt.com" }
```

The product argument is `sleeping`: a dashboard that says "sleeping, wakes in 40
minutes" instead of "offline" raises an alarm when the wake deadline is missed
rather than every time the device does what it was told.

### `ota/progress`

```json
{ "version": "1.4.0", "state": "downloading", "percent": 42 }
```

`state` is one of `downloading`, `verifying`, `applying`. Advisory. A rollout
times out on being stuck rather than on taking a while, so this is what resets
the stall timer.

### `ota/event`

```json
{ "version": "1.4.0", "sha256": "9f86...", "state": "succeeded", "message": "" }
```

`state` is one of `started`, `succeeded`, `failed`, `rolled_back`. Terminal.
`message` carries the probe message when a gating test caused the rollback.

**There is deliberately no `restarting` state, and the device announces its
departure on `status/updating` instead.** Installing an update means the process
goes away, and something has to say so before it does or the console cannot tell
an update from a crash. That is a statement about what the device is doing,
which is what `status/` is for, and `status/updating { at, to }` already says
exactly it. Adding a fourth `ota/event` state to say the same thing would give
two topics one meaning and make the set of terminal outcomes no longer terminal.

So the order before exit is: `ota/event started` when the update is accepted,
then the download and the swap, then `status/updating` as the last thing on the
wire, then a clean DISCONNECT. The intent has to precede the disconnect because
the broker tears the session down and anything published after it is dropped.

### `test/result`, one per probe

```json
{
  "run_id": "0f9b2c1e",
  "test_id": "sd_card",
  "status": "pass",
  "message": "mounted, 3.1 GB free",
  "duration_ms": 412
}
```

`status` is one of `pass`, `warn`, `fail`, `timeout`, `not_registered`.

**Five, not two, and each of the extra three earns its place.** `timeout` means
the device's state is not known, which is different from failing and must not
revert firmware on its own. `not_registered` means the manifest declared a test
the binary does not implement, which is a build mistake and should read as one
rather than as a hardware fault. `warn` is for a probe that passes on purpose
while reporting bad news: without it, an author whose test gates a rollout has
to choose between reverting firmware over a configuration problem and saying
nothing at all.

## The test catalogue lives in the repository

`.openqtt/tests.yml`, at the root of the device's repository, read by the build,
shipped to the platform alongside the artifact and keyed to the artifact's
sha256. The platform never guesses what a device can do: the build that produced
the binary declares the tests that binary has.

```yaml
tests:
  - id: sd_card
    type: connectivity
    description: Mount the card, write and read back, report free space
    gating: true
    timeout_secs: 20
  - id: gps
    type: connectivity
    description: Acquire a fix and report satellites
    gating: false
```

**`gating` absent means gating.** A test that can revert an update is the safe
default, and the flag exists to opt out for hardware that legitimately varies
per unit: a bench unit with no GNSS module, a probe that needs sky. Without the
flag the only choices are a gate that blocks every update on hardware variance
or no gate at all, and the second is what you end up with.

**`timeout_secs` is enforced by the library, not requested of the author.** Range
1 to 300. A probe is customer code running on our worker and a probe that blocks
forever must not hold the connection.

**A gating test with no registered probe fails the build.** The build has the
manifest and the binary in front of it, so the two lists are checked against each
other there rather than discovered in the field, where a typo would revert a
fleet.

## Versioning

There is no version field in any payload and that is deliberate. Every message
is either desired state, which an old device compares and ignores what it does
not understand, or a report, which the platform reads field by field. A device
that meets a field it does not know skips it. If that ever stops being enough,
the answer is a new topic, not a version number inside an old one.
