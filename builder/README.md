# The device builder image

What a customer's device code compiles in. Steps, image and toolchain are ours;
a linked repository supplies source and nothing else.

```sh
docker build --platform=linux/amd64 -t openqtt-device-builder .
```

## Two numbers, and they move for different reasons

**The base image sets the glibc floor, which is the device compatibility
promise.** Debian 12 gives glibc 2.36, which is Raspberry Pi OS Bookworm. A
binary linked against a newer glibc than a device has does not fail at build
time or at install time. It fails the first time systemd starts it, with a
message about a missing symbol version that nobody recognises. Moving this to
trixie raises the floor to 2.41 and strands every Bookworm device in the field,
so it is a release note rather than a bump.

**The Rust version wants to be current, and is not the crate's MSRV.** The first
version of this file pinned 1.85 to match `openqtt-device`'s `rust-version`,
which is the wrong number: this image compiles the customer's code against the
customer's lockfile, and one routinely pins a dependency needing a newer
compiler than we do. It failed on exactly that:

```
error: time-core@0.1.9 requires rustc 1.88.0
```

## Pinned to amd64, because the arch decides what is native

Cloud Build is amd64, so `x86_64-unknown-linux-gnu` is the native target there
and the two ARM targets are cross-compiled. Built on an arm64 laptop without
`--platform=linux/amd64`, that inverts: cc-rs goes looking for
`x86_64-linux-gnu-gcc`, and the one target that works fine in production is the
one that fails. An image that behaves differently depending on who built it is
not a pinned toolchain.

## Measured

2026-09-08, building `openqtt-device` from a read-only mount, on the amd64
image:

```text
x86_64-unknown-linux-gnu               OK
aarch64-unknown-linux-gnu              OK
armv7-unknown-linux-gnueabihf          OK
```

Both ARM targets were also built, not just checked, on the arm64 image before
the platform pin went in. `ring` and `aws-lc-sys` are the two crates that
actually exercise the cross linkers: both compile C, so a missing sysroot fails
there rather than in any Rust.

## Not here

**No QEMU.** rustc cross-compiles natively and only the linker has to be
target-aware, so emulating a whole toolchain to compile buys nothing. QEMU earns
its place for *running* an ARM binary to smoke test it, which is a later step
and a different image.

**No entrypoint.** Cloud Build supplies the command, and an entrypoint here
would be a second place deciding what a build does.
