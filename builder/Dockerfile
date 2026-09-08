# The image every customer device build runs in.
#
# WE PIN THIS, NOT THE CUSTOMER. A repository linked to a namespace supplies
# source and nothing else: no Dockerfile, no cloudbuild.yaml, no toolchain
# choice. That is what makes "which compiler produced this binary" a question
# with one answer rather than one per repository.
#
# ---------------------------------------------------------------------------
# THE BASE IS CHOSEN BY THE OLDEST DEVICE WE INTEND TO RUN ON, and this is the
# decision most likely to be got wrong later by someone bumping a tag.
#
# A binary linked against glibc 2.38 does not run on a device with 2.36. It
# does not fail at build time, it does not fail at install time, it fails the
# first time systemd tries to start it, with a message about a missing version
# of a symbol nobody recognises. So the floor here IS the support floor.
#
# Debian 12 gives glibc 2.36, which is Raspberry Pi OS Bookworm. Moving this to
# trixie raises the floor to 2.41 and silently strands every Bookworm device in
# the field. If that is ever the intent, it is a release note, not a bump.
# ---------------------------------------------------------------------------
# PINNED TO amd64 BECAUSE CLOUD BUILD IS amd64, and the arch of this image
# decides which of the three targets is native and which are cross-compiled.
# Built on an arm64 laptop without this, x86_64 becomes a cross target, cc-rs
# goes looking for `x86_64-linux-gnu-gcc`, and the build fails on the one
# target that works fine in production. An image that behaves differently
# depending on who built it is not a pinned toolchain.
FROM --platform=linux/amd64 debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH

# The cross linkers, and nothing that is not needed to link.
#
# NOT QEMU. Emulating a whole toolchain to compile for ARM is slow and buys
# nothing: rustc cross-compiles natively and only the linker has to be
# target-aware. QEMU earns its place for RUNNING an ARM binary, which is a
# later step and a different image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      gcc \
      libc6-dev \
      gcc-aarch64-linux-gnu \
      libc6-dev-arm64-cross \
      gcc-arm-linux-gnueabihf \
      libc6-dev-armhf-cross \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Pinned, for the same reason the base is. A toolchain that floats is a
# reproducibility claim nobody can make.
#
# CURRENT, NOT THE CRATE'S MSRV, and the first attempt got this backwards. This
# image compiles the CUSTOMER's code against the CUSTOMER's lockfile, and a
# lockfile we do not control routinely pins a dependency needing a newer rustc
# than openqtt-device itself asks for. Building at 1.85 failed on exactly that:
#
#   error: time-core@0.1.9 requires rustc 1.88.0
#
# The device's compatibility floor is glibc, set by the base image above. The
# compiler wants to be recent so that a customer adding an ordinary dependency
# does not get a build failure about our toolchain.
ARG RUST_VERSION=1.94.1

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "${RUST_VERSION}" \
    && rustup target add \
         x86_64-unknown-linux-gnu \
         aarch64-unknown-linux-gnu \
         armv7-unknown-linux-gnueabihf \
    && chmod -R a+w "$CARGO_HOME" "$RUSTUP_HOME"

# WHICH LINKER FOR WHICH TARGET. Without this, cargo invokes the host `cc` for
# every target and an ARM build fails with a wall of "file in wrong format"
# from the host linker, which reads like a corrupt dependency rather than a
# missing setting.
#
# `armv7-unknown-linux-gnueabihf` is a promise about the target's floating
# point unit: `hf` means the hardware one, with arguments passed in FPU
# registers. Linking that against a soft-float sysroot produces a binary that
# starts and then computes wrong answers, which is worse than one that does not
# start.
COPY cargo-config.toml /opt/cargo/config.toml

# The build runs as nobody in particular and writes only where it is told.
# Customer build scripts execute here.
RUN useradd --create-home --uid 10001 build
USER 10001
WORKDIR /work

# Deliberately no ENTRYPOINT. Cloud Build supplies the command, so an
# entrypoint here would be a second place that decides what a build does.
