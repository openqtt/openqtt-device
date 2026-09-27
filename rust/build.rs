//! Tells the crate which target triple it is being compiled for.
//!
//! A NAMESPACE HOLDS DEVICES OF SEVERAL ARCHITECTURES, and a binary built for
//! one of them fails on another with `Exec format error` the first time the
//! service manager starts it: after the swap, where the rollback that lives
//! inside the binary never gets to run. So a device has to know which build it
//! is, and the compiler that made it is the only source with the whole answer.
//! `uname -m` says `aarch64` and cannot say glibc or musl. Cargo hands a build
//! script `TARGET` and nothing else sees it, so this passes it on.

fn main() {
    // Always set for a build script, so a missing one is a broken toolchain
    // rather than something to default around.
    let target = std::env::var("TARGET").expect("cargo sets TARGET for every build script");
    println!("cargo::rustc-env=OPENQTT_TARGET={target}");
    // Nothing in the package changes what this prints, and without the line
    // every edit to any file in it would run this again.
    println!("cargo::rerun-if-changed=build.rs");
}
