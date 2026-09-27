//! What Windows does to a running `.exe`, which an update's swap and rollback
//! are built on and which nothing but Windows can show.
//!
//! What the update needs, each of them a rename or a delete the crate makes:
//!
//! 1. A running `.exe` can be renamed, and another file renamed into the name
//!    it left. That is the whole of an install: the running binary to `.old`,
//!    the download into its place.
//! 2. The same the other way round is a rollback on Windows: the running
//!    candidate to `.rejected`, and `.old` back into its place.
//! 3. Once the process has gone, the file it ran from can be deleted. That is
//!    when a parked candidate is deleted: on a later start.
//!
//! What it does not need is reported rather than asserted, because the answer
//! depends on the Windows and the filesystem: whether a running `.exe` can be
//! deleted, or replaced with one rename. `DeleteFile` and `MoveFileEx` refuse
//! both, and std then tries again with POSIX semantics, which newer Windows
//! allows on NTFS. The update never does either, so it works the same way
//! whichever the answer is.
//!
//! A program rather than a test function, because it needs a running `.exe`
//! to try these on, and the simplest one is a copy of itself started with
//! `--wait`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--wait") {
        // Bounded, so a check that fails half way does not leave a copy
        // running for long.
        std::thread::sleep(Duration::from_secs(120));
        return;
    }
    if !cfg!(windows) {
        println!("running_binary: nothing to check off Windows");
        return;
    }
    let home = Scratch::new();
    install_and_roll_back(&home.0);
    report_what_std_can_do(&home.0);
    println!("running_binary: ok");
}

/// The install and the rollback, in the crate's order, on binaries that are
/// really running.
fn install_and_roll_back(home: &Path) {
    let binary = home.join("device.exe");
    let staged = home.join("device.exe.new");
    let previous = home.join("device.exe.old");
    let rejected = home.join("device.exe.rejected");

    // An install, with the old firmware running from the binary's path.
    copy_of_this(&binary);
    let old = Running::start(&binary);
    copy_of_this(&staged);
    std::fs::rename(&binary, &previous).expect("a running .exe can be renamed");
    std::fs::rename(&staged, &binary).expect("and another file renamed into the name it left");

    // Exit 73, and the service manager starts what is at the path now.
    drop(old);
    let candidate = Running::start(&binary);

    // The candidate fails its gate. Parked, not replaced, and `.old` back.
    std::fs::rename(&binary, &rejected).expect("the running candidate can be renamed aside");
    std::fs::rename(&previous, &binary)
        .expect("and the last binary that worked renamed into its place");

    // Exit 73 again. A later start deletes the parked candidate, once nothing
    // is running it.
    drop(candidate);
    delete_once_let_go(&rejected);

    assert!(binary.exists());
    for gone in [&staged, &previous, &rejected] {
        assert!(!gone.exists(), "{} is still there", gone.display());
    }
}

/// Whether std can delete a running `.exe` here, or replace one with a single
/// rename. Printed, not asserted: see the module.
fn report_what_std_can_do(home: &Path) {
    let doomed = home.join("delete-me.exe");
    copy_of_this(&doomed);
    let running = Running::start(&doomed);
    println!(
        "running_binary: deleting a running .exe: {}",
        said(&std::fs::remove_file(&doomed))
    );
    drop(running);

    let target = home.join("replace-me.exe");
    let other = home.join("other.exe");
    copy_of_this(&target);
    std::fs::write(&other, b"not a program").expect("a file to rename");
    let running = Running::start(&target);
    println!(
        "running_binary: replacing a running .exe with one rename: {}",
        said(&std::fs::rename(&other, &target))
    );
    drop(running);
}

fn said(result: &std::io::Result<()>) -> String {
    match result {
        Ok(()) => "allowed".to_string(),
        Err(error) => format!("refused, {error}"),
    }
}

/// Delete a file whose process has just gone. With a few seconds of retrying,
/// because a scanner can hold a freshly closed executable for a moment, which
/// is also why the crate retries at every start rather than once.
fn delete_once_let_go(path: &Path) {
    let started = Instant::now();
    loop {
        match std::fs::remove_file(path) {
            Ok(()) => return,
            Err(_) if started.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(error) => panic!(
                "{} could not be deleted after its process had gone: {error}",
                path.display()
            ),
        }
    }
}

fn copy_of_this(path: &Path) {
    let this = std::env::current_exe().expect("this program's path");
    std::fs::copy(this, path).expect("a copy of this program");
}

/// A program running from `path`, stopped when this goes out of scope.
struct Running(Child);

impl Running {
    fn start(path: &Path) -> Running {
        // Mapped by the time this returns: CreateProcess maps the image
        // before it hands back the process.
        Running(
            Command::new(path)
                .arg("--wait")
                .spawn()
                .expect("the copy starts"),
        )
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A directory of its own, removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let path =
            std::env::temp_dir().join(format!("openqtt-running-binary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
