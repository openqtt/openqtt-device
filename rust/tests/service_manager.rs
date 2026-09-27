//! The claim about Windows that only the service control manager can check:
//! that the recovery settings the README gives restart a service that exits
//! 73, which is how every update ends.
//!
//! A program rather than a test function, because the SCM starts programs.
//! `cargo test` runs it as one, and it registers ITSELF as a service, with
//! `--service`, starts it, and reads what the service writes down. That takes
//! an elevated prompt and makes a real service, so it happens only when asked
//! with `OPENQTT_SCM_TEST=1`. CI's Windows runner is elevated and asks.
//!
//! What the service does depends on how many times it has been started:
//!
//! 1. It exits 73 without a word to the SCM, as an update does.
//! 2. Its `main` returns an error, which `service::run` reports as a stop with
//!    an error.
//! 3. It runs until the SCM asks it to stop, and stops cleanly.
//!
//! Reaching the third start proves both of the others were restarted: the
//! first by the recovery action alone, the second by `failureflag`. Every
//! start also writes down a variable set on the service the way the README
//! sets one, and `ProgramData`, which the default paths are built from.
//!
//! Before any of that, and every time because it needs no elevation: run by
//! hand, `service::run` runs `main` itself, which is what lets a first
//! enrollment be watched from a prompt with the binary the service runs.

#[cfg(windows)]
fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.get(1).map(String::as_str) == Some("--service") {
        scm::service(&arguments[2], std::path::Path::new(&arguments[3]));
        return;
    }
    scm::by_hand();
    println!("service_manager: run by hand, main runs and its answer comes back");
    if std::env::var_os("OPENQTT_SCM_TEST").is_none() {
        println!(
            "service_manager: the real service is skipped. Set OPENQTT_SCM_TEST=1 in an \
             elevated prompt to register one and restart it"
        );
        return;
    }
    scm::check();
    println!("service_manager: ok");
}

#[cfg(not(windows))]
fn main() {
    println!("service_manager: nothing to check off Windows");
}

#[cfg(windows)]
mod scm {
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    /// The service's side: what to do on this start.
    pub fn service(name: &str, log: &Path) {
        let written = log.to_path_buf();
        let outcome = openqtt_device::service::run(name, move |stop| {
            let log = written;
            let starts = std::fs::read_to_string(&log).map_or(0, |text| text.lines().count());
            let seen = format!(
                "programdata={} probe={}",
                variable("ProgramData"),
                variable("OPENQTT_SCM_PROBE")
            );
            match starts {
                0 => {
                    note(&log, &format!("exit-73 {seen}"));
                    // Long enough for `sc.exe start` to have its answer, as an
                    // update always would, then what `ota::restart` does.
                    std::thread::sleep(Duration::from_secs(1));
                    std::process::exit(73)
                }
                1 => {
                    note(&log, &format!("error {seen}"));
                    Err("stopping with an error, which failureflag makes a failure".into())
                }
                _ => {
                    note(&log, &format!("running {seen}"));
                    tokio::runtime::Builder::new_current_thread()
                        .build()?
                        .block_on(stop.requested());
                    note(&log, "stopped");
                    Ok(())
                }
            }
        });
        if let Err(error) = outcome {
            note(log, &format!("run failed: {error}"));
        }
    }

    fn variable(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| "MISSING".to_string())
    }

    /// Run by hand, `main` runs here, with a stop nobody has asked for, and
    /// what it returns comes back rather than going to a service manager
    /// that is not there.
    pub fn by_hand() {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::clone(&ran);
        openqtt_device::service::run("openqtt-scm-by-hand", move |stop| {
            assert!(!stop.is_requested(), "nobody asked this to stop");
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .expect("run by hand, main's answer comes back");
        assert!(ran.load(std::sync::atomic::Ordering::SeqCst), "main ran");

        let error = openqtt_device::service::run("openqtt-scm-by-hand", |_| {
            Err("an error of main's own".into())
        })
        .expect_err("and so does its error");
        assert_eq!(error.to_string(), "an error of main's own");
    }

    fn note(log: &Path, line: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .expect("the log opens");
        writeln!(file, "{line}").expect("a line goes into the log");
    }

    /// The test's side: register, start, and watch.
    pub fn check() {
        let name = format!("openqtt-scm-test-{}", std::process::id());
        let log = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.log"));
        let _ = std::fs::remove_file(&log);
        let probe = format!("probe-{}", std::process::id());
        let this = std::env::current_exe().expect("this program's path");

        // Quoted as the README quotes it, so a path with a space in it would
        // not be read as a shorter one.
        let service = Service::create(
            &name,
            &format!(
                "\"{}\" --service {name} \"{}\"",
                this.display(),
                log.display()
            ),
        );
        run(
            "sc.exe",
            &["failure", &name, "reset=", "0", "actions=", "restart/2000"],
        );
        run("sc.exe", &["failureflag", &name, "1"]);
        // A variable for the service, set the way the README sets one.
        run(
            "reg.exe",
            &[
                "add",
                &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
                "/v",
                "Environment",
                "/t",
                "REG_MULTI_SZ",
                "/d",
                &format!("OPENQTT_SCM_PROBE={probe}"),
                "/f",
            ],
        );
        run("sc.exe", &["start", &name]);

        let lines = service.wait_for(&log, 3, Duration::from_secs(90));
        for line in &lines {
            println!("service_manager: the service wrote: {line}");
        }
        let ways: Vec<&str> = lines
            .iter()
            .map(|line| line.split(' ').next().unwrap_or_default())
            .collect();
        if ways != ["exit-73", "error", "running"] {
            service.fail(&format!(
                "expected a restart after exit 73 and after an error: {lines:?}"
            ));
        }
        if let Some(line) = lines
            .iter()
            .find(|line| !line.contains(&format!("probe={probe}")))
        {
            service.fail(&format!(
                "the variable set on the service did not reach it: {line}"
            ));
        }

        // And it stops when it is asked to, without being restarted.
        run("sc.exe", &["stop", &name]);
        let lines = service.wait_for(&log, 4, Duration::from_secs(30));
        if lines[3] != "stopped" {
            service.fail(&format!("expected a clean stop: {lines:?}"));
        }
    }

    /// A service registered for one run, deleted afterwards whatever happened.
    struct Service {
        name: String,
    }

    impl Service {
        fn create(name: &str, command_line: &str) -> Service {
            run(
                "sc.exe",
                &["create", name, "binPath=", command_line, "start=", "demand"],
            );
            Service {
                name: name.to_string(),
            }
        }

        fn wait_for(&self, log: &Path, count: usize, patience: Duration) -> Vec<String> {
            let started = Instant::now();
            loop {
                let lines: Vec<String> = std::fs::read_to_string(log)
                    .map(|text| text.lines().map(str::to_string).collect())
                    .unwrap_or_default();
                if lines.len() >= count {
                    return lines;
                }
                if started.elapsed() > patience {
                    self.fail(&format!(
                        "waited {patience:?} for {count} lines and the service wrote {lines:?}"
                    ));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }

        /// Stop, with everything the SCM can say about why first.
        fn fail(&self, why: &str) -> ! {
            for query in ["qc", "qfailure", "qfailureflag", "queryex"] {
                println!("{}", said("sc.exe", &[query, &self.name]));
            }
            println!(
                "{}",
                said(
                    "wevtutil.exe",
                    &[
                        "qe",
                        "System",
                        "/q:*[System[Provider[@Name='Service Control Manager']]]",
                        "/c:15",
                        "/rd:true",
                        "/f:text",
                    ],
                )
            );
            panic!("{why}");
        }
    }

    impl Drop for Service {
        fn drop(&mut self) {
            let _ = Command::new("sc.exe").args(["stop", &self.name]).output();
            // A service is deleted only once it has stopped, so wait for that
            // rather than leave a name marked for deletion behind.
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(20) {
                let state = said("sc.exe", &["query", &self.name]);
                if !state.contains("RUNNING") && !state.contains("PENDING") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            let _ = Command::new("sc.exe").args(["delete", &self.name]).output();
        }
    }

    /// Run a command that has to succeed.
    fn run(program: &str, arguments: &[&str]) {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("{program} did not start: {error}"));
        assert!(
            output.status.success(),
            "{program} {arguments:?} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Whatever a command says, for a report.
    fn said(program: &str, arguments: &[&str]) -> String {
        match Command::new(program).args(arguments).output() {
            Ok(output) => format!(
                "{program} {arguments:?}:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("{program} did not start: {error}"),
        }
    }
}
