//! The claim about macOS that only launchd can check: that the plist the
//! README gives restarts a device that exits 73, which is how every update
//! ends.
//!
//! A program rather than a test function, because launchd starts programs.
//! `cargo test` runs it as one. Every time, and with no privilege, it takes
//! the plist out of the README and checks that it parses and keeps the job
//! alive. Asked with `OPENQTT_LAUNCHD_TEST=1`, it then installs that plist as
//! a real LaunchDaemon for a copy of itself run with `--daemon`, lets launchd
//! start the copy, and reads what the copy writes down. That takes root,
//! which it asks `sudo -n` for so that it never waits on a password: CI's
//! macOS runner has sudo without one. `OPENQTT_LAUNCHD_TEST=user` loads the
//! same plist as an agent of the user running it instead, which needs no root
//! and goes through the same keys.
//!
//! Only the label, the program and the log paths are changed, with `plutil`.
//! `KeepAlive`, `ThrottleInterval` and `EnvironmentVariables` are the README's.
//! What the copy does depends on how many times it has been started:
//!
//! 1. It exits 73 a second after it starts, as an update does.
//! 2. It exits 0 a second after it starts, which `KeepAlive` true restarts
//!    and `SuccessfulExit` false would not.
//! 3. It runs past `ThrottleInterval` and then exits 73, which is the shape of
//!    nearly every real update, and has to be started again at once.
//! 4. It runs until it is booted out.
//!
//! The two quick exits are started again no sooner than `ThrottleInterval`
//! after the start before them, which is launchd's throttle and what the
//! README says about it. Every start writes down the variables the plist
//! sets, and what the copy prints has to reach the file the plist names.

#[cfg(target_os = "macos")]
fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.get(1).map(String::as_str) == Some("--daemon") {
        launchd::daemon(std::path::Path::new(&arguments[2]), &arguments[3]);
        return;
    }
    let scratch = launchd::Scratch::new();
    let plist = launchd::readme_plist(scratch.path());
    println!("launchd: the README's plist parses and keeps the device alive");
    let Some(domain) = launchd::Domain::asked(scratch.path()) else {
        println!(
            "launchd: the real daemon is skipped. Set OPENQTT_LAUNCHD_TEST=1 where sudo \
             asks for no password, or OPENQTT_LAUNCHD_TEST=user to load it as an agent \
             of this user"
        );
        return;
    };
    launchd::check(&domain, &plist, scratch.path());
    println!("launchd: ok");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("launchd: nothing to check off macOS");
}

#[cfg(target_os = "macos")]
mod launchd {
    use std::collections::BTreeMap;
    use std::io::Write as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Where the plist this proves is written down.
    const README: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../README.md");

    /// The daemon's side: what to do on this start.
    pub fn daemon(log: &Path, throttle: &str) {
        let throttle: u64 = throttle.parse().expect("the throttle is whole seconds");
        let starts = lines(log)
            .iter()
            .filter(|line| line.starts_with("start "))
            .count();
        let step = match starts {
            0 => "exit-73",
            1 => "exit-0",
            2 => "linger",
            _ => "running",
        };
        let seen: BTreeMap<String, String> = std::env::vars()
            .filter(|(name, _)| name.starts_with("OPENQTT_"))
            .collect();
        // Both streams, because the plist names a file for each. Before the
        // start is written down, so that a start the test has seen has
        // already reached that file.
        println!("stdout n={starts}");
        eprintln!("stderr n={starts}");
        note(
            log,
            &format!(
                "start n={starts} step={step} at={} pid={} env={}",
                now(),
                std::process::id(),
                serde_json::to_string(&seen).expect("variables encode")
            ),
        );
        match step {
            "exit-73" => {
                std::thread::sleep(Duration::from_secs(1));
                // What `ota::restart` does.
                std::process::exit(73)
            }
            "exit-0" => {
                std::thread::sleep(Duration::from_secs(1));
                std::process::exit(0)
            }
            "linger" => {
                std::thread::sleep(Duration::from_secs(throttle + 2));
                note(log, &format!("exit n={starts} at={}", now()));
                std::process::exit(73)
            }
            // Booted out by the check, or by `Job` when the check fails.
            // Whatever this did instead, `KeepAlive` would start it again.
            _ => std::thread::sleep(Duration::from_secs(3600)),
        }
    }

    /// The plist in the README's macOS section, checked to parse and to keep
    /// the job alive whatever it exits with.
    pub fn readme_plist(scratch: &Path) -> String {
        let readme = std::fs::read_to_string(README).expect("the README reads");
        let plist = readme
            .split_once("\n## macOS\n")
            .and_then(|(_, section)| section.split_once("```xml\n"))
            .and_then(|(_, block)| block.split_once("\n```"))
            .map(|(plist, _)| format!("{plist}\n"))
            .expect("the README's macOS section holds a plist in an xml block");
        let path = scratch.join("readme.plist");
        std::fs::write(&path, &plist).expect("the plist is written out");
        run(Command::new("plutil").arg("-lint").arg(&path));
        // THE KEY THAT DECIDES WHETHER AN UPDATE COMES BACK. `SuccessfulExit`
        // false restarts after 73 as well and leaves the device down after an
        // exit 0, which is `Restart=on-failure` again.
        assert_eq!(
            extract(&path, "KeepAlive", "raw"),
            "true",
            "the README's plist has to keep the device alive after any exit"
        );
        plist
    }

    /// Where the job is loaded.
    pub enum Domain {
        /// Where the README installs it: the system domain, as root.
        System,
        /// The login session of the user running this, with no root.
        User(u32),
    }

    impl Domain {
        pub fn asked(scratch: &Path) -> Option<Domain> {
            let asked = std::env::var_os("OPENQTT_LAUNCHD_TEST")?;
            if asked == "user" {
                // This process's own uid, read off a folder it made, rather
                // than through libc, which this crate does not depend on.
                let uid = std::fs::metadata(scratch)
                    .expect("the scratch folder")
                    .uid();
                return Some(Domain::User(uid));
            }
            Some(Domain::System)
        }

        /// `system` or `gui/<uid>`.
        fn target(&self) -> String {
            match self {
                Domain::System => "system".to_string(),
                Domain::User(uid) => format!("gui/{uid}"),
            }
        }

        /// A command, as root in the system domain. `-n`, so that a sudo that
        /// wants a password fails at once rather than waiting for one.
        fn command(&self, program: &str) -> Command {
            match self {
                Domain::System => {
                    let mut command = Command::new("sudo");
                    command.arg("-n").arg(program);
                    command
                }
                Domain::User(_) => Command::new(program),
            }
        }
    }

    /// The test's side: load the README's plist for a copy of this program,
    /// and watch what launchd does with it.
    pub fn check(domain: &Domain, plist: &str, scratch: &Path) {
        let label = format!("com.openqtt.device.test.{}", std::process::id());
        let program = scratch.join("device");
        let log = scratch.join("starts.log");
        let printed = scratch.join("device.log");
        let this = std::env::current_exe().expect("this program's path");
        std::fs::copy(this, &program).expect("a copy of this program");

        // What a test has to change about the README's plist, and nothing
        // else.
        let written = scratch.join(format!("{label}.plist"));
        std::fs::write(&written, plist).expect("the plist is written out");
        let throttle = extract(&written, "ThrottleInterval", "raw");
        let arguments =
            serde_json::to_string(&[text(&program), "--daemon", text(&log), throttle.as_str()])
                .expect("arguments encode");
        for (key, kind, value) in [
            ("Label", "-string", label.as_str()),
            ("ProgramArguments", "-json", arguments.as_str()),
            ("StandardOutPath", "-string", text(&printed)),
            ("StandardErrorPath", "-string", text(&printed)),
        ] {
            run(Command::new("plutil")
                .args(["-replace", key, kind, value])
                .arg(&written));
        }
        run(Command::new("plutil").arg("-lint").arg(&written));
        let set: BTreeMap<String, String> =
            serde_json::from_str(&extract(&written, "EnvironmentVariables", "json"))
                .expect("the plist's variables are strings");
        let throttle: u128 = throttle
            .parse::<u128>()
            .expect("ThrottleInterval is whole seconds")
            * 1000;

        let job = Job::load(domain, &label, &written);
        job.wait_for(&log, 4, Duration::from_secs(120));
        let lines = lines(&log);
        for line in &lines {
            println!("launchd: the daemon wrote: {line}");
        }
        let starts: Vec<Start> = lines
            .iter()
            .filter(|line| line.starts_with("start "))
            .map(|line| Start::parse(line))
            .collect();

        let steps: Vec<&str> = starts.iter().map(|start| start.step.as_str()).collect();
        if steps != ["exit-73", "exit-0", "linger", "running"] {
            job.fail(&format!(
                "expected a start after exit 73, after exit 0, and after a long run: {steps:?}"
            ));
        }
        for start in &starts {
            if let Some((name, value)) = set
                .iter()
                .find(|(name, value)| start.env.get(*name) != Some(*value))
            {
                job.fail(&format!(
                    "{name}={value} is set in the plist and start {} saw {:?}",
                    start.step, start.env
                ));
            }
        }

        // THE THROTTLE, both ways. A job that ran for a second is started
        // again no sooner than ThrottleInterval after its last start...
        for pair in starts[..3].windows(2) {
            let waited = pair[1].at.saturating_sub(pair[0].at);
            if waited + 1000 < throttle {
                job.fail(&format!(
                    "{} was started {waited} ms after {}, inside ThrottleInterval",
                    pair[1].step, pair[0].step
                ));
            }
        }
        // ...and one that ran for longer, as a device nearly always has by
        // the time an update ends it, is started again at once.
        let exited = lines
            .iter()
            .find(|line| line.starts_with("exit n=2 "))
            .map(|line| field(line, "at").parse::<u128>().expect("a time"))
            .unwrap_or_else(|| job.fail("the long run did not write down its exit"));
        let waited = starts[3].at.saturating_sub(exited);
        if waited * 2 > throttle {
            job.fail(&format!(
                "a daemon that ran past ThrottleInterval waited {waited} ms to be started again"
            ));
        }

        let printed = std::fs::read_to_string(&printed).unwrap_or_default();
        for start in 0..starts.len() {
            for stream in ["stdout", "stderr"] {
                if !printed.contains(&format!("{stream} n={start}\n")) {
                    job.fail(&format!(
                        "{stream} of start {start} did not reach the file the plist names: \
                         {printed:?}"
                    ));
                }
            }
        }

        // And it stops when it is booted out, and nothing starts it again.
        job.boot_out(starts[3].pid);
    }

    /// What one start wrote down.
    struct Start {
        step: String,
        at: u128,
        pid: u32,
        env: BTreeMap<String, String>,
    }

    impl Start {
        fn parse(line: &str) -> Start {
            let (fields, env) = line.split_once(" env=").expect("a start line");
            Start {
                step: field(fields, "step").to_string(),
                at: field(fields, "at").parse().expect("a time"),
                pid: field(fields, "pid").parse().expect("a pid"),
                env: serde_json::from_str(env).expect("the variables the daemon saw"),
            }
        }
    }

    fn field<'a>(line: &'a str, name: &str) -> &'a str {
        line.split(' ')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("no {name} in {line}"))
    }

    /// A job loaded for one run, booted out and its plist removed afterwards,
    /// whatever happened.
    struct Job<'a> {
        domain: &'a Domain,
        service: String,
        installed: Option<PathBuf>,
    }

    impl<'a> Job<'a> {
        fn load(domain: &'a Domain, label: &str, plist: &Path) -> Job<'a> {
            let service = format!("{}/{label}", domain.target());
            match domain {
                Domain::System => {
                    // Where the README puts it, and owned the way the README
                    // says, because launchd refuses a plist anybody but its
                    // owner can write.
                    let installed = PathBuf::from(format!("/Library/LaunchDaemons/{label}.plist"));
                    run(domain
                        .command("install")
                        .args(["-m", "644", "-o", "root", "-g", "wheel"])
                        .arg(plist)
                        .arg(&installed));
                    let job = Job {
                        domain,
                        service,
                        installed: Some(installed.clone()),
                    };
                    run(domain
                        .command("launchctl")
                        .args(["bootstrap", "system"])
                        .arg(&installed));
                    job
                }
                Domain::User(_) => {
                    let job = Job {
                        domain,
                        service,
                        installed: None,
                    };
                    run(Command::new("launchctl")
                        .args(["bootstrap", &domain.target()])
                        .arg(plist));
                    job
                }
            }
        }

        fn wait_for(&self, log: &Path, count: usize, patience: Duration) {
            let started = Instant::now();
            loop {
                let starts = lines(log)
                    .iter()
                    .filter(|line| line.starts_with("start "))
                    .count();
                if starts >= count {
                    return;
                }
                if started.elapsed() > patience {
                    self.fail(&format!(
                        "waited {patience:?} for {count} starts and saw {starts}: {:?}",
                        lines(log)
                    ));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }

        /// Boot the job out, wait for its process to go, and check that
        /// launchd no longer holds anything that could start it again.
        fn boot_out(&self, pid: u32) {
            run(self
                .domain
                .command("launchctl")
                .args(["bootout", &self.service]));
            let started = Instant::now();
            while Command::new("ps")
                .args(["-p", &pid.to_string()])
                .output()
                .is_ok_and(|output| output.status.success())
            {
                if started.elapsed() > Duration::from_secs(30) {
                    self.fail(&format!("{pid} is still running after the bootout"));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            // Only whether it answers: what `print` says is not an interface.
            let listed = self
                .domain
                .command("launchctl")
                .args(["print", &self.service])
                .output()
                .is_ok_and(|output| output.status.success());
            if listed {
                self.fail("the service is still loaded after the bootout");
            }
        }

        /// Stop, with everything launchd can say about why first.
        fn fail(&self, why: &str) -> ! {
            println!(
                "{}",
                said(
                    self.domain
                        .command("launchctl")
                        .args(["print", &self.service])
                )
            );
            let label = self.service.rsplit('/').next().unwrap_or_default();
            println!(
                "{}",
                said(self.domain.command("log").args([
                    "show",
                    "--last",
                    "5m",
                    "--style",
                    "compact",
                    "--predicate",
                    &format!("eventMessage CONTAINS \"{label}\""),
                ]))
            );
            panic!("{why}");
        }
    }

    impl Drop for Job<'_> {
        fn drop(&mut self) {
            let _ = self
                .domain
                .command("launchctl")
                .args(["bootout", &self.service])
                .output();
            if let Some(installed) = &self.installed {
                let _ = self.domain.command("rm").arg("-f").arg(installed).output();
            }
        }
    }

    /// A folder of its own, removed afterwards. Under the target directory,
    /// which the daemon, running as root, can write to as well.
    pub struct Scratch(PathBuf);

    impl Scratch {
        pub fn new() -> Scratch {
            let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
                .join(format!("launchd-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch folder");
            Scratch(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A key out of a plist, as `plutil` prints it in `format`.
    fn extract(plist: &Path, key: &str, format: &str) -> String {
        run(Command::new("plutil")
            .args(["-extract", key, format, "-o", "-"])
            .arg(plist))
        .trim()
        .to_string()
    }

    fn text(path: &Path) -> &str {
        path.to_str().expect("the scratch path is UTF-8")
    }

    fn lines(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn note(log: &Path, line: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .expect("the log opens");
        writeln!(file, "{line}").expect("a line goes into the log");
    }

    /// Milliseconds since the epoch. The daemon and the test read the same
    /// clock, so the two can be compared.
    fn now() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_millis()
    }

    /// Run a command that has to succeed, and answer what it printed.
    fn run(command: &mut Command) -> String {
        let output = command
            .output()
            .unwrap_or_else(|error| panic!("{command:?} did not start: {error}"));
        assert!(
            output.status.success(),
            "{command:?} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Whatever a command says, for a report.
    fn said(command: &mut Command) -> String {
        match command.output() {
            Ok(output) => format!(
                "{command:?}:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("{command:?} did not start: {error}"),
        }
    }
}
