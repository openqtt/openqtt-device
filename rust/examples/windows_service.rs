//! The `publish` device, run as a Windows service.
//!
//! A Windows device that updates itself runs under the service control
//! manager, because something has to start the new binary after the exit 73
//! an update ends with. The SCM kills a program that does not talk to it
//! within about thirty seconds, and `openqtt_device::service::run` is that
//! conversation. It is behind a feature:
//!
//! ```text
//! cargo build --release --target x86_64-pc-windows-gnu --features windows-service --example windows_service
//! ```
//!
//! Run it by hand first, from an elevated prompt, with `OPENQTT_DEVICE` and
//! `OPENQTT_TOKEN` set: it is the same binary, the stop simply never comes, and
//! the enrollment is there to watch. Then register it as a service with no
//! token anywhere near it. The README has the commands.

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    device::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("this example is a Windows service; `publish` is the same device everywhere else");
}

#[cfg(windows)]
mod device {
    use std::error::Error;
    use std::time::Duration;

    use openqtt_device::service::{self, Stop};
    use openqtt_device::{Device, Outcome, Probe};

    /// The name given to `sc.exe create`.
    const SERVICE: &str = "openqtt-device";

    pub fn main() -> Result<(), Box<dyn Error>> {
        service::run(SERVICE, |stop| {
            // A service has no console, so under the SCM these lines go
            // nowhere; run by hand, they are the enrollment to watch. A device
            // in the field says what matters through `Device::log`, which
            // reaches the platform either way.
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_env("OPENQTT_LOG")
                        .unwrap_or_else(|_| "openqtt_device=info".into()),
                )
                .init();
            tokio::runtime::Runtime::new()?.block_on(run(stop))
        })
    }

    async fn run(stop: Stop) -> Result<(), Box<dyn Error>> {
        let device = Device::builder()
            .firmware(env!("CARGO_PKG_VERSION"))
            .probe(
                Probe::new("uplink", |message| {
                    message.push_str("connected");
                    Outcome::Pass
                })
                .timeout_secs(10),
            )
            .connect()
            .await?;

        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                () = stop.requested() => break,
                _ = tick.tick() => device.publish("temperature", 21.5).await?,
            }
        }

        // A clean DISCONNECT suppresses the last will, so a stop the service
        // manager asked for reads as a planned departure and not as a machine
        // that fell over.
        device.shutdown().await;
        Ok(())
    }
}
