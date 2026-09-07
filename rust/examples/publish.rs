//! A device that enrols itself and then publishes a reading every five
//! seconds. This is the whole of what most devices do.
//!
//! ```sh
//! export OPENQTT_DEVICE=acme/production/pump-3
//! export OPENQTT_TOKEN=oqe_...          # first run only
//! export OPENQTT_ROOT_CA=./root.pem
//! export OPENQTT_STATE=./state.json
//! cargo run --example publish
//! ```
//!
//! Watch it from the other side with a service credential:
//!
//! ```sh
//! mosquitto_sub -h <broker> -p 1883 -t 'ingest/acme/production/pump-3/#' -v
//! ```

use std::time::Duration;

use openqtt_device::Device;
use serde::Serialize;

/// Anything that serialises works. A struct is usually better than a bare
/// number, because the reading arrives with its units attached.
#[derive(Serialize)]
struct Reading {
    celsius: f64,
    rpm: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The crate logs through `tracing`. Without a subscriber it says nothing,
    // which on a first run is the difference between "enrolling, will try
    // again in 4s" and silence.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("OPENQTT_LOG")
                .unwrap_or_else(|_| "openqtt_device=info".into()),
        )
        .init();

    // Enrols if it has to, connects, and starts renewing in the background.
    let device = Device::connect().await?;
    println!("connected as {}", device.common_name());

    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut turn = 0u32;
    loop {
        tick.tick().await;
        turn += 1;

        // RELATIVE TOPICS. The broker prepends ingest/<device>/ itself, so
        // this arrives as ingest/acme/production/pump-3/temperature. Passing
        // the full path would publish it twice over and nobody would see it;
        // `publish` refuses that rather than let it happen.
        device.publish("temperature", 21.5).await?;
        device
            .publish(
                "pump",
                Reading {
                    celsius: 21.5,
                    rpm: 1450,
                },
            )
            .await?;

        if turn % 12 == 0 {
            println!("{turn} readings sent");
        }
    }
}
