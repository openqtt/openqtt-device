//! Running under the Windows service control manager.
//!
//! AN UPDATE ENDS BY EXITING 73, AND SOMETHING HAS TO START THE NEW BINARY. On
//! Linux that is systemd. On Windows it is the service control manager, and the
//! SCM only hosts a program that talks to it: one that has not called
//! `StartServiceCtrlDispatcher` about thirty seconds after it was started is
//! killed, and the start fails with error 1053. This module is that
//! conversation and nothing else.
//!
//! ```text
//! sc.exe create openqtt-device binPath= "\"C:\Program Files\OpenQTT\device.exe\"" start= auto
//! sc.exe failure openqtt-device reset= 0 actions= restart/2000
//! sc.exe failureflag openqtt-device 1
//! ```
//!
//! THE EXIT LOOKS LIKE A CRASH TO THE SCM, AND THAT IS WHAT RESTARTS IT. An
//! update calls `std::process::exit(73)` without reporting that the service
//! stopped, which the SCM counts as a failure whatever the code, and the
//! recovery action on the second line turns every failure into a start two
//! seconds later. There is no recovery action by default, so without that line
//! a device is dead after its first update. `failureflag` covers the other way
//! out: `main` returning an error is reported as a stop with an error, which
//! counts as a failure only with the flag set.
//!
//! `tests/service_manager.rs` registers a real service and checks both.

use std::error::Error;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;

/// What `StartServiceCtrlDispatcher` answers in a process the SCM did not
/// start, which means somebody ran it from a console.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// The service's `main`.
type Main = Box<dyn FnOnce(Stop) -> Result<(), Box<dyn Error>> + Send>;

/// The name and `main` of the one service this process hosts, handed from
/// [`run`] to `service_main`. The SCM calls that on a thread of its own and
/// offers no way to pass it anything.
static PENDING: Mutex<Option<(String, Main)>> = Mutex::new(None);

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Asks a running service to stop.
///
/// Cloned freely: every clone sees the same request.
#[derive(Debug, Clone)]
pub struct Stop {
    asked: watch::Receiver<bool>,
}

impl Stop {
    /// Resolves once the service control manager asks this service to stop,
    /// or the machine is shutting down. Never, when the process was started
    /// by hand.
    pub async fn requested(&self) {
        let mut asked = self.asked.clone();
        // An error means the sender is gone, which happens only once the
        // service is over, so it is a stop as well.
        let _ = asked.wait_for(|asked| *asked).await;
    }

    /// Whether a stop has been asked for.
    pub fn is_requested(&self) -> bool {
        *self.asked.borrow()
    }
}

/// Run `main` as the Windows service `name`, or as an ordinary program when
/// the service control manager did not start this process.
///
/// `name` is the one the service was created with. `main` gets a [`Stop`]
/// that resolves when the service is asked to stop, and should shut the
/// device down and return. Returning an error reports a stop with an error,
/// which restarts the service when its `failureflag` is set. An update's exit
/// needs nothing from here: see the module.
///
/// Started from a console, `main` simply runs, with a `Stop` that never comes.
/// So the binary a service runs can also be run by hand, which is the easiest
/// way to watch a first enrollment.
///
/// ```no_run
/// use openqtt_device::Device;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     openqtt_device::service::run("openqtt-device", |stop| {
///         tokio::runtime::Builder::new_current_thread()
///             .enable_all()
///             .build()?
///             .block_on(async move {
///                 let device = Device::connect().await?;
///                 stop.requested().await;
///                 device.shutdown().await;
///                 Ok::<(), Box<dyn std::error::Error>>(())
///             })
///     })
/// }
/// ```
pub fn run<F>(name: &str, main: F) -> Result<(), Box<dyn Error>>
where
    F: FnOnce(Stop) -> Result<(), Box<dyn Error>> + Send + 'static,
{
    *pending() = Some((name.to_string(), Box::new(main)));
    match service_dispatcher::start(name, ffi_service_main) {
        Ok(()) => Ok(()),
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
        {
            let (_, main) = pending()
                .take()
                .ok_or("the service's main has already been run")?;
            // Held until `main` returns. Dropped, it would read as a stop.
            let (_asking, stop) = channel();
            main(stop)
        }
        Err(error) => Err(Box::new(error)),
    }
}

fn pending() -> MutexGuard<'static, Option<(String, Main)>> {
    PENDING.lock().unwrap_or_else(PoisonError::into_inner)
}

fn channel() -> (watch::Sender<bool>, Stop) {
    let (asking, asked) = watch::channel(false);
    (asking, Stop { asked })
}

/// What the SCM calls, on a thread of its own, once the dispatcher is
/// connected. Returns when the service has stopped.
fn service_main(_arguments: Vec<OsString>) {
    let Some((name, main)) = pending().take() else {
        return;
    };
    let (asking, stop) = channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            asking.send_replace(true);
            ServiceControlHandlerResult::NoError
        }
        // The SCM answers this from the last status reported. Accepting it
        // is all that is asked.
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = match service_control_handler::register(&name, handler) {
        Ok(status) => status,
        Err(error) => {
            tracing::error!(error = %describe(&error), "could not register with the service control manager");
            return;
        }
    };
    report(
        status,
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::NO_ERROR,
    );
    let exit = match main(stop) {
        Ok(()) => ServiceExitCode::NO_ERROR,
        Err(error) => {
            tracing::error!(%error, "the service stopped on an error");
            // Any service-specific code would do: the SCM asks only whether
            // there is one.
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    report(
        status,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit,
    );
}

fn report(
    status: ServiceStatusHandle,
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit: ServiceExitCode,
) {
    let reported = status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: exit,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
    if let Err(error) = reported {
        tracing::warn!(error = %describe(&error), ?state, "could not tell the service control manager");
    }
}

/// `windows_service::Error` says "IO error in winapi call" and keeps the part
/// worth reading in its source.
fn describe(error: &windows_service::Error) -> String {
    match error.source() {
        Some(source) => format!("{error}: {source}"),
        None => error.to_string(),
    }
}
