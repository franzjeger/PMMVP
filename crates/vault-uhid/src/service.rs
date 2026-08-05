//! The run loop: a virtual HID device on one side, Arca's CTAP2 authenticator
//! on the other.
//!
//! # Why there are threads
//!
//! A ceremony blocks on the user typing their master password, which can take
//! tens of seconds. CTAPHID hosts do not wait that long in silence — they
//! expect a `CTAPHID_KEEPALIVE` roughly every 100 ms, and give up without one.
//! So the authenticator cannot run on the loop that owns the device.
//!
//! ```text
//!   reader thread ──┐
//!   (blocking read) │
//!                   ├─▶ one channel ─▶ main loop ─▶ writes to the device
//!   worker thread ──┘                  (recv_timeout 100 ms; on timeout,
//!   (owns the authenticator)            emit KEEPALIVE if busy)
//! ```
//!
//! Merging both sources into one channel means the main loop can wait on the
//! device and on the authenticator at once with nothing but `recv_timeout` —
//! no polling, no non-blocking I/O, no `unsafe`. Every write to the device
//! happens on the main loop, so the reports never interleave.
//!
//! SECURITY: the kernel does not tell us which process wrote a report, and
//! anything that can open the hidraw node can start a ceremony. That is true of
//! a real security key too, and the answer is the same: the user's approval at
//! the prompt is the authorisation, and the prompt must name the relying party
//! it is approving.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use vault_ctap::hid::{
    error_report, frame, keepalive_report, HidError, HidOutcome, HidTransport, Keepalive,
    CTAPHID_CBOR,
};
use vault_ctap::{Authenticator, Backend, Config, CtapError};

use crate::device::{DeviceOptions, Event, UhidDevice};

/// How often to reassure the host while a ceremony is outstanding. CTAP 2.1
/// §11.2.9.1.4 puts the ceiling at 100 ms.
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);

/// `EIO`, returned for the report types a FIDO device does not have.
const EIO: u16 = 5;

/// A flag the host sets by sending `CTAPHID_CANCEL`.
///
/// Hand a clone to the [`Backend`] so a prompt can be dismissed the moment the
/// browser gives up, instead of leaving a dialog on screen for a ceremony
/// nobody is waiting for any more. Watching it is optional: a backend that
/// ignores it still behaves correctly, because the run loop discards the answer
/// to a cancelled command either way.
#[derive(Debug, Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    /// A fresh, unset flag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the host has withdrawn the operation in flight.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    fn set(&self, cancelled: bool) {
        self.0.store(cancelled, Ordering::SeqCst);
    }
}

/// Create the virtual key and serve CTAP2 on it until the device goes away.
///
/// Blocks for as long as the device exists, so callers generally want this on
/// its own thread. Returns `Ok(())` on an orderly teardown (the kernel unbound
/// the device) and an error if the device could not be created or the loop lost
/// it mid-flight.
///
/// Creating the device needs write access to `/dev/uhid`; see the crate docs
/// for what that grants and how to scope it.
///
/// One caveat if you plan to call this more than once per process: destroying
/// the device does not wake a thread already blocked reading it, so the reader
/// thread outlives the call and is only reclaimed when the process exits. That
/// is fine for a service started once at launch, and is why there is no
/// `stop()` — it would promise a teardown this design cannot deliver.
pub fn serve<B>(backend: B, options: &DeviceOptions, cancellation: &Cancellation) -> io::Result<()>
where
    B: Backend + Send + 'static,
{
    serve_with_config(backend, options, cancellation, Config::default())
}

/// [`serve`], with an explicit authenticator [`Config`].
pub fn serve_with_config<B>(
    backend: B,
    options: &DeviceOptions,
    cancellation: &Cancellation,
    config: Config,
) -> io::Result<()>
where
    B: Backend + Send + 'static,
{
    let mut device = UhidDevice::create(options)?;
    let (incoming, events) = mpsc::channel::<Incoming>();

    spawn_reader(device.try_clone()?, incoming.clone());
    let commands = spawn_worker(backend, config, incoming.clone());

    // The loop's only exit signal is both threads going away, so the original
    // sender must not be held here or `Disconnected` never arrives.
    drop(incoming);

    run(&mut device, &events, &commands, cancellation)
}

/// Either half of what the main loop waits on.
enum Incoming {
    Device(io::Result<Event>),
    Response { channel: u32, response: Vec<u8> },
}

/// The command the authenticator is working on, if any.
#[derive(Default)]
struct InFlight {
    channel: Option<u32>,
    cancelled: bool,
}

fn spawn_reader(mut device: UhidDevice, incoming: Sender<Incoming>) {
    thread::spawn(move || loop {
        let event = device.read_event();
        let fatal = event.is_err();
        if incoming.send(Incoming::Device(event)).is_err() || fatal {
            return;
        }
    });
}

fn spawn_worker<B>(backend: B, config: Config, incoming: Sender<Incoming>) -> Sender<(u32, Vec<u8>)>
where
    B: Backend + Send + 'static,
{
    let (commands, requests) = mpsc::channel::<(u32, Vec<u8>)>();
    thread::spawn(move || {
        let mut authenticator = Authenticator::with_config(backend, config);
        while let Ok((channel, payload)) = requests.recv() {
            let response = authenticator.handle_message(&payload);
            if incoming
                .send(Incoming::Response { channel, response })
                .is_err()
            {
                return;
            }
        }
    });
    commands
}

fn run(
    device: &mut UhidDevice,
    events: &Receiver<Incoming>,
    commands: &Sender<(u32, Vec<u8>)>,
    cancellation: &Cancellation,
) -> io::Result<()> {
    let mut transport = HidTransport::new();
    let mut in_flight = InFlight::default();

    loop {
        match events.recv_timeout(KEEPALIVE_INTERVAL) {
            Ok(Incoming::Device(Ok(event))) => {
                match event {
                    // The kernel unbound the device; nothing more will arrive.
                    Event::Stop => return Ok(()),
                    Event::Start | Event::Open | Event::Close | Event::Other(_) => {}
                    Event::Output(report) => dispatch(
                        device,
                        &mut transport,
                        commands,
                        &mut in_flight,
                        cancellation,
                        &report,
                    )?,
                    Event::SetReport { id, report } => {
                        // Acknowledge first: the writing process stays blocked
                        // until this lands, and a ceremony can take a while.
                        device.set_report_reply(id, 0)?;
                        dispatch(
                            device,
                            &mut transport,
                            commands,
                            &mut in_flight,
                            cancellation,
                            &report,
                        )?;
                    }
                    // A FIDO device has no readable reports. Refusing is
                    // required; leaving it unanswered hangs the caller.
                    Event::GetReport { id } => device.get_report_reply(id, EIO)?,
                }
            }
            Ok(Incoming::Device(Err(e))) => return Err(e),

            Ok(Incoming::Response { channel, response }) => {
                let payload = if in_flight.cancelled {
                    // The host stopped waiting. Answering with the real result
                    // would complete a ceremony it has already abandoned.
                    vec![CtapError::KeepaliveCancel.code()]
                } else {
                    response
                };
                for report in frame(channel, CTAPHID_CBOR, &payload) {
                    device.write_report(&report)?;
                }
                in_flight = InFlight::default();
                cancellation.set(false);
            }

            Err(RecvTimeoutError::Timeout) => {
                if let Some(channel) = in_flight.channel {
                    // Arca is showing a prompt; tell the host to keep waiting
                    // and to say so in its own UI.
                    device
                        .write_report(&keepalive_report(channel, Keepalive::UserPresenceNeeded))?;
                } else if let Some(report) = transport.poll_timeout() {
                    device.write_report(&report)?;
                }
            }

            // Both the reader and the worker are gone.
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

fn dispatch(
    device: &mut UhidDevice,
    transport: &mut HidTransport,
    commands: &Sender<(u32, Vec<u8>)>,
    in_flight: &mut InFlight,
    cancellation: &Cancellation,
    report: &[u8],
) -> io::Result<()> {
    match transport.handle_report(report) {
        HidOutcome::Idle => {}

        HidOutcome::Reply(reports) => {
            for report in reports {
                device.write_report(&report)?;
            }
        }

        HidOutcome::Command { channel, payload } => {
            if in_flight.channel.is_some() {
                // One ceremony at a time. The transport reassembles one message
                // at a time, but a second host can still complete one while the
                // authenticator is mid-prompt.
                device.write_report(&error_report(channel, HidError::ChannelBusy))?;
                return Ok(());
            }
            in_flight.channel = Some(channel);
            in_flight.cancelled = false;
            cancellation.set(false);
            // The worker owns the authenticator for the process's lifetime, so
            // a send failure means it died — treat that as losing the device
            // rather than silently answering nothing ever again.
            if commands.send((channel, payload)).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "authenticator worker stopped",
                ));
            }
        }

        HidOutcome::Cancel { channel } => {
            if in_flight.channel == Some(channel) {
                in_flight.cancelled = true;
                cancellation.set(true);
            }
        }
    }
    Ok(())
}
