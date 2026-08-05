//! Serve Arca's CTAP2 authenticator as a virtual HID security key on Linux.
//!
//! [`vault_ctap`] implements the protocol a security key speaks. This crate
//! gives it a device to speak on: a HID device created through `/dev/uhid`,
//! carrying the FIDO usage page, which the kernel exposes as `/dev/hidrawN`.
//! Chromium, Firefox, Electron apps and `ssh-keygen -t ecdsa-sk` already know
//! how to talk CTAP2 to such a device, so none of them need to change and none
//! of them need to know Arca exists.
//!
//! ```no_run
//! use vault_uhid::{serve, Cancellation, DeviceOptions};
//! # fn example<B: vault_ctap::Backend + Send + 'static>(vault: B) -> std::io::Result<()> {
//! let cancellation = Cancellation::new();
//! // Hand `cancellation.clone()` to the backend so a prompt can be dropped
//! // when the browser gives up. Blocks until the device goes away.
//! serve(vault, &DeviceOptions::default(), &cancellation)
//! # }
//! ```
//!
//! # Permissions, and what they cost
//!
//! Two nodes need permissions, and they are not the same kind of ask.
//!
//! The hidraw node is the easy one: browsers must be able to read and write it,
//! which is what `TAG+="uaccess"` does for whoever is logged in at the seat —
//! the same rule distributions already ship for real security keys.
//!
//! `/dev/uhid` is the one to think about. It is root-only by default, and for
//! good reason: **the ability to create arbitrary HID devices is the ability to
//! synthesise input**, keyboards included. Granting it to the login user means
//! anything running as that user can inject keystrokes into the session, which
//! under Wayland is a capability it does not otherwise have. That is a real
//! escalation, not a formality.
//!
//! Two ways to live with it, in order of preference:
//!
//! 1. **A privileged helper opens `/dev/uhid` and passes the descriptor to
//!    Arca.** A tiny systemd unit, socket-activated, that does nothing but hand
//!    over one file descriptor. Arca never holds the capability; the helper
//!    never parses anything. This is the version to end up at.
//! 2. **A udev rule granting the active seat.** `70-arca-uhid.rules` in this
//!    crate does that, and is what makes development bearable. It buys the
//!    convenience with the escalation described above — deploy it knowingly.
//!
//! # What this path gives up
//!
//! Arca's browser extension binds a ceremony's `rp_id` to a page origin the
//! page cannot forge. A CTAP authenticator never sees an origin: it gets an
//! `rpId` string that the *client* vouches for. Browsers do that check
//! correctly and always have. A malicious native process does not have to — it
//! can ask for any relying party it likes, exactly as it could with a real
//! security key plugged into the machine.
//!
//! The consequence is that the consent prompt is the anti-phishing control on
//! this path, so it must name the relying party it is approving. A backend that
//! shows "Approve?" without saying *for whom* has removed the only check left.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(target_os = "linux")]
mod device;
#[cfg(target_os = "linux")]
mod service;

#[cfg(target_os = "linux")]
pub use device::{DeviceOptions, Event, UhidDevice, UHID_PATH};
#[cfg(target_os = "linux")]
pub use service::{serve, serve_with_config, Cancellation};
