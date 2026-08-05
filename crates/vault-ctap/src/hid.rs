//! CTAPHID: the framing a security key uses to carry CTAP2 over USB HID.
//!
//! CTAP2 messages are up to 7609 bytes; a HID report is 64. CTAPHID splits a
//! message across one **initialization** packet and up to 128 **continuation**
//! packets, multiplexed over 32-bit *channels* so several processes can talk to
//! one key without interleaving their traffic.
//!
//! ```text
//!   initialization   CID(4) │ 0x80|CMD(1) │ BCNTH(1) BCNTL(1) │ data[0..57]
//!   continuation     CID(4) │      SEQ(1) │                     data[0..59]
//! ```
//!
//! Like the rest of this crate the module is pure: bytes in, bytes out, no I/O.
//! [`HidTransport::handle_report`] returns an [`HidOutcome`] telling the caller
//! what to write back or what command to run, which is what makes the whole
//! framing testable by feeding it packets.
//!
//! SECURITY: channels are a multiplexing convenience, not a security boundary.
//! Anything that can open the HID device can allocate a channel, and the kernel
//! does not tell us which process is on the other end. A channel therefore
//! carries no authority whatsoever — every ceremony is authorised by the user
//! at the prompt, never by the channel it arrived on.

use std::time::{Duration, Instant};

/// A HID report is always 64 bytes in both directions.
pub const HID_REPORT_SIZE: usize = 64;

/// Payload capacity of an initialization packet.
const INIT_PAYLOAD: usize = HID_REPORT_SIZE - 7;

/// Payload capacity of a continuation packet.
const CONT_PAYLOAD: usize = HID_REPORT_SIZE - 5;

/// The largest message CTAPHID can express: one initialization packet plus 128
/// continuation packets.
pub const MAX_MESSAGE_LEN: usize = INIT_PAYLOAD + 128 * CONT_PAYLOAD;

/// The channel a host uses before it has been allocated one.
pub const BROADCAST_CHANNEL: u32 = 0xffff_ffff;

/// `CTAPHID_INIT` carries exactly this many bytes of nonce.
const INIT_NONCE_LEN: usize = 8;

/// `CTAPHID_PING` — echo the payload back.
pub const CTAPHID_PING: u8 = 0x01;
/// `CTAPHID_MSG` — a CTAP1/U2F APDU. Not supported; we advertise `NMSG`.
pub const CTAPHID_MSG: u8 = 0x03;
/// `CTAPHID_INIT` — allocate a channel, or resynchronise an existing one.
pub const CTAPHID_INIT: u8 = 0x06;
/// `CTAPHID_CBOR` — carries a CTAP2 command.
pub const CTAPHID_CBOR: u8 = 0x10;
/// `CTAPHID_CANCEL` — withdraw the operation in flight.
pub const CTAPHID_CANCEL: u8 = 0x11;
/// `CTAPHID_KEEPALIVE` — authenticator to host only, while it is busy.
pub const CTAPHID_KEEPALIVE: u8 = 0x3b;
/// `CTAPHID_ERROR` — authenticator to host only, one status byte.
pub const CTAPHID_ERROR: u8 = 0x3f;

/// CTAPHID protocol version, reported in the `INIT` response.
const CTAPHID_PROTOCOL_VERSION: u8 = 2;

/// Capability flags in the `INIT` response.
const CAPABILITY_CBOR: u8 = 0x04;
/// Set to say `CTAPHID_MSG` (CTAP1/U2F) is **not** supported.
const CAPABILITY_NMSG: u8 = 0x08;

/// How long a half-received message may sit before the host is told it timed
/// out (CTAP 2.1 §11.2.5).
const TRANSACTION_TIMEOUT: Duration = Duration::from_millis(500);

/// A CTAPHID-level error. Distinct from [`CtapError`](crate::CtapError): these
/// describe framing going wrong, before any CTAP2 command exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum HidError {
    /// The command byte is not one CTAPHID defines, or we do not implement it.
    InvalidCommand = 0x01,
    /// A parameter was unusable.
    InvalidParameter = 0x02,
    /// The declared message length is impossible.
    InvalidLength = 0x03,
    /// A continuation packet arrived out of order.
    InvalidSequence = 0x04,
    /// A half-received message was abandoned.
    MessageTimeout = 0x05,
    /// Another transaction is already in progress.
    ChannelBusy = 0x06,
    /// The channel is not one we allocated.
    InvalidChannel = 0x0b,
    /// Catch-all.
    Other = 0x7f,
}

impl HidError {
    /// The byte carried in a `CTAPHID_ERROR` payload.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// The status byte of a `CTAPHID_KEEPALIVE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keepalive {
    /// Still working on it.
    Processing = 1,
    /// Waiting for the user — the host should keep waiting too, and may say so.
    UserPresenceNeeded = 2,
}

/// What the caller should do with a report it just fed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidOutcome {
    /// More packets are expected; nothing to send.
    Idle,
    /// Write these reports back to the host, in order.
    Reply(Vec<[u8; HID_REPORT_SIZE]>),
    /// A complete CTAP2 command arrived. Run it, then frame the answer with
    /// [`frame`] as a [`CTAPHID_CBOR`] message on this channel.
    Command {
        /// The channel the answer belongs on.
        channel: u32,
        /// The CTAP2 message: a command byte followed by a CBOR payload.
        payload: Vec<u8>,
    },
    /// The host withdrew whatever is in flight on this channel.
    Cancel {
        /// The channel that was cancelled.
        channel: u32,
    },
}

/// A message being reassembled from its packets.
struct Pending {
    channel: u32,
    command: u8,
    expected: usize,
    data: Vec<u8>,
    next_sequence: u8,
    started: Instant,
}

/// The CTAPHID framing state machine.
///
/// One message is reassembled at a time — CTAPHID transactions are atomic, and
/// a second host that starts one meanwhile is told [`HidError::ChannelBusy`].
pub struct HidTransport {
    allocated: Vec<u32>,
    next_channel: u32,
    pending: Option<Pending>,
    transaction_timeout: Duration,
}

impl Default for HidTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HidTransport {
    /// A transport with no channels allocated yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            allocated: Vec::new(),
            next_channel: 1,
            pending: None,
            transaction_timeout: TRANSACTION_TIMEOUT,
        }
    }

    /// Override how long a half-received message may sit. Mainly for tests.
    #[must_use]
    pub fn with_transaction_timeout(mut self, timeout: Duration) -> Self {
        self.transaction_timeout = timeout;
        self
    }

    /// Feed one 64-byte report from the host.
    pub fn handle_report(&mut self, report: &[u8]) -> HidOutcome {
        if report.len() < HID_REPORT_SIZE {
            // Short reports cannot carry a header we can trust to route a
            // reply, so there is nothing to answer on.
            return HidOutcome::Idle;
        }
        let channel = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);

        if report[4] & 0x80 == 0 {
            self.continuation(channel, report)
        } else {
            self.initialization(channel, report[4] & 0x7f, report)
        }
    }

    /// Emit a timeout error if a half-received message has gone stale. The run
    /// loop should call this whenever it is otherwise idle.
    pub fn poll_timeout(&mut self) -> Option<[u8; HID_REPORT_SIZE]> {
        let pending = self.pending.as_ref()?;
        if pending.started.elapsed() <= self.transaction_timeout {
            return None;
        }
        let channel = pending.channel;
        self.pending = None;
        Some(error_report(channel, HidError::MessageTimeout))
    }

    /// Whether a message is currently being reassembled.
    #[must_use]
    pub fn is_reassembling(&self) -> bool {
        self.pending.is_some()
    }

    fn initialization(&mut self, channel: u32, command: u8, report: &[u8]) -> HidOutcome {
        let length = usize::from(u16::from_be_bytes([report[5], report[6]]));

        // INIT is the one command that may interrupt anything: it exists so a
        // host that has lost track of its own state can start over.
        if command == CTAPHID_INIT {
            // The payload is exactly an 8-byte nonce. Accepting a shorter one
            // would mean echoing back uninitialised packet padding as if the
            // host had chosen it, which is how a host detects a stale reply.
            if length != INIT_NONCE_LEN {
                return reply(error_report(channel, HidError::InvalidLength));
            }
            return self.init(channel, &report[7..7 + INIT_NONCE_LEN]);
        }

        if channel == BROADCAST_CHANNEL || channel == 0 || !self.allocated.contains(&channel) {
            return reply(error_report(channel, HidError::InvalidChannel));
        }

        // CANCEL must get through while the authenticator is busy — that is its
        // entire purpose — so it is answered before the busy check.
        if command == CTAPHID_CANCEL {
            if self.pending.as_ref().is_some_and(|p| p.channel == channel) {
                self.pending = None;
            }
            return HidOutcome::Cancel { channel };
        }

        if self.pending.is_some() {
            return reply(error_report(channel, HidError::ChannelBusy));
        }

        if !matches!(command, CTAPHID_PING | CTAPHID_CBOR) {
            // CTAPHID_MSG lands here too: we advertise NMSG in the INIT
            // response, so a host asking for U2F is asking for something we
            // told it we do not have.
            let _ = CTAPHID_MSG;
            return reply(error_report(channel, HidError::InvalidCommand));
        }

        if length > MAX_MESSAGE_LEN {
            return reply(error_report(channel, HidError::InvalidLength));
        }

        let first = length.min(INIT_PAYLOAD);
        let mut data = Vec::with_capacity(length);
        data.extend_from_slice(&report[7..7 + first]);

        if data.len() == length {
            return self.dispatch(channel, command, data);
        }

        self.pending = Some(Pending {
            channel,
            command,
            expected: length,
            data,
            next_sequence: 0,
            started: Instant::now(),
        });
        HidOutcome::Idle
    }

    fn continuation(&mut self, channel: u32, report: &[u8]) -> HidOutcome {
        let sequence = report[4];

        let Some(pending) = self.pending.as_mut() else {
            // "Spurious continuation packets will be ignored" (CTAP 2.1
            // §11.2.4). Answering would let one host disrupt another's
            // transaction by guessing a channel.
            return HidOutcome::Idle;
        };
        if pending.channel != channel {
            return HidOutcome::Idle;
        }
        if sequence != pending.next_sequence {
            self.pending = None;
            return reply(error_report(channel, HidError::InvalidSequence));
        }

        let remaining = pending.expected - pending.data.len();
        let take = remaining.min(CONT_PAYLOAD);
        pending.data.extend_from_slice(&report[5..5 + take]);
        pending.next_sequence += 1;

        if pending.data.len() < pending.expected {
            return HidOutcome::Idle;
        }

        let pending = self.pending.take().expect("borrowed just above");
        self.dispatch(channel, pending.command, pending.data)
    }

    fn dispatch(&mut self, channel: u32, command: u8, data: Vec<u8>) -> HidOutcome {
        match command {
            CTAPHID_PING => reply_all(frame(channel, CTAPHID_PING, &data)),
            CTAPHID_CBOR => {
                if data.is_empty() {
                    // A CBOR message is at minimum a command byte.
                    return reply(error_report(channel, HidError::InvalidLength));
                }
                HidOutcome::Command {
                    channel,
                    payload: data,
                }
            }
            _ => reply(error_report(channel, HidError::InvalidCommand)),
        }
    }

    /// Allocate a channel (on the broadcast channel) or resynchronise one.
    fn init(&mut self, channel: u32, nonce: &[u8]) -> HidOutcome {
        let assigned = if channel == BROADCAST_CHANNEL {
            let assigned = self.allocate();
            self.allocated.push(assigned);
            assigned
        } else if self.allocated.contains(&channel) {
            // Resync: the host has lost track, so drop whatever it had in
            // flight and let it start over on the same channel.
            if self.pending.as_ref().is_some_and(|p| p.channel == channel) {
                self.pending = None;
            }
            channel
        } else {
            return reply(error_report(channel, HidError::InvalidChannel));
        };

        let mut payload = Vec::with_capacity(17);
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(&assigned.to_be_bytes());
        payload.push(CTAPHID_PROTOCOL_VERSION);
        // Device version. Zeroed: it identifies a firmware build, and Arca has
        // no firmware — a made-up number would only invite quirk-matching.
        payload.extend_from_slice(&[0, 0, 0]);
        payload.push(CAPABILITY_CBOR | CAPABILITY_NMSG);

        reply_all(frame(channel, CTAPHID_INIT, &payload))
    }

    /// Next free channel id. 0 and the broadcast id are reserved.
    fn allocate(&mut self) -> u32 {
        loop {
            let candidate = self.next_channel;
            self.next_channel = self.next_channel.wrapping_add(1);
            if candidate != 0
                && candidate != BROADCAST_CHANNEL
                && !self.allocated.contains(&candidate)
            {
                return candidate;
            }
        }
    }
}

/// Split `data` into the reports that carry it as `command` on `channel`.
///
/// Data beyond [`MAX_MESSAGE_LEN`] cannot be expressed and is truncated — the
/// length field would otherwise disagree with what follows it, which a host
/// reads as a corrupt stream rather than an over-long one.
#[must_use]
pub fn frame(channel: u32, command: u8, data: &[u8]) -> Vec<[u8; HID_REPORT_SIZE]> {
    let data = &data[..data.len().min(MAX_MESSAGE_LEN)];
    let channel = channel.to_be_bytes();

    let mut first = [0u8; HID_REPORT_SIZE];
    first[..4].copy_from_slice(&channel);
    first[4] = 0x80 | command;
    first[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let taken = data.len().min(INIT_PAYLOAD);
    first[7..7 + taken].copy_from_slice(&data[..taken]);

    let mut reports = vec![first];
    let mut offset = taken;
    let mut sequence = 0u8;
    while offset < data.len() {
        let mut report = [0u8; HID_REPORT_SIZE];
        report[..4].copy_from_slice(&channel);
        report[4] = sequence;
        let taken = (data.len() - offset).min(CONT_PAYLOAD);
        report[5..5 + taken].copy_from_slice(&data[offset..offset + taken]);
        reports.push(report);
        offset += taken;
        sequence += 1;
    }
    reports
}

/// A single `CTAPHID_KEEPALIVE` report.
#[must_use]
pub fn keepalive_report(channel: u32, status: Keepalive) -> [u8; HID_REPORT_SIZE] {
    frame(channel, CTAPHID_KEEPALIVE, &[status as u8])[0]
}

/// A single `CTAPHID_ERROR` report.
#[must_use]
pub fn error_report(channel: u32, error: HidError) -> [u8; HID_REPORT_SIZE] {
    frame(channel, CTAPHID_ERROR, &[error.code()])[0]
}

fn reply(report: [u8; HID_REPORT_SIZE]) -> HidOutcome {
    HidOutcome::Reply(vec![report])
}

fn reply_all(reports: Vec<[u8; HID_REPORT_SIZE]>) -> HidOutcome {
    HidOutcome::Reply(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_packet(channel: u32, command: u8, data: &[u8]) -> [u8; HID_REPORT_SIZE] {
        let mut report = [0u8; HID_REPORT_SIZE];
        report[..4].copy_from_slice(&channel.to_be_bytes());
        report[4] = 0x80 | command;
        report[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
        let taken = data.len().min(INIT_PAYLOAD);
        report[7..7 + taken].copy_from_slice(&data[..taken]);
        report
    }

    fn cont_packet(channel: u32, sequence: u8, data: &[u8]) -> [u8; HID_REPORT_SIZE] {
        let mut report = [0u8; HID_REPORT_SIZE];
        report[..4].copy_from_slice(&channel.to_be_bytes());
        report[4] = sequence;
        report[5..5 + data.len()].copy_from_slice(data);
        report
    }

    fn reports(outcome: HidOutcome) -> Vec<[u8; HID_REPORT_SIZE]> {
        match outcome {
            HidOutcome::Reply(reports) => reports,
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    /// Run INIT and return the allocated channel.
    fn open(transport: &mut HidTransport) -> u32 {
        let out = reports(transport.handle_report(&init_packet(
            BROADCAST_CHANNEL,
            CTAPHID_INIT,
            &[1, 2, 3, 4, 5, 6, 7, 8],
        )));
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][7..15], &[1, 2, 3, 4, 5, 6, 7, 8], "nonce echoed");
        u32::from_be_bytes([out[0][15], out[0][16], out[0][17], out[0][18]])
    }

    #[test]
    fn init_allocates_a_channel_and_reports_our_capabilities() {
        let mut transport = HidTransport::new();
        let out = reports(transport.handle_report(&init_packet(
            BROADCAST_CHANNEL,
            CTAPHID_INIT,
            &[9; 8],
        )));
        let report = out[0];

        assert_eq!(&report[..4], &BROADCAST_CHANNEL.to_be_bytes());
        assert_eq!(report[4], 0x80 | CTAPHID_INIT);
        assert_eq!(u16::from_be_bytes([report[5], report[6]]), 17);
        assert_eq!(&report[7..15], &[9; 8]);

        let channel = u32::from_be_bytes([report[15], report[16], report[17], report[18]]);
        assert!(channel != 0 && channel != BROADCAST_CHANNEL);
        assert_eq!(report[19], CTAPHID_PROTOCOL_VERSION);
        // CBOR yes, U2F no.
        assert_eq!(report[23], CAPABILITY_CBOR | CAPABILITY_NMSG);
    }

    #[test]
    fn every_init_hands_out_a_distinct_channel() {
        let mut transport = HidTransport::new();
        let a = open(&mut transport);
        let b = open(&mut transport);
        let c = open(&mut transport);
        assert!(a != b && b != c && a != c);
    }

    #[test]
    fn a_short_init_nonce_is_a_length_error() {
        let mut transport = HidTransport::new();
        let out = reports(transport.handle_report(&init_packet(
            BROADCAST_CHANNEL,
            CTAPHID_INIT,
            &[1, 2, 3],
        )));
        assert_eq!(out[0][7], HidError::InvalidLength.code());
    }

    #[test]
    fn commands_on_an_unallocated_channel_are_refused() {
        let mut transport = HidTransport::new();
        let out =
            reports(transport.handle_report(&init_packet(0xDEAD_BEEF, CTAPHID_CBOR, &[0x04])));
        assert_eq!(out[0][4], 0x80 | CTAPHID_ERROR);
        assert_eq!(out[0][7], HidError::InvalidChannel.code());
    }

    #[test]
    fn channel_zero_is_never_valid() {
        let mut transport = HidTransport::new();
        let out = reports(transport.handle_report(&init_packet(0, CTAPHID_CBOR, &[0x04])));
        assert_eq!(out[0][7], HidError::InvalidChannel.code());
    }

    #[test]
    fn a_short_cbor_command_arrives_in_one_packet() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        let outcome = transport.handle_report(&init_packet(channel, CTAPHID_CBOR, &[0x04]));
        assert_eq!(
            outcome,
            HidOutcome::Command {
                channel,
                payload: vec![0x04]
            }
        );
    }

    #[test]
    fn a_long_command_is_reassembled_across_continuation_packets() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);

        // 200 bytes: 57 in the init packet, then 59 + 59 + 25.
        let payload: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            transport.handle_report(&init_packet(channel, CTAPHID_CBOR, &payload)),
            HidOutcome::Idle
        );
        assert!(transport.is_reassembling());
        assert_eq!(
            transport.handle_report(&cont_packet(channel, 0, &payload[57..116])),
            HidOutcome::Idle
        );
        assert_eq!(
            transport.handle_report(&cont_packet(channel, 1, &payload[116..175])),
            HidOutcome::Idle
        );
        let outcome = transport.handle_report(&cont_packet(channel, 2, &payload[175..200]));

        assert_eq!(
            outcome,
            HidOutcome::Command {
                channel,
                payload: payload.clone()
            }
        );
        assert!(!transport.is_reassembling());
    }

    #[test]
    fn framing_and_reassembly_are_inverses() {
        // Whatever `frame` produces, the state machine must read back.
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        let payload: Vec<u8> = (0..4000u32).map(|i| (i % 253) as u8).collect();

        let mut outcome = HidOutcome::Idle;
        for report in frame(channel, CTAPHID_CBOR, &payload) {
            outcome = transport.handle_report(&report);
        }
        assert_eq!(
            outcome,
            HidOutcome::Command {
                channel,
                payload: payload.clone()
            }
        );
    }

    #[test]
    fn an_out_of_order_continuation_aborts_the_transaction() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        let payload = [7u8; 200];

        transport.handle_report(&init_packet(channel, CTAPHID_CBOR, &payload));
        // Sequence 1 where 0 was expected.
        let out = reports(transport.handle_report(&cont_packet(channel, 1, &payload[57..116])));
        assert_eq!(out[0][7], HidError::InvalidSequence.code());
        assert!(!transport.is_reassembling());
    }

    #[test]
    fn a_stray_continuation_is_ignored_rather_than_answered() {
        // Answering would let one host disrupt another's transaction by
        // guessing at a channel id.
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        assert_eq!(
            transport.handle_report(&cont_packet(channel, 0, &[1, 2, 3])),
            HidOutcome::Idle
        );
    }

    #[test]
    fn a_continuation_for_the_wrong_channel_is_ignored() {
        let mut transport = HidTransport::new();
        let a = open(&mut transport);
        let b = open(&mut transport);
        transport.handle_report(&init_packet(a, CTAPHID_CBOR, &[1u8; 200]));
        assert_eq!(
            transport.handle_report(&cont_packet(b, 0, &[9; 59])),
            HidOutcome::Idle
        );
        assert!(transport.is_reassembling(), "a's transaction survives");
    }

    #[test]
    fn a_second_transaction_is_told_the_channel_is_busy() {
        let mut transport = HidTransport::new();
        let a = open(&mut transport);
        let b = open(&mut transport);
        transport.handle_report(&init_packet(a, CTAPHID_CBOR, &[1u8; 200]));

        let out = reports(transport.handle_report(&init_packet(b, CTAPHID_CBOR, &[0x04])));
        assert_eq!(out[0][7], HidError::ChannelBusy.code());
    }

    #[test]
    fn init_resynchronises_a_channel_that_lost_its_place() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        transport.handle_report(&init_packet(channel, CTAPHID_CBOR, &[1u8; 200]));
        assert!(transport.is_reassembling());

        let out = reports(transport.handle_report(&init_packet(
            channel,
            CTAPHID_INIT,
            &[4, 4, 4, 4, 4, 4, 4, 4],
        )));
        // Same channel back, and the half-received message is gone.
        assert_eq!(
            u32::from_be_bytes([out[0][15], out[0][16], out[0][17], out[0][18]]),
            channel
        );
        assert!(!transport.is_reassembling());
    }

    #[test]
    fn cancel_gets_through_even_mid_transaction() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        transport.handle_report(&init_packet(channel, CTAPHID_CBOR, &[1u8; 200]));

        assert_eq!(
            transport.handle_report(&init_packet(channel, CTAPHID_CANCEL, &[])),
            HidOutcome::Cancel { channel }
        );
        assert!(!transport.is_reassembling());
    }

    #[test]
    fn ping_is_echoed_back_whole() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        // 100 bytes does not fit one packet, so this also proves a multi-packet
        // message is echoed at its full length rather than the first 57 bytes.
        let payload: Vec<u8> = (0..100u8).collect();

        assert_eq!(
            transport.handle_report(&init_packet(channel, CTAPHID_PING, &payload)),
            HidOutcome::Idle
        );
        let out = reports(transport.handle_report(&cont_packet(channel, 0, &payload[57..100])));
        assert_eq!(out[0][4], 0x80 | CTAPHID_PING);
        assert_eq!(u16::from_be_bytes([out[0][5], out[0][6]]), 100);
        assert_eq!(&out[0][7..64], &payload[..57]);
        assert_eq!(&out[1][5..5 + 43], &payload[57..100]);
    }

    #[test]
    fn u2f_messages_are_refused_because_we_advertise_nmsg() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        let out = reports(transport.handle_report(&init_packet(channel, CTAPHID_MSG, &[0; 7])));
        assert_eq!(out[0][7], HidError::InvalidCommand.code());
    }

    #[test]
    fn an_unknown_command_is_refused() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        let out = reports(transport.handle_report(&init_packet(channel, 0x42, &[0; 4])));
        assert_eq!(out[0][7], HidError::InvalidCommand.code());
    }

    #[test]
    fn an_impossible_message_length_is_refused() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        let mut report = init_packet(channel, CTAPHID_CBOR, &[]);
        report[5..7].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let out = reports(transport.handle_report(&report));
        assert_eq!(out[0][7], HidError::InvalidLength.code());
    }

    #[test]
    fn an_empty_cbor_message_is_refused() {
        let mut transport = HidTransport::new();
        let channel = open(&mut transport);
        let out = reports(transport.handle_report(&init_packet(channel, CTAPHID_CBOR, &[])));
        assert_eq!(out[0][7], HidError::InvalidLength.code());
    }

    #[test]
    fn a_half_received_message_times_out() {
        let mut transport = HidTransport::new().with_transaction_timeout(Duration::ZERO);
        let channel = open(&mut transport);
        transport.handle_report(&init_packet(channel, CTAPHID_CBOR, &[1u8; 200]));

        let report = transport.poll_timeout().expect("timed out");
        assert_eq!(report[4], 0x80 | CTAPHID_ERROR);
        assert_eq!(report[7], HidError::MessageTimeout.code());
        assert!(!transport.is_reassembling());
        // And it only fires once.
        assert!(transport.poll_timeout().is_none());
    }

    #[test]
    fn nothing_times_out_when_nothing_is_pending() {
        let mut transport = HidTransport::new().with_transaction_timeout(Duration::ZERO);
        open(&mut transport);
        assert!(transport.poll_timeout().is_none());
    }

    #[test]
    fn a_short_report_is_dropped_rather_than_answered_blindly() {
        let mut transport = HidTransport::new();
        assert_eq!(transport.handle_report(&[0u8; 10]), HidOutcome::Idle);
    }

    #[test]
    fn framing_covers_the_largest_expressible_message() {
        let payload = vec![0xA5u8; MAX_MESSAGE_LEN];
        let reports = frame(1, CTAPHID_CBOR, &payload);
        assert_eq!(reports.len(), 129, "one init plus 128 continuations");
        // The sequence number never has to exceed 0x7f.
        assert_eq!(reports[128][4], 127);
    }

    #[test]
    fn keepalive_and_error_reports_are_single_packets() {
        let report = keepalive_report(7, Keepalive::UserPresenceNeeded);
        assert_eq!(&report[..4], &7u32.to_be_bytes());
        assert_eq!(report[4], 0x80 | CTAPHID_KEEPALIVE);
        assert_eq!(u16::from_be_bytes([report[5], report[6]]), 1);
        assert_eq!(report[7], 2);

        let report = error_report(7, HidError::ChannelBusy);
        assert_eq!(report[4], 0x80 | CTAPHID_ERROR);
        assert_eq!(report[7], 0x06);
    }
}
