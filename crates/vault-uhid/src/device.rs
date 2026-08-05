//! A virtual HID device on `/dev/uhid`.
//!
//! uhid lets userspace create a HID device the kernel treats as real: it gets a
//! `/dev/hidrawN` node, udev sees it, and anything that enumerates HID devices
//! finds it. That is the whole trick behind this path — Chromium and Firefox
//! already know how to talk CTAP2 to a HID security key, so a device that looks
//! like one needs no cooperation from either.
//!
//! The interface is a character device you write event structures to and read
//! event structures from. Because it is `read`/`write` and not `ioctl`, the
//! whole thing can be driven by assembling byte arrays — which is why this
//! crate can keep `forbid(unsafe_code)` despite being FFI-shaped work. The
//! layouts below are transcribed from `include/uapi/linux/uhid.h`; the structs
//! are `__attribute__((packed))` and the integers are **native endian**, hence
//! `to_ne_bytes` throughout.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// Where the kernel exposes the interface.
pub const UHID_PATH: &str = "/dev/uhid";

// struct uhid_event {
//     __u32 type;
//     union { struct uhid_create2_req create2; ... } u;
// } __attribute__((__packed__));
//
// The union's largest member is uhid_create2_req (4372 bytes), so an event is
// 4376. The kernel zeroes its input buffer before copying, so a short write is
// legal and everything we leave off reads as zero.
const EVENT_SIZE: usize = 4376;
/// Offset of the union within an event.
const U: usize = 4;

// --- event types ---------------------------------------------------------

const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;

// --- struct uhid_create2_req ---------------------------------------------

const CREATE2_NAME: usize = U; // __u8 name[128]
const CREATE2_PHYS: usize = U + 128; // __u8 phys[64]
const CREATE2_UNIQ: usize = U + 192; // __u8 uniq[64]
const CREATE2_RD_SIZE: usize = U + 256; // __u16
const CREATE2_BUS: usize = U + 258; // __u16
const CREATE2_VENDOR: usize = U + 260; // __u32
const CREATE2_PRODUCT: usize = U + 264; // __u32
const CREATE2_VERSION: usize = U + 268; // __u32
const CREATE2_COUNTRY: usize = U + 272; // __u32
const CREATE2_RD_DATA: usize = U + 276; // __u8 rd_data[4096]

// --- struct uhid_output_req ----------------------------------------------

const OUTPUT_DATA: usize = U; // __u8 data[4096]
const OUTPUT_SIZE: usize = U + 4096; // __u16
const OUTPUT_RTYPE: usize = U + 4098; // __u8

// --- struct uhid_input2_req ----------------------------------------------

const INPUT2_SIZE: usize = U; // __u16
const INPUT2_DATA: usize = U + 2; // __u8 data[4096]

// --- struct uhid_get_report_req / uhid_set_report_req --------------------

const REPORT_ID: usize = U; // __u32
const SET_REPORT_SIZE: usize = U + 6; // __u16
const SET_REPORT_DATA: usize = U + 8; // __u8 data[4096]

// --- reply structs -------------------------------------------------------

const REPLY_ERR: usize = U + 4; // __u16

/// `BUS_USB` from `include/uapi/linux/input.h`.
const BUS_USB: u16 = 0x03;

/// `UHID_OUTPUT_REPORT` from `enum uhid_report_type`. A FIDO device declares no
/// feature reports, so anything else arriving on the output path is not for us.
const UHID_OUTPUT_REPORT: u8 = 1;

/// The report descriptor every FIDO HID authenticator carries: usage page
/// 0xF1D0 (FIDO Alliance), usage 0x01, with 64-byte input and output reports.
/// Hosts discover FIDO devices by matching this usage page, which is why the
/// device is found without anyone registering a vendor id.
const FIDO_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, //       Usage (CTAPHID)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Input Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Variable, Absolute)
    0x09, 0x21, //         Usage (Output Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Variable, Absolute)
    0xC0, //             End Collection
];

/// How the device presents itself to the system.
#[derive(Debug, Clone)]
pub struct DeviceOptions {
    /// Shown in `hidraw` metadata and in some browsers' authenticator UI.
    pub name: String,
    /// The `phys` string, a stable-ish location identifier.
    pub phys: String,
    /// The `uniq` string, a per-device serial.
    pub uniq: String,
    /// USB vendor id.
    pub vendor: u32,
    /// USB product id.
    pub product: u32,
    /// Device version.
    pub version: u32,
}

impl Default for DeviceOptions {
    fn default() -> Self {
        Self {
            name: "Arca Passkey Authenticator".into(),
            phys: "arca/uhid".into(),
            uniq: String::new(),
            // Zero, deliberately. Every real value belongs to a real company,
            // and borrowing one would make Arca claim to be their hardware —
            // to the user, to udev quirk tables, and to any relying party that
            // reads the id. Nothing needs it: hosts find FIDO devices by the
            // report descriptor's usage page, not by vendor.
            vendor: 0,
            product: 0,
            version: 0,
        }
    }
}

/// Something the kernel told us about the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The device was bound to a driver.
    Start,
    /// The device was unbound; nothing more will arrive.
    Stop,
    /// A process opened the hidraw node.
    Open,
    /// The last reader closed the hidraw node.
    Close,
    /// The host sent us a 64-byte output report.
    Output(Vec<u8>),
    /// The host sent an output report through the SET_REPORT path, which needs
    /// an acknowledgement before the caller is unblocked.
    SetReport {
        /// Correlates the acknowledgement with the request.
        id: u32,
        /// The 64-byte report.
        report: Vec<u8>,
    },
    /// The host asked to read a report. FIDO devices have none.
    GetReport {
        /// Correlates the acknowledgement with the request.
        id: u32,
    },
    /// An event this crate does not act on.
    Other(u32),
}

/// A live virtual HID device.
pub struct UhidDevice {
    file: File,
    destroyed: bool,
}

impl UhidDevice {
    /// Create the device. It appears as `/dev/hidrawN` as soon as this returns.
    ///
    /// Fails with [`io::ErrorKind::PermissionDenied`] unless the process can
    /// open `/dev/uhid`, which is root-only by default — see the crate docs.
    pub fn create(options: &DeviceOptions) -> io::Result<Self> {
        Self::create_at(Path::new(UHID_PATH), options)
    }

    /// Create the device against a specific path. Exists so the event codec can
    /// be exercised against an ordinary file in tests.
    pub fn create_at(path: &Path, options: &DeviceOptions) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut device = Self {
            file,
            destroyed: false,
        };
        device.write_event(&create2_event(options))?;
        Ok(device)
    }

    /// Block until the kernel has something to say.
    pub fn read_event(&mut self) -> io::Result<Event> {
        let mut buffer = [0u8; EVENT_SIZE];
        let read = self.file.read(&mut buffer)?;
        if read < U {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short uhid event",
            ));
        }
        decode_event(&buffer[..read])
    }

    /// Send a 64-byte input report to the host.
    pub fn write_report(&mut self, report: &[u8]) -> io::Result<()> {
        let mut event = vec![0u8; INPUT2_DATA + report.len()];
        event[..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
        let size = u16::try_from(report.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "report too large for uhid")
        })?;
        event[INPUT2_SIZE..INPUT2_SIZE + 2].copy_from_slice(&size.to_ne_bytes());
        event[INPUT2_DATA..].copy_from_slice(report);
        self.write_event(&event)
    }

    /// Acknowledge a [`Event::SetReport`]. The kernel blocks the writing
    /// process until this arrives, so it must not be skipped.
    pub fn set_report_reply(&mut self, id: u32, error: u16) -> io::Result<()> {
        let mut event = vec![0u8; REPLY_ERR + 2];
        event[..4].copy_from_slice(&UHID_SET_REPORT_REPLY.to_ne_bytes());
        event[REPORT_ID..REPORT_ID + 4].copy_from_slice(&id.to_ne_bytes());
        event[REPLY_ERR..REPLY_ERR + 2].copy_from_slice(&error.to_ne_bytes());
        self.write_event(&event)
    }

    /// Refuse a [`Event::GetReport`]. Same rule: the caller is blocked until
    /// this arrives, so an unanswered read request hangs whoever made it.
    pub fn get_report_reply(&mut self, id: u32, error: u16) -> io::Result<()> {
        let mut event = vec![0u8; REPLY_ERR + 2];
        event[..4].copy_from_slice(&UHID_GET_REPORT_REPLY.to_ne_bytes());
        event[REPORT_ID..REPORT_ID + 4].copy_from_slice(&id.to_ne_bytes());
        event[REPLY_ERR..REPLY_ERR + 2].copy_from_slice(&error.to_ne_bytes());
        self.write_event(&event)
    }

    /// A second handle on the same device, so one thread can block on reads
    /// while another writes.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
            // Only the original destroys the device; a clone going out of
            // scope must not take the real one down with it.
            destroyed: true,
        })
    }

    /// Remove the device. Idempotent, and also done on drop.
    pub fn destroy(&mut self) -> io::Result<()> {
        if self.destroyed {
            return Ok(());
        }
        self.destroyed = true;
        self.write_event(&UHID_DESTROY.to_ne_bytes())
    }

    fn write_event(&mut self, event: &[u8]) -> io::Result<()> {
        self.file.write_all(event)
    }
}

impl Drop for UhidDevice {
    fn drop(&mut self) {
        // A device left behind would keep answering ceremonies with a vault
        // nobody is watching, so this is best-effort but not optional.
        let _ = self.destroy();
    }
}

fn create2_event(options: &DeviceOptions) -> Vec<u8> {
    let mut event = vec![0u8; CREATE2_RD_DATA + FIDO_REPORT_DESCRIPTOR.len()];
    event[..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());

    // Each of these is a fixed-size NUL-terminated field; truncate rather than
    // overflow into the next one.
    put_string(&mut event, CREATE2_NAME, 128, &options.name);
    put_string(&mut event, CREATE2_PHYS, 64, &options.phys);
    put_string(&mut event, CREATE2_UNIQ, 64, &options.uniq);

    let rd_size = FIDO_REPORT_DESCRIPTOR.len() as u16;
    event[CREATE2_RD_SIZE..CREATE2_RD_SIZE + 2].copy_from_slice(&rd_size.to_ne_bytes());
    event[CREATE2_BUS..CREATE2_BUS + 2].copy_from_slice(&BUS_USB.to_ne_bytes());
    event[CREATE2_VENDOR..CREATE2_VENDOR + 4].copy_from_slice(&options.vendor.to_ne_bytes());
    event[CREATE2_PRODUCT..CREATE2_PRODUCT + 4].copy_from_slice(&options.product.to_ne_bytes());
    event[CREATE2_VERSION..CREATE2_VERSION + 4].copy_from_slice(&options.version.to_ne_bytes());
    event[CREATE2_COUNTRY..CREATE2_COUNTRY + 4].copy_from_slice(&0u32.to_ne_bytes());
    event[CREATE2_RD_DATA..].copy_from_slice(&FIDO_REPORT_DESCRIPTOR);
    event
}

fn put_string(event: &mut [u8], offset: usize, capacity: usize, value: &str) {
    let bytes = value.as_bytes();
    // Leave room for the terminating NUL the kernel expects.
    let take = bytes.len().min(capacity - 1);
    event[offset..offset + take].copy_from_slice(&bytes[..take]);
}

fn decode_event(buffer: &[u8]) -> io::Result<Event> {
    let kind = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    match kind {
        UHID_START => Ok(Event::Start),
        UHID_STOP => Ok(Event::Stop),
        UHID_OPEN => Ok(Event::Open),
        UHID_CLOSE => Ok(Event::Close),
        UHID_OUTPUT => {
            let rtype = *buffer.get(OUTPUT_RTYPE).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "truncated uhid output event")
            })?;
            if rtype != UHID_OUTPUT_REPORT {
                return Ok(Event::Other(kind));
            }
            let size = read_u16(buffer, OUTPUT_SIZE)? as usize;
            let end = OUTPUT_DATA
                .checked_add(size)
                .filter(|end| *end <= buffer.len())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "uhid output size out of range")
                })?;
            Ok(Event::Output(strip_report_id(&buffer[OUTPUT_DATA..end])))
        }
        UHID_SET_REPORT => {
            let id = read_u32(buffer, REPORT_ID)?;
            let size = read_u16(buffer, SET_REPORT_SIZE)? as usize;
            let end = SET_REPORT_DATA
                .checked_add(size)
                .filter(|end| *end <= buffer.len())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "uhid set_report size out of range",
                    )
                })?;
            Ok(Event::SetReport {
                id,
                report: strip_report_id(&buffer[SET_REPORT_DATA..end]),
            })
        }
        UHID_GET_REPORT => Ok(Event::GetReport {
            id: read_u32(buffer, REPORT_ID)?,
        }),
        other => Ok(Event::Other(other)),
    }
}

/// Drop the leading report-number byte hidraw prepends.
///
/// The FIDO report descriptor declares no report IDs, so a host writing to
/// hidraw must send `0x00` followed by the 64-byte report — and hidraw hands
/// the whole 65-byte buffer down to us unchanged. Anything that already sent a
/// bare 64-byte report is passed through untouched, because both shapes turn up
/// depending on which HID API the host used.
fn strip_report_id(data: &[u8]) -> Vec<u8> {
    match data {
        [0x00, rest @ ..] if rest.len() == 64 => rest.to_vec(),
        other => other.to_vec(),
    }
}

fn read_u16(buffer: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = buffer
        .get(offset..offset + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated uhid event"))?;
    Ok(u16::from_ne_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buffer: &[u8], offset: usize) -> io::Result<u32> {
    let bytes = buffer
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated uhid event"))?;
    Ok(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout constants are transcribed by hand from a C header, so pin the
    /// arithmetic: an off-by-one here would corrupt every field after it and
    /// show up only as a device the kernel silently refuses to create.
    #[test]
    fn the_struct_layout_matches_uhid_h() {
        // uhid_create2_req: name[128] phys[64] uniq[64] rd_size rd_bus vendor
        // product version country rd_data[4096] = 4372 bytes, after a 4-byte
        // type tag.
        assert_eq!(CREATE2_NAME, 4);
        assert_eq!(CREATE2_PHYS, 132);
        assert_eq!(CREATE2_UNIQ, 196);
        assert_eq!(CREATE2_RD_SIZE, 260);
        assert_eq!(CREATE2_BUS, 262);
        assert_eq!(CREATE2_VENDOR, 264);
        assert_eq!(CREATE2_PRODUCT, 268);
        assert_eq!(CREATE2_VERSION, 272);
        assert_eq!(CREATE2_COUNTRY, 276);
        assert_eq!(CREATE2_RD_DATA, 280);
        assert_eq!(CREATE2_RD_DATA + 4096, EVENT_SIZE);

        // uhid_output_req: data[4096] size rtype
        assert_eq!(OUTPUT_DATA, 4);
        assert_eq!(OUTPUT_SIZE, 4100);
        assert_eq!(OUTPUT_RTYPE, 4102);

        // uhid_input2_req: size data[4096]
        assert_eq!(INPUT2_SIZE, 4);
        assert_eq!(INPUT2_DATA, 6);

        // uhid_set_report_req: id rnum rtype size data[4096]
        assert_eq!(REPORT_ID, 4);
        assert_eq!(SET_REPORT_SIZE, 10);
        assert_eq!(SET_REPORT_DATA, 12);

        // uhid_{get,set}_report_reply_req: id err ...
        assert_eq!(REPLY_ERR, 8);
    }

    #[test]
    fn the_create_event_carries_the_fido_report_descriptor() {
        let event = create2_event(&DeviceOptions::default());
        assert_eq!(&event[..4], &UHID_CREATE2.to_ne_bytes());
        assert_eq!(
            read_u16(&event, CREATE2_RD_SIZE).unwrap() as usize,
            FIDO_REPORT_DESCRIPTOR.len()
        );
        assert_eq!(read_u16(&event, CREATE2_BUS).unwrap(), BUS_USB);
        assert_eq!(&event[CREATE2_RD_DATA..], &FIDO_REPORT_DESCRIPTOR);

        // The usage page is what hosts match on to find a FIDO device.
        assert_eq!(&FIDO_REPORT_DESCRIPTOR[..3], &[0x06, 0xD0, 0xF1]);
    }

    #[test]
    fn the_name_is_nul_terminated_and_never_overruns_its_field() {
        let options = DeviceOptions {
            name: "x".repeat(500),
            ..DeviceOptions::default()
        };
        let event = create2_event(&options);
        assert_eq!(event[CREATE2_NAME + 126], b'x');
        assert_eq!(event[CREATE2_NAME + 127], 0, "terminator survives");
        // And nothing spilled into phys.
        assert_eq!(event[CREATE2_PHYS], b'a', "phys still starts with 'arca'");
    }

    #[test]
    fn an_input_report_is_framed_as_input2() {
        let report = [0xABu8; 64];
        let mut event = vec![0u8; INPUT2_DATA + report.len()];
        event[..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
        event[INPUT2_SIZE..INPUT2_SIZE + 2].copy_from_slice(&64u16.to_ne_bytes());
        event[INPUT2_DATA..].copy_from_slice(&report);

        assert_eq!(event.len(), 70);
        assert_eq!(read_u16(&event, INPUT2_SIZE).unwrap(), 64);
        assert_eq!(&event[INPUT2_DATA..], &report);
    }

    fn output_event(payload: &[u8]) -> Vec<u8> {
        let mut event = vec![0u8; EVENT_SIZE];
        event[..4].copy_from_slice(&UHID_OUTPUT.to_ne_bytes());
        event[OUTPUT_DATA..OUTPUT_DATA + payload.len()].copy_from_slice(payload);
        event[OUTPUT_SIZE..OUTPUT_SIZE + 2].copy_from_slice(&(payload.len() as u16).to_ne_bytes());
        event[OUTPUT_RTYPE] = UHID_OUTPUT_REPORT;
        event
    }

    #[test]
    fn a_feature_report_is_not_mistaken_for_a_ctaphid_packet() {
        let mut event = output_event(&[0x33u8; 64]);
        event[OUTPUT_RTYPE] = 0; // UHID_FEATURE_REPORT
        assert_eq!(decode_event(&event).unwrap(), Event::Other(UHID_OUTPUT));
    }

    #[test]
    fn the_report_number_byte_hidraw_prepends_is_stripped() {
        // What a host actually writes: 0x00 then the 64-byte report.
        let mut payload = vec![0x00];
        payload.extend_from_slice(&[0x11u8; 64]);

        match decode_event(&output_event(&payload)).unwrap() {
            Event::Output(report) => {
                assert_eq!(report.len(), 64);
                assert_eq!(report[0], 0x11);
            }
            other => panic!("expected Output, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_64_byte_report_is_passed_through_untouched() {
        let payload = [0x00u8; 64]; // starts with 0x00 but is only 64 long
        match decode_event(&output_event(&payload)).unwrap() {
            Event::Output(report) => assert_eq!(report.len(), 64),
            other => panic!("expected Output, got {other:?}"),
        }
    }

    #[test]
    fn set_report_carries_its_correlation_id() {
        let mut event = vec![0u8; EVENT_SIZE];
        event[..4].copy_from_slice(&UHID_SET_REPORT.to_ne_bytes());
        event[REPORT_ID..REPORT_ID + 4].copy_from_slice(&0xCAFEu32.to_ne_bytes());
        event[SET_REPORT_SIZE..SET_REPORT_SIZE + 2].copy_from_slice(&65u16.to_ne_bytes());
        event[SET_REPORT_DATA] = 0x00;
        event[SET_REPORT_DATA + 1..SET_REPORT_DATA + 65].copy_from_slice(&[0x22u8; 64]);

        match decode_event(&event).unwrap() {
            Event::SetReport { id, report } => {
                assert_eq!(id, 0xCAFE);
                assert_eq!(report.len(), 64);
                assert_eq!(report[0], 0x22);
            }
            other => panic!("expected SetReport, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_events_decode() {
        for (kind, expected) in [
            (UHID_START, Event::Start),
            (UHID_STOP, Event::Stop),
            (UHID_OPEN, Event::Open),
            (UHID_CLOSE, Event::Close),
        ] {
            let mut event = vec![0u8; EVENT_SIZE];
            event[..4].copy_from_slice(&kind.to_ne_bytes());
            assert_eq!(decode_event(&event).unwrap(), expected);
        }
    }

    #[test]
    fn an_unknown_event_type_is_carried_rather_than_failing() {
        let mut event = vec![0u8; EVENT_SIZE];
        event[..4].copy_from_slice(&999u32.to_ne_bytes());
        assert_eq!(decode_event(&event).unwrap(), Event::Other(999));
    }

    #[test]
    fn a_lying_size_field_is_an_error_not_a_panic() {
        // A size that runs past the buffer must not index out of bounds.
        let mut event = output_event(&[0x44u8; 64]);
        event[OUTPUT_SIZE..OUTPUT_SIZE + 2].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert_eq!(
            decode_event(&event).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn a_truncated_event_is_an_error_not_a_panic() {
        let mut event = vec![0u8; 8];
        event[..4].copy_from_slice(&UHID_OUTPUT.to_ne_bytes());
        assert!(decode_event(&event).is_err());
    }
}
