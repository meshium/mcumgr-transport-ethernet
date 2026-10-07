//! SMP over raw Ethernet (layer 2) frames, as a transport for
//! [`mcumgr-toolkit`](https://crates.io/crates/mcumgr-toolkit).
//!
//! Each SMP frame is carried in the payload of a single Ethernet frame with
//! the EtherType [`ETHERTYPE_SMP`], without any IP stack involvement.
//! The device is expected to reply from the MAC address the request was sent to.
//!
//! The transport itself is only available on Linux, as it relies on
//! `AF_PACKET` sockets. Opening such a socket requires the `CAP_NET_RAW`
//! capability.
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> miette::Result<()> {
//! use std::time::Duration;
//!
//! use mcumgr_toolkit::MCUmgrClient;
//! use mcumgr_transport_ethernet::EthernetTransport;
//!
//! let mac = "02:00:00:00:00:01".parse()?;
//! let transport = EthernetTransport::new("eth0", mac, Duration::from_millis(1000))?;
//! let client = MCUmgrClient::new_from_transport(transport);
//! client.use_auto_frame_size()?;
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! Devices on the local link can be found with [`EthernetTransport::discover`],
//! which broadcasts an `os echo` probe and collects the answers:
//!
//! ```no_run
//! # #[cfg(target_os = "linux")]
//! # fn main() -> miette::Result<()> {
//! use std::time::Duration;
//!
//! use mcumgr_transport_ethernet::EthernetTransport;
//!
//! for device in EthernetTransport::discover("eth0", Duration::from_secs(2))? {
//!     println!("{} replied after {:?}", device.mac, device.rtt);
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(target_os = "linux"))]
//! # fn main() {}
//! ```
//!
//! With the `cli` feature, [`cli`] integrates the transport into `mcumgrctl`.

#![deny(missing_docs)]
#![deny(unreachable_pub)]
// Binding the packet socket needs exactly one unsafe block
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{fmt, str::FromStr};

use miette::Diagnostic;
use thiserror::Error;

#[cfg(target_os = "linux")]
pub use linux::{DiscoveredDevice, EthernetError, EthernetTransport};

#[cfg(feature = "cli")]
pub mod cli;

/// The version of this crate, e.g. for a `-V` output of a binary that
/// depends on it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The EtherType used for SMP frames.
///
/// `0x88B5` is the IEEE 802 "Local Experimental EtherType 1".
pub const ETHERTYPE_SMP: u16 = 0x88B5;

const ETH_ALEN: usize = 6;

/// An Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddress(
    /// The six address bytes, in transmission order.
    pub [u8; ETH_ALEN],
);

impl MacAddress {
    /// Whether this is the broadcast address, `ff:ff:ff:ff:ff:ff`.
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; ETH_ALEN]
    }
}

/// The error returned when parsing a [`MacAddress`] fails.
#[derive(Error, Debug, Diagnostic, Clone, PartialEq, Eq)]
#[error("Invalid MAC address '{0}', expected 'xx:xx:xx:xx:xx:xx'")]
#[diagnostic(code(mcumgr_transport_ethernet::invalid_mac_address))]
pub struct MacAddressParseError(String);

impl FromStr for MacAddress {
    type Err = MacAddressParseError;

    /// Parses six hex byte pairs separated by either `:` or `-`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || MacAddressParseError(s.to_string());

        let separator = if s.contains('-') { '-' } else { ':' };
        let mut parts = s.split(separator);

        let mut bytes = [0u8; ETH_ALEN];
        for byte in &mut bytes {
            let part = parts.next().ok_or_else(err)?;
            // from_str_radix alone would also accept a sign or a single digit
            if part.len() != 2 || !part.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(err());
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| err())?;
        }

        if parts.next().is_some() {
            return Err(err());
        }

        Ok(Self(bytes))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        io::{self, Read},
        ops::Range,
        path::Path,
        time::{Duration, Instant},
    };

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    use mcumgr_toolkit::transport::{
        ReceiveError, SMP_HEADER_SIZE, SMP_TRANSFER_BUFFER_SIZE, SendError, Transport,
    };
    use miette::Diagnostic;
    use thiserror::Error;

    use super::{ETH_ALEN, ETHERTYPE_SMP, MacAddress};

    const ETH_HEADER_SIZE: usize = 2 * ETH_ALEN + 2;

    const ETH_DATA_LEN: usize = 1500;

    /// The largest Ethernet frame read during discovery: a full payload, the
    /// header, and a VLAN tag. Larger frames are truncated by the read, which
    /// is harmless, as only the headers of a frame are inspected.
    const ETH_MAX_FRAME: usize = ETH_HEADER_SIZE + ETH_DATA_LEN + 4;

    const BROADCAST: MacAddress = MacAddress([0xff; ETH_ALEN]);

    /// The SMP protocol version of `mcumgr-toolkit`, stored in the first
    /// header byte above the operation code.
    const SMP_VERSION: u8 = 0b01;

    /// SMP operation codes of the discovery probe and its answer; `os echo`
    /// is a read command, and reads are answered with `SMP_OP_READ_RSP`.
    const SMP_OP_READ: u8 = 0;
    const SMP_OP_READ_RSP: u8 = 1;

    /// The `os echo` command id, in the OS group, whose group id is 0.
    const OS_MGMT_ID_ECHO: u8 = 0;

    const DISCOVERY_SEQ: u8 = 0;

    /// The probe payload, a CBOR map: `{"d": "ping"}`.
    const DISCOVERY_PAYLOAD: &[u8] = &[0xa1, 0x61, 0x64, 0x64, 0x70, 0x69, 0x6e, 0x67];

    /// A device that answered an [`EthernetTransport::discover`] probe.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DiscoveredDevice {
        /// The MAC address the answer was sent from.
        pub mac: MacAddress,
        /// How long after the probe was sent the answer arrived.
        pub rtt: Duration,
    }

    /// Possible errors of [`EthernetTransport::new`].
    #[derive(Error, Debug, Diagnostic)]
    pub enum EthernetError {
        /// The process is not allowed to open raw sockets
        #[error("Not permitted to open a raw Ethernet socket")]
        #[diagnostic(
            code(mcumgr_transport_ethernet::permission_denied),
            help(
                "raw sockets require the CAP_NET_RAW capability, e.g. `sudo setcap cap_net_raw+ep <executable>`"
            )
        )]
        PermissionDenied(#[source] io::Error),
        /// An I/O error occurred while opening the raw Ethernet socket
        #[error("Failed to open raw Ethernet socket")]
        #[diagnostic(code(mcumgr_transport_ethernet::io_error))]
        Io(#[source] io::Error),
    }

    impl From<io::Error> for EthernetError {
        fn from(e: io::Error) -> Self {
            if e.kind() == io::ErrorKind::PermissionDenied {
                Self::PermissionDenied(e)
            } else {
                Self::Io(e)
            }
        }
    }

    /// A transport layer implementation for raw Ethernet frames.
    pub struct EthernetTransport {
        socket: Socket,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        timeout: Duration,
        send_buffer: Vec<u8>,
    }

    impl EthernetTransport {
        /// Create a new [`EthernetTransport`] that talks to the given device.
        ///
        /// # Arguments
        ///
        /// * `iface` - The name of the local network interface, e.g. `"eth0"`.
        /// * `dst_mac` - The MAC address of the device.
        /// * `timeout` - The initial communication timeout.
        ///
        pub fn new(
            iface: &str,
            dst_mac: MacAddress,
            timeout: Duration,
        ) -> Result<Self, EthernetError> {
            let (socket, src_mac) = open_socket(iface, timeout)?;

            Ok(Self {
                socket,
                src_mac,
                dst_mac,
                timeout,
                send_buffer: Vec::new(),
            })
        }

        /// Scan `iface` for SMP devices.
        ///
        /// Broadcasts a single `os echo` probe and collects the answers for
        /// `timeout`, returning one [`DiscoveredDevice`] per device, in the
        /// order they replied.
        ///
        /// Firmware must accept frames addressed to the broadcast address to
        /// be found. Firmware that answers with a broadcast source address,
        /// in violation of this transport's reply convention, appears as a
        /// single `ff:ff:ff:ff:ff:ff` entry.
        ///
        /// # Arguments
        ///
        /// * `iface` - The name of the local network interface, e.g. `"eth0"`.
        /// * `timeout` - How long answers are collected.
        pub fn discover(
            iface: &str,
            timeout: Duration,
        ) -> Result<Vec<DiscoveredDevice>, EthernetError> {
            let (mut socket, src_mac) = open_socket(iface, timeout)?;

            let mut probe = Vec::new();
            write_frame(
                &mut probe,
                &BROADCAST,
                &src_mac,
                &probe_header(),
                DISCOVERY_PAYLOAD,
            );
            socket.send(&probe)?;
            log::debug!("Sent discovery probe on '{iface}'");

            let start = Instant::now();
            let mut buffer = [0u8; ETH_MAX_FRAME];
            let mut devices: Vec<DiscoveredDevice> = Vec::new();
            loop {
                let remaining = timeout.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    break;
                }
                // Each read would restart the socket timeout, so the
                // deadline is enforced by shrinking it to the remaining time.
                set_read_timeout(&socket, remaining)?;

                let len = match socket.read(&mut buffer) {
                    Ok(len) => len,
                    // SO_RCVTIMEO reports an expired deadline as EAGAIN
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => break,
                    Err(e) => return Err(e.into()),
                };

                if let Some((src, smp)) = parse_smp_frame(&buffer[..len])
                    && src != src_mac
                    && is_probe_response(&buffer[smp])
                    && !devices.iter().any(|device| device.mac == src)
                {
                    let rtt = start.elapsed();
                    log::debug!("Discovered SMP device {src} after {rtt:?}");
                    devices.push(DiscoveredDevice { mac: src, rtt });
                } else {
                    log::debug!("Ignoring Ethernet frame during discovery ({len} bytes)");
                }
            }

            Ok(devices)
        }
    }

    impl Transport for EthernetTransport {
        fn send_raw_frame(
            &mut self,
            header: [u8; SMP_HEADER_SIZE],
            data: &[u8],
        ) -> Result<(), SendError> {
            self.send_buffer.clear();
            write_frame(
                &mut self.send_buffer,
                &self.dst_mac,
                &self.src_mac,
                &header,
                data,
            );
            // The socket is bound to the interface, and the destination
            // is part of the frame, so no address is needed here.
            self.socket.send(&self.send_buffer)?;
            log::debug!("Sent Ethernet SMP Frame ({} bytes)", data.len());
            Ok(())
        }

        fn recv_raw_frame<'a>(
            &mut self,
            buffer: &'a mut [u8; SMP_TRANSFER_BUFFER_SIZE],
        ) -> Result<&'a [u8], ReceiveError> {
            let start = Instant::now();
            let smp_range = loop {
                // SO_RCVTIMEO reports an expired deadline as EAGAIN; normalise
                // it to TimedOut, like the UDP transport does.
                let len = self.socket.read(buffer).map_err(|e| {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        io::Error::new(io::ErrorKind::TimedOut, e)
                    } else {
                        e
                    }
                })?;

                if let Some(range) = extract_smp_frame(&buffer[..len], &self.dst_mac) {
                    break range;
                }

                // Every read restarts the socket timeout, so keep frames from
                // other devices from extending the wait indefinitely.
                log::debug!("Ignoring unrelated Ethernet frame ({len} bytes)");
                if start.elapsed() >= self.timeout {
                    return Err(ReceiveError::Timeout);
                }
            };

            let smp_len = smp_range.len();
            buffer.copy_within(smp_range, 0);
            log::debug!(
                "Received Ethernet SMP Frame ({} bytes)",
                smp_len - SMP_HEADER_SIZE
            );
            Ok(&buffer[..smp_len])
        }

        fn set_timeout(
            &mut self,
            timeout: Duration,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            set_read_timeout(&self.socket, timeout)?;
            self.timeout = timeout;
            Ok(())
        }

        fn max_smp_frame_size(&self) -> usize {
            ETH_DATA_LEN
        }
    }

    fn open_socket(iface: &str, timeout: Duration) -> Result<(Socket, MacAddress), EthernetError> {
        let (ifindex, src_mac) = read_interface(iface)?;

        let protocol = Protocol::from(i32::from(ETHERTYPE_SMP.to_be()));
        let socket = Socket::new(Domain::PACKET, Type::RAW, Some(protocol))?;
        socket.bind(&packet_sockaddr(ifindex)?)?;
        set_read_timeout(&socket, timeout)?;

        Ok((socket, src_mac))
    }

    fn read_interface(iface: &str) -> io::Result<(i32, MacAddress)> {
        // The name becomes a path component below, so reject anything that
        // could escape the interface directory.
        if iface.is_empty()
            || iface.len() >= libc::IFNAMSIZ
            || iface.contains('/')
            || iface == "."
            || iface == ".."
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid network interface name '{iface}'"),
            ));
        }

        let dir = Path::new("/sys/class/net").join(iface);
        let read_attr = |attr: &str| {
            fs::read_to_string(dir.join(attr)).map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Network interface '{iface}' not found"),
                    )
                } else {
                    e
                }
            })
        };

        let ifindex = read_attr("ifindex")?
            .trim()
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mac = read_attr("address")?.trim().parse().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Network interface '{iface}' is not an Ethernet interface"),
            )
        })?;

        Ok((ifindex, mac))
    }

    #[allow(unsafe_code)]
    fn packet_sockaddr(ifindex: i32) -> io::Result<SockAddr> {
        let sll = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: ETHERTYPE_SMP.to_be(),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        // SAFETY: The storage is a zeroed, suitably aligned `sockaddr_storage`,
        // which is larger than `sockaddr_ll`. We fully initialise it as a
        // `sockaddr_ll` with the matching family `AF_PACKET`, and set the
        // length to exactly that type.
        let ((), addr) = unsafe {
            SockAddr::try_init(|storage, len| {
                storage.cast::<libc::sockaddr_ll>().write(sll);
                *len = size_of::<libc::sockaddr_ll>() as socket2::socklen_t;
                Ok(())
            })
        }?;

        Ok(addr)
    }

    fn set_read_timeout(socket: &Socket, timeout: Duration) -> io::Result<()> {
        // A zero timeval disables the timeout, and sub-microsecond values are
        // truncated to zero; follow std's UdpSocket instead of blocking forever.
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Timeout must not be zero",
            ));
        }
        socket.set_read_timeout(Some(timeout.max(Duration::from_micros(1))))
    }

    fn write_frame(
        buffer: &mut Vec<u8>,
        dst: &MacAddress,
        src: &MacAddress,
        header: &[u8; SMP_HEADER_SIZE],
        data: &[u8],
    ) {
        buffer.extend_from_slice(&dst.0);
        buffer.extend_from_slice(&src.0);
        buffer.extend_from_slice(&ETHERTYPE_SMP.to_be_bytes());
        buffer.extend_from_slice(header);
        buffer.extend_from_slice(data);
    }

    /// Returns `None` for frames that were not sent by `expected_src`.
    fn extract_smp_frame(frame: &[u8], expected_src: &MacAddress) -> Option<Range<usize>> {
        let (src, range) = parse_smp_frame(frame)?;
        (src == *expected_src).then_some(range)
    }

    /// Returns the sender and the SMP payload of any frame that carries our
    /// EtherType, regardless of who sent it.
    ///
    /// Short frames get padded to the 60 byte Ethernet minimum, so the SMP
    /// frame is cut to the length stated in its header. Truncated frames are
    /// passed on as-is and rejected by the SMP header validation.
    fn parse_smp_frame(frame: &[u8]) -> Option<(MacAddress, Range<usize>)> {
        let (eth_header, payload) = frame.split_at_checked(ETH_HEADER_SIZE)?;

        if eth_header[2 * ETH_ALEN..] != ETHERTYPE_SMP.to_be_bytes() {
            return None;
        }
        let src = MacAddress(*eth_header[ETH_ALEN..2 * ETH_ALEN].first_chunk::<ETH_ALEN>()?);

        // Bytes 2..4 of the SMP header are the body length, big endian
        let smp_header = payload.first_chunk::<SMP_HEADER_SIZE>()?;
        let data_length = u16::from_be_bytes([smp_header[2], smp_header[3]]);
        let smp_len = (SMP_HEADER_SIZE + usize::from(data_length)).min(payload.len());

        Some((src, ETH_HEADER_SIZE..ETH_HEADER_SIZE + smp_len))
    }

    /// The SMP header of the discovery probe: a version 1 read request for
    /// `os echo` in the OS group.
    fn probe_header() -> [u8; SMP_HEADER_SIZE] {
        let [len_0, len_1] = u16::try_from(DISCOVERY_PAYLOAD.len())
            .expect("the probe payload fits into an SMP frame")
            .to_be_bytes();

        [
            (SMP_VERSION << 3) | SMP_OP_READ,
            0,
            len_0,
            len_1,
            0,
            0,
            DISCOVERY_SEQ,
            OS_MGMT_ID_ECHO,
        ]
    }

    /// Whether `smp` is an `os echo` response to the discovery probe.
    fn is_probe_response(smp: &[u8]) -> bool {
        let Some(header) = smp.first_chunk::<SMP_HEADER_SIZE>() else {
            return false;
        };

        header[0] == (SMP_VERSION << 3) | SMP_OP_READ_RSP && header[6] == DISCOVERY_SEQ
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const DEVICE: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x01]);
        const HOST: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 0x02]);

        fn smp_header(data_length: u16) -> [u8; SMP_HEADER_SIZE] {
            let [len_0, len_1] = data_length.to_be_bytes();
            [0x09, 0, len_0, len_1, 0, 0, 0x42, 0]
        }

        fn frame_from(src: &MacAddress, data: &[u8]) -> Vec<u8> {
            let mut frame = Vec::new();
            write_frame(&mut frame, &HOST, src, &smp_header(data.len() as u16), data);
            frame
        }

        #[test]
        fn write_frame_layout() {
            let frame = frame_from(&DEVICE, &[0xAA, 0xBB]);
            assert_eq!(frame[..6], HOST.0);
            assert_eq!(frame[6..12], DEVICE.0);
            assert_eq!(frame[12..14], [0x88, 0xB5]);
            assert_eq!(frame[14..22], smp_header(2));
            assert_eq!(frame[22..], [0xAA, 0xBB]);
        }

        #[test]
        fn extract_exact_frame() {
            let frame = frame_from(&DEVICE, &[1, 2, 3]);
            let range = extract_smp_frame(&frame, &DEVICE).unwrap();
            assert_eq!(range, ETH_HEADER_SIZE..frame.len());
        }

        #[test]
        fn extract_strips_padding() {
            let mut frame = frame_from(&DEVICE, &[1, 2, 3]);
            frame.resize(60, 0);
            let range = extract_smp_frame(&frame, &DEVICE).unwrap();
            assert_eq!(range.len(), SMP_HEADER_SIZE + 3);
            assert_eq!(frame[range][SMP_HEADER_SIZE..], [1, 2, 3]);
        }

        #[test]
        fn extract_keeps_truncated_frame() {
            let mut frame = frame_from(&DEVICE, &[1, 2, 3]);
            frame.pop();
            let range = extract_smp_frame(&frame, &DEVICE).unwrap();
            assert_eq!(range, ETH_HEADER_SIZE..frame.len());
        }

        #[test]
        fn extract_ignores_other_sender() {
            let frame = frame_from(&HOST, &[1, 2, 3]);
            assert_eq!(extract_smp_frame(&frame, &DEVICE), None);
        }

        #[test]
        fn extract_ignores_other_ethertype() {
            let mut frame = frame_from(&DEVICE, &[1, 2, 3]);
            frame[12..14].copy_from_slice(&[0x08, 0x00]);
            assert_eq!(extract_smp_frame(&frame, &DEVICE), None);
        }

        #[test]
        fn extract_ignores_short_frames() {
            let frame = frame_from(&DEVICE, &[]);
            for len in 0..ETH_HEADER_SIZE + SMP_HEADER_SIZE {
                assert_eq!(extract_smp_frame(&frame[..len], &DEVICE), None);
            }
        }

        fn frame_with_header(
            src: &MacAddress,
            header: [u8; SMP_HEADER_SIZE],
            data: &[u8],
        ) -> Vec<u8> {
            let mut frame = Vec::new();
            write_frame(&mut frame, &HOST, src, &header, data);
            frame
        }

        fn echo_response_frame(src: &MacAddress, seq: u8) -> Vec<u8> {
            let [len_0, len_1] = 2u16.to_be_bytes();
            frame_with_header(
                src,
                [0x09, 0x00, len_0, len_1, 0x00, 0x00, seq, 0x00],
                &[0xab, 0xcd],
            )
        }

        #[test]
        fn probe_header_layout() {
            let [len_0, len_1] = (DISCOVERY_PAYLOAD.len() as u16).to_be_bytes();
            assert_eq!(
                probe_header(),
                [0x08, 0x00, len_0, len_1, 0x00, 0x00, DISCOVERY_SEQ, 0x00]
            );
            assert_eq!(
                DISCOVERY_PAYLOAD,
                [0xa1, 0x61, 0x64, 0x64, 0x70, 0x69, 0x6e, 0x67]
            );
        }

        #[test]
        fn probe_response_recognised() {
            let frame = echo_response_frame(&DEVICE, DISCOVERY_SEQ);
            let (src, smp) = parse_smp_frame(&frame).unwrap();
            assert_eq!(src, DEVICE);
            assert!(is_probe_response(&frame[smp]));
        }

        #[test]
        fn probe_ignores_wrong_sequence() {
            let frame = echo_response_frame(&DEVICE, DISCOVERY_SEQ.wrapping_add(1));
            let (_, smp) = parse_smp_frame(&frame).unwrap();
            assert!(!is_probe_response(&frame[smp]));
        }

        #[test]
        fn probe_ignores_requests_from_other_hosts() {
            // A discovery probe from another host is a read request, not an
            // answer, and must not be counted as a device.
            let frame = frame_with_header(&HOST, probe_header(), DISCOVERY_PAYLOAD);
            let (src, smp) = parse_smp_frame(&frame).unwrap();
            assert_eq!(src, HOST);
            assert!(!is_probe_response(&frame[smp]));
        }

        #[test]
        fn invalid_interface_names() {
            for name in ["", ".", "..", "a/b", "../lo", "abcdefghijklmnop"] {
                let err = read_interface(name).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{name:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parse_valid() {
        let expected = MacAddress([0x00, 0x1a, 0x2B, 0x3c, 0x4D, 0xff]);
        assert_eq!("00:1a:2B:3c:4D:ff".parse(), Ok(expected));
        assert_eq!("00-1a-2B-3c-4D-ff".parse(), Ok(expected));
    }

    #[test]
    fn parse_invalid() {
        for s in [
            "",
            "00:11:22:33:44",
            "00:11:22:33:44:55:66",
            "0:1:2:3:4:5",
            "+0:11:22:33:44:55",
            "00:11:22:33:44:5g",
            "00:11-22:33:44:55",
            "001122334455",
            "00:11:22:33:44:55:",
        ] {
            assert!(s.parse::<MacAddress>().is_err(), "{s:?}");
        }
    }

    #[test]
    fn display() {
        let mac = MacAddress([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0xff]);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:ff");
    }

    #[test]
    fn broadcast_detection() {
        assert!(MacAddress([0xff; ETH_ALEN]).is_broadcast());
        assert!(!MacAddress([0xfe, 0xff, 0xff, 0xff, 0xff, 0xff]).is_broadcast());
    }

    proptest! {
        #[test]
        fn display_parse_roundtrip(bytes: [u8; ETH_ALEN]) {
            let mac = MacAddress(bytes);
            prop_assert_eq!(mac.to_string().parse(), Ok(mac));
        }
    }
}
