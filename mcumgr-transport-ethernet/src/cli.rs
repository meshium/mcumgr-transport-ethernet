//! Integration into the `mcumgrctl` command line tool.
//!
//! [`init_backend`] can be passed to `mcumgrctl::cli_main` directly:
//!
//! ```no_run
//! fn main() -> miette::Result<()> {
//!     mcumgrctl::cli_main(mcumgr_transport_ethernet::cli::init_backend)
//! }
//! ```
//!
//! To combine it with other custom backends, flatten [`EthernetArgs`] into
//! your own arguments and call [`init_backend`] from your handler.
//!
//! `--discover` makes [`init_backend`] scan the interface for devices and
//! return [`BackendInitResult::Finished`] instead of a connected client.

use mcumgrctl::{BackendInitResult, CommonArgs};

use crate::MacAddress;

/// Command line arguments of the raw Ethernet backend.
#[derive(Debug, clap::Args)]
pub struct EthernetArgs {
    /// Use the device with the given MAC address via raw Ethernet as backend
    ///
    /// Linux only. Requires --iface and the CAP_NET_RAW capability.
    #[arg(
        long,
        verbatim_doc_comment,
        group = "transport",
        requires = "iface",
        value_name = "MAC"
    )]
    pub ethernet: Option<MacAddress>,

    /// Scan the interface for SMP devices, then exit
    ///
    /// Broadcasts an os echo probe and lists every device that answers,
    /// together with the time its answer took. Answers are collected for
    /// --timeout milliseconds; a command, if given, is not executed.
    ///
    /// Linux only. Requires --iface and the CAP_NET_RAW capability.
    #[arg(long, verbatim_doc_comment, group = "transport", requires = "iface")]
    pub discover: bool,

    /// Network interface to use with --ethernet or --discover (e.g. "eth0")
    #[arg(long, value_name = "IFACE")]
    pub iface: Option<String>,
}

/// Initializes the raw Ethernet backend, if `args` select it.
///
/// Returns `Ok(None)` if neither `--ethernet` nor `--discover` was given.
/// With `--discover`, the interface is scanned, the results printed, and
/// `Ok(Some(BackendInitResult::Finished))` returned.
pub fn init_backend(
    args: &EthernetArgs,
    common: &CommonArgs,
) -> miette::Result<Option<BackendInitResult>> {
    let Some(iface) = args.iface.as_deref() else {
        return Ok(None);
    };

    #[cfg(target_os = "linux")]
    {
        let timeout = std::time::Duration::from_millis(common.timeout);

        if args.discover {
            let devices = crate::EthernetTransport::discover(iface, timeout)?;
            print_discovered(iface, &devices);
            return Ok(Some(BackendInitResult::Finished));
        }

        let Some(mac) = args.ethernet else {
            return Err(miette::miette!(
                "--iface requires --ethernet or --discover"
            ));
        };

        if mac.is_broadcast() {
            return Err(miette::miette!(
                "the broadcast address is not a valid --ethernet device, \
                 use --discover to scan for devices"
            ));
        }

        let transport = crate::EthernetTransport::new(iface, mac, timeout)?;
        Ok(Some(BackendInitResult::Connected(
            mcumgr_toolkit::MCUmgrClient::new_from_transport(transport),
        )))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (iface, common);
        Err(miette::miette!(
            "The raw Ethernet transport is only supported on Linux"
        ))
    }
}

#[cfg(target_os = "linux")]
fn print_discovered(iface: &str, devices: &[crate::DiscoveredDevice]) {
    if devices.is_empty() {
        println!("No SMP devices found on '{iface}'.");
        println!("Try a longer --timeout if the device is slow to answer.");
    } else {
        println!("Available SMP devices on '{iface}':");
        for device in devices {
            println!(" - {} (replied after {:?})", device.mac, device.rtt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        ethernet: EthernetArgs,

        #[command(flatten)]
        common: CommonArgs,
    }

    #[test]
    fn check_cli() {
        TestCli::command().debug_assert();
    }

    #[test]
    fn parse_ethernet() {
        let cli =
            TestCli::try_parse_from(["test", "--ethernet", "02:00:00:00:00:01", "--iface", "eth0"])
                .unwrap();
        assert_eq!(
            cli.ethernet.ethernet,
            Some(MacAddress([0x02, 0, 0, 0, 0, 0x01]))
        );
        assert_eq!(cli.ethernet.iface.as_deref(), Some("eth0"));
    }

    #[test]
    fn ethernet_requires_iface() {
        assert!(TestCli::try_parse_from(["test", "--ethernet", "02:00:00:00:00:01"]).is_err());
    }

    #[test]
    fn parse_discover() {
        let cli = TestCli::try_parse_from(["test", "--discover", "--iface", "eth0"]).unwrap();
        assert!(cli.ethernet.discover);
        assert_eq!(cli.ethernet.ethernet, None);
        assert_eq!(cli.ethernet.iface.as_deref(), Some("eth0"));
    }

    #[test]
    fn discover_requires_iface() {
        assert!(TestCli::try_parse_from(["test", "--discover"]).is_err());
    }

    #[test]
    fn discover_conflicts_with_ethernet() {
        assert!(TestCli::try_parse_from([
            "test",
            "--discover",
            "--ethernet",
            "02:00:00:00:00:01",
            "--iface",
            "eth0"
        ])
        .is_err());
    }

    #[test]
    fn iface_requires_ethernet_or_discover() {
        let cli = TestCli::try_parse_from(["test", "--iface", "eth0"]).unwrap();
        assert!(init_backend(&cli.ethernet, &cli.common).is_err());
    }

    #[test]
    fn broadcast_ethernet_rejected() {
        let cli = TestCli::try_parse_from([
            "test",
            "--ethernet",
            "ff:ff:ff:ff:ff:ff",
            "--iface",
            "eth0"
        ])
        .unwrap();
        assert!(init_backend(&cli.ethernet, &cli.common).is_err());
    }

    #[test]
    fn discover_fails_on_unknown_interface() {
        let cli = TestCli::try_parse_from(["test", "--discover", "--iface", "missing0"]).unwrap();
        assert!(init_backend(&cli.ethernet, &cli.common).is_err());
    }

    #[test]
    fn rejects_invalid_mac() {
        assert!(
            TestCli::try_parse_from(["test", "--ethernet", "0:1:2:3:4:5", "--iface", "eth0"])
                .is_err()
        );
    }

    #[test]
    fn not_selected() {
        let cli = TestCli::try_parse_from(["test"]).unwrap();
        assert!(matches!(init_backend(&cli.ethernet, &cli.common), Ok(None)));
    }
}
