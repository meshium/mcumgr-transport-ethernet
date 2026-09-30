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

    /// Network interface to use with --ethernet (e.g. "eth0")
    #[arg(long, requires = "ethernet", value_name = "IFACE")]
    pub iface: Option<String>,
}

/// Initializes the raw Ethernet backend, if `args` select it.
///
/// Returns `Ok(None)` if `--ethernet` was not given.
pub fn init_backend(
    args: &EthernetArgs,
    common: &CommonArgs,
) -> miette::Result<Option<BackendInitResult>> {
    let (Some(mac), Some(iface)) = (args.ethernet, args.iface.as_deref()) else {
        return Ok(None);
    };

    #[cfg(target_os = "linux")]
    {
        let timeout = std::time::Duration::from_millis(common.timeout);
        let transport = crate::EthernetTransport::new(iface, mac, timeout)?;
        Ok(Some(BackendInitResult::Connected(
            mcumgr_toolkit::MCUmgrClient::new_from_transport(transport),
        )))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (mac, iface, common);
        Err(miette::miette!(
            "The raw Ethernet transport is only supported on Linux"
        ))
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
    fn requires_both_arguments() {
        assert!(TestCli::try_parse_from(["test", "--ethernet", "02:00:00:00:00:01"]).is_err());
        assert!(TestCli::try_parse_from(["test", "--iface", "eth0"]).is_err());
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
