#![forbid(unsafe_code)]

fn main() -> miette::Result<()> {
    // clap builds the -V output inside mcumgrctl, which reports the upstream
    // library's version; intercept the flag to report the actual stack.
    if std::env::args_os()
        .any(|arg| arg == "-V" || arg == "--version")
    {
        println!("mcumgrctl-eth {}", env!("CARGO_PKG_VERSION"));
        println!(
            "mcumgr-transport-ethernet {}",
            mcumgr_transport_ethernet::VERSION
        );
        println!("mcumgrctl {}", env!("MCUMGRCTL_VERSION"));
        return Ok(());
    }

    mcumgrctl::cli_main(mcumgr_transport_ethernet::cli::init_backend)
}
