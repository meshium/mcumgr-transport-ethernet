#![forbid(unsafe_code)]

fn main() -> miette::Result<()> {
    mcumgrctl::cli_main(mcumgr_transport_ethernet::cli::init_backend)
}
