# mcumgr-transport-ethernet

Raw Ethernet (layer 2) transport for [`mcumgr-toolkit`](https://github.com/Finomnis/mcumgr-toolkit),
built on its external transport support introduced in
[0.18.0](https://github.com/Finomnis/mcumgr-toolkit/releases/tag/0.18.0).

Each SMP frame is carried in the payload of a single Ethernet frame with
EtherType `0x88B5` (IEEE 802 Local Experimental 1), so devices can be
managed on the local link without an IP stack. The device replies from the
MAC address the request was sent to.

Linux only (`AF_PACKET` sockets). Requires the `CAP_NET_RAW` capability.

## Library

```rust no_run
use std::time::Duration;

use mcumgr_toolkit::MCUmgrClient;
use mcumgr_transport_ethernet::EthernetTransport;

fn main() -> miette::Result<()> {
    let mac = "02:00:00:00:00:01".parse()?;
    let transport = EthernetTransport::new("eth0", mac, Duration::from_millis(1000))?;
    let client = MCUmgrClient::new_from_transport(transport);
    println!("{:?}", client.os_echo("Hello world!")?);
    Ok(())
}
```

## Command line

The `mcumgrctl-eth` binary is `mcumgrctl` with this transport added:

```none
$ cargo build --release --bin mcumgrctl-eth
$ sudo setcap cap_net_raw+ep target/release/mcumgrctl-eth
$ target/release/mcumgrctl-eth --ethernet 02:00:00:00:00:01 --iface eth0
Device alive and responsive.
```

BLE is disabled by default, so no D-Bus library is needed. Enable it with
`--features ble`.

To combine this transport with other custom backends in your own CLI,
enable the `cli` feature and flatten `cli::EthernetArgs` into your
arguments.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
