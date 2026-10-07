# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `mcumgrctl-eth -V` reports the versions of the binary, of
  `mcumgr-transport-ethernet`, and of the upstream `mcumgrctl` library,
  instead of only the `mcumgrctl` version.

## [0.2.0] - 2026-10-07

### Added

- `EthernetTransport::discover`: scans a network interface for SMP devices
  by broadcasting an `os echo` probe and collecting the answers for a given
  duration. Each responder is reported by a `DiscoveredDevice` with its MAC
  address and reply time.
- `MacAddress::is_broadcast`.
- `--discover` flag of the `cli` feature and `mcumgrctl-eth`: requires
  `--iface`, prints every device that answers within `--timeout`
  milliseconds, and exits without running a command.

### Fixed

- `--ethernet ff:ff:ff:ff:ff:ff` now fails with an explanation and a pointer
  to `--discover`, instead of opening a transport that could never receive
  a response.

## [0.1.0] - 2026-09-30

- Initial release: raw Ethernet (layer 2) transport for `mcumgr-toolkit`
  on Linux, the `mcumgrctl-eth` binary, and the `cli` feature for
  integrating the backend into custom `mcumgrctl` builds.
