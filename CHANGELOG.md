# Changelog

## 0.2.0

- Linux redirect inbound support for transparent proxy validation.
- Transparent proxy validation guides for OpenWrt-class systems.
- Added a dedicated `release-test` Cargo profile for validation and distribution builds.
- Improved redirect and original destination test stability across different Linux environments.

## 0.1.0

- Initial VeeX CLI release.
- SOCKS5 inbound support for TCP `CONNECT`.
- Trojan outbound support over TLS.
- direct outbound support for bypass and local destinations.
- Config validation through `veex check`.
- Foreground runtime with graceful shutdown on `SIGINT` and `SIGTERM`.
