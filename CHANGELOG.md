# Changelog

## 0.4.2

- Tightened tracing and event-schema boundaries across transport, outbound, relay, and dispatcher layers without changing the validated session-path semantics.
- Added stable `tls_handshake_*` `host` / `port` / `resolved_addr` coverage and aligned connect-failure diagnostics around consistent `error_kind` ownership.
- Clarified config responsibilities by separating raw parse entry points from semantic validation and keeping bootstrap focused on runtime object completeness.
- Reorganized the router into a clearer minimal decision pipeline for built-in bypass, configured bypass, and final fallback ahead of future `route.rules` work.
- Reduced repeated tracing test scaffolding inside `veex-core` and `veex-transport` with small crate-local test helpers.

## 0.4.1

- Added session-aware tracing for Trojan transport connect and TLS handshake paths so a session can be followed from route selection into transport setup.
- Added structured direct outbound connect events, including stable `routing_mark` fields suitable for non-debug log collection and grep-based diagnostics.
- Added `relay_start`, `relay_failed`, and `relay_half_close` coverage while preserving existing relay partial-byte accounting and abort semantics.
- Raised critical session-path tracing to `info` or `warn` where appropriate, and normalized transport failure fields for real-device troubleshooting.

## 0.4.0

- Added structured tracing coverage across runtime, session, TLS, and transparent-socket paths with stable field contracts.
- Hardened relay accounting so `session_finish` preserves partial `bytes_up` and `bytes_down` on relay failure instead of collapsing to `0/0`.
- Tightened `route.bypass` semantics to exact domain and exact IP matches, with wildcard and suffix-style patterns rejected explicitly.
- Replaced the hand-rolled Trojan password SHA-224 implementation with `sha2::Sha224` and added standard-vector coverage.
- Improved transparent listener diagnostics with explicit socket-option status fields and clearer fallback events.

## 0.3.1

- Hardened dual-stack transparent proxy handling for `redirect` and `tproxy` validation paths.
- Fixed `listen="::"` and bracketed IPv6 listen parsing for transparent-proxy inbounds.
- Improved original-destination recovery for IPv4-mapped IPv6 sockets and aligned transparent-proxy docs with the Phase3.1 behavior.

## 0.3.0

- Added TCP-only `tproxy` inbound support for the Phase3 transparent proxy path.
- Added Linux `direct.routing_mark` support through `SO_MARK` for no-loop direct egress.
- Extended route config with explicit `bypass` entries and a repository compatibility fixture.
- Added TPROXY, routing-mark, OpenWrt SOP, and Phase3 regression documentation.

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
