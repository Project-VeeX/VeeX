# Changelog

## 0.6.0

- Implemented a minimal formal closed loop for the DNS (include hijack-dns router action, dns-executor, dns-router, dns-server, etc.).
- Added DOT and DOH upstream support for secure DNS resolution.    
- Implemented the domain resolver to use for resolving outbound domain names it own.
- Implemented and decoupled the TCP path.
- Added minimal UDP packet execution path.
- Added direct  inbound support for direct traffic handling. 

## 0.5.3

- Refactored the runtime skeleton around protocol-owned subjects: inbound and outbound implementations now own their long-lived state directly, without shadow runtime wrappers or split execution copies.
- Collapsed outbound execution wiring into a single registry plus a thin dispatcher path, removed the transitional outbound execution enum, and narrowed inbound submission to a small request-sink interface instead of dispatcher internals.
- Simplified transparent inbound internals by merging the transparent crates, sharing listen/session bootstrap helpers, and keeping protocol-specific original-destination recovery split by `redirect` and `tproxy` behavior.
- Normalized module layout and runtime field boundaries without changing config semantics, including a shared `listen` value object and a narrower Trojan runtime shape around upstream address, key material, and TLS.

## 0.5.2

- Closed remaining route execution gaps around sniff upgrades and default-final selection, and expanded route explainability tracing/docs for rule-miss, upgrade, and final-selection paths.
- Clarified config compatibility diagnostics so compatibility-accepted ignored fields are reported more precisely, with stable per-path messages instead of being mixed with unrelated unknown fields.
- Reorganized runtime assembly and session ownership boundaries without changing the validated session-path behavior: transport resolution/connect seams are explicit, CLI config lowering is centralized, and `session_finish` emission now has a single observability owner.
- Aligned inbound session bootstrap flow across `socks`, `redirect`, and `tproxy`, and shared tracing test support across workspace crates to reduce maintenance drift while keeping behavior unchanged.

## 0.5.1

- Split sniff timeout semantics out from connect and TLS handshake timeouts. `route.rules[].timeout` now applies only to bounded sniff reads and remains best effort.
- Added route sniff as an ordered upgrade action for TLS SNI and HTTP `Host`, with stronger parser and replay handling for partial and non-matching inputs.
- Unified router execution into a single ordered rule/action pipeline: upgrade actions enrich routing context and continue, final actions terminate routing, and `route.final` is lowered into the default final action.
- Modeled private, loopback, and link-local direct routing as ordinary `route.rules` decisions inside the same pipeline.

## 0.5.0

- Added minimal `route.rules` support for `domain`, `domain_suffix`, `ip_cidr`, `port`, and `inbound`, with `outbound` as the only action.
- Refined the router decision flow to keep built-in/configured bypass and `route.final` semantics while adding first-match `route.rules`.
- Added sequential multi-address connect fallback for transport, `trojan`, and `direct`; resolved addresses are tried in order until one succeeds or all fail.
- Updated connect-path tracing, tests, and project docs to match the current routing and dialing behavior.

## 0.4.3

- Config parsing is now serde-based and easier to extend for future config fields.
- Added `log.timestamp` config option to enable RFC3339 timestamps in tracing output.
- Refresh veex-project skill to match phase4 state, and cleaned up the `.agents/skills/` directory.
- 

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
