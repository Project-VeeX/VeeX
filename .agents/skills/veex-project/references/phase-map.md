# VeeX Phase Map

Use this file when the task depends on what each major phase delivered, what changed between phases, or which conclusions are phase-specific versus still active.

## Phase 1

Phase 1 established the minimum executable path:

- `socks` inbound
- `trojan` outbound
- `direct` outbound
- relay
- CLI startup
- config loading and checking

The main result of this phase was proving that the core execution path and crate split were viable.

## Phase 2

Phase 2 moved the project from a local demo path toward router usability.

Key additions:

- `redirect` inbound
- Linux original-destination recovery
- stronger bypass behavior
- better runtime behavior and shutdown handling

The important phase conclusion was that system-integration knowledge had to become a first-class deliverable, not just an implementation detail.

## Phase 3

Phase 3 focused on replacing the transparent-proxy TCP execution surface in real router topologies.

Key additions:

- `tproxy` inbound
- `direct.routing_mark`
- narrower but more explicit config compatibility
- transparent-proxy engineering for dual-stack and IPv4-mapped-IPv6 realities

The important phase conclusion was that this was no longer just "add one inbound"; it required a robust Linux transparent-socket subsystem and clear validation discipline.

## Phase 4

Phase 4 was an **engineering hardening** phase focused on observability, error modeling, and config infrastructure. No new inbounds, outbounds, or protocol features were added. All changes were cross-cutting improvements to existing paths.

### v0.4.0 — Structured Observability Foundation

Key additions:

- `thiserror` unified error modeling across all crates
- `tracing` as the structured observability backbone across runtime, session, TLS, and transparent-socket paths
- stable field contracts for key events (`session_start`, `route_select`, `session_finish`, etc.)
- relay failure accounting: `session_finish` now preserves partial `bytes_up`/`bytes_down` instead of collapsing to `0/0`
- `route.bypass` semantics tightened to exact domain and exact IP matches; wildcard/suffix patterns rejected explicitly
- Trojan SHA-224: replaced hand-rolled implementation with `sha2::Sha224`

### v0.4.1 — Session-Aware Tracing and Relay Events

Key additions:

- session-aware tracing through Trojan transport connect and TLS handshake paths
- structured `direct` outbound connect events with `routing_mark` fields
- `relay_start`, `relay_failed`, `relay_half_close` coverage
- raised critical session-path events to `info`/`warn` levels
- normalized transport failure fields for real-device troubleshooting

### v0.4.2 — Event Schema Tightening

Key additions:

- tighter tracing and event-schema boundaries across transport, outbound, relay, and dispatcher layers
- stable `tls_handshake_*` coverage with `host`/`port`/`resolved_addr`
- clarified config responsibilities: raw parse separated from semantic validation
- reorganized router into clearer decision pipeline (built-in bypass → configured bypass → final fallback) ahead of future `route.rules` work
- UTF-8 string preservation fix in config parser

### v0.4.3 — Serde-Based Config Parsing

Key additions:

- full migration from hand-written JSON preflight parser to **serde-based** deserialization for the config model
- `crates/config/src/preflight.rs` retains the controlled minimal JSON-subset preflight (duplicate-key detection, JSON subset validation only)
- `crates/config/src/input.rs` introduced as the serde deserialization layer (`InputConfig` structs with `#[serde]`)
- `crates/config/src/parse.rs` rewritten to combine preflight validation with serde loading
- `log.timestamp` config field implemented (controls RFC3339 timestamps in tracing output)

The Phase 4 conclusion was that the project had reached **observability maturity**: the core execution path was now fully instrumented, the error model was clean and stable, and the config subsystem was maintainable and extensible.

### v0.5.0 — Minimal Route Rules And Sequential Connect Fallback

Key additions:

- minimal `route.rules` subset implemented: `domain`, `domain_suffix`, `ip_cidr`, `port`, `inbound`
- router closure around explicit `RouteInput` and stable decision order: built-in bypass → configured bypass → `route.rules` → final
- sequential multi-address connect fallback made explicit across transport, `trojan`, and `direct`
- connect-path tests now cover multi-address partial failure before later-address success and all-address failure cases

The v0.5.0 carry-forward conclusion is that the TCP execution path now assumes sequential multi-address dialing as a normal connect behavior, while still explicitly excluding Happy Eyeballs, parallel dialing, and post-connect retry semantics.

## Current Carry-Forward Conclusions

The following conclusions still matter across phases:

- VeeX remains a TCP execution plane, not a full proxy platform
- platform-specific transparent-proxy details must stay out of `core`
- config compatibility must stay narrow and explicit
- validation maturity must not be overstated beyond recorded evidence
- downstream OpenWrt packaging and LuCI work stay outside this repository

## Usage Rule

- Use this file for phase-aware context, not as a roadmap wishlist.
- If a phase detail matters only as historical background and not as an active constraint, prefer the current project guide and active references instead.
