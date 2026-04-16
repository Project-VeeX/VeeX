# VeeX Repo Map

## Workspace Snapshot

- Root crates:
  - `crates/cli`
  - `crates/config`
  - `crates/core`
  - `crates/dns`
  - `crates/infra-linux`
  - `crates/observability`
  - `crates/portal-inbound`
  - `crates/portal-outbound`
  - `crates/protocol`
  - `crates/transport`

## Crate Ownership

- `crates/cli`
  - CLI contract
  - runtime / bootstrap / factory wiring
  - process startup, signal handling, and foreground lifecycle
- `crates/config`
  - config schema, semantic validation, and compatibility boundary
  - internal structure:
    - `preflight.rs`: controlled minimal JSON-subset preflight for duplicate-key detection and subset validation before deserialization
    - `input.rs`: serde input layer
    - `parse.rs`: preflight + serde loading
    - `schema.rs`: internal config model
    - `validate.rs`: semantic validation after deserialization
  - the `preflight` + serde split is intentional
- `crates/core`
  - core types such as `Destination`, `Host`, `SessionContext`, and metadata models
  - error model and `ErrorKind`
  - `Router`, `StreamDispatcher`, `PacketDispatcher`, `relay`, and shared portal primitives
  - platform-agnostic execution and component contracts
- `crates/dns`
  - DNS executor, DNS router, request lowering, wire parsing, and upstream runtime assembly
  - client-query execution and dial-side domain resolution
  - DNS upstream access through outbound execution capability
- `crates/infra-linux`
  - Linux transparent-socket capabilities
  - original-destination and transparent helper functions
  - shared system-facing functionality for transparent ingress
- `crates/observability`
  - session observation and logging support
- `crates/portal-inbound`
  - aggregated inbound component crate
  - `direct`: plain TCP ingress and minimal UDP packet ingress
  - `socks`: SOCKS5 CONNECT inbound, including a crate-local server-side protocol module
  - `transparent`: `redirect` and `tproxy` ingress plus destination-lowering helpers
- `crates/portal-outbound`
  - aggregated outbound component crate
  - `direct`: direct stream and packet outbound plus Linux `SO_MARK` support
  - `trojan`: outbound component runtime fields and connect-pipeline wiring
- `crates/protocol`
  - shared protocol adapter crate
  - generic adapter types plus Trojan stream adapter logic
  - architecture-layer `protocol` is broader than this crate; SOCKS inbound protocol currently remains inside `portal-inbound::socks`
- `crates/transport`
  - host resolution, TCP connect, sequential fallback, TLS, and verifier support
  - stream-carrier transport building blocks only

## Dependency Constraints

- `core` must stay platform-agnostic and must not absorb Linux transparent-socket details.
- `Router` stays pure computation: no I/O and no DNS resolution during construction.
- `routing_mark` belongs to direct outbound config and implementation; it should not become a `core` trait or routing abstraction.
- `protocol` remains independent from `portal-outbound`; Trojan protocol logic must not be folded back into component code.
- `portal-inbound` and `portal-outbound` are crate-organization boundaries, not architecture layers.
- runtime, factory, and bootstrap orchestration stay in `cli`; do not bloat `runtime.rs` or `core` again.
- The `preflight` / serde split in `crates/config` is intentional. Do not collapse it back into a single hand-written parser.

## Common Landing Zones

- New or changed config fields:
  - `crates/config`
  - `crates/cli` factory wiring
  - `examples/`
  - `references/config-contract.md`
  - `docs/architecture.md` when the public boundary changes
- Transparent proxy, original destination, or dual-stack issues:
  - `crates/infra-linux`
  - `crates/portal-inbound/src/transparent`
  - `references/internal-architecture.md`
  - `references/validation-contract.md`
- Direct no-loop and `routing_mark` behavior:
  - `crates/portal-outbound/src/direct`
  - `crates/config`
  - `references/config-contract.md`
  - `references/validation-contract.md`
- UDP packet execution / association behavior:
  - `crates/core`
  - `crates/dns`
  - `crates/portal-inbound/src/direct`
  - `crates/portal-outbound/src/direct`
  - `crates/cli`
  - `references/config-contract.md`
- Trojan outbound protocol or connect-pipeline questions:
  - `crates/portal-outbound/src/trojan`
  - `crates/protocol`
  - `crates/transport`
- SOCKS inbound protocol questions:
  - `crates/portal-inbound/src/socks`
  - `crates/core`
- Session failure semantics, summaries, or logging:
  - `crates/core`
  - `crates/observability`
  - CLI smoke or related tests

## Default Decision Rule

- Decide first whether the problem is a project-boundary issue or an implementation issue.
- If a proposal pushes Linux details back into `core`, drags non-goals into the main path, or confuses crate organization with architecture layers, step back to the boundary discussion first.
- If the problem is purely language-level Rust detail, switch to a narrower Rust skill.
