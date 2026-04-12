# VeeX Repo Map

## Workspace Snapshot

- Root crates:
  - `crates/cli`
  - `crates/config`
  - `crates/core`
  - `crates/dns`
  - `crates/infra-linux`
  - `crates/inbound-direct`
  - `crates/inbound-transparent`
  - `crates/inbound-socks`
  - `crates/observability`
  - `crates/outbound-direct`
  - `crates/outbound-trojan`
  - `crates/transport`

## Crate Ownership

- `crates/cli`
  - CLI contract
  - runtime / bootstrap / factory wiring
  - process startup, signal handling, foreground lifecycle
- `crates/config`
  - config schema, semantic validation, and compatibility boundary
  - internal structure:
    - `preflight.rs`: controlled minimal JSON-subset preflight for duplicate-key detection and JSON subset validation before deserialization
    - `input.rs`: serde deserialization layer (`InputConfig` structs with `#[serde]`)
    - `parse.rs`: combines preflight validation with serde loading
    - `schema.rs`: internal config model (`ProxyConfig`, `InboundConfig`, etc.)
    - `validate.rs`: semantic validation after deserialization
  - This two-layer design (preflight + serde) enables future config surface extension (e.g. `route.rules`, sniff) without growing the JSON preflight
- `crates/core`
  - core types such as `Destination`, `Host`, and `SessionContext`
  - error model and `ErrorKind`
  - `Router`, `Dispatcher`, `PacketDispatcher`, and `relay`
  - platform-agnostic core contracts
- `crates/dns`
  - DNS executor, DNS router, and DNS wire parsing
  - short-lived UDP upstream query execution via outbound packet capability
- `crates/infra-linux`
  - Linux transparent-socket capabilities
  - original-destination and transparent helper functions
  - shared system-facing functionality for transparent inbounds
- `crates/inbound-transparent`
  - Linux transparent inbound lifecycle
  - `redirect` original-destination recovery via shared Linux infrastructure
  - TCP-only `tproxy` inbound plus protocol-specific transparent destination recovery
- `crates/inbound-direct`
  - plain direct ingress for TCP stream and minimal UDP packet modes
  - listener-local destination forwarding plus optional override-address / override-port rewriting
- `crates/inbound-socks`
  - SOCKS5 CONNECT inbound
- `crates/outbound-direct`
  - direct outbound for TCP stream and UDP packet session
  - Linux `SO_MARK` path and no-loop egress behavior
- `crates/outbound-trojan`
  - Trojan outbound
  - runtime wiring for upstream address, key material, and TLS
- `crates/transport`
  - TCP / TLS abstractions
  - transport layer used by Trojan TLS
- `crates/observability`
  - session observation and logging support

## Dependency Constraints

- `core` must stay platform-agnostic and must not absorb Linux transparent-socket details.
- `Router` stays pure computation: no I/O and no DNS resolution during construction.
- `routing_mark` belongs to direct outbound config and implementation; it should not become a `core` trait or routing abstraction.
- runtime, factory, and bootstrap orchestration stay in `cli`; do not bloat `runtime.rs` or `core` again.
- The `preflight` / `serde` split in `crates/config` is intentional. Do not collapse them back into a single hand-written parser; the serde layer is what enables future config surface extension.

## Common Landing Zones

- New or changed config fields:
  - `crates/config`
  - `crates/cli` factory wiring
  - `examples/`
  - `references/config-contract.md`
  - `docs/architecture.md` when the public boundary changes
- Transparent proxy, original destination, or dual-stack issues:
  - `crates/infra-linux`
  - `crates/inbound-transparent`
  - `references/internal-architecture.md`
  - `references/validation-contract.md`
- Direct no-loop and `routing_mark` behavior:
  - `crates/outbound-direct`
  - `crates/config`
  - `references/config-contract.md`
  - `references/validation-contract.md`
- UDP packet execution / association behavior:
  - `crates/core`
  - `crates/dns`
  - `crates/inbound-direct`
  - `crates/outbound-direct`
  - `crates/cli`
  - `references/config-contract.md`
- Session failure semantics, summaries, or logging:
  - `crates/core`
  - `crates/observability`
  - CLI smoke or related tests

## Default Decision Rule

- Decide first whether the problem is a project-boundary issue or an implementation issue.
- If a proposal pushes Linux details back into `core` or drags non-goals into the main path, step back to the boundary discussion first.
- If the problem is purely language-level Rust detail, switch to a narrower Rust skill.
