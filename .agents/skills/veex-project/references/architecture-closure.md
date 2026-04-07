# VeeX Architecture Closure

Use this file when a task depends on internal boundary decisions rather than only public project description.

## Session Direction

The internal direction is to keep immutable session identity, route selection, and mutable session state conceptually separate.

Treat these as distinct concerns:

- immutable identity and destination metadata
- route result and selected outbound
- buffered or prefetched payload and other mutable session state

Do not expand a single session structure without checking whether it is mixing these concerns again.

## Router Direction

`Router` is intended to stay a static decision component.

Keep these rules:

- no I/O in the router
- no DNS resolution during router construction
- keep bypass semantics explicit and conservative
- when host classification matters, do not blur domains and IPs into one vague conceptual bucket

Current router decision pipeline: built-in bypass → configured bypass → final fallback. This order is stable.

## Lifecycle Direction

Do not push control-plane concepts back into data-plane traits just for convenience.

In particular:

- `Inbound`, `Outbound`, and `Dispatcher` should not be expanded into generic lifecycle containers
- runtime-owned handles are the right place for shutdown, health, and reload style behavior

## Relay Direction

Keep the default relay path simple.

If relay behavior grows, prefer extending around policy or hooks rather than turning the hot path into a generic callback bus.

Relay termination rules (current):
- EOF in one direction is a normal completion path, not a relay error
- EOF still attempts `shutdown()` on the opposite writer before that direction returns success
- True relay errors fail fast and return the latest observed progress snapshot (partial bytes) rather than waiting indefinitely

## TLS And Config Direction

Do not generalize configuration surfaces earlier than needed.

Keep config abstractions aligned with actual consumers, and do not widen them only because a future shape is imaginable.

## Config Parse Direction

The config crate has a two-layer design:

1. **`preflight.rs`** — Controlled minimal JSON-subset preflight. Handles duplicate-key detection and JSON subset validation before serde. Does not grow into a general-purpose JSON engine.
2. **`input.rs` + `parse.rs`** — Serde-based deserialization layer. The serde layer is what enables future config surface extension (e.g. `route.rules`, sniff) without touching the preflight.

This separation is intentional. Do not collapse `preflight` and `serde` back into a single hand-written parser.

## Error Model Direction

`ProxyError` remains the cross-crate runtime error boundary and must not be removed.

`ErrorKind` remains the stable classification contract for session summaries and tracing diagnostics.

`thiserror` is for crate-local typed errors; it does not replace `ProxyError` or `ErrorKind`.

`ProxyError::kind()` is stable; changes that break the current `ErrorKind` mapping are contract changes.

## Observability Direction

`tracing` is the structured observability backbone for the main TCP execution path. This is a closed decision.

- Text output via `tracing-subscriber` is the current baseline; do not assume JSON logging, file appenders, metrics, or OpenTelemetry exist
- Structured tracing fields are preferred over hand-built `key=value` strings on the hot path
- Event names and core field names are stable; changes require a coordination decision

## Non-Goals

These are explicitly out of scope and should not be quietly introduced:

- no inbound common harness abstraction
- no `route.bypass` semantic expansion (CIDR, suffix, wildcard)
- no DNS / UDP / TUN / sniff / fake-ip work
- no Happy Eyeballs or parallel dialing
- no TLS config cache or reuse layer
- no OpenTelemetry or metrics pipeline
- no deep span-tree redesign
