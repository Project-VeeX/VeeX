# VeeX Architecture Closure

This reference records internal boundary decisions that remain closed and should continue guiding implementation work.

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
- keep recursion-prevention direct-routing rules explicit and conservative
- when host classification matters, do not blur domains and IPs into one vague conceptual bucket

Current router decision pipeline: ordered `route.rules` actions → default final action.

`action="sniff"` is part of this runtime path, but only as bounded context enrichment. Do not turn it into destination override, DNS control, or transport policy.

## Transport Direction

Outbound dialing keeps the default connect path simple:

- host resolution may yield multiple candidate addresses
- address attempts are sequential, not parallel
- stop on first successful connect
- do not retry a different IP after TLS or relay has already started

## Lifecycle Direction

Keep top-level service traits thin, but let component objects remain the stable runtime owners of their own minimal lifecycle.

In particular:

- `Inbound` and `Outbound` may own only `meta` / `logger` / `start` / `close` style lifecycle surface
- protocol execution behavior should stay in execution-model-specific traits such as `StreamInbound`, `TransparentInbound`, `StreamOutbound`, and `ProxyOutbound`, rather than a single mega trait
- runtime should keep registry and start/close orchestration, but should not pull long-lived component state back out of component objects
- listener handlers should bind during component construction rather than via start-time callback injection
- route and dispatcher views must reference the same outbound objects that runtime starts and closes
- inbound components should hand sessions to `StreamDispatch` or `PacketDispatch` rather than reaching into dispatcher internals
- dispatcher should execute selected outbounds through `ExecutionOutbound`, not through protocol-family matching or ad hoc runtime enums
- `OutboundRegistry` is the sole outbound holder; do not recreate separate runtime, routing, or dispatcher copies
- transparent destination recovery should stay in component-specific destination providers rather than `Listener`
- normalized trojan runtime state should prefer upstream address + key + TLS capability over raw config bags
- shared `veex-protocol` currently means generic adapter types plus Trojan adapter logic; do not assume that every architectural protocol step must live in that crate
- do not introduce public `struct Inbound` / `struct Outbound` base carriers just to centralize fields
- do not add health, reload, or control-plane callback buses to the protocol traits just for convenience

## Shared Capability Direction

`Listener` and `Dialer` remain shared infrastructure objects rather than protocol containers.

Keep these rules:

- `Listener` owns bind / accept / spawn / close and does not own protocol parsing, routing, or protocol-specific state machines
- `Dialer` owns generic connect semantics such as timeout and routing mark, and does not own handshake or protocol framing
- component objects should keep only the normalized runtime fields they still actively use

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

Lower parse-time config aggregates before component construction. Runtime component objects should keep normalized runtime fields, not raw `*Options` bags.

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

`tracing` is the structured observability backbone for the execution model across stream and packet paths. This is a closed decision.

- Text output via `tracing-subscriber` is the current baseline; do not assume JSON logging, file appenders, metrics, or OpenTelemetry exist
- Structured tracing fields are preferred over hand-built `key=value` strings on the hot path
- Event names and core field names are stable; changes require a coordination decision

## Non-Goals

These are explicitly out of scope and should not be quietly introduced:

- no protocol-agnostic mega harness that hides the real inbound execution model
- no kernel-level bypass action semantics
- no DNS / UDP / TUN / fake-ip work
- no sniff destination override or generalized protocol-routing platform
- no Happy Eyeballs or parallel dialing
- no TLS config cache or reuse layer
- no OpenTelemetry or metrics pipeline
- no deep span-tree redesign
