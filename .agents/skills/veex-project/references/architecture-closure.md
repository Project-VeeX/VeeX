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

## Lifecycle Direction

Do not push control-plane concepts back into data-plane traits just for convenience.

In particular:

- `Inbound`, `Outbound`, and `Dispatcher` should not be expanded into generic lifecycle containers
- runtime-owned handles are the right place for shutdown, health, and reload style behavior

## Relay Direction

Keep the default relay path simple.

If relay behavior grows, prefer extending around policy or hooks rather than turning the hot path into a generic callback bus.

## TLS And Config Direction

Do not generalize configuration surfaces earlier than needed.

Keep config abstractions aligned with actual consumers, and do not widen them only because a future shape is imaginable.

## JSON Parser Direction

The custom parser is intentionally a controlled parser for the current config subset.

Do not treat it as a general-purpose JSON implementation, and do not broaden its compatibility contract casually.
