# VeeX Observability And Error Contract

Use this reference when a task depends on the current error-model closure, tracing event shape, or what this round intentionally did not expand.

The canonical repository document is `docs/observability-and-errors.md`. This reference keeps only the stable project-level takeaways that should guide future work.

## Current Direction

- `thiserror` is now the preferred crate-local error-definition tool.
- `ProxyError` remains the cross-crate runtime error boundary.
- `ErrorKind` remains the stable classification contract used by runtime diagnostics and session summaries.
- `tracing` is now the structured observability backbone for the main TCP execution path.

## Error Model Rules

- Do not remove `ProxyError`.
- Do not remove or weaken `ErrorKind`.
- Do not replace `ErrorKind` with `thiserror`; they solve different problems.
- Prefer local typed errors inside crates, but converge back to `ProxyError` at runtime boundaries.
- Keep `ProxyError::kind()` stable. Changes that break current `ErrorKind` mapping are contract changes.

## Tracing Rules

- Prefer structured tracing fields over hand-built `key=value` strings on the hot path.
- Keep event names and core field names stable unless there is a strong reason to change them.
- Text output via `tracing-subscriber` is the current baseline. Do not assume JSON logging, file appenders, metrics, or OpenTelemetry exist.

## Structured Events Present In Current Baseline

- runtime lifecycle:
  - `runtime_start`
  - `service_start`
  - `inbound_service_failed`
  - `shutdown_begin`
  - `shutdown_complete`
  - `task_join_failed`
- session path:
  - `session_start`
  - `route_select`
  - `session_finish`
  - `session_failed`
  - `handshake_failed`
  - `destination_resolve_failed`
- transport / transparent diagnostics:
  - `tls_handshake_failed`
  - `transparent_socket_config`
  - `original_dst_retry`
  - `listener_fallback`

## Field Alignment That Should Stay Stable

- `session_start`:
  - `session_id`
  - `inbound`
  - `peer`
  - `destination`
  - `network`
- `route_select`:
  - `session_id`
  - `inbound`
  - `peer`
  - `destination`
  - `outbound`
  - `route_reason`
- `session_finish`:
  - `session_id`
  - `inbound`
  - `peer`
  - `destination`
  - `outbound`
  - `route_reason`
  - `success`
  - `duration_ms`
  - `bytes_up`
  - `bytes_down`
- failure-side events should carry `error_kind` and `error` when the boundary already has a `ProxyError`.
- TLS handshake failures should carry:
  - `host`
  - `server_name`
  - `insecure`
  - `disable_sni`

## Non-Goals Carried Forward

- no inbound common harness abstraction in this round
- no `route.bypass` semantic expansion
- no DNS / UDP / TUN / sniff / fake-ip work
- no Happy Eyeballs or parallel dialing
- no TLS config cache or reuse layer
- no OpenTelemetry or metrics pipeline
- no deep span-tree redesign

## Validation Reminder

- `tproxy`, `routing_mark`, transparent socket behavior, and dual-stack fallback still require Linux/OpenWrt device validation beyond unit and integration tests.
