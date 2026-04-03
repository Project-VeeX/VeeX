# Observability And Errors

## Why `thiserror`

This round introduces `thiserror` to make crate-local and boundary error types explicit without replacing the existing VeeX error model.

Goals:

- remove `Result<_, String>` as the main boundary shape in runtime/bootstrap paths
- make config, SOCKS, TLS, verifier, and runtime/bootstrap failures easier to classify
- keep error messages stable while reducing ad-hoc `format!` drift

## Why `ErrorKind` Stays

`ErrorKind` remains the stable cross-cutting classification used by session summaries, runtime assertions, and operational diagnostics.

`thiserror` is used to improve type-local error modeling. It does not replace `ErrorKind`, and it does not remove `ProxyError`.

Current rule:

- local crates can use typed errors internally
- cross-crate runtime flow still converges on `ProxyError`
- `ProxyError::kind()` remains the canonical `ErrorKind` mapping

## Why `tracing`

This round introduces `tracing` as the structured observability backbone for the main TCP execution path.

Goals:

- replace hand-built `key=value` log strings on the hot path
- keep field names stable for operator inspection
- make handshake, dispatch, runtime, and transparent-socket failures easier to diagnose

The current output stays simple text via `tracing-subscriber`. This round does not add JSON logging, file appenders, metrics, or OpenTelemetry.

## Structured Events Added

Main-path events now emitted as structured tracing events include:

- `runtime_start`
- `service_start`
- `inbound_service_failed`
- `shutdown_begin`
- `shutdown_complete`
- `task_join_failed`
- `session_start`
- `route_select`
- `session_finish`
- `session_failed`
- `handshake_failed`
- `destination_resolve_failed`
- `tls_handshake_failed`
- `transparent_socket_config`
- `original_dst_retry`
- `listener_fallback`

Important field alignment in this round:

- `session_start`: `session_id`, `inbound`, `peer`, `destination`, `network`
- `route_select`: `session_id`, `inbound`, `peer`, `destination`, `outbound`, `route_reason`
- `session_finish`: `session_id`, `inbound`, `peer`, `destination`, `outbound`, `route_reason`, `success`, `duration_ms`, `bytes_up`, `bytes_down`
- failure events carry `error_kind` and `error` where the boundary already has a `ProxyError`
- TLS handshake failures include `host`, `server_name`, `insecure`, `disable_sni`

## What This Round Did Not Do

Explicitly out of scope for this round:

- no inbound common harness abstraction
- no route rule or bypass semantic expansion
- no DNS, UDP, TUN, sniff, or fake-ip work
- no Happy Eyeballs or parallel dialing
- no TLS config cache or reuse layer
- no OpenTelemetry or metrics pipeline
- no deep span tree redesign

## Next Safe Follow-Ups

Reasonable follow-up work after this round:

- add more targeted tracing assertions for redirect/tproxy/TLS failure paths
- propagate finer-grained spans across inbound -> dispatcher -> outbound if needed
- keep shrinking legacy string-only error construction where it improves stability
- add Linux/OpenWrt device validation for `tproxy`, `routing_mark`, and transparent socket events
