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

Field rendering rules in the current baseline:

- human-readable host, domain, and tag fields should stay in structured fields and use display-style rendering
- structured values and error kinds should use debug-style rendering
- user-controlled string fields should not be emitted via hand-built `key=value` strings
- line breaks in string-like log fields should be sanitized so text output does not break event structure

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
- `tcp_connect_attempt`
- `tcp_connect_success`
- `tcp_connect_failed`
- `tls_handshake_start`
- `tls_handshake_success`
- `tls_handshake_failed`
- `sniff_start`
- `sniff_success`
- `sniff_timeout`
- `sniff_no_match`
- `sniff_error`
- `transparent_socket_config`
- `original_dst_retry`
- `listener_fallback`

Important field alignment in this round:

- `session_start`: `session_id`, `inbound`, `peer`, `destination`, `network`
- `route_select`: `session_id`, `inbound`, `peer`, `destination`, `outbound`, `route_reason`, `default_final`
- `session_finish`: `session_id`, `inbound`, `peer`, `destination`, `outbound`, `route_reason`, `success`, `duration_ms`, `bytes_up`, `bytes_down`
- `session_finish.bytes_up` and `session_finish.bytes_down` are observed relay bytes; relay failures may report partial non-zero stats and must not be normalized back to `0/0`
- failure events carry `error_kind` and `error` where the boundary already has a `ProxyError`
- `tcp_connect_attempt` includes `network`, `host`, `port`, `resolved_addr`, `attempt_index`, and `timeout_ms` when a connect timeout is configured
- `tcp_connect_failed` includes `network`, `host`, `port`, `resolved_addr`, `attempt_index`, `failure_reason`, `error_kind`, and `timeout_ms` when configured
- direct outbound reuses the shared TCP connect events and adds `routing_mark` when present
- TLS handshake failures include `host`, `server_name`, `insecure`, `disable_sni`
- `tls_handshake_start` includes `host`, `port`, `resolved_addr`, `server_name`, and `handshake_timeout_ms`
- `tls_handshake_failed` includes `failure_reason`, `error_kind`, and `handshake_timeout_ms`
- `sniff_start` includes `session_id`, `inbound_tag`, and `sniff_timeout_ms`
- `sniff_success` includes `session_id`, `inbound_tag`, `sniff_timeout_ms`, `protocol`, `domain`, and `result=matched`
- `sniff_timeout` includes `session_id`, `inbound_tag`, `sniff_timeout_ms`, and `result=timeout`
- `sniff_no_match` includes `session_id`, `inbound_tag`, `sniff_timeout_ms`, and `result=not_matched|unsupported`
- `sniff_error` includes `session_id`, `inbound_tag`, `sniff_timeout_ms`, `result=error`, and `error`
- sniff timeout and no-match are routing diagnostics, not session failures
- `transparent_socket_config` includes `socket_family`, `local_addr`, `peer_addr`, `ipv4_transparent_ok`, `ipv4_transparent_errno`, `ipv6_transparent_ok`, `ipv6_transparent_errno`
- `listener_fallback` includes `from`, `to`, `reason`, `errno`

Relay termination rules in the current baseline:

- EOF in one direction is a normal completion path, not a relay error
- EOF still attempts `shutdown()` on the opposite writer before that direction returns success
- true relay errors fail fast and may return the latest observed progress snapshot instead of waiting indefinitely for the peer direction to finish

## What This Round Did Not Do

Explicitly out of scope for this round:

- no inbound common harness abstraction
- no kernel-level bypass action semantics
- no DNS, UDP, TUN, fake-ip, or sniff destination override work
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
