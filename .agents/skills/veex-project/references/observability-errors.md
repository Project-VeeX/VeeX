# VeeX Observability And Error Contract

This reference records the internal observability rules, event-shape expectations, and error-model boundaries that continue guiding implementation work.

The canonical public document is `docs/observability.md`. This file keeps only the internal rules and stable engineering takeaways.

## Core Contract

- `tracing` is the structured observability backbone for the current execution model across stream and packet paths, even though stage coverage is richer on some paths than on others.
- `ProxyError` remains the cross-crate runtime error boundary.
- `ErrorKind` remains the stable failure-classification contract for runtime diagnostics and session summaries.
- crate-local typed errors are allowed, but runtime boundaries still converge to `ProxyError`.

## Error Model Rules

- do not remove `ProxyError`
- do not remove or weaken `ErrorKind`
- do not replace `ErrorKind` with crate-local typed errors
- keep `ProxyError::kind()` stable; breaking its mapping is a contract change

## Tracing Rules

- prefer structured tracing fields over hand-built `key=value` strings on the hot path
- keep event names and core field names stable unless there is a strong reason to change them
- the current baseline is structured text output, not JSON logging or a metrics pipeline
- human-readable host, domain, and tag values should stay directly inspectable
- structured classifications such as `error_kind` should remain machine-comparable
- line breaks in string-like fields should not break event structure

## Stable Event Families

- runtime lifecycle events
- session lifecycle events
- route-selection events
- connect and TLS events
- sniff diagnostic events
- relay events
- transparent-socket diagnostic events

Representative baseline events:

- `session_start`
- `route_select`
- `tcp_connect_attempt`
- `tcp_connect_failed`
- `tls_handshake_start`
- `tls_handshake_failed`
- `sniff_start`
- `sniff_success`
- `sniff_timeout`
- `sniff_no_match`
- `sniff_error`
- `session_finish`
- `transparent_socket_config`
- `listener_fallback`

## Stable Field Expectations

- `session_start` should keep `session_id`, `inbound`, `peer`, `destination`, and `network`
- `route_select` should keep `session_id`, `inbound`, `peer`, `destination`, `outbound`, and `route_reason`
- `session_finish` should keep `session_id`, `outbound`, `route_reason`, `success`, `duration_ms`, `bytes_up`, and `bytes_down`
- failure-side events should carry `error_kind` and `error` when the boundary already has a `ProxyError`
- connect and TLS events should keep `host`, `port`, and `resolved_addr` where applicable
- transparent-socket diagnostics should keep socket-family and errno-style fields needed for Linux troubleshooting

## Interpretation Rules

- sniff timeout and sniff no-match are routing diagnostics, not automatic session failures
- relay byte counters are observed progress metrics, not billing-grade accounting
- EOF in one direction is a normal relay completion path, not automatically a relay error

## Carried-Forward Non-Goals

- no kernel-level bypass action semantics
- no DNS / UDP / TUN / fake-ip observability surface
- no sniff destination override or generalized protocol-routing platform
- no Happy Eyeballs or parallel dialing observability model
- no built-in OpenTelemetry or metrics pipeline

## Validation Reminder

- `tproxy`, `routing_mark`, transparent socket behavior, and dual-stack transparent-proxy fallback still require Linux/OpenWrt device validation beyond unit and integration tests
