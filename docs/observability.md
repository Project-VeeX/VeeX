# VeeX Observability Whitepaper

> Public observability whitepaper for VeeX.
> Focuses on operational visibility, stable diagnostics, and error-model expectations.
> For architecture and capability boundaries, see `docs/architecture.md`. For roadmap direction, see `docs/roadmap.md`.

## 1. Purpose

VeeX treats observability as part of the product surface, not as an afterthought. The goal is to make routing, connection setup, transparent-proxy behavior, and session termination explainable in production-oriented environments.

The public observability model answers four questions:

- what stage a session reached
- which route decision was selected
- why a connect or handshake failed
- whether the session transferred data before termination

## 2. Public Observability Model

VeeX uses structured tracing across its execution model. The current baseline is intentionally simple:

- structured events with stable names
- stable core fields for session and transport diagnostics
- text output through the current tracing subscriber stack

This document does not promise JSON logging, metrics export, file appenders, or OpenTelemetry integration.

## 3. Session Lifecycle Visibility

The execution model is observable as a sequence of stages. Some stages are stream-specific, some are packet-specific, and some are shared:

| Stage | What operators should be able to see |
| --- | --- |
| session start | who connected, through which inbound, toward which destination |
| route selection | which outbound was chosen and why |
| sniff | whether routing context was enriched, timed out, or produced no match |
| connect | which resolved address was attempted and whether it succeeded |
| TLS | whether handshake setup succeeded or failed on stream paths that use TLS |
| protocol | whether outbound protocol setup succeeded or failed on protocol-bearing stream paths |
| relay or packet forwarding | whether stream transfer or packet forwarding completed normally or failed |
| session finish | whether the session succeeded and how much traffic was observed |

The intent is stage clarity, not log volume for its own sake.

## 4. Error Model Contract

VeeX keeps a stable runtime error boundary so failures can be classified consistently across the system.

Public consequences:

- failures are expected to converge to stable runtime classifications
- routing and transport failures should remain explainable at the event level
- failure reporting should distinguish between session failure, stage timeout, and non-fatal routing diagnostics

For example, a sniff timeout is a routing diagnostic, not automatically a session failure.

## 5. Stable Event Families

The public baseline centers on these event families:

- runtime lifecycle events
- session lifecycle events
- route-selection events
- connect and TLS events
- protocol-setup events
- sniff diagnostic events
- relay completion and relay failure events
- transparent-socket diagnostic events

Representative event names include:

- `session_start`
- `route_select`
- `route_rule_eval`
- `route_rule_match`
- `route_rule_miss`
- `route_upgrade_applied`
- `route_final_selected`
- `route_default_final_selected`
- `tcp_connect_attempt`
- `tcp_connect_success`
- `tcp_connect_failed`
- `tls_handshake_start`
- `tls_handshake_failed`
- `protocol_handshake_start`
- `protocol_handshake_success`
- `protocol_handshake_failed`
- `sniff_start`
- `sniff_success`
- `sniff_timeout`
- `sniff_no_match`
- `sniff_error`
- `session_finish`
- `transparent_socket_config`

The exact set may evolve, but the event families and their operational purpose should remain stable.

## 6. Stable Diagnostic Fields

Operators and integrators should expect the core event model to preserve stable diagnostic fields such as:

- `session_id`
- `inbound`
- `peer`
- `destination`
- `outbound`
- `route_reason`
- `error_kind`
- `resolved_addr`
- `duration_ms`
- `bytes_up`
- `bytes_down`

For route-rule explainability, debug-level routing events also preserve fields such as:

- `rule_index`
- `action_kind`
- `matcher_summary`
- `miss_reason`
- `domain_before`
- `domain_after`

Two important interpretation rules:

- relay byte counters are observed transfer progress, useful for diagnosis rather than billing-grade accounting
- human-readable identifiers such as host, domain, and tag values should remain directly inspectable in event output

## 7. Transparent Proxy Diagnostics

Transparent-proxy deployments require visibility into Linux-specific behavior that cannot be inferred from generic TCP logs alone.

The public model therefore includes diagnostics around:

- transparent socket configuration
- original-destination recovery
- listener fallback behavior
- route outcomes around transparent-proxy ingress

This is especially important for `redirect`, `tproxy`, dual-stack listeners, and policy-routing environments.

## 8. Current Boundaries

The current observability whitepaper deliberately does not define:

- a metrics platform
- a trace-export backend
- a log shipping pipeline
- a kernel-bypass observability layer
- generalized observability for unsupported features outside the current VeeX scope

VeeX focuses on making the existing execution surface observable before widening into larger telemetry systems.

## 9. Validation Boundary

Some diagnostics can be validated in tests, but some still require real Linux or OpenWrt device closure.

That is especially true for:

- `tproxy`
- `routing_mark`
- transparent socket behavior
- dual-stack transparent-proxy edge cases

Public documentation should not overstate closure beyond the evidence actually recorded in the repository.

## 10. Summary

VeeX observability is designed around stage visibility, stable error classification, and production-facing diagnostics for stream and packet execution paths.

In one sentence:

```text
VeeX aims to make each major session stage visible, classifiable, and explainable.
```

## 11. Related Documents

- `docs/architecture.md` for the public architecture and capability boundary
- `docs/roadmap.md` for milestones and roadmap direction
- `CHANGELOG.md` for release-by-release changes
