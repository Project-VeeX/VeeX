# Task-Derived Gotchas

These constraints come from actual phase task packs, closure notes, and completed task results. Treat them as hard-earned project guidance, not generic best practices.

## Scope Constraints

- VeeX is currently a TCP execution plane. Do not silently expand the work into a DNS platform, UDP stack, TUN path, sniffing system, fake-ip, or full rule engine.
- `route.bypass` has been removed; express direct-routing exceptions through ordinary `route.rules` instead.
- OpenWrt packaging, `procd`, and LuCI/feed work belong to downstream repositories, not this main repo.

## Architecture Constraints

- Linux transparent-socket details belong in `crates/infra-linux` or equivalent platform-facing layers, not back in `crates/core`.
- `Router` stays pure computation: no I/O and no DNS during construction.
- `routing_mark` belongs only to direct outbound config and implementation; do not promote it into a `core` abstraction.
- Prefer conservative incremental changes. Do not reopen already-closed runtime or dispatcher boundaries just to fit a new feature.

## Real Failure Modes Already Seen

- `listen="::"` is not an edge input. On dual-stack OpenWrt systems it can receive IPv4-mapped-IPv6 traffic.
- Original-destination recovery must handle IPv4-mapped-IPv6 fallback, not just one attempt based on the socket family.
- IPv6 listener formatting must produce `[::]:port`, not `:::port`.
- Do not rely completely on system-default `bindv6only`; explicit `IPV6_V6ONLY=false` handling is safer.
- `tproxy` interception marks and `direct.routing_mark` must stay separate. Reusing one value for both creates loop and policy ambiguity.
- Direct egress currently keeps separate no-mark and marked paths. The marked path is an incremental extension and must not regress the no-mark baseline.

## Compatibility And Public-Doc Rules

- "Unknown fields tolerated, known fields strictly typed" is an intentional parser policy. Do not turn it into blanket permissiveness.
- Ignored fields do not imply implemented features; they only mean the current compatibility subset allows them to appear. Exception: `log.timestamp` is explicitly implemented, not ignored.
- Prefer neutral naming in public docs and fixtures. Internal tasks may discuss Passwall replacement, but public artifacts do not need to bind the repo to a single downstream product name.

## Phase 4 Engineering Gotchas

These are lessons from the Phase 4 engineering hardening work:

- Serde deserialization error messages include a path (e.g. `$.inbounds[0].listen`) via `serde_path_to_error`; this is the canonical diagnostic path, not something to re-implement
- Config parse errors from serde are distinct from preflight duplicate-key errors; preflight runs before serde, so duplicate-key errors are reported separately from type/structure errors
- `log.timestamp` controls RFC3339 timestamps in tracing output; enabling it requires `time::macros::format_description` and `UtcOffset::current_local_offset()`, which can fail on some platforms — the fallback is UTC without timestamps
- UTF-8 strings in JSON config must be preserved literally; the preflight parser validates UTF-8 validity and the `push_string_chunk` approach avoids double-decoding
- Relay partial bytes (`bytes_up`/`bytes_down`) are engineering observability metrics, not billing-grade counters; they are meaningful for diagnosing "did this fail early or mid-stream" but should not be treated as exact accounting

## Validation Rules

- `tproxy`, `routing_mark`, policy routing, and `CAP_NET_ADMIN`-dependent behavior cannot be proven by unit tests alone. Be explicit about which checks still require Linux/OpenWrt device closure.
- Config-compatibility changes should not stop at documentation language; align fixtures or automated tests too.
- If a proposal conflicts with these constraints, say so first, then discuss alternatives.
