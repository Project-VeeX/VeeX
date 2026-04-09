# VeeX Roadmap

> Public roadmap document for VeeX.
> Focuses on completed phases, current priorities, and conditions for future expansion.
> For the current architecture boundary, see `docs/architecture.md`. For observability principles, see `docs/observability.md`.

## 1. Current Position

As of the current repository state (`0.5.1`), VeeX has established a narrow but usable TCP execution-plane baseline for router-oriented environments.

That baseline includes:

- TCP ingress through `socks`, `redirect`, and `tproxy`
- outbound execution through `direct` and `trojan`
- ordered `route.rules` evaluation with `route.final`
- bounded `action="sniff"` context enrichment
- sequential multi-address connect fallback
- structured observability and stable error classification

The project priority remains consolidation and validation of this TCP execution plane rather than expansion into a broader network platform.

## 2. Completed Phases

### Phase 1: Minimum Executable Path

Delivered:

- `socks` inbound
- `trojan` and `direct` outbounds
- relay
- CLI startup
- config load and config check

Phase conclusion:

- the execution path and crate split were viable

### Phase 2: Router Usability

Delivered:

- `redirect` inbound
- Linux original-destination recovery
- improved runtime and shutdown handling

Phase conclusion:

- system-integration knowledge had to become a durable project concern rather than remain only in task notes

### Phase 3: Transparent Proxy Execution Surface

Delivered:

- `tproxy` inbound
- `direct.routing_mark`
- dual-stack and IPv4-mapped-IPv6 transparent-proxy support

Phase conclusion:

- transparent proxy support required a dedicated Linux subsystem and explicit validation discipline, not just another inbound

### Phase 4: Engineering Hardening

Delivered:

- structured tracing
- typed error-model cleanup
- stronger config parsing and validation foundations
- a clearer observability baseline

Phase conclusion:

- observability, error classification, and config boundaries had to stabilize before widening the feature surface

### Phase 5: Unified Route Pipeline

Delivered:

- a minimal `route.rules` subset
- a unified ordered upgrade/final routing pipeline
- best-effort `action="sniff"` context enrichment
- ordinary route-rule modeling for private, loopback, and link-local direct routing

Phase conclusion:

- the routing model is now centered on `single-pass rules + context enrichment + default final action`

## 3. Current Priorities

The current roadmap remains focused on tightening the existing surface:

- real-device transparent-proxy validation, especially for `tproxy`, `routing_mark`, and `fw4/nft`
- keeping config contract, examples, tests, and public docs aligned
- preserving router, transport, and observability boundaries while implementation quality improves
- continuing to harden the existing TCP execution path rather than broadening scope prematurely

## 4. Out Of Scope For The Current Roadmap

The following are not part of the current roadmap:

- built-in DNS or FakeDNS
- DoH or DoT
- UDP proxying
- TUN
- kernel-level bypass semantics
- full sing-box compatibility
- expansion into a broader protocol-routing or network-platform role

## 5. Conditions For Future Expansion

Any future expansion should satisfy the current project constraints first:

- preserve the single ordered rule pipeline
- avoid hidden or implicit behavior
- keep Linux- or transport-specific behavior out of `core`
- preserve the current validation and observability contract

Under those conditions, future discussion may include:

- a richer but still explicit route matching or action surface
- stronger sniff-assisted routing within the current model
- incremental capabilities that still fit the TCP execution-plane role

## 6. Summary

VeeX is still in a consolidation phase: the main work is to harden, validate, and clarify the existing TCP execution plane rather than to widen the project into a larger networking system.

In one sentence:

```text
VeeX is prioritizing consolidation of its TCP execution plane over broad platform expansion.
```

## 7. Related Documents

- `docs/architecture.md` for the public architecture and capability boundary
- `docs/observability.md` for the public observability and error-model principles
- `CHANGELOG.md` for release-by-release changes
