# VeeX Architecture Whitepaper

> Public architecture whitepaper for VeeX.
> Focuses on the current execution model, capability boundary, and stable design semantics.
> For phase history and roadmap, see `docs/roadmap.md`. For observability and error-model principles, see `docs/observability.md`.

## 1. Overview

VeeX is a Rust execution core for OpenWrt-class and Linux router environments. Its role is intentionally narrow: provide a correct and observable TCP data plane plus a minimal UDP packet foundation for explicit-proxy and transparent-proxy-adjacent deployments.

The target topology is:

```text
SOCKS / REDIRECT / TPROXY
    -> VeeX
    -> direct | trojan
```

VeeX is not designed to be a full proxy platform, a DNS system, or a general network policy engine.

## 2. Design Principles

### 2.1 Minimal Yet Correct

VeeX prefers a small, reliable capability surface over broad feature coverage. The current project deliberately focuses on:

- TCP ingress and egress
- a minimal UDP packet execution path for `direct` inbound to `direct` outbound
- explicit routing decisions
- bounded context enrichment
- connection execution
- structured observability

### 2.2 Single Source Of Truth

Each responsibility belongs to one layer:

| Capability | Owning layer |
| --- | --- |
| configuration parsing | config |
| runtime orchestration | runtime / cli |
| route decision | router |
| outbound execution | outbound |
| connection setup | transport |
| stream forwarding | relay |

This keeps behavior explainable and avoids hidden policy spread across multiple layers.

### 2.3 Explicit Behavior

VeeX does not rely on implicit policy injection for routing. Direct-routing exceptions, private-network handling, and upstream recursion prevention must be expressed explicitly in configuration.

### 2.4 Observability First

The architecture assumes that key execution stages must remain visible and explainable. Routing, sniff, connect, TLS, and relay are treated as distinct stages with distinct diagnostics.

## 3. System Architecture

The main stream data path is:

```text
Inbound
-> Dispatcher
-> Router
-> Outbound
-> Transport (TCP / TLS)
-> Relay
```

The current minimal packet data path is:

```text
Direct UDP Inbound
-> PacketDispatcher
-> Router
-> Outbound
-> Packet session
-> Reverse packet path
```

At a high level:

| Component | Role |
| --- | --- |
| config | parse and validate the supported configuration surface |
| runtime | build services and own process lifecycle |
| router | evaluate ordered route rules and produce a route result |
| sniff | enrich routing context without changing destination semantics |
| outbound | execute the selected outbound behavior |
| transport | perform TCP connect and optional TLS handshake |
| relay | forward bytes between inbound and outbound streams |
| packet dispatcher | maintain UDP associations, outbound packet sessions, and reverse packet flow |

The current runtime ownership model is intentionally simple:

- protocol objects are the stable runtime owners of their own listener or dialer, protocol state, and lifecycle
- runtime and factory construct, register, start, and close services, but do not duplicate protocol state
- configuration input is lowered before protocol construction; runtime protocol objects keep runtime fields rather than raw input option bags

The current runtime skeleton is also intentionally layered:

- top-level `Inbound` and `Outbound` traits stay thin and lifecycle-oriented
- execution-model traits separate protocol families rather than collapsing all behavior into one mega trait
- inbound protocol objects submit normalized execution requests through a narrow sink view (`InboundSink`) rather than depending on dispatcher internals directly
- dispatcher stays thin: route still selects an outbound tag, dispatcher resolves that tag through a single outbound registry, and the selected outbound executes through one unified dispatcher-facing connector view (`OutboundConnector`) for stream and packet capabilities
- transparent destination recovery remains protocol-specific and does not get folded into `Listener`
- normalized trojan runtime fields use upstream address, key, and TLS capability rather than a raw config bag
- `Listener` and `Dialer` are shared infrastructure capabilities, not protocol-logic containers
- UDP association state belongs to the packet dispatcher, not to protocol-private inbound state

## 4. Routing Model

VeeX uses one ordered rule pipeline.

```text
for rule in ordered rules:
    if match(rule):
        execute action

        if action is Upgrade:
            continue

        if action is Final:
            return decision

return default final action
```

This model has two public consequences:

- upgrade actions enrich routing context and allow later rules to see that richer context
- final actions terminate routing and select the outbound path

`route.final` remains the default decision when no rule returns a final result.
In the current accepted configuration subset, `outbound` selection is the only supported final routing action, and `action="sniff"` is the only supported upgrade action.

Private, loopback, and link-local direct handling belongs in ordinary `route.rules`, not in a hidden bypass subsystem.

## 5. Sniff Model

Sniff is a bounded context-enrichment step inside routing. Its purpose is to extract domain information that later route rules may use.

Current public behavior:

- supports TLS SNI and HTTP `Host`
- writes enriched domain context for routing
- does not override the original destination
- does not trigger DNS behavior
- does not change transport policy
- is best effort rather than session-fatal

Sniff-dependent rules must be placed after the sniff rule that enriches the routing context.

## 6. Connection And Timeout Model

When a destination resolves to multiple candidate addresses, VeeX tries them sequentially.

```text
resolve -> addr1 -> addr2 -> addr3
```

Current behavior:

- attempts are ordered, not parallel
- each connect attempt is bounded by the configured connect timeout
- success stops the sequence
- there is no Happy Eyeballs or parallel dialing behavior

Timeouts remain stage-specific:

- sniff timeout
- TCP connect timeout
- TLS handshake timeout

VeeX does not merge these into a single global session deadline.

## 7. Transparent Proxy Positioning

Transparent proxy support is part of the intended project surface, but VeeX still treats it as a user-space execution plane rather than a kernel policy platform.

Important consequences:

- `redirect` and `tproxy` are ingress modes, not separate architecture models
- `tproxy` interception marks and `direct.routing_mark` serve different purposes
- dual-stack and IPv4-mapped IPv6 behavior are first-class deployment concerns
- explicit route rules remain the policy surface

## 8. Current Capability Boundary

The current public capability surface includes:

- inbound: `direct` for TCP and minimal UDP, `socks`, `redirect`, `tproxy` for TCP
- outbound: `direct` for TCP stream and UDP packet session, `trojan` for TCP stream
- routing: ordered `route.rules`, `route.final`, and `action="sniff"` upgrades
- connect behavior: sequential multi-address fallback
- runtime: foreground daemon-style execution with config checking
- packet execution: dispatcher-owned UDP association mapping for `direct-in -> direct-out`

The current public non-goals include:

- built-in DNS or FakeDNS
- generalized UDP proxying beyond the current `direct-in -> direct-out` foundation
- TUN
- kernel-level bypass semantics
- destination override based on sniffed data
- a generalized protocol-routing platform
- full sing-box compatibility

## 9. Relationship To Router Integrations

VeeX is intended to serve router-oriented deployments, including OpenWrt-class environments, but it does not attempt to absorb the entire integration stack.

This repository owns the execution core, configuration surface, examples, and core documentation. Packaging, service integration, and UI layers remain outside the main repository boundary.

## 10. Summary

VeeX is a focused execution core built around one routing pipeline, bounded context enrichment, explicit policy, and observable stage boundaries, with a deliberately small UDP packet foundation.

In one sentence:

```text
VeeX is a focused execution core built around ordered routing, bounded context enrichment, and a minimal UDP packet foundation.
```

## 11. Related Documents

- `docs/roadmap.md` for milestones and evolution direction
- `docs/observability.md` for public observability and error-model principles
- `CHANGELOG.md` for release-by-release changes
