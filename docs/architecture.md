# VeeX Architecture Whitepaper

> Public architecture whitepaper for VeeX.
> Focuses on the current capability boundary, stable execution model, and implementation-independent terminology.
> For roadmap direction, see `docs/roadmap.md`. For observability and error-model principles, see `docs/observability.md`.

## 1. Overview

VeeX is a rust-based proxy runtime core. It implements a deliberately scoped sing-box-compatible subset and a deliberately narrow proxy execution surface.

The current deployment shape is:

```text
direct | socks | redirect | tproxy
    -> VeeX
    -> direct | trojan
```

VeeX is not a full networking platform, a general-purpose DNS platform, or a generalized UDP proxy stack.

## 2. Layer And Pipeline

VeeX documentation distinguishes between `Layer` and `Pipeline`.

### 2.1 Layer

Layer describes capability ownership.

```text
portal
  -> [protocol]
  -> transport
  -> execution
```

`protocol` is optional. Direct components do not pass through it.

### 2.2 Pipeline

Pipeline describes runtime execution order for a specific component path.

Example outbound pipelines:

- Trojan outbound:

```text
dial -> tls -> protocol establish
```

- Direct outbound:

```text
dial
```

Layer and Pipeline are intentionally different concepts. A crate layout also does not define a Layer on its own.

## 3. Core Capability Boundary

At a high level:

| Capability | Current owner |
| --- | --- |
| core types, session metadata, and runtime contracts | `core` |
| config preflight, parse, validate, and schema | `config` |
| runtime assembly and lifecycle | `cli` |
| route decision | `router` |
| stream execution | `execution` |
| packet execution | `execution` |
| transport connect and TLS | `transport` |
| shared outbound protocol adapter surface | `protocol` |
| inbound components | `portal-inbound` |
| outbound components | `portal-outbound` |
| DNS runtime | `dns` |

The current semantic mainline is:

```text
config -> router -> execution
```

where `config` is the semantic entry, `router` is the policy plane, and `execution` is the data plane.

`cli/factory` is the control-plane assembly path that performs:

```text
config -> lowering -> builder -> runtime wiring
```

The current workspace structure includes `config`, `router`, `execution`, `cli`, `core`, `transport`, `protocol`, `portal-inbound`, `portal-outbound`, `dns`, `infra-linux`, and `observability`.

## 4. Execution

Execution is an explicit dual-plane model and a pure data-plane runtime. It performs network execution from an already selected route result; it does not own route rules or make routing decisions.

At the plane boundary, routed dispatch bridges obtain a `RouteResult` from the router and then hand that result to the execution runtime.

- `StreamDispatch` for stream execution
- `PacketDispatch` for packet execution

The stream path is:

```text
inbound handoff
-> StreamDispatch
-> Router
-> selected outbound
-> relay
```

The current packet path is:

```text
first packet
-> PacketDispatch
-> Router
-> association create
-> selected outbound packet session
-> association-managed reverse flow
-> idle reclaim or runtime shutdown
```

These two execution paths are peers. VeeX does not collapse them into a single TCP/UDP abstraction, and documentation should not describe one of them as architecturally subordinate to the other.

Packet execution keeps its own lifecycle semantics:

- the first packet owns route selection and association creation
- the association owns packet-session state, outbound packet binding, and reverse-path lifetime
- subsequent packets with the same association key bypass routing and stay on the existing association
- reverse-path exit, idle reclaim, and runtime shutdown are all close paths, but they remain distinct lifecycle reasons

## 5. Transport

`veex-transport` is the foundation stream-carrier layer.

Its current responsibilities are:

- host resolution
- TCP connect
- sequential multi-address fallback
- TLS handshake
- certificate verifier setup

Its current non-responsibilities are:

- proxy protocol framing
- route selection
- relay logic
- listener behavior

The current transport crate is stream-oriented. Direct UDP packet dialing remains a component-level responsibility in `portal-outbound::direct`.

## 6. Protocol

Protocol is the optional protocol-semantics layer. It exists only where a component has proxy protocol meaning beyond carrier setup.

Current protocol-bearing paths:

- outbound-side:
  - Trojan
- inbound-side:
  - SOCKS5 server-side processing

Current protocol rules:

- protocol does not own listener accept loops
- protocol does not own TCP connect
- protocol does not own route selection or dispatch
- protocol runs on top of an already accepted or already connected carrier

The current shared protocol crate, `veex-protocol`, contains:

- generic adapter types
- Trojan stream adapter logic

SOCKS5 inbound protocol processing is currently a local module inside `portal-inbound::socks`. It is an inbound protocol step in the architecture sense, but it is not yet part of the shared `veex-protocol` crate.

## 7. Portal

Portal is the component layer. It owns:

- component lifecycle
- runtime fields such as `meta` and `logger`
- listener or dialer composition
- component-local pipeline organization
- handoff into execution

Portal does not absorb transport internals or execution internals.

Current top-level component traits remain intentionally thin:

- `Inbound`
- `StreamInbound`
- `TransparentInbound`
- `Outbound`
- `StreamOutbound`
- `ProxyOutbound`

## 8. Inbound Model

Inbound currently has two stable shapes.

### 8.1 No Access Protocol

This shape applies to:

- `direct`
- `transparent`

Layer view:

```text
portal -> listener -> execution
```

`direct` does not perform handshake or protocol parsing. It lowers destination metadata from the accepted carrier and hands the session to execution.

`transparent` is also a no-access-protocol model. `redirect` and `tproxy` are special ingress modes, not protocols. Their defining behavior is listener-side destination recovery and metadata lowering.

### 8.2 Access Protocol Present

This shape currently applies to:

- `socks`

Layer view:

```text
portal -> inbound protocol -> execution
```

The SOCKS inbound portal accepts the carrier through a listener, runs SOCKS5 server-side protocol processing on the accepted stream, receives a normalized request result, and then hands the session to `StreamDispatch`.

## 9. Listener

`Listener` and `PacketListener` are shared ingress primitives.

Their current responsibilities are:

- bind
- listen
- accept or receive
- spawn and close listener tasks
- expose carrier-local metadata to component code

Their current non-responsibilities are:

- proxy protocol parsing
- route selection
- outbound behavior

Transparent destination recovery is still component-specific and remains outside `core::portal::listener`.

## 10. Outbound Model

Outbound currently has two stable shapes.

The current shared outbound stream chain is:

```text
resolve -> connect -> (tls) -> (protocol) -> relay
```

Phase ownership stays explicit:

- resolve: domain resolution to concrete socket targets
- connect: TCP dialing over resolved targets, including connect-timeout handling
- tls: optional TLS handshake, including TLS handshake timeout
- protocol: protocol-specific stream setup after carrier setup
- relay: bidirectional transfer after outbound preparation succeeds

Relay keeps its own terminal lifecycle semantics:

- relay starts only after the outbound stream is fully established
- upstream and downstream are symmetric relay directions inside execution, not routing concepts
- EOF on one direction triggers relay-local half-close and shutdown propagation toward the peer writer
- relay finish, relay failure, and stats finalization are separate outcomes that must remain observable

### 10.1 No Protocol

This shape applies to:

- `direct`

Layer view:

```text
portal -> transport -> execution
```

Direct outbound uses `Dialer` for streams and `PacketDialer` for packet sessions. These are peer carrier paths inside the direct outbound model. Direct outbound does not enter the protocol layer.
On the stream path, direct outbound uses the shared resolve/connect chain and then enters relay directly.

### 10.2 Protocol Present

This shape applies to:

- `trojan`

Layer view:

```text
portal -> protocol -> transport -> execution
```

Trojan protocol logic remains outside the component crate in `veex-protocol`. The outbound component does not hold a protocol field. Instead, protocol is invoked inside the connect pipeline after TCP and TLS setup.
On the stream path, trojan outbound keeps the same resolve/connect base semantics as direct outbound, then adds optional TLS and Trojan request setup before relay.

## 11. Dialer

`Dialer` and `PacketDialer` are outbound-side carrier dialing primitives.

The current `Dial` model includes:

- `detour`
- `connect_timeout`
- `routing_mark`
- `disable_tcp_keep_alive`
- `tcp_keep_alive`
- `tcp_keep_alive_interval`
- `domain_resolver`

Dispatcher does not call transport directly. The runtime flow is:

```text
session -> selected outbound -> dialer or packet_dialer
```

Dialers derive request-specific dialing context from `SessionContext`, including resolver context propagation.

Timeout boundaries stay phase-specific:

- `connect_timeout` applies only to the connect stage
- `disable_tcp_keep_alive` / `tcp_keep_alive` / `tcp_keep_alive_interval` apply only to TCP socket dialing behavior
- `tls.handshake_timeout` and `tls.alpn` apply only to the TLS stage
- protocol setup failures stay in the protocol stage
- relay failures stay in the relay stage and do not back-propagate as connect or TLS failures

## 12. Routing And Sniff

Router is not a pure rule matcher. It is a policy runtime with one ordered route pipeline.

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

This runtime supports both upgrade actions and final actions, and the router runtime yields a `RouteResult` that execution consumes.

Current public consequences:

- `action="sniff"` is an upgrade action
- `action="hijack-dns"` is a final action
- `route.final` remains the default final decision
- private, loopback, and link-local handling belong in ordinary `route.rules`

The route model should not be described as a legacy select-style API or as a pure `rule scan -> return outbound` matcher.

Sniff is bounded context enrichment. It can enrich route-visible domain context, but it does not override the original destination and does not change transport policy by itself.

## 13. DNS

`veex-dns` is a separate runtime subsystem.

Its current roles are:

- execute client DNS queries
- resolve outbound domain names through a controlled resolver path
- select DNS upstreams through a DNS-specific router
- reach upstream servers through outbound detour capability
- apply in-memory response cache at the DNS runtime layer
- run single or concurrent upstream exchange after server selection

For dial-side resolution, the current upstream selection order is:

1. explicit `domain_resolver.server`
2. safe `dns.final`
3. safe default fallback, preferring `detour="direct"`
4. fail when no safe DNS server is available

The current safety guard is explicit and narrow:

- do not reuse the caller outbound as the DNS server detour
- do not recurse back into the caller DNS server tag
- keep recursion bounded by resolver-depth checks

The current DNS runtime closure keeps cache and concurrency inside the existing execution boundary:

- router still selects DNS server candidates and does not become a cache or policy engine
- cache lookup happens after server selection and before upstream exchange
- cache key is scoped by normalized query name, query type, and the selected candidate-set context
- only successful responses with a usable TTL are cached; negative and stale/expired responses are not reused
- concurrent upstream exchange chooses the first usable success from the selected candidate set and cancels or ignores losers
- explicit `domain_resolver`, safe `dns.final`, and safe default fallback semantics remain unchanged
- FakeDNS, fake-ip reverse mapping, persistent cache, and optimistic/stale cache are not part of the current architecture

Current dial-side resolution failures stay inside the existing runtime error model, including:

- recursion depth exceeded
- no safe DNS server available
- explicit `domain_resolver` points to a missing server
- upstream exchange failure
- upstream response without usable `A`/`AAAA` answers

Current DNS upstream transports include:

- `local`
- `udp`
- `tcp`
- `tls`
- `https`

`hijack-dns` is integrated as a route final action. Stream and packet execution can both hand requests to the DNS executor.

## 14. CLI And Factory

`cli`, especially `cli/factory`, is the control-plane assembly layer.

It is responsible for:

- consuming config that has already passed `preflight -> parse -> validate`
- lowering validated config into explicit runtime inputs
- constructing type-specific builders from lowered config
- constructing the route pipeline from lowered route config
- constructing outbounds
- constructing DNS services
- constructing routed stream and packet dispatchers
- constructing inbounds
- wiring lifecycle ownership and runtime references together
- starting and closing runtime services

It is not responsible for implementing listener behavior, transport behavior, or protocol logic.

## 15. Current Non-Goals

The current architecture does not imply support for:

- full sing-box compatibility
- generalized UDP proxying beyond the current direct packet foundation
- TUN
- FakeDNS
- destination override from sniffed metadata
- Happy Eyeballs or parallel dialing
- a protocol-agnostic mega framework that hides the real stream and packet models

## 16. Summary

VeeX uses explicit stream and packet execution paths, a transport layer for carrier setup, an optional protocol layer for protocol-bearing components, and a portal layer for component lifecycle and pipeline organization.

The current component surface is still uneven across those paths: some components are stream-only today, while others implement both stream and packet behavior. That implementation asymmetry should be documented as a component fact, not as an execution-layer hierarchy.

In one sentence:

```text
VeeX is a rust-based proxy runtime core with explicit stream and packet execution boundaries, optional protocol steps, and a deliberately narrow current packet and DNS surface.
```

## 17. Related Documents

- `docs/roadmap.md` for current priorities and future-direction constraints
- `docs/observability.md` for public observability and error-model principles
- `CHANGELOG.md` for release-by-release changes
