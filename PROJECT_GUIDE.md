# Project Guide

## Purpose

VeeX is a Rust proxy core for OpenWrt-class and Linux router environments.

The project goal is narrow and explicit:

- provide a TCP execution plane
- support explicit proxy and transparent proxy paths
- stay small enough to evolve predictably in router-oriented deployments

## Role

VeeX is a daemon-style TCP execution plane. It is designed to take local inbound traffic and forward it to either `direct` or `trojan` outbounds in explicit-proxy and transparent-proxy deployments.

The intended replacement surface is narrow:

- `socks`, `redirect`, and `tproxy` TCP ingress
- `direct` and `trojan` outbound execution
- minimal routing, bypass, and first-match rule behavior

VeeX is not intended to replace a full DNS stack, a general policy platform, or a broader network subsystem.

## Supported Surface

Supported surface:

- inbound:
  - `socks`
  - `redirect`
  - `tproxy` for TCP only
- outbound:
  - `trojan`
  - `direct`
  - sequential multi-address connect fallback
- route:
  - `final`
  - basic `bypass`
  - minimal `rules` matcher subset: `domain`, `domain_suffix`, `ip_cidr`, `port`, `inbound`
  - `route.rules` supports final route actions via `outbound` and the `sniff` upgrade action
- CLI:
  - `veex run -c <config>`
  - `veex check -c <config>`
  - `veex version`

## Non-Goals

The following are outside the current project scope:

- built-in DNS server
- DoH / DoT client
- fake-ip
- UDP proxying
- TUN
- full `route.rules` engine
- sniff destination override, FakeDNS, or protocol routing
- full sing-box compatibility
- OpenWrt packaging, `procd`, and LuCI integration in this repository

## Repository Boundary

This repository owns:

- Rust core crates
- CLI
- config parsing and validation
- Linux transparent-proxy infrastructure
- tests
- examples

This repository does not own:

- downstream OpenWrt package feeds
- service integration repositories
- LuCI applications

## Target Topology

The target topology is the TCP data plane commonly used in router deployments:

```text
SOCKS / REDIRECT / TPROXY
    -> veex
    -> direct | trojan
```

DNS and higher-level routing systems are intentionally outside this repository and outside the current VeeX scope.

## Workspace Structure

Workspace crates:

- `crates/cli`
- `crates/config`
- `crates/core`
- `crates/infra-linux`
- `crates/inbound-redirect`
- `crates/inbound-socks`
- `crates/inbound-tproxy`
- `crates/observability`
- `crates/outbound-direct`
- `crates/outbound-trojan`
- `crates/transport`

High-level responsibility split:

- `cli`: command entrypoints, runtime, bootstrap, factory wiring
- `config`: schema, parse, validate, compatibility boundary
- `core`: platform-agnostic types, router, dispatcher, relay, error model
- `infra-linux`: Linux transparent-socket and original-destination support
- `inbound-*`: inbound protocol implementations
- `outbound-*`: outbound implementations
- `transport`: shared transport and TLS support
- `observability`: session logging and observation support

## Runtime Model

VeeX runs as a foreground daemon.

Expected behavior:

- no self-daemonization
- logs go to stdout/stderr
- clean process shutdown on `SIGINT` and `SIGTERM`
- `veex check` validates config without starting the daemon

## Compatibility Contract

VeeX accepts a minimal sing-box-compatible JSON subset.

Commonly used fields include:

- `log.level`
- `log.disabled`
- `inbounds[]`
- `outbounds[]`
- `outbounds[].connect_timeout`
- `outbounds[].tls.handshake_timeout`
- `route.final`
- `route.bypass`
- `route.rules`
- `route.rules[].action`
- `route.rules[].timeout`
- `direct.routing_mark`

Compatibility rules:

- supported inbound types: `socks`, `redirect`, `tproxy`
- inbound `listen` accepts IPv4 literals, IPv6 literals, and bracketed IPv6 literals
- supported outbound types: `trojan`, `direct`
- `outbounds[].connect_timeout` is a per-address TCP connect timeout
- `outbounds[].tls.handshake_timeout` is a TLS handshake-only timeout
- trojan currently requires `tls.enabled=true`; `tls.enabled=false` is rejected, so `handshake_timeout` only has meaning when TLS is enabled
- omitted `tproxy.network` is treated as TCP
- `tproxy.network="tcp"` is accepted
- any other `tproxy.network` value is rejected
- unknown unrelated fields may be tolerated by the parser
- tolerated fields do not imply implemented features

Route and compatibility notes:

- `route.bypass` currently supports exact domain and exact IP matches
- `route.bypass` does not currently support CIDR ranges, suffix matching, or a rule engine
- wildcard and suffix-style bypass entries such as `*.example.com` and `.example.com` are rejected as unsupported patterns
- `route.rules` currently supports `domain`, `domain_suffix`, `ip_cidr`, `port`, and `inbound` matchers
- regular route rules still use `outbound` as the final route action
- `route.rules[].action="sniff"` is a route upgrade action that extracts `RouteInput.domain` from TLS SNI or HTTP Host
- `route.rules[].timeout` is only valid for `action="sniff"` and defaults to `300ms`
- sniff is best effort: timeout, no-match, or unsupported input does not fail the session
- sniff does not override destination, does not do DNS resolution, and does not change connect or TLS handshake timeout behavior
- `route.rules` evaluates in declaration order: matching upgrade actions continue with enriched context, and the first matching final action ends routing
- built-in bypass order is loopback, private, link-local, configured bypass, `route.rules`, then final outbound
- built-in bypass still applies before configured bypass
- ignored fields must not be described as supported features

Fields that may appear in compatibility fixtures but are not part of the current implementation surface include:

- `dns`
- `domain_resolver`
- `log.output`

## Design Constraints

Project-level constraints that should remain stable:

- VeeX is a TCP execution plane, not a general network platform
- `core` stays platform-agnostic
- Linux transparent-socket details belong in Linux-facing layers, not `core`
- `Router` construction remains pure; runtime route upgrades may perform bounded best-effort sniff I/O before outbound selection
- config compatibility should stay explicit and conservative

Additional engineering constraints:

- `routing_mark` belongs to direct outbound configuration and implementation, not a `core` routing abstraction
- runtime, bootstrap, and factory orchestration should remain in `cli`
- the controlled JSON parser is for the current config subset, not a general-purpose JSON implementation
- when a resolved host yields multiple addresses, outbound connect paths try them sequentially and stop on first success
- VeeX does not implement Happy Eyeballs, parallel dialing, or post-connect retry to another IP

## Transparent Proxy Notes

Transparent proxy support is a first-class part of the current project, not an afterthought.

Important engineering conclusions:

- dual-stack listeners matter in real deployments
- `listen="::"` and bracketed IPv6 literals are valid inputs for the current compatibility surface
- IPv4-mapped-IPv6 traffic must be handled correctly during transparent-proxy recovery paths
- `tproxy` interception marks and `direct.routing_mark` serve different purposes and must remain distinct

These constraints should shape both code changes and documentation changes.

## Operational Signals

The operational contract centers around structured session events.

Important event names include:

- `event=tcp_connect_attempt`
- `event=tcp_connect_failed`
- `event=tcp_connect_success`
- `event=tls_handshake_start`
- `event=tls_handshake_failed`
- `event=tls_handshake_success`
- `event=sniff_start`
- `event=sniff_success`
- `event=sniff_timeout`
- `event=sniff_no_match`
- `event=sniff_error`
- `event=session_start`
- `event=route_select`
- `event=session_finish`

Important fields include:

- `original_dst`
- `outbound`
- `reason`
- `error_kind`

Successful sessions should end with `error_kind=none`.

## Examples

Repository examples:

- `examples/socks-trojan.json`
- `examples/redirect-trojan.json`
- `examples/tproxy-compat.json`

Use these as starting points for local validation and smoke checks.
