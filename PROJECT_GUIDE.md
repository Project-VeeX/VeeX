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
- minimal routing and bypass behavior

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
- route:
  - `final`
  - basic `bypass`
- CLI:
  - `veex run -c <config>`
  - `veex check -c <config>`
  - `veex version`

## Non-Goals

The following are outside the current project scope:

- built-in DNS server
- DoH / DoT client
- fake-ip
- sniff
- UDP proxying
- TUN
- full `route.rules` execution
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
- `route.final`
- `route.bypass`
- `direct.routing_mark`

Compatibility rules:

- supported inbound types: `socks`, `redirect`, `tproxy`
- inbound `listen` accepts IPv4 literals, IPv6 literals, and bracketed IPv6 literals
- supported outbound types: `trojan`, `direct`
- omitted `tproxy.network` is treated as TCP
- `tproxy.network="tcp"` is accepted
- any other `tproxy.network` value is rejected
- unknown unrelated fields may be tolerated by the parser
- tolerated fields do not imply implemented features

Route and compatibility notes:

- `route.bypass` currently supports exact domain and exact IP matches
- `route.bypass` does not currently support CIDR ranges, suffix matching, or a rule engine
- wildcard and suffix-style bypass entries such as `*.example.com` and `.example.com` are rejected as unsupported patterns
- built-in bypass order is loopback, private, link-local, configured bypass, then final outbound
- built-in bypass still applies before configured bypass
- ignored fields must not be described as supported features

Fields that may appear in compatibility fixtures but are not part of the current implementation surface include:

- `dns`
- `route.rules`
- `domain_resolver`
- `log.timestamp`
- `log.output`

## Design Constraints

Project-level constraints that should remain stable:

- VeeX is a TCP execution plane, not a general network platform
- `core` stays platform-agnostic
- Linux transparent-socket details belong in Linux-facing layers, not `core`
- `Router` remains pure computation and does not perform I/O or DNS resolution during construction
- config compatibility should stay explicit and conservative

Additional engineering constraints:

- `routing_mark` belongs to direct outbound configuration and implementation, not a `core` routing abstraction
- runtime, bootstrap, and factory orchestration should remain in `cli`
- the controlled JSON parser is for the current config subset, not a general-purpose JSON implementation

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
