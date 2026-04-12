# VeeX Project Positioning

## One-Line Definition

VeeX is a Rust proxy core for OpenWrt-class and Linux router environments, intentionally focused on a narrow execution plane rather than a full networking platform.

## Role

- External shape:
  - `veex run -c <config>`
  - `veex check -c <config>`
  - `veex version`
- The real target is to replace the stream-first execution slice sing-box commonly provides in OpenWrt router topologies, while only taking on a minimal DNS hijack slice that still fits that execution-plane role.
- The typical target path is:
  - `DIRECT / SOCKS / REDIRECT / TPROXY -> veex -> direct | trojan`
- The current scope now includes a minimal UDP packet foundation for `direct-in -> direct-out`, primarily as groundwork for later DNS/detour work rather than as a broad UDP platform.

## Supported Surface

- Inbounds:
  - `direct`, TCP and minimal UDP
  - `socks`
  - `redirect`
  - `tproxy`, TCP only
- Outbounds:
  - `trojan`
  - `direct`, TCP stream and UDP packet session
  - sequential multi-address connect fallback
- Route:
  - `final`
  - minimal `route.rules` subset with ordered upgrade/final semantics
  - bounded `action="sniff"` context enrichment
  - `action="hijack-dns"` final handoff
- DNS:
  - internal DNS executor for TCP/UDP DNS ingress
  - `dns.rules` and `dns.final` server selection
  - UDP/TCP/TLS/HTTPS upstream via detour-aware outbound stream/packet capability
- Config compatibility:
  - a minimal sing-box-compatible JSON subset
  - `direct.routing_mark` is supported

## Explicit Non-Goals

- full built-in DNS platform
- fake-ip
- generalized UDP proxying beyond the current `direct-in -> direct-out` foundation
- TUN
- full `route.rules` engine
- sniff destination override or generalized protocol routing
- full sing-box compatibility
- downstream OpenWrt packaging / feed / LuCI integration

## DNS Boundary

- Minimal DNS hijack and UDP/TCP/TLS/HTTPS upstream execution are now in scope because they reuse the packet foundation, stream path, and detour model.
- DNS still must not pull VeeX into a larger platform shape: no FakeDNS, no cache-first resolver platform, and no general-purpose DNS policy engine in the current scope.
- Router deployments can still choose to keep DNS outside VeeX when that better fits the deployment.

## Repository Boundary

- Main repository owns:
  - Rust core
  - CLI
  - config
  - Linux transparent infrastructure
  - tests
  - examples
  - persistent project docs
- Downstream repositories own:
  - OpenWrt package / ipk
  - `procd` / init scripts
  - LuCI / feed integration

## Scope Notes

- the primary scope question is whether a request still serves the current execution-plane goal
- work that pushes VeeX beyond this minimal DNS execution slice toward a DNS platform, a generic routing engine, or downstream packaging belongs outside the current project scope or later roadmap
- `README.md` and `docs/architecture.md` are the stable public entrypoints for project framing
- `docs/roadmap.md` carries phase, milestone, and roadmap direction
