# VeeX Project Positioning

## One-Line Definition

VeeX is a Rust proxy core for OpenWrt-class and Linux router environments, intentionally focused on a narrow execution plane rather than a full networking platform.

## Role

- External shape:
  - `veex run -c <config>`
  - `veex check -c <config>`
  - `veex version`
- The real target is to replace the TCP data-plane slice sing-box commonly provides in OpenWrt router topologies, not its DNS stack, policy platform, or full protocol surface.
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
- Config compatibility:
  - a minimal sing-box-compatible JSON subset
  - `direct.routing_mark` is supported

## Explicit Non-Goals

- built-in DNS server
- DoH / DoT client
- fake-ip
- generalized UDP proxying beyond the current `direct-in -> direct-out` foundation
- TUN
- full `route.rules` engine
- sniff destination override or generalized protocol routing
- full sing-box compatibility
- downstream OpenWrt packaging / feed / LuCI integration

## DNS Boundary

- The project conclusion is that DNS can stay decoupled from VeeX.
- Router deployments can continue to use external DNS split/steering components.
- Do not let DNS requirements pull VeeX into a larger platform shape.

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
- work that pushes VeeX toward a DNS platform, a generic routing engine, or downstream packaging belongs outside the current project scope or later roadmap
- `README.md` and `docs/architecture.md` are the stable public entrypoints for project framing
- `docs/roadmap.md` carries phase, milestone, and roadmap direction
